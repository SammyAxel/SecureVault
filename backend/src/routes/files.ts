import { FastifyInstance } from 'fastify';
import { db, schema } from '../db/index.js';
import { eq, and, isNull } from 'drizzle-orm';
import { authenticate, AuthenticatedRequest } from '../middleware/auth.js';
import { saveFile, getFile, deleteFile, getStream, getStats } from '../lib/storage.js';
import { scanFile as virusTotalScan } from '../lib/virustotal.js';
import { scanFile as malwareBazaarScan } from '../lib/malwarebazaar.js';
import { generateUUID, generateUID } from '../lib/crypto.js';
import { purgeTrashedOlderThanDays } from '../lib/trashRetention.js';
import { z } from 'zod';
import { logAudit } from './admin.js';
import { getClientIp } from '../lib/clientIp.js';

const createFolderSchema = z.object({
  name: z.string().min(1).max(255),
  parentId: z.string().uuid().optional().nullable(),
});

const renameSchema = z.object({
  name: z.string().min(1).max(255),
});

const moveSchema = z.object({
  parentId: z.string().uuid().nullable(),
});

export async function fileRoutes(app: FastifyInstance): Promise<void> {
  // Helper: recursively collect all descendants (files + folders)
  const getAllChildFiles = async (parentId: string): Promise<typeof schema.files.$inferSelect[]> => {
    const children = await db.query.files.findMany({
      where: eq(schema.files.parentId, parentId),
    });
    
    let allFiles: typeof schema.files.$inferSelect[] = [...children];
    for (const child of children) {
      if (child.isFolder) {
        const subChildren = await getAllChildFiles(child.id);
        allFiles = [...allFiles, ...subChildren];
      }
    }
    return allFiles;
  };
  
  // ============ LIST FILES ============
  app.get('/api/files', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;
    const { parentId } = request.query as { parentId?: string };
    
    const files = await db.query.files.findMany({
      where: and(
        eq(schema.files.ownerId, user.id),
        eq(schema.files.isDeleted, false),
        parentId ? eq(schema.files.parentId, parentId) : isNull(schema.files.parentId)
      ),
      orderBy: (files: any, { desc }: any) => [desc(files.isFolder), desc(files.createdAt)],
    });
    
    return {
      ok: true,
      files: files.map((f: any) => ({
        id: f.id,
        uid: f.uid,
        filename: f.filename,
        fileSize: f.fileSize,
        isFolder: f.isFolder,
        parentId: f.parentId,
        createdAt: f.createdAt,
        encryptedKey: f.encryptedKey,
        iv: f.iv,
      })),
    };
  });
  
  // ============ GET FILE/FOLDER BY UID (Authenticated) ============
  app.get('/api/f/:uid', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;
    const { uid } = request.params as { uid: string };
    
    const file = await db.query.files.findFirst({
      where: and(
        eq(schema.files.uid, uid),
        eq(schema.files.isDeleted, false)
      ),
    });
    
    if (!file) {
      return reply.status(404).send({ ok: false, msg: 'File not found' });
    }
    
    // Check ownership or share access
    if (file.ownerId !== user.id) {
      const share = await db.query.fileShares.findFirst({
        where: and(
          eq(schema.fileShares.fileId, file.id),
          eq(schema.fileShares.recipientId, user.id)
        ),
      });
      
      if (!share) {
        return reply.status(403).send({ ok: false, msg: 'Access denied' });
      }
    }
    
    // Get parent path for navigation
    const getParentPath = async (parentId: string | null): Promise<Array<{ id: string; uid: string | null; name: string }>> => {
      if (!parentId) return [];
      const parent = await db.query.files.findFirst({
        where: eq(schema.files.id, parentId),
      });
      if (!parent) return [];
      const ancestors = await getParentPath(parent.parentId);
      return [...ancestors, { id: parent.id, uid: parent.uid, name: parent.filename }];
    };
    
    const parentPath = await getParentPath(file.parentId);
    
    return {
      ok: true,
      file: {
        id: file.id,
        uid: file.uid,
        filename: file.filename,
        fileSize: file.fileSize,
        isFolder: file.isFolder,
        parentId: file.parentId,
        createdAt: file.createdAt,
        encryptedKey: file.encryptedKey,
        iv: file.iv,
      },
      parentPath,
    };
  });
  
  // ============ UPLOAD FILE ============
  app.post('/api/upload', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;
    
    const data = await request.file();
    if (!data) {
      return reply.status(400).send({ ok: false, msg: 'No file provided' });
    }
    
    const buffer = await data.toBuffer();
    const fileSize = buffer.length;
    
    // Check storage quota
    const remaining = user.storageQuota! - user.storageUsed!;
    if (fileSize > remaining) {
      return reply.status(400).send({
        ok: false,
        msg: `Storage quota exceeded. You have ${remaining} bytes remaining.`,
        quotaExceeded: true,
      });
    }

    // Check filesystem free space (total storage follows backend disk/mount)
    const backendStats = await getStats();
    if (backendStats && backendStats.free < fileSize) {
      return reply.status(507).send({
        ok: false,
        msg: 'Storage backend is full. Not enough disk space.',
      });
    }

    // Get metadata from fields
    const fields = data.fields as any;
    const encryptedKey = fields.encrypted_key?.value;
    const iv = fields.iv?.value;
    const fileHash = fields.file_hash?.value;
    const parentId = fields.parent_id?.value || null;
    
    if (!encryptedKey || !iv) {
      return reply.status(400).send({ ok: false, msg: 'Missing encryption metadata' });
    }

    // Malware scan: VirusTotal and/or Malware Bazaar (when configured)
    const vtResult = await virusTotalScan(buffer, data.filename, fileHash);
    const mbResult = await malwareBazaarScan(buffer, data.filename, fileHash);

    if (!vtResult.safe || !mbResult.safe) {
      const msg = !vtResult.safe
        ? (vtResult.error ?? `File flagged as malicious (${vtResult.malicious ?? 0} engines). Upload blocked.`)
        : (mbResult.error ?? (mbResult.signature ? `File is known malware (${mbResult.signature}). Upload blocked.` : 'File flagged by Malware Bazaar. Upload blocked.'));

      await logAudit(
        user.id,
        user.username,
        'UPLOAD_BLOCKED',
        'FILE',
        undefined,
        {
          filename: data.filename,
          fileSize,
          virusTotalScan: !vtResult.safe ? {
            result: 'MALICIOUS',
            maliciousCount: vtResult.malicious ?? 0,
            suspiciousCount: vtResult.suspicious ?? 0,
            hashFound: vtResult.hashFound ?? false,
            error: vtResult.error ?? null,
          } : undefined,
          malwareBazaarScan: !mbResult.safe ? {
            result: 'MALICIOUS',
            hashFound: mbResult.hashFound,
            signature: mbResult.signature,
            error: mbResult.error ?? null,
          } : undefined,
        },
        getClientIp(request),
        request.headers['user-agent']
      );

      return reply.status(400).send({
        ok: false,
        msg,
        malwareDetected: true,
      });
    }

    // Save file to storage
    const { relativePath } = await saveFile(user.id, buffer);
    
    // Save metadata to database
    const fileId = generateUUID();
    const fileUid = generateUID();
    await db.insert(schema.files).values({
      id: fileId,
      uid: fileUid,
      filename: data.filename,
      ownerId: user.id,
      encryptedKey,
      iv,
      storagePath: relativePath,
      fileSize,
      parentId,
    });
    
    // Update user storage
    await db.update(schema.users)
      .set({ storageUsed: user.storageUsed! + fileSize })
      .where(eq(schema.users.id, user.id));
    
    // Log audit with scan details (VirusTotal + Malware Bazaar)
    await logAudit(
      user.id,
      user.username,
      'UPLOAD',
      'FILE',
      fileId,
      {
        filename: data.filename,
        fileSize,
        uid: fileUid,
        virusTotalScan: {
          result: vtResult.hashFound === false ? 'UNKNOWN' : 'CLEAN',
          maliciousCount: vtResult.malicious ?? 0,
          suspiciousCount: vtResult.suspicious ?? 0,
          hashFound: vtResult.hashFound ?? false,
          error: vtResult.error ?? null,
        },
        malwareBazaarScan: {
          result: mbResult.hashFound === false ? 'UNKNOWN' : 'CLEAN',
          hashFound: mbResult.hashFound ?? false,
          error: mbResult.error ?? null,
        },
      },
      getClientIp(request),
      request.headers['user-agent']
    );
    
    return { ok: true, fileId, uid: fileUid };
  });
  
  // ============ CREATE FOLDER ============
  app.post('/api/folders', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;
    
    const body = createFolderSchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ ok: false, msg: 'Invalid request' });
    }
    
    const { name, parentId } = body.data;
    
    const folderId = generateUUID();
    const folderUid = generateUID();
    await db.insert(schema.files).values({
      id: folderId,
      uid: folderUid,
      filename: name,
      ownerId: user.id,
      encryptedKey: '', // Folders don't have encrypted keys
      iv: '',
      isFolder: true,
      parentId: parentId || null,
    });
    
    return { ok: true, folderId, uid: folderUid };
  });
  
  // ============ DOWNLOAD FILE ============
  app.get('/api/files/:fileId/download', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;
    const { fileId } = request.params as { fileId: string };
    
    // Check ownership or share access
    const file = await db.query.files.findFirst({
      where: and(
        eq(schema.files.id, fileId),
        eq(schema.files.isDeleted, false)
      ),
    });
    
    if (!file) {
      return reply.status(404).send({ ok: false, msg: 'File not found' });
    }
    
    // Check if user owns the file or has share access
    let encryptedKey = file.encryptedKey;
    
    if (file.ownerId !== user.id) {
      const share = await db.query.fileShares.findFirst({
        where: and(
          eq(schema.fileShares.fileId, fileId),
          eq(schema.fileShares.recipientId, user.id)
        ),
      });
      
      if (!share) {
        return reply.status(403).send({ ok: false, msg: 'Access denied' });
      }
      
      encryptedKey = share.encryptedKey;
    }
    
    if (file.isFolder || !file.storagePath) {
      return reply.status(400).send({ ok: false, msg: 'Cannot download folder' });
    }
    
    // Stream file
    const stream = getStream(file.storagePath);
    
    reply.header('Content-Type', 'application/octet-stream');
    reply.header('Content-Disposition', `attachment; filename="${file.filename}"`);
    reply.header('X-Encrypted-Key', encryptedKey);
    reply.header('X-IV', file.iv);
    
    return reply.send(stream);
  });
  
  // ============ DELETE FILE ============
  app.delete('/api/files/:fileId', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;
    const { fileId } = request.params as { fileId: string };
    const { permanent } = request.query as { permanent?: string };
    const isPermanent = permanent === 'true';
    
    const file = await db.query.files.findFirst({
      where: and(
        eq(schema.files.id, fileId),
        eq(schema.files.ownerId, user.id)
      ),
    });
    
    if (!file) {
      return reply.status(404).send({ ok: false, msg: 'File not found' });
    }

    // Default behavior: move to trash (soft delete)
    if (!isPermanent) {
      const now = new Date();
      const descendants = file.isFolder ? await getAllChildFiles(file.id) : [];
      const toTrash = [file, ...descendants];
      
      for (const f of toTrash) {
        await db.update(schema.files)
          .set({ isDeleted: true, deletedAt: now })
          .where(and(
            eq(schema.files.id, f.id),
            eq(schema.files.ownerId, user.id)
          ));
      }

      await logAudit(
        user.id,
        user.username,
        'MOVE_TO_TRASH',
        file.isFolder ? 'FOLDER' : 'FILE',
        fileId,
        { filename: file.filename },
        getClientIp(request),
        request.headers['user-agent']
      );
      
      return { ok: true, trashed: true };
    }

    // Permanent delete: remove blobs + rows and reclaim storage
    let totalSizeToReclaim = 0;
    const descendants = file.isFolder ? await getAllChildFiles(file.id) : [];
    const toDelete = [file, ...descendants];
    totalSizeToReclaim = toDelete.reduce((sum, f) => sum + (f.fileSize || 0), 0);

    for (const f of toDelete) {
      if (f.storagePath) {
        const deleted = await deleteFile(f.storagePath);
        if (!deleted) console.warn(`Failed to delete physical file: ${f.storagePath}`);
      }
    }

    await db.delete(schema.files).where(eq(schema.files.id, fileId));

    await db.update(schema.users)
      .set({ storageUsed: Math.max(0, user.storageUsed! - totalSizeToReclaim) })
      .where(eq(schema.users.id, user.id));

    await logAudit(
      user.id,
      user.username,
      'DELETE_PERMANENT',
      file.isFolder ? 'FOLDER' : 'FILE',
      fileId,
      { filename: file.filename, fileSize: totalSizeToReclaim },
      getClientIp(request),
      request.headers['user-agent']
    );

    return { ok: true, deleted: true };
  });
  
  // ============ RESTORE FILE ============
  app.post('/api/files/:fileId/restore', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;
    const { fileId } = request.params as { fileId: string };
    
    const file = await db.query.files.findFirst({
      where: and(
        eq(schema.files.id, fileId),
        eq(schema.files.ownerId, user.id),
        eq(schema.files.isDeleted, true)
      ),
    });
    
    if (!file) {
      return reply.status(404).send({ ok: false, msg: 'File not found in trash' });
    }

    const descendants = file.isFolder ? await getAllChildFiles(file.id) : [];
    const toRestore = [file, ...descendants];

    for (const f of toRestore) {
      await db.update(schema.files)
        .set({ isDeleted: false, deletedAt: null })
        .where(and(
          eq(schema.files.id, f.id),
          eq(schema.files.ownerId, user.id)
        ));
    }

    await logAudit(
      user.id,
      user.username,
      'RESTORE_FROM_TRASH',
      file.isFolder ? 'FOLDER' : 'FILE',
      fileId,
      { filename: file.filename },
      getClientIp(request),
      request.headers['user-agent']
    );
    
    return { ok: true };
  });
  
  // ============ GET TRASH ============
  app.get('/api/trash', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;

    // Auto-purge items older than retention window.
    await purgeTrashedOlderThanDays({
      db,
      schema,
      deleteFile,
      days: 30,
      ownerId: user.id,
    });
    
    const files = await db.query.files.findMany({
      where: and(
        eq(schema.files.ownerId, user.id),
        eq(schema.files.isDeleted, true)
      ),
      orderBy: (files: any, { desc }: any) => [desc(files.deletedAt)],
    });
    
    return {
      ok: true,
      files: files.map((f: any) => ({
        id: f.id,
        filename: f.filename,
        fileSize: f.fileSize,
        isFolder: f.isFolder,
        deletedAt: f.deletedAt,
      })),
    };
  });

  // ============ EMPTY TRASH (Permanent Delete All) ============
  app.delete('/api/trash/empty', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;

    // Ensure expired items don't count toward the confirmation expectation
    await purgeTrashedOlderThanDays({
      db,
      schema,
      deleteFile,
      days: 30,
      ownerId: user.id,
    });

    const trashed = await db.query.files.findMany({
      where: and(
        eq(schema.files.ownerId, user.id),
        eq(schema.files.isDeleted, true)
      ),
    });

    if (trashed.length === 0) {
      return { ok: true, deletedCount: 0 };
    }

    // Delete physical blobs for all trashed items that have a storagePath
    for (const f of trashed) {
      if (f.storagePath) {
        const deleted = await deleteFile(f.storagePath);
        if (!deleted) console.warn(`Failed to delete physical file: ${f.storagePath}`);
      }
    }

    const totalSizeToReclaim = trashed.reduce((sum, f) => sum + (f.fileSize || 0), 0);

    // Delete all trashed rows for this user (child rows are included since they are individually marked deleted too)
    await db.delete(schema.files).where(and(
      eq(schema.files.ownerId, user.id),
      eq(schema.files.isDeleted, true)
    ));

    // Update storage used
    await db.update(schema.users)
      .set({ storageUsed: Math.max(0, user.storageUsed! - totalSizeToReclaim) })
      .where(eq(schema.users.id, user.id));

    await logAudit(
      user.id,
      user.username,
      'EMPTY_TRASH',
      'USER',
      user.id.toString(),
      { deletedCount: trashed.length, fileSize: totalSizeToReclaim },
      getClientIp(request),
      request.headers['user-agent']
    );

    return { ok: true, deletedCount: trashed.length };
  });

  // ============ RENAME FILE/FOLDER ============
  app.patch('/api/files/:fileId/rename', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;
    const { fileId } = request.params as { fileId: string };
    
    const body = renameSchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ ok: false, msg: 'Invalid request' });
    }
    
    const { name } = body.data;
    
    const file = await db.query.files.findFirst({
      where: and(
        eq(schema.files.id, fileId),
        eq(schema.files.ownerId, user.id),
        eq(schema.files.isDeleted, false)
      ),
    });
    
    if (!file) {
      return reply.status(404).send({ ok: false, msg: 'File not found' });
    }
    
    await db.update(schema.files)
      .set({ filename: name })
      .where(eq(schema.files.id, fileId));
    
    return { ok: true, filename: name };
  });

  // ============ MOVE FILE/FOLDER ============
  app.patch('/api/files/:fileId/move', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;
    const { fileId } = request.params as { fileId: string };
    
    const body = moveSchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ ok: false, msg: 'Invalid request' });
    }
    
    const { parentId } = body.data;
    
    const file = await db.query.files.findFirst({
      where: and(
        eq(schema.files.id, fileId),
        eq(schema.files.ownerId, user.id),
        eq(schema.files.isDeleted, false)
      ),
    });
    
    if (!file) {
      return reply.status(404).send({ ok: false, msg: 'File not found' });
    }
    
    // Prevent moving into itself or its descendants
    if (parentId === fileId) {
      return reply.status(400).send({ ok: false, msg: 'Cannot move folder into itself' });
    }
    
    // If moving to a folder, verify the destination exists and belongs to user
    if (parentId) {
      const destFolder = await db.query.files.findFirst({
        where: and(
          eq(schema.files.id, parentId),
          eq(schema.files.ownerId, user.id),
          eq(schema.files.isFolder, true),
          eq(schema.files.isDeleted, false)
        ),
      });
      
      if (!destFolder) {
        return reply.status(404).send({ ok: false, msg: 'Destination folder not found' });
      }
      
      // Check for circular reference (can't move a folder into its descendant)
      if (file.isFolder) {
        let currentParentId: string | null = parentId;
        while (currentParentId) {
          if (currentParentId === fileId) {
            return reply.status(400).send({ ok: false, msg: 'Cannot move folder into its descendant' });
          }
          const parent: { parentId: string | null } | undefined = await db.query.files.findFirst({
            where: eq(schema.files.id, currentParentId),
          });
          currentParentId = parent?.parentId || null;
        }
      }
    }
    
    await db.update(schema.files)
      .set({ parentId: parentId || null })
      .where(eq(schema.files.id, fileId));
    
    return { ok: true, parentId };
  });

  // ============ GET ALL FOLDERS (for move dialog) ============
  app.get('/api/folders', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;
    
    const folders = await db.query.files.findMany({
      where: and(
        eq(schema.files.ownerId, user.id),
        eq(schema.files.isFolder, true),
        eq(schema.files.isDeleted, false)
      ),
      orderBy: (files: any, { asc }: any) => [asc(files.filename)],
    });
    
    return {
      ok: true,
      folders: folders.map((f: any) => ({
        id: f.id,
        filename: f.filename,
        parentId: f.parentId,
      })),
    };
  });
}
