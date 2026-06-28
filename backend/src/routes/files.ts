import { FastifyInstance, type FastifyRequest } from 'fastify';
import { db, schema } from '../db/index.js';
import { eq, and, isNull, sql, inArray } from 'drizzle-orm';
import { authenticate, AuthenticatedRequest } from '../middleware/auth.js';
import { deleteFile, getFile, getStream, getStats, saveFileStream } from '../lib/storage.js';
import { scanUploadByHash } from '../lib/uploadMalwareScan.js';
import { generateUUID, generateUID } from '../lib/crypto.js';
import { getTrashRetentionDays, purgeTrashedOlderThanDays } from '../lib/trashRetention.js';
import { z } from 'zod';
import { logAudit } from './admin.js';
import { getClientIp } from '../lib/clientIp.js';
import { isDemoAdmin, demoSessionFilter, DEMO_SESSION_UPLOAD_LIMIT } from '../lib/demo.js';
import { safeContentDisposition } from '../lib/sanitize.js';
import { config } from '../config.js';

const uploadGlobalMax = config.UPLOAD_MAX_CONCURRENT_GLOBAL;
const uploadPerUserMax = config.UPLOAD_MAX_CONCURRENT_PER_USER;
type UploadReleaseFn = () => void;
const uploadWaiters: Array<() => void> = [];
let uploadGlobalActive = 0;
const uploadPerUserActive = new Map<string, number>();

function tryGrantUploadSlot(userId: string): UploadReleaseFn | null {
  const u = uploadPerUserActive.get(userId) ?? 0;
  if (uploadGlobalActive >= uploadGlobalMax || u >= uploadPerUserMax) return null;
  uploadGlobalActive++;
  uploadPerUserActive.set(userId, u + 1);
  return () => {
    uploadGlobalActive--;
    const nextU = (uploadPerUserActive.get(userId) ?? 1) - 1;
    if (nextU <= 0) uploadPerUserActive.delete(userId);
    else uploadPerUserActive.set(userId, nextU);
    const w = uploadWaiters.shift();
    if (w) w();
  };
}

async function acquireUploadSlot(userId: string): Promise<UploadReleaseFn> {
  for (;;) {
    const rel = tryGrantUploadSlot(userId);
    if (rel) return rel;
    await new Promise<void>((resolve) => uploadWaiters.push(resolve));
  }
}

const createFolderSchema = z.object({
  name: z.string().min(1).max(2048),
  parentId: z.string().uuid().optional().nullable(),
  encryptedKey: z.string().min(1),
  iv: z.string().min(1),
  keySignature: z.string().optional(),
});

const renameSchema = z
  .object({
    name: z.string().min(1).max(2048).optional(),
    encryptedName: z.string().min(1).max(4096).optional(),
  })
  .refine((d) => d.name != null || d.encryptedName != null, {
    message: 'Provide name or encryptedName',
  });

const folderCryptoMetadataSchema = z.object({
  encryptedKey: z.string().min(1),
  iv: z.string().min(1),
  filename: z.string().min(1).max(4096).optional(),
  keySignature: z.string().optional(),
});

const moveSchema = z.object({
  parentId: z.string().uuid().nullable(),
});

function warnIfBlobDeleteFailed(
  request: FastifyRequest,
  storagePath: string | null | undefined,
  deleted: boolean
) {
  if (storagePath && !deleted) {
    request.log.warn({ storagePath }, 'Failed to delete physical file');
  }
}

export async function fileRoutes(app: FastifyInstance): Promise<void> {
  /** All descendants of a folder in one recursive query (avoids N round-trips per tree level). */
  const getAllChildFiles = async (parentId: string): Promise<typeof schema.files.$inferSelect[]> => {
    const idRows = db.all(sql`
      WITH RECURSIVE descendants AS (
        SELECT id FROM files WHERE parent_id = ${parentId}
        UNION ALL
        SELECT f.id FROM files f INNER JOIN descendants d ON f.parent_id = d.id
      )
      SELECT id FROM descendants
    `) as { id: string }[];
    if (idRows.length === 0) return [];
    const ids = idRows.map((r) => r.id);
    return db.query.files.findMany({ where: inArray(schema.files.id, ids) });
  };

  /** Breadcrumb chain from root to immediate parent of `file` (single query). */
  const getParentPathOrdered = (startParentId: string): Array<{ id: string; uid: string | null; name: string; encryptedKey?: string }> => {
    const rows = db.all(sql`
      WITH RECURSIVE ancestors AS (
        SELECT id, uid, filename, parent_id, encrypted_key, 0 AS depth FROM files WHERE id = ${startParentId}
        UNION ALL
        SELECT f.id, f.uid, f.filename, f.parent_id, f.encrypted_key, a.depth + 1
        FROM files f
        INNER JOIN ancestors a ON f.id = a.parent_id
      )
      SELECT id, uid, filename, encrypted_key FROM ancestors ORDER BY depth DESC
    `) as { id: string; uid: string | null; filename: string; encrypted_key: string }[];
    return rows.map((r) => ({ id: r.id, uid: r.uid, name: r.filename, encryptedKey: r.encrypted_key || undefined }));
  };
  
  // ============ LIST FILES ============
  app.get('/api/files', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;
    const { parentId, q, all } = request.query as { parentId?: string; q?: string; all?: string };
    const qTrim = typeof q === 'string' ? q.trim().slice(0, 200) : '';
    const dsid = demoSessionFilter(request);

    const mapFile = (f: any) => ({
      id: f.id,
      uid: f.uid,
      filename: f.filename,
      fileSize: f.fileSize,
      isFolder: f.isFolder,
      parentId: f.parentId,
      createdAt: f.createdAt,
      encryptedKey: f.encryptedKey,
      iv: f.iv,
      keySignature: f.keySignature,
      ownerId: f.ownerId,
    });

    if (all === 'true') {
      const files = await db.query.files.findMany({
        where: and(
          eq(schema.files.ownerId, user.id),
          eq(schema.files.isDeleted, false),
          dsid != null ? eq(schema.files.demoSessionId, dsid) : undefined,
        ),
        orderBy: (files: any, { desc }: any) => [desc(files.isFolder), desc(files.createdAt)],
      });
      return { ok: true, files: files.map(mapFile) };
    }

    if (qTrim.length > 0) {
      const files = await db.query.files.findMany({
        where: and(
          eq(schema.files.ownerId, user.id),
          eq(schema.files.isDeleted, false),
          sql`instr(lower(${schema.files.filename}), lower(${qTrim})) > 0`,
          dsid != null ? eq(schema.files.demoSessionId, dsid) : undefined,
        ),
        orderBy: (files: any, { desc }: any) => [desc(files.isFolder), desc(files.createdAt)],
      });
      return { ok: true, files: files.map(mapFile) };
    }

    const files = await db.query.files.findMany({
      where: and(
        eq(schema.files.ownerId, user.id),
        eq(schema.files.isDeleted, false),
        parentId ? eq(schema.files.parentId, parentId) : isNull(schema.files.parentId),
        dsid != null ? eq(schema.files.demoSessionId, dsid) : undefined,
      ),
      orderBy: (files: any, { desc }: any) => [desc(files.isFolder), desc(files.createdAt)],
    });

    return { ok: true, files: files.map(mapFile) };
  });
  
  // ============ GET FILE/FOLDER BY UID (Authenticated) ============
  app.get('/api/f/:uid', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;
    const { uid } = request.params as { uid: string };
    const dsid = demoSessionFilter(request);
    
    const file = await db.query.files.findFirst({
      where: and(
        eq(schema.files.uid, uid),
        eq(schema.files.isDeleted, false),
        dsid != null ? eq(schema.files.demoSessionId, dsid) : undefined
      ),
    });
    
    if (!file) {
      return reply.status(404).send({ ok: false, msg: 'File not found' });
    }

    // Check ownership or share access — always 404 to avoid revealing file existence
    if (file.ownerId !== user.id) {
      const share = await db.query.fileShares.findFirst({
        where: and(
          eq(schema.fileShares.fileId, file.id),
          eq(schema.fileShares.recipientId, user.id)
        ),
      });

      if (!share) {
        return reply.status(404).send({ ok: false, msg: 'File not found' });
      }
    }
    
    const parentPath = file.parentId ? getParentPathOrdered(file.parentId) : [];
    
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
        keySignature: file.keySignature,
        ownerId: file.ownerId,
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

    const releaseSlot = await acquireUploadSlot(user.id);
    let savedPath: string | null = null;
    try {
      if (!data.file) {
        return reply.status(400).send({ ok: false, msg: 'No file stream' });
      }

      const { relativePath, size: fileSize, sha256: streamSha256 } = await saveFileStream(user.id, data.file);
      savedPath = relativePath;

      const remaining = user.storageQuota! - user.storageUsed!;
      if (fileSize > remaining) {
        await deleteFile(relativePath);
        return reply.status(400).send({
          ok: false,
          msg: `Storage quota exceeded. You have ${remaining} bytes remaining.`,
          quotaExceeded: true,
        });
      }

      const backendStats = await getStats();
      if (backendStats && backendStats.free < fileSize) {
        await deleteFile(relativePath);
        return reply.status(507).send({
          ok: false,
          msg: 'Storage backend is full. Not enough disk space.',
        });
      }

      const fields = data.fields as Record<string, { value?: string }>;
      const encryptedKey = fields.encrypted_key?.value;
      const iv = fields.iv?.value;
      const fileHashField = fields.file_hash?.value?.trim().toLowerCase();
      const parentId = fields.parent_id?.value || null;
      const encryptedFilename = fields.encrypted_filename?.value;
      const keySignature = fields.key_signature?.value;

      if (!encryptedKey || !iv) {
        await deleteFile(relativePath);
        request.log.warn({ encryptedKey, iv, fields }, 'Missing encryption metadata');
        return reply.status(400).send({ ok: false, msg: 'Missing encryption metadata' });
      }

      if (parentId) {
        const parentFolder = await db.query.files.findFirst({
          where: and(
            eq(schema.files.id, parentId),
            eq(schema.files.ownerId, user.id),
            eq(schema.files.isFolder, true),
            eq(schema.files.isDeleted, false)
          ),
        });
        if (!parentFolder) {
          await deleteFile(relativePath);
          return reply.status(404).send({ ok: false, msg: 'Parent folder not found' });
        }
      }

      // We don't compare fileHashField with streamSha256 anymore.
      // fileHashField is the hash of the ORIGINAL unencrypted file (for VirusTotal),
      // while streamSha256 is the hash of the ENCRYPTED stream. They will never match.

      const storedFilename = encryptedFilename || data.filename;

      const scanHash = fileHashField || streamSha256;
      const { vtResult, mbResult } = await scanUploadByHash(scanHash, data.filename);

      if (!vtResult.safe || !mbResult.safe) {
        await deleteFile(relativePath);
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

      const dsid = demoSessionFilter(request);
      if (dsid != null) {
        const [row] = db.all(sql`
          SELECT COALESCE(SUM(file_size), 0) AS total
          FROM files WHERE demo_session_id = ${dsid}
        `) as { total: number }[];
        if ((row?.total ?? 0) + fileSize > DEMO_SESSION_UPLOAD_LIMIT) {
          await deleteFile(relativePath);
          return reply.status(400).send({
            ok: false,
            msg: `Demo upload limit reached (25 MB per session). You have used ${Math.round((row?.total ?? 0) / 1024 / 1024)} MB.`,
          });
        }
      }

      const fileId = generateUUID();
      const fileUid = generateUID();
      await db.insert(schema.files).values({
        id: fileId,
        uid: fileUid,
        filename: storedFilename,
        ownerId: user.id,
        encryptedKey,
        iv,
        keySignature,
        storagePath: relativePath,
        fileSize,
        parentId,
        demoSessionId: dsid,
      });

      await db.update(schema.users)
        .set({ storageUsed: user.storageUsed! + fileSize })
        .where(eq(schema.users.id, user.id));

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
    } catch (err) {
      if (savedPath) await deleteFile(savedPath);
      throw err;
    } finally {
      releaseSlot();
    }
  });
  
  // ============ CREATE FOLDER ============
  app.post('/api/folders', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;
    
    const body = createFolderSchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ ok: false, msg: 'Invalid request' });
    }
    
    const { name, parentId, encryptedKey: folderKey, iv: folderIv, keySignature } = body.data;

    if (parentId) {
      const parentFolder = await db.query.files.findFirst({
        where: and(
          eq(schema.files.id, parentId),
          eq(schema.files.ownerId, user.id),
          eq(schema.files.isFolder, true),
          eq(schema.files.isDeleted, false)
        ),
      });
      if (!parentFolder) {
        return reply.status(404).send({ ok: false, msg: 'Parent folder not found' });
      }
    }

    const folderId = generateUUID();
    const folderUid = generateUID();
    await db.insert(schema.files).values({
      id: folderId,
      uid: folderUid,
      filename: name,
      ownerId: user.id,
      encryptedKey: folderKey,
      iv: folderIv,
      keySignature,
      isFolder: true,
      parentId: parentId || null,
      demoSessionId: demoSessionFilter(request),
    });
    
    return { ok: true, folderId, uid: folderUid };
  });
  
  // ============ DOWNLOAD FILE ============
  app.get('/api/files/:fileId/download', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;
    const { fileId } = request.params as { fileId: string };
    const dsid = demoSessionFilter(request);
    
    // Check ownership or share access
    const file = await db.query.files.findFirst({
      where: eq(schema.files.id, fileId),
    });
    
    if (!file) {
      return reply.status(404).send({ ok: false, msg: 'File not found' });
    }

    // Demo isolation: block access to files from other demo sessions
    if (dsid != null && file.ownerId === user.id && file.demoSessionId !== dsid) {
      return reply.status(404).send({ ok: false, msg: 'File not found' });
    }
    
    // Check if user owns the file or has share access — always 404 to avoid revealing file existence
    let encryptedKey = file.encryptedKey;

    if (file.ownerId !== user.id) {
      // Trashed files are only accessible by their owner, not shared recipients
      if (file.isDeleted) {
        return reply.status(404).send({ ok: false, msg: 'File not found' });
      }
      const share = await db.query.fileShares.findFirst({
        where: and(
          eq(schema.fileShares.fileId, fileId),
          eq(schema.fileShares.recipientId, user.id)
        ),
      });

      if (!share) {
        return reply.status(404).send({ ok: false, msg: 'File not found' });
      }

      encryptedKey = share.encryptedKey;
    }
    
    if (file.isFolder || !file.storagePath) {
      return reply.status(400).send({ ok: false, msg: 'Cannot download folder' });
    }
    
    // Stream file
    const stream = getStream(file.storagePath);
    
    reply.header('Content-Type', 'application/octet-stream');
    reply.header('Content-Disposition', safeContentDisposition(file.filename));
    reply.header('X-Encrypted-Key', encryptedKey);
    reply.header('X-IV', file.iv);
    if (file.keySignature) {
      reply.header('X-Key-Signature', file.keySignature);
    }
    
    return reply.send(stream);
  });
  
  // ============ DELETE FILE ============
  app.delete('/api/files/:fileId', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;
    const { fileId } = request.params as { fileId: string };
    const { permanent } = request.query as { permanent?: string };
    const isPermanent = permanent === 'true';
    const dsid = demoSessionFilter(request);
    
    const file = await db.query.files.findFirst({
      where: and(
        eq(schema.files.id, fileId),
        eq(schema.files.ownerId, user.id),
        dsid != null ? eq(schema.files.demoSessionId, dsid) : undefined
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
      const trashIds = toTrash.map((f) => f.id);
      if (trashIds.length > 0) {
        await db
          .update(schema.files)
          .set({ isDeleted: true, deletedAt: now })
          .where(and(eq(schema.files.ownerId, user.id), inArray(schema.files.id, trashIds)));
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
        warnIfBlobDeleteFailed(request, f.storagePath, deleted);
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
    const dsid = demoSessionFilter(request);
    
    const file = await db.query.files.findFirst({
      where: and(
        eq(schema.files.id, fileId),
        eq(schema.files.ownerId, user.id),
        eq(schema.files.isDeleted, true),
        dsid != null ? eq(schema.files.demoSessionId, dsid) : undefined
      ),
    });
    
    if (!file) {
      return reply.status(404).send({ ok: false, msg: 'File not found in trash' });
    }

    const descendants = file.isFolder ? await getAllChildFiles(file.id) : [];
    const toRestore = [file, ...descendants];
    const restoreIds = toRestore.map((f) => f.id);
    if (restoreIds.length > 0) {
      await db
        .update(schema.files)
        .set({ isDeleted: false, deletedAt: null })
        .where(and(eq(schema.files.ownerId, user.id), inArray(schema.files.id, restoreIds)));
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
    const dsid = demoSessionFilter(request);

    // Auto-purge items older than retention window.
    await purgeTrashedOlderThanDays({
      db,
      schema,
      deleteFile,
      days: getTrashRetentionDays(),
      ownerId: user.id,
    });
    
    const files = await db.query.files.findMany({
      where: and(
        eq(schema.files.ownerId, user.id),
        eq(schema.files.isDeleted, true),
        dsid != null ? eq(schema.files.demoSessionId, dsid) : undefined
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
        parentId: f.parentId,
        deletedAt: f.deletedAt,
        encryptedKey: f.encryptedKey,
        iv: f.iv,
        keySignature: f.keySignature,
        ownerId: f.ownerId,
      })),
    };
  });

  // ============ EMPTY TRASH (Permanent Delete All) ============
  app.delete('/api/trash/empty', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;
    const dsid = demoSessionFilter(request);

    // Ensure expired items don't count toward the confirmation expectation
    await purgeTrashedOlderThanDays({
      db,
      schema,
      deleteFile,
      days: getTrashRetentionDays(),
      ownerId: user.id,
    });

    const trashed = await db.query.files.findMany({
      where: and(
        eq(schema.files.ownerId, user.id),
        eq(schema.files.isDeleted, true),
        dsid != null ? eq(schema.files.demoSessionId, dsid) : undefined
      ),
    });

    if (trashed.length === 0) {
      return { ok: true, deletedCount: 0 };
    }

    // Delete physical blobs for all trashed items that have a storagePath
    for (const f of trashed) {
      if (f.storagePath) {
        const deleted = await deleteFile(f.storagePath);
        warnIfBlobDeleteFailed(request, f.storagePath, deleted);
      }
    }

    const totalSizeToReclaim = trashed.reduce((sum, f) => sum + (f.fileSize || 0), 0);

    // Delete trashed rows (scoped to demo session when applicable)
    const trashIds = trashed.map((f) => f.id);
    if (trashIds.length > 0) {
      await db.delete(schema.files).where(inArray(schema.files.id, trashIds));
    }

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
    const dsid = demoSessionFilter(request);
    
    const body = renameSchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ ok: false, msg: 'Invalid request' });
    }
    
    const storedName = body.data.encryptedName ?? body.data.name!;
    
    const file = await db.query.files.findFirst({
      where: and(
        eq(schema.files.id, fileId),
        eq(schema.files.ownerId, user.id),
        eq(schema.files.isDeleted, false),
        dsid != null ? eq(schema.files.demoSessionId, dsid) : undefined
      ),
    });
    
    if (!file) {
      return reply.status(404).send({ ok: false, msg: 'File not found' });
    }
    
    await db.update(schema.files)
      .set({ filename: storedName })
      .where(eq(schema.files.id, fileId));
    
    return { ok: true, filename: storedName };
  });

  // ============ REPAIR FOLDER CRYPTO METADATA (owner only) ============
  app.patch('/api/files/:fileId/crypto-metadata', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;
    const { fileId } = request.params as { fileId: string };
    const dsid = demoSessionFilter(request);

    const body = folderCryptoMetadataSchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ ok: false, msg: 'Invalid request' });
    }

    const file = await db.query.files.findFirst({
      where: and(
        eq(schema.files.id, fileId),
        eq(schema.files.ownerId, user.id),
        eq(schema.files.isDeleted, false),
        dsid != null ? eq(schema.files.demoSessionId, dsid) : undefined
      ),
    });

    if (!file) {
      return reply.status(404).send({ ok: false, msg: 'File not found' });
    }

    if (!file.isFolder) {
      return reply.status(400).send({ ok: false, msg: 'Only folder items support this metadata update' });
    }

    await db
      .update(schema.files)
      .set({
        encryptedKey: body.data.encryptedKey,
        iv: body.data.iv,
        ...(body.data.keySignature !== undefined ? { keySignature: body.data.keySignature } : {}),
        ...(body.data.filename !== undefined ? { filename: body.data.filename } : {}),
      })
      .where(eq(schema.files.id, fileId));

    return { ok: true };
  });

  // ============ MOVE FILE/FOLDER ============
  app.patch('/api/files/:fileId/move', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;
    const { fileId } = request.params as { fileId: string };
    const dsid = demoSessionFilter(request);
    
    const body = moveSchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ ok: false, msg: 'Invalid request' });
    }
    
    const { parentId } = body.data;
    
    const file = await db.query.files.findFirst({
      where: and(
        eq(schema.files.id, fileId),
        eq(schema.files.ownerId, user.id),
        eq(schema.files.isDeleted, false),
        dsid != null ? eq(schema.files.demoSessionId, dsid) : undefined
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
      // Depth cap prevents DoS via deeply nested trees (same limit as folder recursion elsewhere)
      if (file.isFolder) {
        let currentParentId: string | null = parentId;
        let depth = 0;
        while (currentParentId && depth < 20) {
          depth++;
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
    const dsid = demoSessionFilter(request);
    
    const folders = await db.query.files.findMany({
      where: and(
        eq(schema.files.ownerId, user.id),
        eq(schema.files.isFolder, true),
        eq(schema.files.isDeleted, false),
        dsid != null ? eq(schema.files.demoSessionId, dsid) : undefined
      ),
      orderBy: (files: any, { asc }: any) => [asc(files.filename)],
    });
    
    return {
      ok: true,
      folders: folders.map((f: any) => ({
        id: f.id,
        filename: f.filename,
        parentId: f.parentId,
        encryptedKey: f.encryptedKey,
        iv: f.iv,
      })),
    };
  });
}
