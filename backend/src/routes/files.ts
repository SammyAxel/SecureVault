import { FastifyInstance } from 'fastify';
import { db, schema } from '../db/index';
import { eq, and, isNull } from 'drizzle-orm';
import { authenticate, AuthenticatedRequest } from '../middleware/auth.js';
import { saveFile, getFile, deleteFile, getFullPath } from '../lib/storage.js';
import { generateUUID, generateUID } from '../lib/crypto.js';
import { z } from 'zod';
import { createReadStream } from 'fs';
import { logAudit } from './admin.js';

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
    
    // Get metadata from fields
    const fields = data.fields as any;
    const encryptedKey = fields.encrypted_key?.value;
    const iv = fields.iv?.value;
    const parentId = fields.parent_id?.value || null;
    
    if (!encryptedKey || !iv) {
      return reply.status(400).send({ ok: false, msg: 'Missing encryption metadata' });
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
    
    // Log audit
    await logAudit(
      user.id,
      user.username,
      'UPLOAD',
      'FILE',
      fileId,
      { filename: data.filename, fileSize, uid: fileUid },
      request.ip,
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
    const fullPath = getFullPath(file.storagePath);
    const stream = createReadStream(fullPath);
    
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
    
    const file = await db.query.files.findFirst({
      where: and(
        eq(schema.files.id, fileId),
        eq(schema.files.ownerId, user.id)
      ),
    });
    
    if (!file) {
      return reply.status(404).send({ ok: false, msg: 'File not found' });
    }
    
    // Always permanent delete - remove physical file
    if (file.storagePath) {
      const deleted = await deleteFile(file.storagePath);
      if (!deleted) {
        console.warn(`Failed to delete physical file: ${file.storagePath}`);
      }
    }
    
    // Delete from database
    await db.delete(schema.files).where(eq(schema.files.id, fileId));
    
    // Update storage quota
    await db.update(schema.users)
      .set({ storageUsed: Math.max(0, user.storageUsed! - file.fileSize!) })
      .where(eq(schema.users.id, user.id));
    
    // Log audit
    await logAudit(
      user.id,
      user.username,
      'DELETE',
      file.isFolder ? 'FOLDER' : 'FILE',
      fileId,
      { filename: file.filename, fileSize: file.fileSize },
      request.ip,
      request.headers['user-agent']
    );
    
    return { ok: true };
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
    
    await db.update(schema.files)
      .set({ isDeleted: false, deletedAt: null })
      .where(eq(schema.files.id, fileId));
    
    return { ok: true };
  });
  
  // ============ GET TRASH ============
  app.get('/api/trash', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;
    
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
