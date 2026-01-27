import { FastifyInstance } from 'fastify';
import { db, schema } from '../db/index.js';
import { eq, and, gt } from 'drizzle-orm';
import { authenticate, optionalAuth, AuthenticatedRequest } from '../middleware/auth.js';
import { generateUUID, getExpiryDate } from '../lib/crypto.js';
import { getFile, getFullPath } from '../lib/storage.js';
import { z } from 'zod';
import { createReadStream } from 'fs';
import { logAudit } from './admin.js';

const shareWithUserSchema = z.object({
  fileId: z.string().uuid(),
  recipientUsername: z.string(),
  encryptedKey: z.string(), // File key re-encrypted with recipient's public key
});

const createPublicShareSchema = z.object({
  fileId: z.string().uuid(),
  expiresInHours: z.number().min(1).max(87600).default(24), // Max 10 years (87600 hours) for "permanent" links
  maxAccess: z.number().min(1).optional(),
});

export async function shareRoutes(app: FastifyInstance): Promise<void> {
  
  // ============ SHARE WITH USER ============
  app.post('/api/share', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;
    
    const body = shareWithUserSchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ ok: false, msg: 'Invalid request' });
    }
    
    const { fileId, recipientUsername, encryptedKey } = body.data;
    
    // Verify ownership
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
    
    // Find recipient
    const recipient = await db.query.users.findFirst({
      where: eq(schema.users.username, recipientUsername),
    });
    
    if (!recipient) {
      return reply.status(404).send({ ok: false, msg: 'Recipient not found' });
    }
    
    if (recipient.id === user.id) {
      return reply.status(400).send({ ok: false, msg: 'Cannot share with yourself' });
    }
    
    // Check if already shared
    const existingShare = await db.query.fileShares.findFirst({
      where: and(
        eq(schema.fileShares.fileId, fileId),
        eq(schema.fileShares.recipientId, recipient.id)
      ),
    });
    
    if (existingShare) {
      // Update existing share
      await db.update(schema.fileShares)
        .set({ encryptedKey })
        .where(eq(schema.fileShares.id, existingShare.id));
    } else {
      // Create new share
      await db.insert(schema.fileShares).values({
        fileId,
        recipientId: recipient.id,
        encryptedKey,
      });
    }
    
    // Log audit
    await logAudit(
      user.id,
      user.username,
      'SHARE_USER',
      'FILE',
      fileId,
      { filename: file.filename, recipientUsername },
      request.ip,
      request.headers['user-agent']
    );
    
    return { ok: true };
  });
  
  // ============ GET FILES SHARED WITH ME ============
  app.get('/api/shared-with-me', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;
    
    const shares = await db.query.fileShares.findMany({
      where: eq(schema.fileShares.recipientId, user.id),
      with: {
        file: {
          with: { owner: true },
        },
      },
    });
    
    return {
      ok: true,
      files: shares
        .filter(s => !s.file.isDeleted)
        .map(s => ({
          id: s.file.id,
          filename: s.file.filename,
          fileSize: s.file.fileSize,
          isFolder: s.file.isFolder,
          owner: s.file.owner.username,
          encryptedKey: s.encryptedKey,
          iv: s.file.iv,
          sharedAt: s.createdAt,
        })),
    };
  });
  
  // ============ REVOKE USER SHARE ============
  app.delete('/api/share/:fileId/:recipientId', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;
    const { fileId, recipientId } = request.params as { fileId: string; recipientId: string };
    
    // Verify ownership
    const file = await db.query.files.findFirst({
      where: and(
        eq(schema.files.id, fileId),
        eq(schema.files.ownerId, user.id)
      ),
    });
    
    if (!file) {
      return reply.status(404).send({ ok: false, msg: 'File not found' });
    }
    
    await db.delete(schema.fileShares)
      .where(and(
        eq(schema.fileShares.fileId, fileId),
        eq(schema.fileShares.recipientId, parseInt(recipientId))
      ));
    
    return { ok: true };
  });
  
  // ============ GET MY SHARES FOR FILE ============
  app.get('/api/files/:fileId/shares', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;
    const { fileId } = request.params as { fileId: string };
    
    // Verify ownership
    const file = await db.query.files.findFirst({
      where: and(
        eq(schema.files.id, fileId),
        eq(schema.files.ownerId, user.id)
      ),
    });
    
    if (!file) {
      return reply.status(404).send({ ok: false, msg: 'File not found' });
    }
    
    // Get public shares
    const publicShares = await db.query.publicShares.findMany({
      where: eq(schema.publicShares.fileId, fileId),
    });
    
    return {
      ok: true,
      shares: publicShares.map(s => ({
        token: s.token,
        expiresAt: s.expiresAt,
        accessCount: s.accessCount,
        maxAccess: s.maxAccess,
        createdAt: s.createdAt,
        url: `/share/${s.token}`,
      })),
    };
  });
  
  // ============ CREATE PUBLIC SHARE ============
  app.post('/api/share/public', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;
    
    const body = createPublicShareSchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ ok: false, msg: 'Invalid request' });
    }
    
    const { fileId, expiresInHours, maxAccess } = body.data;
    
    // Verify ownership
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
    
    const token = generateUUID();
    const expiresAt = getExpiryDate(expiresInHours);
    
    await db.insert(schema.publicShares).values({
      fileId,
      token,
      expiresAt,
      maxAccess,
    });
    
    // Log audit
    await logAudit(
      user.id,
      user.username,
      'SHARE_PUBLIC',
      file.isFolder ? 'FOLDER' : 'FILE',
      fileId,
      { filename: file.filename, expiresInHours, maxAccess, isFolder: file.isFolder },
      request.ip,
      request.headers['user-agent']
    );
    
    return {
      ok: true,
      token,
      url: `/public/${token}`,
      expiresAt: expiresAt.toISOString(),
      isFolder: file.isFolder,
    };
  });
  
  // Helper function to recursively get all files in a folder
  async function getFolderContents(folderId: string, ownerId: number): Promise<any[]> {
    const items = await db.query.files.findMany({
      where: and(
        eq(schema.files.parentId, folderId),
        eq(schema.files.ownerId, ownerId),
        eq(schema.files.isDeleted, false)
      ),
    });
    
    const result: any[] = [];
    
    for (const item of items) {
      if (item.isFolder) {
        // Recursively get folder contents
        const children = await getFolderContents(item.id, ownerId);
        result.push({
          id: item.id,
          filename: item.filename,
          isFolder: true,
          children,
        });
      } else {
        result.push({
          id: item.id,
          filename: item.filename,
          fileSize: item.fileSize,
          encryptedKey: item.encryptedKey,
          iv: item.iv,
          isFolder: false,
        });
      }
    }
    
    return result;
  }
  
  // ============ ACCESS PUBLIC SHARE ============
  app.get('/api/public/:token', async (request, reply) => {
    const { token } = request.params as { token: string };
    
    const share = await db.query.publicShares.findFirst({
      where: and(
        eq(schema.publicShares.token, token),
        gt(schema.publicShares.expiresAt, new Date())
      ),
      with: { file: true },
    });
    
    if (!share) {
      return reply.status(404).send({ ok: false, msg: 'Link not found or expired' });
    }
    
    // Check max access
    if (share.maxAccess && share.accessCount! >= share.maxAccess) {
      return reply.status(403).send({ ok: false, msg: 'Link access limit reached' });
    }
    
    // Increment access count
    await db.update(schema.publicShares)
      .set({ accessCount: share.accessCount! + 1 })
      .where(eq(schema.publicShares.id, share.id));
    
    // If it's a folder, return folder structure with all files
    if (share.file.isFolder) {
      const children = await getFolderContents(share.file.id, share.file.ownerId);
      return {
        ok: true,
        isFolder: true,
        folder: {
          id: share.file.id,
          filename: share.file.filename,
          children,
        },
      };
    }
    
    // Regular file
    return {
      ok: true,
      isFolder: false,
      file: {
        id: share.file.id,
        filename: share.file.filename,
        fileSize: share.file.fileSize,
        encryptedKey: share.file.encryptedKey,
        iv: share.file.iv,
      },
    };
  });
  
  // ============ DOWNLOAD FILE FROM PUBLIC FOLDER SHARE ============
  app.get('/api/public/:token/file/:fileId/download', async (request, reply) => {
    const { token, fileId } = request.params as { token: string; fileId: string };
    
    const share = await db.query.publicShares.findFirst({
      where: and(
        eq(schema.publicShares.token, token),
        gt(schema.publicShares.expiresAt, new Date())
      ),
      with: { file: true },
    });
    
    if (!share) {
      return reply.status(404).send({ ok: false, msg: 'Link not found or expired' });
    }
    
    if (share.maxAccess && share.accessCount! >= share.maxAccess) {
      return reply.status(403).send({ ok: false, msg: 'Link access limit reached' });
    }
    
    // Check if this is a folder share
    if (!share.file.isFolder) {
      return reply.status(400).send({ ok: false, msg: 'Not a folder share' });
    }
    
    // Get the file and verify it belongs to the shared folder
    const file = await db.query.files.findFirst({
      where: and(
        eq(schema.files.id, fileId),
        eq(schema.files.ownerId, share.file.ownerId),
        eq(schema.files.isDeleted, false)
      ),
    });
    
    if (!file || !file.storagePath) {
      return reply.status(404).send({ ok: false, msg: 'File not found' });
    }
    
    // Verify the file is within the shared folder (check ancestry)
    let currentParentId = file.parentId;
    let isInFolder = false;
    
    while (currentParentId) {
      if (currentParentId === share.file.id) {
        isInFolder = true;
        break;
      }
      const parent = await db.query.files.findFirst({
        where: eq(schema.files.id, currentParentId),
      });
      currentParentId = parent?.parentId || null;
    }
    
    if (!isInFolder) {
      return reply.status(403).send({ ok: false, msg: 'File not in shared folder' });
    }
    
    const fullPath = getFullPath(file.storagePath);
    const stream = createReadStream(fullPath);
    
    reply.header('Content-Type', 'application/octet-stream');
    reply.header('Content-Disposition', `attachment; filename="${file.filename}"`);
    reply.header('X-Encrypted-Key', file.encryptedKey);
    reply.header('X-IV', file.iv);
    
    return reply.send(stream);
  });
  
  // ============ DOWNLOAD PUBLIC SHARE ============
  app.get('/api/public/:token/download', async (request, reply) => {
    const { token } = request.params as { token: string };
    
    const share = await db.query.publicShares.findFirst({
      where: and(
        eq(schema.publicShares.token, token),
        gt(schema.publicShares.expiresAt, new Date())
      ),
      with: { file: true },
    });
    
    if (!share || !share.file.storagePath) {
      return reply.status(404).send({ ok: false, msg: 'Link not found or expired' });
    }
    
    if (share.maxAccess && share.accessCount! >= share.maxAccess) {
      return reply.status(403).send({ ok: false, msg: 'Link access limit reached' });
    }
    
    const fullPath = getFullPath(share.file.storagePath);
    const stream = createReadStream(fullPath);
    
    reply.header('Content-Type', 'application/octet-stream');
    reply.header('Content-Disposition', `attachment; filename="${share.file.filename}"`);
    reply.header('X-Encrypted-Key', share.file.encryptedKey);
    reply.header('X-IV', share.file.iv);
    
    return reply.send(stream);
  });
  
  // ============ DELETE PUBLIC SHARE ============
  app.delete('/api/share/public/:token', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;
    const { token } = request.params as { token: string };
    
    const share = await db.query.publicShares.findFirst({
      where: eq(schema.publicShares.token, token),
      with: { file: true },
    });
    
    if (!share || share.file.ownerId !== user.id) {
      return reply.status(404).send({ ok: false, msg: 'Share not found' });
    }
    
    await db.delete(schema.publicShares)
      .where(eq(schema.publicShares.id, share.id));
    
    return { ok: true };
  });
}
