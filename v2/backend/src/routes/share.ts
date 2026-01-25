import { FastifyInstance } from 'fastify';
import { db, schema } from '../db/index.js';
import { eq, and, gt } from 'drizzle-orm';
import { authenticate, optionalAuth, AuthenticatedRequest } from '../middleware/auth.js';
import { generateUUID, getExpiryDate } from '../lib/crypto.js';
import { getFile, getFullPath } from '../lib/storage.js';
import { z } from 'zod';
import { createReadStream } from 'fs';

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
    
    if (file.isFolder) {
      return reply.status(400).send({ ok: false, msg: 'Cannot create public link for folders' });
    }
    
    const token = generateUUID();
    const expiresAt = getExpiryDate(expiresInHours);
    
    await db.insert(schema.publicShares).values({
      fileId,
      token,
      expiresAt,
      maxAccess,
    });
    
    return {
      ok: true,
      token,
      url: `/public/${token}`,
      expiresAt: expiresAt.toISOString(),
    };
  });
  
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
    
    return {
      ok: true,
      file: {
        id: share.file.id,
        filename: share.file.filename,
        fileSize: share.file.fileSize,
        encryptedKey: share.file.encryptedKey,
        iv: share.file.iv,
      },
    };
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
