import { FastifyInstance } from 'fastify';
import { db, schema } from '../db/index.js';
import { eq, and, gt, sql } from 'drizzle-orm';
import { authenticate, AuthenticatedRequest } from '../middleware/auth.js';
import { generateUUID, getExpiryDate } from '../lib/crypto.js';
import { getFile, getStream } from '../lib/storage.js';
import { createNotification } from './notifications.js';
import { z } from 'zod';
import { logAudit } from './admin.js';
import { getClientIp } from '../lib/clientIp.js';
import { safeContentDisposition } from '../lib/sanitize.js';

const shareWithUserSchema = z.object({
  fileId: z.string().uuid(),
  recipientUsername: z.string().min(1).max(200),
  encryptedKey: z.string(), // File key re-encrypted with recipient's public key
});

const kdfParamsSchema = z
  .object({
    iterations: z.number().int().min(1000).max(2_000_000),
    hash: z.string().max(32),
  })
  .strict();

const createPublicShareSchema = z.object({
  fileId: z.string().uuid(),
  expiresInHours: z.number().min(1).max(87600).default(24), // Max 10 years (87600 hours) for "permanent" links
  maxAccess: z.number().min(1).optional(),
  // Passphrase-protected wrapping (PBKDF2/etc). Required for new-style shares.
  kdfAlg: z.string().min(1).max(64).optional(),
  kdfParams: kdfParamsSchema.optional(),
  kdfSalt: z.string().min(1).optional(), // base64
  wrappedKey: z.string().min(1).optional(), // base64
  wrappedKeyIv: z.string().min(1).optional(), // base64
  // For folder shares, per-file wrapped keys are stored server-side (not in URL)
  items: z.array(z.object({
    fileId: z.string().uuid(),
    wrappedKey: z.string().min(1),
    wrappedKeyIv: z.string().min(1),
  })).optional(),
});

export async function shareRoutes(app: FastifyInstance): Promise<void> {

  /**
   * Atomically consume one access for a public share, if allowed.
   * Returns true when access is granted; false when maxAccess has been reached.
   */
  const consumePublicShareAccess = (shareId: number): boolean => {
    const res = db.run(sql`
      UPDATE public_shares
      SET access_count = access_count + 1
      WHERE id = ${shareId}
        AND (max_access IS NULL OR access_count < max_access)
    `);
    return (res?.changes ?? 0) > 0;
  };
  
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
      getClientIp(request),
      request.headers['user-agent']
    );
    
    // Create notification for recipient
    await createNotification(
      recipient.id,
      'file_shared',
      'File shared with you',
      `${user.username} shared "${file.filename}" with you`,
      `/dashboard?file=${fileId}`,
      { fileId, filename: file.filename, sharedBy: user.username }
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
        .filter((s: any) => !s.file.isDeleted)
        .map((s: any) => ({
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
        eq(schema.fileShares.recipientId, recipientId)
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
      shares: publicShares.map((s: any) => ({
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
    
    const { fileId, expiresInHours, maxAccess, kdfAlg, kdfParams, kdfSalt, wrappedKey, wrappedKeyIv, items } = body.data;
    
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
    
    const inserted = await db.insert(schema.publicShares).values({
      fileId,
      token,
      expiresAt,
      maxAccess,
      kdfAlg: kdfAlg || null,
      kdfParams: kdfParams ? JSON.stringify(kdfParams) : null,
      kdfSalt: kdfSalt || null,
      wrappedKey: wrappedKey || null,
      wrappedKeyIv: wrappedKeyIv || null,
    });

    // For folder shares, store per-file wrapped keys (if provided).
    if (file.isFolder) {
      const shareRow = await db.query.publicShares.findFirst({ where: eq(schema.publicShares.token, token) });
      if (shareRow && Array.isArray(items) && items.length > 0) {
        await db.delete(schema.publicShareItems).where(eq(schema.publicShareItems.publicShareId, shareRow.id));
        await db.insert(schema.publicShareItems).values(
          items.map((it) => ({
            publicShareId: shareRow.id,
            fileId: it.fileId,
            wrappedKey: it.wrappedKey,
            wrappedKeyIv: it.wrappedKeyIv,
          }))
        );
      }
    }
    
    // Log audit
    await logAudit(
      user.id,
      user.username,
      'SHARE_PUBLIC',
      file.isFolder ? 'FOLDER' : 'FILE',
      fileId,
      { filename: file.filename, expiresInHours, maxAccess, isFolder: file.isFolder },
      getClientIp(request),
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
  async function getFolderContents(folderId: string, ownerId: string): Promise<any[]> {
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
          encryptedKey: item.encryptedKey,
          iv: item.iv,
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
  app.get('/api/public/:token', {
    config: {
      rateLimit: { max: 30, timeWindow: '1 minute' },
    },
  }, async (request, reply) => {
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
    
    // Metadata access counts toward maxAccess (view-limited shares).
    if (share.maxAccess) {
      const ok = consumePublicShareAccess(share.id);
      if (!ok) return reply.status(403).send({ ok: false, msg: 'Link access limit reached' });
    }
    
    // If it's a folder, return folder structure with all files
    if (share.file.isFolder) {
      const children = await getFolderContents(share.file.id, share.file.ownerId);
      const itemRows = await db.query.publicShareItems.findMany({
        where: eq(schema.publicShareItems.publicShareId, share.id),
      });
      const itemKeyMap: Record<string, { wrappedKey: string; wrappedKeyIv: string }> = {};
      for (const r of itemRows as any[]) {
        itemKeyMap[r.fileId] = { wrappedKey: r.wrappedKey, wrappedKeyIv: r.wrappedKeyIv };
      }
      return {
        ok: true,
        isFolder: true,
        kdf: share.kdfAlg && share.kdfSalt ? {
          alg: share.kdfAlg,
          params: share.kdfParams ? JSON.parse(share.kdfParams) : null,
          salt: share.kdfSalt,
        } : null,
        folder: {
          id: share.file.id,
          filename: share.file.filename,
          children,
        },
        items: itemKeyMap,
      };
    }
    
    // Regular file
    return {
      ok: true,
      isFolder: false,
      kdf: share.kdfAlg && share.kdfSalt && share.wrappedKey && share.wrappedKeyIv ? {
        alg: share.kdfAlg,
        params: share.kdfParams ? JSON.parse(share.kdfParams) : null,
        salt: share.kdfSalt,
        wrappedKey: share.wrappedKey,
        wrappedKeyIv: share.wrappedKeyIv,
      } : null,
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
  app.get('/api/public/:token/file/:fileId/download', {
    config: {
      rateLimit: { max: 30, timeWindow: '1 minute' },
    },
  }, async (request, reply) => {
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
    
    // Downloads also count toward maxAccess (prevents bypass by skipping metadata endpoint).
    if (share.maxAccess) {
      const ok = consumePublicShareAccess(share.id);
      if (!ok) return reply.status(403).send({ ok: false, msg: 'Link access limit reached' });
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
    
    const stream = getStream(file.storagePath);
    reply.header('Content-Type', 'application/octet-stream');
    reply.header('Content-Disposition', safeContentDisposition(file.filename));
    reply.header('X-Encrypted-Key', file.encryptedKey);
    reply.header('X-IV', file.iv);
    return reply.send(stream);
  });

  // ============ DOWNLOAD PUBLIC SHARE ============
  app.get('/api/public/:token/download', {
    config: {
      rateLimit: { max: 30, timeWindow: '1 minute' },
    },
  }, async (request, reply) => {
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
    
    if (share.maxAccess) {
      const ok = consumePublicShareAccess(share.id);
      if (!ok) return reply.status(403).send({ ok: false, msg: 'Link access limit reached' });
    }
    
    const stream = getStream(share.file.storagePath);
    reply.header('Content-Type', 'application/octet-stream');
    reply.header('Content-Disposition', safeContentDisposition(share.file.filename));
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
