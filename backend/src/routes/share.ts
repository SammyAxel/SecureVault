import { FastifyInstance } from 'fastify';
import { db, schema } from '../db/index.js';
import { eq, and, gt, inArray, sql } from 'drizzle-orm';
import { authenticate, AuthenticatedRequest } from '../middleware/auth.js';
import { generateUUID, getExpiryDate } from '../lib/crypto.js';
import { getFile, getStream } from '../lib/storage.js';
import { createNotification } from './notifications.js';
import { z } from 'zod';
import { logAudit } from './admin.js';
import { getClientIp } from '../lib/clientIp.js';
import { safeContentDisposition } from '../lib/sanitize.js';
import {
  consumeLimitedPublicShareAccess,
  recordUnlimitedPublicShareUnlock,
} from '../lib/publicShareAccess.js';

const kdfParamsSchema = z
  .object({
    iterations: z.number().int().min(100_000).max(2_000_000),
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
  
  // ============ GET MY OUTGOING SHARES (Share Management) ============
  app.get('/api/my-shares', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;

    const ownedFiles = await db.query.files.findMany({
      where: and(
        eq(schema.files.ownerId, user.id),
        eq(schema.files.isDeleted, false)
      ),
    });

    // 2. Public share links for files I own
    const ownedFileIds = ownedFiles.map((f) => f.id);
    let publicSharesList: Array<{
      id: number;
      fileId: string;
      filename: string;
      fileSize: number;
      isFolder: boolean;
      token: string;
      expiresAt: Date | null;
      accessCount: number;
      maxAccess: number | null;
      createdAt: Date | null;
      isExpired: boolean;
    }> = [];

    if (ownedFileIds.length > 0) {
      const pShares = await db.query.publicShares.findMany({
        where: inArray(schema.publicShares.fileId, ownedFileIds),
        with: { file: true },
      });

      const now = new Date();
      publicSharesList = pShares.map((ps: any) => ({
        id: ps.id,
        fileId: ps.fileId,
        filename: ps.file.filename,
        fileSize: ps.file.fileSize ?? 0,
        isFolder: ps.file.isFolder ?? false,
        token: ps.token,
        expiresAt: ps.expiresAt,
        accessCount: ps.accessCount ?? 0,
        maxAccess: ps.maxAccess ?? null,
        createdAt: ps.createdAt,
        isExpired: (ps.expiresAt ? new Date(ps.expiresAt) < now : false) || (ps.maxAccess !== null && (ps.accessCount ?? 0) >= ps.maxAccess),
      }));
    }

    // 3. Outgoing user-to-user shares for files I own
    let userSharesList: Array<{
      shareId: number;
      fileId: string;
      filename: string;
      fileSize: number;
      isFolder: boolean;
      recipientId: string;
      recipientUsername: string;
      sharedAt: Date | null;
    }> = [];

    if (ownedFileIds.length > 0) {
      const uShares = await db.query.fileShares.findMany({
        where: inArray(schema.fileShares.fileId, ownedFileIds),
        with: { file: true, recipient: true },
      });

      userSharesList = uShares
        .filter((s: any) => s.file && !s.file.isDeleted)
        .map((s: any) => ({
          shareId: s.id,
          fileId: s.fileId,
          filename: s.file.filename,
          fileSize: s.file.fileSize ?? 0,
          isFolder: s.file.isFolder ?? false,
          recipientId: s.recipientId,
          recipientUsername: s.recipient?.username ?? '',
          sharedAt: s.createdAt,
        }));
    }

    return {
      ok: true,
      userShares: userSharesList,
      publicShares: publicSharesList,
    };
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
    // Verify every item fileId is actually a descendant of the shared folder.
    if (file.isFolder) {
      const shareRow = await db.query.publicShares.findFirst({ where: eq(schema.publicShares.token, token) });
      if (shareRow && Array.isArray(items) && items.length > 0) {
        const descendantRows = db.all(sql`
          WITH RECURSIVE tree AS (
            SELECT id FROM files WHERE parent_id = ${file.id} AND owner_id = ${user.id} AND is_deleted = 0
            UNION ALL
            SELECT f.id FROM files f INNER JOIN tree t ON f.parent_id = t.id
            WHERE f.owner_id = ${user.id} AND f.is_deleted = 0
          )
          SELECT id FROM tree
        `) as { id: string }[];
        const descendantIds = new Set(descendantRows.map((r) => r.id));
        const validItems = items.filter((it) => descendantIds.has(it.fileId));

        await db.delete(schema.publicShareItems).where(eq(schema.publicShareItems.publicShareId, shareRow.id));
        if (validItems.length > 0) {
          await db.insert(schema.publicShareItems).values(
            validItems.map((it) => ({
              publicShareId: shareRow.id,
              fileId: it.fileId,
              wrappedKey: it.wrappedKey,
              wrappedKeyIv: it.wrappedKeyIv,
            }))
          );
        }
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
  
  const MAX_FOLDER_DEPTH = 20;

  // Get all non-deleted files in a folder subtree using a single recursive CTE.
  // Avoids N+1 queries; depth cap enforced by the LIMIT guard (CTE walks at most
  // MAX_FOLDER_DEPTH levels before we stop caring about deeper items anyway, and
  // the per-share token lookup is the real auth gate here).
  function getFolderContentsFlat(folderId: string, ownerId: string): Array<{
    id: string; parent_id: string | null; filename: string;
    file_size: number | null; encrypted_key: string; iv: string; is_folder: number;
  }> {
    return db.all(sql`
      WITH RECURSIVE tree AS (
        SELECT id, parent_id, filename, file_size, encrypted_key, iv, is_folder, 1 AS depth
        FROM files
        WHERE parent_id = ${folderId}
          AND owner_id = ${ownerId}
          AND is_deleted = 0
        UNION ALL
        SELECT f.id, f.parent_id, f.filename, f.file_size, f.encrypted_key, f.iv, f.is_folder, t.depth + 1
        FROM files f
        INNER JOIN tree t ON f.parent_id = t.id
        WHERE f.owner_id = ${ownerId}
          AND f.is_deleted = 0
          AND t.depth < ${MAX_FOLDER_DEPTH}
      )
      SELECT id, parent_id, filename, file_size, encrypted_key, iv, is_folder FROM tree
    `) as Array<{ id: string; parent_id: string | null; filename: string; file_size: number | null; encrypted_key: string; iv: string; is_folder: number }>;
  }

  function buildFolderTree(rows: ReturnType<typeof getFolderContentsFlat>, parentId: string): any[] {
    return rows
      .filter((r) => r.parent_id === parentId)
      .map((r) => {
        if (r.is_folder) {
          return {
            id: r.id,
            filename: r.filename,
            encryptedKey: r.encrypted_key,
            iv: r.iv,
            isFolder: true,
            children: buildFolderTree(rows, r.id),
          };
        }
        return {
          id: r.id,
          filename: r.filename,
          fileSize: r.file_size ?? 0,
          encryptedKey: r.encrypted_key,
          iv: r.iv,
          isFolder: false,
        };
      });
  }

  function getFolderContents(folderId: string, ownerId: string): any[] {
    const flat = getFolderContentsFlat(folderId, ownerId);
    return buildFolderTree(flat, folderId);
  }

  // Check if a file is within the subtree of a given folder using a single recursive CTE
  function isFileInFolder(fileId: string, folderId: string): boolean {
    const rows = db.all(sql`
      WITH RECURSIVE ancestors AS (
        SELECT parent_id FROM files WHERE id = ${fileId}
        UNION ALL
        SELECT f.parent_id FROM files f INNER JOIN ancestors a ON f.id = a.parent_id
        WHERE a.parent_id IS NOT NULL
      )
      SELECT 1 FROM ancestors WHERE parent_id = ${folderId} LIMIT 1
    `) as unknown[];
    return rows.length > 0;
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

    if (share.maxAccess && (share.accessCount ?? 0) >= share.maxAccess) {
      return reply.status(403).send({ ok: false, msg: 'Link access limit reached' });
    }

    // NOTE: Limited shares (maxAccess) consume access on each successful download, not here.
    // Unlimited shares increment access_count once after passphrase unlock via POST .../access.

    // If it's a folder, return folder structure with all files
    if (share.file.isFolder) {
      const children = getFolderContents(share.file.id, share.file.ownerId);
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

  // ============ RECORD PUBLIC SHARE UNLOCK (unlimited shares only — analytics) ============
  app.post('/api/public/:token/access', {
    config: {
      rateLimit: { max: 10, timeWindow: '1 minute' },
    },
  }, async (request, reply) => {
    const { token } = request.params as { token: string };

    const share = await db.query.publicShares.findFirst({
      where: and(
        eq(schema.publicShares.token, token),
        gt(schema.publicShares.expiresAt, new Date())
      ),
    });

    if (!share) {
      return reply.status(404).send({ ok: false, msg: 'Link not found or expired' });
    }

    if (share.maxAccess && (share.accessCount ?? 0) >= share.maxAccess) {
      return reply.status(403).send({ ok: false, msg: 'Link access limit reached' });
    }

    // Limited shares: enforcement is on download via consumeLimitedPublicShareAccess (cannot bypass).
    if (!share.maxAccess) {
      recordUnlimitedPublicShareUnlock(share.id);
    }

    return { ok: true };
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

    if (share.maxAccess) {
      const granted = consumeLimitedPublicShareAccess(share.id);
      if (!granted) {
        return reply.status(403).send({ ok: false, msg: 'Link access limit reached' });
      }
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
    
    // Verify the file is within the shared folder (single recursive CTE — no N+1)
    // Return 404 (not 403) so the existence of unrelated files is not revealed
    if (!isFileInFolder(file.id, share.file.id)) {
      return reply.status(404).send({ ok: false, msg: 'File not found' });
    }
    
    const stream = getStream(file.storagePath);
    reply.header('Content-Type', 'application/octet-stream');
    reply.header('Content-Disposition', safeContentDisposition(file.filename));
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
      const granted = consumeLimitedPublicShareAccess(share.id);
      if (!granted) {
        return reply.status(403).send({ ok: false, msg: 'Link access limit reached' });
      }
    }

    const stream = getStream(share.file.storagePath);
    reply.header('Content-Type', 'application/octet-stream');
    reply.header('Content-Disposition', safeContentDisposition(share.file.filename));

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

    await logAudit(
      user.id,
      user.username,
      'REVOKE_SHARE',
      share.file.isFolder ? 'FOLDER' : 'FILE',
      share.fileId,
      { filename: share.file.filename, token: share.token },
      getClientIp(request),
      request.headers['user-agent']
    );

    return { ok: true };
  });

  // ============ GET SHARED WITH ME ============
  app.get('/api/shared-with-me', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;

    const shares = await db.query.fileShares.findMany({
      where: eq(schema.fileShares.recipientId, user.id),
      with: { file: true },
    });

    const ownerIds = [...new Set(
      shares.map((s: any) => s.file?.ownerId).filter(Boolean) as string[]
    )];

    const owners = ownerIds.length > 0
      ? await db.query.users.findMany({
          where: inArray(schema.users.id, ownerIds),
          columns: { id: true, username: true },
        })
      : [];
    const ownerMap = new Map(owners.map((u: any) => [u.id, u.username]));

    const items = shares
      .filter((s: any) => s.file && !s.file.isDeleted)
      .map((s: any) => ({
        shareId: s.id,
        fileId: s.fileId,
        filename: s.file.filename,
        fileSize: s.file.fileSize ?? 0,
        isFolder: s.file.isFolder ?? false,
        encryptedKey: s.encryptedKey,
        iv: s.file.iv,
        parentId: s.file.parentId ?? null,
        ownerId: s.file.ownerId,
        ownerUsername: ownerMap.get(s.file.ownerId) ?? '',
        sharedAt: s.createdAt,
      }));

    return { ok: true, items };
  });

  // ============ CREATE USER SHARE ============
  app.post('/api/share/user', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;

    const body = z.object({
      fileId: z.string().uuid(),
      recipientUsername: z.string().min(1).max(80),
      encryptedKey: z.string().min(1),
    }).safeParse(request.body);

    if (!body.success) return reply.status(400).send({ ok: false, msg: 'Invalid request' });

    const { fileId, recipientUsername, encryptedKey } = body.data;

    if (recipientUsername === user.username) {
      return reply.status(400).send({ ok: false, msg: 'Cannot share with yourself' });
    }

    const file = await db.query.files.findFirst({
      where: and(
        eq(schema.files.id, fileId),
        eq(schema.files.ownerId, user.id),
        eq(schema.files.isDeleted, false)
      ),
    });

    if (!file) return reply.status(404).send({ ok: false, msg: 'File not found' });

    const recipient = await db.query.users.findFirst({
      where: eq(schema.users.username, recipientUsername),
    });

    if (!recipient) return reply.status(404).send({ ok: false, msg: 'User not found' });

    const existing = await db.query.fileShares.findFirst({
      where: and(
        eq(schema.fileShares.fileId, fileId),
        eq(schema.fileShares.recipientId, recipient.id)
      ),
    });

    if (existing) return reply.status(409).send({ ok: false, msg: 'Already shared with this user' });

    await db.insert(schema.fileShares).values({
      fileId,
      recipientId: recipient.id,
      encryptedKey,
    });

    await createNotification(
      recipient.id,
      'SHARE_RECEIVED',
      `${user.username} shared a file with you`,
      file.filename,
    );

    await logAudit(
      user.id,
      user.username,
      'SHARE_USER',
      file.isFolder ? 'FOLDER' : 'FILE',
      fileId,
      { recipientId: recipient.id, recipientUsername },
      getClientIp(request),
      request.headers['user-agent']
    );

    return { ok: true };
  });

  // ============ REVOKE USER SHARE ============
  app.delete('/api/share/:fileId/:recipientId', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;
    const { fileId, recipientId } = request.params as { fileId: string; recipientId: string };

    const file = await db.query.files.findFirst({
      where: and(
        eq(schema.files.id, fileId),
        eq(schema.files.ownerId, user.id)
      ),
    });

    if (!file) return reply.status(404).send({ ok: false, msg: 'File not found' });

    await db.delete(schema.fileShares).where(
      and(
        eq(schema.fileShares.fileId, fileId),
        eq(schema.fileShares.recipientId, recipientId)
      )
    );

    await logAudit(
      user.id,
      user.username,
      'REVOKE_USER_SHARE',
      file.isFolder ? 'FOLDER' : 'FILE',
      fileId,
      { recipientId },
      getClientIp(request),
      request.headers['user-agent']
    );

    return { ok: true };
  });
}
