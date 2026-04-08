import type { FastifyInstance, FastifyRequest } from 'fastify';
import { db, schema } from '../db/index.js';
import { and, eq, lt, sql } from 'drizzle-orm';
import {
  generateToken,
  generateChallenge,
  getExpiryDate,
  generateUUID,
  safeCompare,
  hashSHA256,
  verifyECDSASignature,
  encryptTotpSecret,
  decryptTotpSecret,
} from '../lib/crypto.js';
import { authenticator } from 'otplib';
import QRCode from 'qrcode';
import { z } from 'zod';
import { authenticate, AuthenticatedRequest } from '../middleware/auth.js';
import { logAudit } from './admin.js';
import { setVirusTotalApiKey } from '../lib/virustotal.js';
import { getStats, deleteFile } from '../lib/storage.js';
import { checkTrustedDevice, addTrustedDevice, updateTrustedDeviceLastUsed } from './trustedDevices.js';
import { getClientIp } from '../lib/clientIp.js';
import { DEMO_MODE, DEMO_USERNAME, isDemoAdmin } from '../lib/demo.js';

const DEFAULT_QUOTA_BYTES = 524288000; // 500MB
const ADMIN_QUOTA_BYTES = 5 * 1024 * 1024 * 1024; // 5GB

authenticator.options = { window: 1 };

// ---------- Persistent challenge helpers (SQLite-backed) ----------

async function storeChallenge(
  id: string,
  challenge: string,
  ttlMs: number,
  deviceLinkPairingId?: string
) {
  await db.insert(schema.pendingChallenges).values({
    id,
    challenge,
    expiresAt: new Date(Date.now() + ttlMs),
    deviceLinkPairingId: deviceLinkPairingId ?? null,
  });
}

async function consumeChallenge(id: string) {
  const row = await db.query.pendingChallenges.findFirst({
    where: eq(schema.pendingChallenges.id, id),
  });
  if (!row) return null;
  await db.delete(schema.pendingChallenges).where(eq(schema.pendingChallenges.id, id));
  if (row.expiresAt < new Date()) return null;
  return row;
}

async function cleanupExpiredChallenges() {
  await db.delete(schema.pendingChallenges).where(lt(schema.pendingChallenges.expiresAt, new Date()));
}

// ---------- Persistent device-link helpers ----------

async function storeDeviceLink(pairingId: string, data: {
  linkSecret: string; userId: string; username: string; ttlMs: number;
  encryptedKeys?: string; encryptedKeysIv?: string;
}) {
  await db.insert(schema.pendingDeviceLinks).values({
    pairingId,
    linkSecret: data.linkSecret,
    userId: data.userId,
    username: data.username,
    expiresAt: new Date(Date.now() + data.ttlMs),
    encryptedKeys: data.encryptedKeys ?? null,
    encryptedKeysIv: data.encryptedKeysIv ?? null,
  });
}

async function getDeviceLink(pairingId: string) {
  const row = await db.query.pendingDeviceLinks.findFirst({
    where: eq(schema.pendingDeviceLinks.pairingId, pairingId),
  });
  if (!row) return null;
  if (row.expiresAt < new Date()) {
    await db.delete(schema.pendingDeviceLinks).where(eq(schema.pendingDeviceLinks.pairingId, pairingId));
    return null;
  }
  return row;
}

async function markDeviceLinkCompleted(pairingId: string) {
  await db.update(schema.pendingDeviceLinks)
    .set({ completedAt: new Date() })
    .where(eq(schema.pendingDeviceLinks.pairingId, pairingId));
}

async function cleanupExpiredDeviceLinks() {
  await db.delete(schema.pendingDeviceLinks).where(lt(schema.pendingDeviceLinks.expiresAt, new Date()));
}

// ---------- Session creation helper (hashes token before storing) ----------

async function createSession(rawToken: string, userId: string, expiryHours: number, meta: {
  deviceInfo?: string; ipAddress?: string; userAgent?: string;
}) {
  const tokenHash = hashSHA256(rawToken);
  const expiresAt = getExpiryDate(expiryHours);
  await db.insert(schema.sessions).values({
    token: tokenHash,
    userId,
    expiresAt,
    deviceInfo: meta.deviceInfo,
    ipAddress: meta.ipAddress,
    userAgent: meta.userAgent,
  });
  return expiresAt;
}

// ---------- Request-origin helper ----------

function getRequestOrigin(request: FastifyRequest): string {
  const xfProto = request.headers['x-forwarded-proto'];
  const proto = (Array.isArray(xfProto) ? xfProto[0] : xfProto) || 'http';
  const xfHost = request.headers['x-forwarded-host'];
  const host = (Array.isArray(xfHost) ? xfHost[0] : xfHost) || request.headers.host || 'localhost';
  return `${proto}://${host}`;
}

// ---------- Zod schemas ----------

const registerSchema = z.object({
  username: z.string().min(3).max(80).regex(/^[a-zA-Z0-9_]+$/),
  publicKey: z.string(),
  encryptionPublicKey: z.string().optional(),
});

const loginChallengeSchema = z.object({
  username: z.string(),
  deviceFingerprint: z.string().optional(),
});

const loginVerifySchema = z.object({
  username: z.string(),
  challengeId: z.string(),
  signature: z.string(),
  totp: z.string().optional(),
  trustDevice: z.boolean().optional(),
  deviceFingerprint: z.string().optional(),
  deviceName: z.string().optional(),
  browser: z.string().optional(),
  os: z.string().optional(),
});

const deviceLinkChallengeSchema = z.object({
  pairingId: z.string().uuid(),
  linkSecret: z.string().length(64),
  deviceFingerprint: z.string().optional(),
});

const deviceLinkVerifySchema = z.object({
  pairingId: z.string().uuid(),
  linkSecret: z.string().length(64),
  challengeId: z.string(),
  signature: z.string(),
  totp: z.string().optional(),
  trustDevice: z.boolean().optional(),
  deviceFingerprint: z.string().optional(),
  deviceName: z.string().optional(),
  browser: z.string().optional(),
  os: z.string().optional(),
});

// ======================================================================

export async function authRoutes(app: FastifyInstance): Promise<void> {

  // ============ CHECK SETUP STATUS ============
  app.get('/api/setup/status', async (request, reply) => {
    const admins = await db.query.users.findMany({
      where: eq(schema.users.isAdmin, true),
    });
    const needsSetup = DEMO_MODE ? false : admins.length === 0;

    return {
      ok: true,
      needsSetup,
      demoMode: DEMO_MODE,
      ...(DEMO_MODE ? { demoUsername: DEMO_USERNAME } : {}),
    };
  });

  // ============ INITIAL SETUP (Create First Admin) ============
  const setupAdminSchema = registerSchema.extend({
    virusTotalApiKey: z.string().max(500).optional(),
  });

  app.post('/api/setup/admin', async (request, reply) => {
    if (DEMO_MODE) {
      return reply.status(403).send({
        ok: false,
        msg: 'Initial setup is disabled in demo mode. Use the pre-seeded demo account and keys.',
      });
    }
    const hasAdmin = await db.query.users.findFirst({
      where: eq(schema.users.isAdmin, true),
    });
    if (hasAdmin) {
      return reply.status(400).send({ ok: false, msg: 'Admin already exists. Setup is complete.' });
    }

    const body = setupAdminSchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ ok: false, msg: 'Invalid request', errors: body.error.errors });
    }

    const { username, publicKey, encryptionPublicKey, virusTotalApiKey } = body.data;

    const existing = await db.query.users.findFirst({
      where: eq(schema.users.username, username),
    });
    if (existing) {
      return reply.status(409).send({ ok: false, msg: 'Username already exists' });
    }

    let adminQuota = ADMIN_QUOTA_BYTES;
    const backendStats = await getStats();
    if (backendStats && backendStats.free < adminQuota) {
      adminQuota = Math.max(0, backendStats.free);
    }

    const [user] = await db.insert(schema.users).values({
      username,
      publicKeyPem: publicKey,
      encryptionPublicKeyPem: encryptionPublicKey,
      isAdmin: true,
      storageQuota: adminQuota,
    }).returning();

    if (virusTotalApiKey !== undefined) {
      await setVirusTotalApiKey(virusTotalApiKey.trim() || null);
    }

    await logAudit(user.id, user.username, 'SETUP_ADMIN', 'USER', user.id.toString(),
      { firstSetup: true }, getClientIp(request), request.headers['user-agent']);

    return { ok: true, userId: user.id, username: user.username, isAdmin: true };
  });

  // ============ REGISTER ============
  app.post('/api/register', async (request, reply) => {
    if (DEMO_MODE) {
      return reply.status(403).send({ ok: false, msg: 'Registration is disabled in demo mode. Please use the demo admin account.' });
    }
    const body = registerSchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ ok: false, msg: 'Invalid request', errors: body.error.errors });
    }

    const { username, publicKey, encryptionPublicKey } = body.data;

    const existing = await db.query.users.findFirst({
      where: eq(schema.users.username, username),
    });
    if (existing) {
      return reply.status(409).send({ ok: false, msg: 'Username already exists' });
    }

    let userQuota = DEFAULT_QUOTA_BYTES;
    const backendStats = await getStats();
    if (backendStats && backendStats.free < userQuota) {
      userQuota = Math.max(0, backendStats.free);
    }

    const [user] = await db.insert(schema.users).values({
      username,
      publicKeyPem: publicKey,
      encryptionPublicKeyPem: encryptionPublicKey,
      storageQuota: userQuota,
    }).returning();

    return { ok: true, userId: user.id, username: user.username };
  });

  // ============ LOGIN CHALLENGE ============
  // Returns the same shape for known AND unknown users to prevent username enumeration.
  app.post('/api/auth/challenge', async (request, reply) => {
    const body = loginChallengeSchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ ok: false, msg: 'Invalid request' });
    }

    const { username, deviceFingerprint } = body.data;

    const user = await db.query.users.findFirst({
      where: eq(schema.users.username, username),
    });

    // Generate challenge regardless of whether user exists (anti-enumeration)
    const challenge = generateChallenge();
    const challengeId = generateUUID();

    if (!user || user.isSuspended) {
      // Store a challenge that will never verify (no user to verify against)
      await storeChallenge(challengeId, challenge, 5 * 60 * 1000);
      return { ok: true, challenge, challengeId, requires2FA: false };
    }

    let isTrustedDevice = false;
    if (deviceFingerprint && user.totpEnabled) {
      isTrustedDevice = await checkTrustedDevice(user.id, deviceFingerprint);
    }

    await storeChallenge(challengeId, challenge, 5 * 60 * 1000);
    await cleanupExpiredChallenges();

    return {
      ok: true,
      challenge,
      challengeId,
      requires2FA: user.totpEnabled && !isTrustedDevice,
    };
  });

  // ============ LOGIN VERIFY ============
  app.post('/api/auth/verify', async (request, reply) => {
    const body = loginVerifySchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ ok: false, msg: 'Invalid request' });
    }

    const { username, challengeId, signature, totp, trustDevice, deviceFingerprint, deviceName, browser, os } = body.data;

    const challengeData = await consumeChallenge(challengeId);
    if (!challengeData) {
      return reply.status(400).send({ ok: false, msg: 'Challenge expired or invalid' });
    }

    if (challengeData.deviceLinkPairingId) {
      return reply.status(400).send({
        ok: false,
        msg: 'This challenge belongs to a QR device link. Use the device-link verify endpoint.',
      });
    }

    const user = await db.query.users.findFirst({
      where: eq(schema.users.username, username),
    });

    if (!user) {
      return reply.status(401).send({ ok: false, msg: 'Invalid credentials' });
    }

    // Server-side ECDSA signature verification
    const isValidSig = verifyECDSASignature(user.publicKeyPem, challengeData.challenge, signature);
    if (!isValidSig) {
      return reply.status(401).send({ ok: false, msg: 'Invalid credentials' });
    }

    let isTrustedDevice = false;
    if (deviceFingerprint) {
      isTrustedDevice = await checkTrustedDevice(user.id, deviceFingerprint);
      if (isTrustedDevice) {
        await updateTrustedDeviceLastUsed(user.id, deviceFingerprint);
      }
    }

    if (user.totpEnabled && !isTrustedDevice) {
      if (!totp) {
        return reply.status(400).send({ ok: false, msg: '2FA code required' });
      }

      const isValidTotp = authenticator.verify({ token: totp, secret: decryptTotpSecret(user.totpSecret!) });
      if (!isValidTotp) {
        const backupCodes: string[] = user.backupCodes ? JSON.parse(user.backupCodes) : [];
        const codeIndex = backupCodes.indexOf(totp);

        if (codeIndex === -1) {
          return reply.status(401).send({ ok: false, msg: 'Invalid 2FA code' });
        }

        backupCodes.splice(codeIndex, 1);
        await db.update(schema.users)
          .set({ backupCodes: JSON.stringify(backupCodes) })
          .where(eq(schema.users.id, user.id));
      }
    }

    if (trustDevice && deviceFingerprint && deviceName && user.totpEnabled && totp) {
      await addTrustedDevice(user.id, deviceFingerprint, deviceName, browser || null, os || null, getClientIp(request));
    }

    const rawToken = generateToken();
    const expiryHours = isTrustedDevice ? 720 : 24;
    const expiresAt = await createSession(rawToken, user.id, expiryHours, {
      deviceInfo: (request.body as Record<string, unknown>).deviceInfo as string | undefined,
      ipAddress: getClientIp(request),
      userAgent: request.headers['user-agent'],
    });

    await logAudit(user.id, user.username, 'LOGIN', 'SESSION', undefined,
      { method: totp ? '2FA' : 'ECDSA' }, getClientIp(request), request.headers['user-agent']);

    return {
      ok: true,
      token: rawToken,
      expiresAt: expiresAt.toISOString(),
      user: {
        id: user.id,
        username: user.username,
        isAdmin: user.isAdmin,
        storageUsed: user.storageUsed,
        storageQuota: user.storageQuota,
        demoMode: DEMO_MODE,
      },
    };
  });

  // ============ DEVICE LINK (QR: main device → secondary) ============
  app.post('/api/auth/device-link/create', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;
    await cleanupExpiredDeviceLinks();

    const body = request.body as { encryptedKeys?: string; encryptedKeysIv?: string } | undefined;

    const pairingId = generateUUID();
    const linkSecret = generateToken(32);

    await storeDeviceLink(pairingId, {
      linkSecret,
      userId: user.id,
      username: user.username,
      ttlMs: 3 * 60 * 1000,
      encryptedKeys: body?.encryptedKeys,
      encryptedKeysIv: body?.encryptedKeysIv,
    });

    const origin = getRequestOrigin(request).replace(/\/$/, '');
    const linkUrl = `${origin}/login/link#p=${encodeURIComponent(pairingId)}&s=${encodeURIComponent(linkSecret)}`;
    const qrCodeDataUrl = await QRCode.toDataURL(linkUrl, { width: 256, margin: 2 });

    await logAudit(user.id, user.username, 'DEVICE_LINK_CREATED', 'SESSION', pairingId,
      undefined, getClientIp(request), request.headers['user-agent']);

    return {
      ok: true,
      pairingId,
      linkSecret,
      expiresAt: new Date(Date.now() + 3 * 60 * 1000).toISOString(),
      username: user.username,
      qrCodeDataUrl,
      linkUrl,
    };
  });

  app.get('/api/auth/device-link/status', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const pairingId = (request.query as { pairingId?: string }).pairingId;
    if (!pairingId || typeof pairingId !== 'string') {
      return reply.status(400).send({ ok: false, msg: 'pairingId query parameter required' });
    }

    const link = await getDeviceLink(pairingId);
    const user = request.user!;

    if (!link) return { ok: true, status: 'expired_or_invalid' as const };
    if (link.userId !== user.id) return reply.status(403).send({ ok: false, msg: 'Forbidden' });
    if (link.completedAt) return { ok: true, status: 'completed' as const };
    return { ok: true, status: 'pending' as const };
  });

  app.post('/api/auth/device-link/challenge', async (request, reply) => {
    const body = deviceLinkChallengeSchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ ok: false, msg: 'Invalid request', errors: body.error.errors });
    }

    await cleanupExpiredDeviceLinks();
    const { pairingId, linkSecret, deviceFingerprint } = body.data;
    const link = await getDeviceLink(pairingId);

    if (!link) return reply.status(400).send({ ok: false, msg: 'Invalid or expired link' });
    if (!safeCompare(link.linkSecret, linkSecret)) return reply.status(400).send({ ok: false, msg: 'Invalid or expired link' });
    if (link.completedAt) return reply.status(400).send({ ok: false, msg: 'This link was already used' });

    const user = await db.query.users.findFirst({ where: eq(schema.users.id, link.userId) });
    if (!user) return reply.status(404).send({ ok: false, msg: 'User not found' });
    if (user.isSuspended) return reply.status(403).send({ ok: false, msg: 'Account is suspended' });

    let isTrustedDevice = false;
    if (deviceFingerprint && user.totpEnabled) {
      isTrustedDevice = await checkTrustedDevice(user.id, deviceFingerprint);
    }

    const challenge = generateChallenge();
    const challengeId = generateUUID();
    await storeChallenge(challengeId, challenge, 5 * 60 * 1000, pairingId);
    await cleanupExpiredChallenges();

    return {
      ok: true,
      challenge,
      challengeId,
      username: link.username,
      requires2FA: user.totpEnabled && !isTrustedDevice,
      encryptedKeys: link.encryptedKeys ?? null,
      encryptedKeysIv: link.encryptedKeysIv ?? null,
    };
  });

  app.post('/api/auth/device-link/verify', async (request, reply) => {
    const body = deviceLinkVerifySchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ ok: false, msg: 'Invalid request', errors: body.error.errors });
    }

    await cleanupExpiredDeviceLinks();
    const { pairingId, linkSecret, challengeId, signature, totp, trustDevice, deviceFingerprint, deviceName, browser, os } = body.data;

    const link = await getDeviceLink(pairingId);
    if (!link) return reply.status(400).send({ ok: false, msg: 'Invalid or expired link' });
    if (!safeCompare(link.linkSecret, linkSecret)) return reply.status(400).send({ ok: false, msg: 'Invalid or expired link' });
    if (link.completedAt) return reply.status(400).send({ ok: false, msg: 'This link was already used' });

    const challengeData = await consumeChallenge(challengeId);
    if (!challengeData) return reply.status(400).send({ ok: false, msg: 'Challenge expired or invalid' });
    if (challengeData.deviceLinkPairingId !== pairingId) {
      return reply.status(400).send({ ok: false, msg: 'Challenge does not match this link' });
    }

    const user = await db.query.users.findFirst({ where: eq(schema.users.id, link.userId) });
    if (!user) return reply.status(404).send({ ok: false, msg: 'User not found' });

    const isValidSig = verifyECDSASignature(user.publicKeyPem, challengeData.challenge, signature);
    if (!isValidSig) {
      return reply.status(401).send({ ok: false, msg: 'Invalid credentials' });
    }

    let isTrustedDevice = false;
    if (deviceFingerprint) {
      isTrustedDevice = await checkTrustedDevice(user.id, deviceFingerprint);
      if (isTrustedDevice) await updateTrustedDeviceLastUsed(user.id, deviceFingerprint);
    }

    if (user.totpEnabled && !isTrustedDevice) {
      if (!totp) return reply.status(400).send({ ok: false, msg: '2FA code required' });

      const isValidTotp = authenticator.verify({ token: totp, secret: decryptTotpSecret(user.totpSecret!) });
      if (!isValidTotp) {
        const backupCodes: string[] = user.backupCodes ? JSON.parse(user.backupCodes) : [];
        const codeIndex = backupCodes.indexOf(totp);
        if (codeIndex === -1) return reply.status(401).send({ ok: false, msg: 'Invalid 2FA code' });

        backupCodes.splice(codeIndex, 1);
        await db.update(schema.users)
          .set({ backupCodes: JSON.stringify(backupCodes) })
          .where(eq(schema.users.id, user.id));
      }
    }

    if (trustDevice && deviceFingerprint && deviceName && user.totpEnabled && totp) {
      await addTrustedDevice(user.id, deviceFingerprint, deviceName, browser || null, os || null, getClientIp(request));
    }

    const rawToken = generateToken();
    const expiryHours = isTrustedDevice ? 720 : 24;
    const expiresAt = await createSession(rawToken, user.id, expiryHours, {
      deviceInfo: (request.body as Record<string, unknown>).deviceInfo as string | undefined,
      ipAddress: getClientIp(request),
      userAgent: request.headers['user-agent'],
    });

    await markDeviceLinkCompleted(pairingId);

    await logAudit(user.id, user.username, 'LOGIN', 'SESSION', undefined,
      { method: 'DEVICE_LINK_QR' }, getClientIp(request), request.headers['user-agent']);

    return {
      ok: true,
      token: rawToken,
      expiresAt: expiresAt.toISOString(),
      user: {
        id: user.id,
        username: user.username,
        isAdmin: user.isAdmin,
        storageUsed: user.storageUsed,
        storageQuota: user.storageQuota,
      },
    };
  });

  // ============ LOGOUT ============
  app.post('/api/logout', { preHandler: authenticate }, async (request: AuthenticatedRequest) => {
    const user = request.user!;
    const tokenHash = hashSHA256(request.rawToken!);

    if (isDemoAdmin(request)) {
      const sessionId = request.session!.id;
      const demoFiles = db.all(sql`
        SELECT id, storage_path, file_size FROM files
        WHERE demo_session_id = ${sessionId}
      `) as { id: string; storage_path: string | null; file_size: number }[];

      let reclaimBytes = 0;
      for (const f of demoFiles) {
        if (f.storage_path) await deleteFile(f.storage_path);
        reclaimBytes += f.file_size || 0;
      }

      if (demoFiles.length > 0) {
        const ids = demoFiles.map((f) => f.id);
        for (const id of ids) {
          db.run(sql`DELETE FROM file_shares WHERE file_id = ${id}`);
          db.run(sql`DELETE FROM public_shares WHERE file_id = ${id}`);
        }
        db.run(sql`DELETE FROM files WHERE demo_session_id = ${sessionId}`);
      }

      if (reclaimBytes > 0) {
        await db.update(schema.users)
          .set({ storageUsed: Math.max(0, (user.storageUsed ?? 0) - reclaimBytes) })
          .where(eq(schema.users.id, user.id));
      }
    }

    await db.delete(schema.sessions).where(eq(schema.sessions.token, tokenHash));

    await logAudit(user.id, user.username, 'LOGOUT', 'SESSION', undefined,
      undefined, getClientIp(request), request.headers['user-agent']);

    return { ok: true };
  });

  // ============ GET CURRENT USER ============
  app.get('/api/me', { preHandler: authenticate }, async (request: AuthenticatedRequest) => {
    const user = request.user!;
    return {
      ok: true,
      user: {
        id: user.id,
        username: user.username,
        displayName: user.displayName,
        avatar: user.avatar,
        isAdmin: user.isAdmin,
        storageUsed: user.storageUsed,
        storageQuota: user.storageQuota,
        totpEnabled: user.totpEnabled,
        createdAt: user.createdAt,
        demoMode: DEMO_MODE,
      },
    };
  });

  // ============ SETUP 2FA ============
  app.post('/api/auth/2fa/setup', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;
    if (user.totpEnabled) return reply.status(400).send({ ok: false, msg: '2FA is already enabled' });

    const secret = authenticator.generateSecret();
    const otpauth = authenticator.keyuri(user.username, 'SecureVault', secret);
    const qrCode = await QRCode.toDataURL(otpauth);

    await db.update(schema.users).set({ totpSecret: encryptTotpSecret(secret) }).where(eq(schema.users.id, user.id));

    return { ok: true, secret, qrCode };
  });

  // ============ CONFIRM 2FA ============
  app.post('/api/auth/2fa/confirm', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;
    const { code } = request.body as { code: string };

    if (!user.totpSecret) return reply.status(400).send({ ok: false, msg: 'Please setup 2FA first' });

    const isValid = authenticator.verify({ token: code, secret: decryptTotpSecret(user.totpSecret) });
    if (!isValid) return reply.status(400).send({ ok: false, msg: 'Invalid code' });

    const backupCodes = Array.from({ length: 10 }, () => generateToken(4).toUpperCase());

    await db.update(schema.users)
      .set({ totpEnabled: true, backupCodes: JSON.stringify(backupCodes) })
      .where(eq(schema.users.id, user.id));

    return { ok: true, backupCodes };
  });

  // ============ DISABLE 2FA ============
  app.post('/api/auth/2fa/disable', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;
    const { code } = request.body as { code: string };

    if (!user.totpEnabled) return reply.status(400).send({ ok: false, msg: '2FA is not enabled' });

    const isValid = authenticator.verify({ token: code, secret: decryptTotpSecret(user.totpSecret!) });
    if (!isValid) return reply.status(400).send({ ok: false, msg: 'Invalid code' });

    await db.update(schema.users)
      .set({ totpEnabled: false, totpSecret: null, backupCodes: null })
      .where(eq(schema.users.id, user.id));

    return { ok: true };
  });

  // ============ GET USER PUBLIC KEY ============
  app.get('/api/users/:username/publickey', async (request, reply) => {
    const { username } = request.params as { username: string };
    const user = await db.query.users.findFirst({ where: eq(schema.users.username, username) });

    if (!user) return reply.status(404).send({ ok: false, msg: 'User not found' });

    return {
      ok: true,
      username: user.username,
      publicKey: user.publicKeyPem,
      encryptionPublicKey: user.encryptionPublicKeyPem,
    };
  });

  // ============ UPDATE PROFILE ============
  app.put('/api/profile', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;
    const { displayName, avatar } = request.body as { displayName?: string; avatar?: string };

    const updates: Record<string, string | null> = {};

    if (displayName !== undefined) updates.displayName = displayName?.trim() || null;
    if (avatar !== undefined) {
      if (avatar && avatar.length > 500 * 1024) {
        return reply.status(400).send({ ok: false, msg: 'Avatar too large (max 500KB)' });
      }
      updates.avatar = avatar || null;
    }

    if (Object.keys(updates).length > 0) {
      await db.update(schema.users).set(updates).where(eq(schema.users.id, user.id));
    }

    await logAudit(user.id, user.username, 'UPDATE_PROFILE', 'USER', user.id.toString(),
      { fields: Object.keys(updates) }, getClientIp(request), request.headers['user-agent']);

    return { ok: true };
  });

  // ============ GET ACTIVE SESSIONS ============
  app.get('/api/sessions', { preHandler: authenticate }, async (request: AuthenticatedRequest) => {
    const user = request.user!;
    const currentTokenHash = hashSHA256(request.rawToken!);
    const currentSessionId = request.session!.id;

    const sessions = await db.query.sessions.findMany({
      where: isDemoAdmin(request)
        ? and(eq(schema.sessions.userId, user.id), eq(schema.sessions.id, currentSessionId))
        : eq(schema.sessions.userId, user.id),
    });

    return {
      ok: true,
      sessions: sessions.map((s) => ({
        id: s.id,
        deviceInfo: s.deviceInfo,
        ipAddress: s.ipAddress,
        userAgent: s.userAgent,
        createdAt: s.createdAt,
        lastActive: s.lastActive,
        isCurrent: s.token === currentTokenHash,
      })),
    };
  });

  // ============ REVOKE SESSION ============
  app.delete('/api/sessions/:id', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    if (DEMO_MODE) {
      return reply.status(403).send({ ok: false, msg: 'Session management is disabled in demo mode' });
    }
    const user = request.user!;
    const { id } = request.params as { id: string };

    const session = await db.query.sessions.findFirst({
      where: eq(schema.sessions.id, parseInt(id)),
    });

    if (!session || session.userId !== user.id) {
      return reply.status(404).send({ ok: false, msg: 'Session not found' });
    }

    await db.delete(schema.sessions).where(eq(schema.sessions.id, parseInt(id)));

    await logAudit(user.id, user.username, 'REVOKE_SESSION', 'SESSION', id,
      undefined, getClientIp(request), request.headers['user-agent']);

    return { ok: true };
  });

  // ============ REVOKE ALL OTHER SESSIONS ============
  app.post('/api/sessions/revoke-all', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    if (DEMO_MODE) {
      return reply.status(403).send({ ok: false, msg: 'Session management is disabled in demo mode' });
    }
    const user = request.user!;
    const currentTokenHash = hashSHA256(request.rawToken!);

    await db.delete(schema.sessions).where(eq(schema.sessions.userId, user.id));

    const expiresAt = getExpiryDate(24);
    await db.insert(schema.sessions).values({
      token: currentTokenHash,
      userId: user.id,
      expiresAt,
      ipAddress: getClientIp(request),
      userAgent: request.headers['user-agent'],
    });

    await logAudit(user.id, user.username, 'REVOKE_ALL_SESSIONS', 'SESSION', undefined,
      undefined, getClientIp(request), request.headers['user-agent']);

    return { ok: true };
  });

  // ============ DELETE ACCOUNT ============
  app.delete('/api/account', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    if (DEMO_MODE) {
      return reply.status(403).send({ ok: false, msg: 'Account deletion is disabled in demo mode' });
    }
    const user = request.user!;
    const { confirmation } = request.body as { confirmation: string };

    if (confirmation !== user.username) {
      return reply.status(400).send({ ok: false, msg: 'Please type your username to confirm' });
    }

    await logAudit(user.id, user.username, 'DELETE_ACCOUNT', 'USER', user.id.toString(),
      undefined, getClientIp(request), request.headers['user-agent']);

    await db.delete(schema.users).where(eq(schema.users.id, user.id));

    return { ok: true };
  });
}
