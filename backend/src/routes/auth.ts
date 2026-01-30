import { FastifyInstance } from 'fastify';
import { db, schema } from '../db/index.js';
import { eq } from 'drizzle-orm';
import { generateToken, generateChallenge, getExpiryDate, generateUUID } from '../lib/crypto.js';
import { authenticator } from 'otplib';
import QRCode from 'qrcode';
import { z } from 'zod';
import { authenticate, AuthenticatedRequest } from '../middleware/auth.js';
import { logAudit } from './admin.js';
import { setVirusTotalApiKey } from '../lib/virustotal.js';

// Temporary challenge storage (in production, use Redis)
const pendingChallenges = new Map<string, { challenge: string; expires: number }>();

// Validation schemas
const registerSchema = z.object({
  username: z.string().min(3).max(80).regex(/^[a-zA-Z0-9_]+$/),
  publicKey: z.string(),
  encryptionPublicKey: z.string().optional(),
});

const loginChallengeSchema = z.object({
  username: z.string(),
});

const loginVerifySchema = z.object({
  username: z.string(),
  signature: z.string(),
  totp: z.string().optional(),
});

export async function authRoutes(app: FastifyInstance): Promise<void> {
  
  // ============ CHECK SETUP STATUS ============
  app.get('/api/setup/status', async (request, reply) => {
    // Check if any admin user exists
    const admins = await db.query.users.findMany({
      where: eq(schema.users.isAdmin, true),
    });
    
    return {
      ok: true,
      needsSetup: admins.length === 0,
    };
  });

  // ============ INITIAL SETUP (Create First Admin) ============
  const setupAdminSchema = registerSchema.extend({
    virusTotalApiKey: z.string().max(500).optional(),
  });

  app.post('/api/setup/admin', async (request, reply) => {
    // Check if setup is still needed
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
    
    // Check if username exists
    const existing = await db.query.users.findFirst({
      where: eq(schema.users.username, username),
    });
    
    if (existing) {
      return reply.status(409).send({ ok: false, msg: 'Username already exists' });
    }
    
    // Create admin user
    const [user] = await db.insert(schema.users).values({
      username,
      publicKeyPem: publicKey,
      encryptionPublicKeyPem: encryptionPublicKey,
      isAdmin: true, // First user is admin!
      storageQuota: 5 * 1024 * 1024 * 1024, // 5GB for admin
    }).returning();
    
    // Save VirusTotal API key if provided (optional malware scan on upload)
    if (virusTotalApiKey !== undefined) {
      await setVirusTotalApiKey(virusTotalApiKey.trim() || null);
    }
    
    // Log audit
    await logAudit(
      user.id,
      user.username,
      'SETUP_ADMIN',
      'USER',
      user.id.toString(),
      { firstSetup: true },
      request.ip,
      request.headers['user-agent']
    );
    
    return { ok: true, userId: user.id, username: user.username, isAdmin: true };
  });

  // ============ REGISTER ============
  app.post('/api/register', async (request, reply) => {
    const body = registerSchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ ok: false, msg: 'Invalid request', errors: body.error.errors });
    }
    
    const { username, publicKey, encryptionPublicKey } = body.data;
    
    // Check if username exists
    const existing = await db.query.users.findFirst({
      where: eq(schema.users.username, username),
    });
    
    if (existing) {
      return reply.status(409).send({ ok: false, msg: 'Username already exists' });
    }
    
    // Create user
    const [user] = await db.insert(schema.users).values({
      username,
      publicKeyPem: publicKey,
      encryptionPublicKeyPem: encryptionPublicKey,
    }).returning();
    
    return { ok: true, userId: user.id, username: user.username };
  });
  
  // ============ LOGIN CHALLENGE ============
  app.post('/api/auth/challenge', async (request, reply) => {
    const body = loginChallengeSchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ ok: false, msg: 'Invalid request' });
    }
    
    const { username } = body.data;
    
    const user = await db.query.users.findFirst({
      where: eq(schema.users.username, username),
    });
    
    if (!user) {
      return reply.status(404).send({ ok: false, msg: 'User not found' });
    }
    
    if (user.isSuspended) {
      return reply.status(403).send({ ok: false, msg: 'Account is suspended' });
    }
    
    // Generate challenge
    const challenge = generateChallenge();
    const challengeId = generateUUID();
    
    pendingChallenges.set(challengeId, {
      challenge,
      expires: Date.now() + 5 * 60 * 1000, // 5 minutes
    });
    
    // Cleanup old challenges
    for (const [id, data] of pendingChallenges) {
      if (data.expires < Date.now()) pendingChallenges.delete(id);
    }
    
    return {
      ok: true,
      challenge,
      challengeId,
      requires2FA: user.totpEnabled,
    };
  });
  
  // ============ LOGIN VERIFY ============
  app.post('/api/auth/verify', async (request, reply) => {
    const body = loginVerifySchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ ok: false, msg: 'Invalid request' });
    }
    
    const { username, signature, totp } = body.data;
    const challengeId = (request.body as any).challengeId;
    
    // Verify challenge exists
    const challengeData = pendingChallenges.get(challengeId);
    if (!challengeData || challengeData.expires < Date.now()) {
      return reply.status(400).send({ ok: false, msg: 'Challenge expired or invalid' });
    }
    
    pendingChallenges.delete(challengeId);
    
    const user = await db.query.users.findFirst({
      where: eq(schema.users.username, username),
    });
    
    if (!user) {
      return reply.status(404).send({ ok: false, msg: 'User not found' });
    }
    
    // TODO: Verify ECDSA signature using user.publicKeyPem
    // For now, we'll trust the signature (implement WebCrypto verification)
    
    // Verify 2FA if enabled
    if (user.totpEnabled) {
      if (!totp) {
        return reply.status(400).send({ ok: false, msg: '2FA code required' });
      }
      
      const isValidTotp = authenticator.verify({ token: totp, secret: user.totpSecret! });
      if (!isValidTotp) {
        // Check backup codes
        const backupCodes: string[] = user.backupCodes ? JSON.parse(user.backupCodes) : [];
        const codeIndex = backupCodes.indexOf(totp);
        
        if (codeIndex === -1) {
          return reply.status(401).send({ ok: false, msg: 'Invalid 2FA code' });
        }
        
        // Remove used backup code
        backupCodes.splice(codeIndex, 1);
        await db.update(schema.users)
          .set({ backupCodes: JSON.stringify(backupCodes) })
          .where(eq(schema.users.id, user.id));
      }
    }
    
    // Create session
    const token = generateToken();
    const expiresAt = getExpiryDate(24); // 24 hours
    
    await db.insert(schema.sessions).values({
      token,
      userId: user.id,
      expiresAt,
      deviceInfo: (request.body as any).deviceInfo,
      ipAddress: request.ip,
      userAgent: request.headers['user-agent'],
    });
    
    // Log audit
    await logAudit(
      user.id,
      user.username,
      'LOGIN',
      'SESSION',
      undefined,
      { method: '2FA' in body.data && body.data.totp ? '2FA' : 'ECDSA' },
      request.ip,
      request.headers['user-agent']
    );
    
    return {
      ok: true,
      token,
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
  app.post('/api/logout', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;
    
    await db.delete(schema.sessions)
      .where(eq(schema.sessions.token, request.session!.token));
    
    // Log audit
    await logAudit(
      user.id,
      user.username,
      'LOGOUT',
      'SESSION',
      undefined,
      undefined,
      request.ip,
      request.headers['user-agent']
    );
    
    return { ok: true };
  });
  
  // ============ GET CURRENT USER ============
  app.get('/api/me', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
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
      },
    };
  });
  
  // ============ SETUP 2FA ============
  app.post('/api/auth/2fa/setup', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;
    
    if (user.totpEnabled) {
      return reply.status(400).send({ ok: false, msg: '2FA is already enabled' });
    }
    
    const secret = authenticator.generateSecret();
    const otpauth = authenticator.keyuri(user.username, 'SecureVault', secret);
    const qrCode = await QRCode.toDataURL(otpauth);
    
    // Store secret temporarily (will be confirmed when user verifies)
    await db.update(schema.users)
      .set({ totpSecret: secret })
      .where(eq(schema.users.id, user.id));
    
    return {
      ok: true,
      secret,
      qrCode,
    };
  });
  
  // ============ CONFIRM 2FA ============
  app.post('/api/auth/2fa/confirm', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;
    const { code } = request.body as { code: string };
    
    if (!user.totpSecret) {
      return reply.status(400).send({ ok: false, msg: 'Please setup 2FA first' });
    }
    
    const isValid = authenticator.verify({ token: code, secret: user.totpSecret });
    if (!isValid) {
      return reply.status(400).send({ ok: false, msg: 'Invalid code' });
    }
    
    // Generate backup codes
    const backupCodes = Array.from({ length: 10 }, () => generateToken(4).toUpperCase());
    
    await db.update(schema.users)
      .set({
        totpEnabled: true,
        backupCodes: JSON.stringify(backupCodes),
      })
      .where(eq(schema.users.id, user.id));
    
    return {
      ok: true,
      backupCodes,
    };
  });
  
  // ============ DISABLE 2FA ============
  app.post('/api/auth/2fa/disable', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;
    const { code } = request.body as { code: string };
    
    if (!user.totpEnabled) {
      return reply.status(400).send({ ok: false, msg: '2FA is not enabled' });
    }
    
    const isValid = authenticator.verify({ token: code, secret: user.totpSecret! });
    if (!isValid) {
      return reply.status(400).send({ ok: false, msg: 'Invalid code' });
    }
    
    await db.update(schema.users)
      .set({
        totpEnabled: false,
        totpSecret: null,
        backupCodes: null,
      })
      .where(eq(schema.users.id, user.id));
    
    return { ok: true };
  });
  
  // ============ GET USER PUBLIC KEY ============
  app.get('/api/users/:username/publickey', async (request, reply) => {
    const { username } = request.params as { username: string };
    
    const user = await db.query.users.findFirst({
      where: eq(schema.users.username, username),
    });
    
    if (!user) {
      return reply.status(404).send({ ok: false, msg: 'User not found' });
    }
    
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
    
    const updates: Record<string, any> = {};
    
    if (displayName !== undefined) {
      updates.displayName = displayName?.trim() || null;
    }
    
    if (avatar !== undefined) {
      // Validate avatar is base64 image (max 500KB)
      if (avatar && avatar.length > 500 * 1024) {
        return reply.status(400).send({ ok: false, msg: 'Avatar too large (max 500KB)' });
      }
      updates.avatar = avatar || null;
    }
    
    if (Object.keys(updates).length > 0) {
      await db.update(schema.users)
        .set(updates)
        .where(eq(schema.users.id, user.id));
    }
    
    // Log audit
    await logAudit(
      user.id,
      user.username,
      'UPDATE_PROFILE',
      'USER',
      user.id.toString(),
      { fields: Object.keys(updates) },
      request.ip,
      request.headers['user-agent']
    );
    
    return { ok: true };
  });

  // ============ GET ACTIVE SESSIONS ============
  app.get('/api/sessions', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;
    const currentToken = request.session!.token;
    
    const sessions = await db.query.sessions.findMany({
      where: eq(schema.sessions.userId, user.id),
    });
    
    return {
      ok: true,
      sessions: sessions.map((s: any) => ({
        id: s.id,
        deviceInfo: s.deviceInfo,
        ipAddress: s.ipAddress,
        userAgent: s.userAgent,
        createdAt: s.createdAt,
        lastActive: s.lastActive,
        isCurrent: s.token === currentToken,
      })),
    };
  });

  // ============ REVOKE SESSION ============
  app.delete('/api/sessions/:id', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;
    const { id } = request.params as { id: string };
    
    const session = await db.query.sessions.findFirst({
      where: eq(schema.sessions.id, parseInt(id)),
    });
    
    if (!session || session.userId !== user.id) {
      return reply.status(404).send({ ok: false, msg: 'Session not found' });
    }
    
    await db.delete(schema.sessions)
      .where(eq(schema.sessions.id, parseInt(id)));
    
    // Log audit
    await logAudit(
      user.id,
      user.username,
      'REVOKE_SESSION',
      'SESSION',
      id,
      undefined,
      request.ip,
      request.headers['user-agent']
    );
    
    return { ok: true };
  });

  // ============ REVOKE ALL OTHER SESSIONS ============
  app.post('/api/sessions/revoke-all', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;
    const currentToken = request.session!.token;
    
    await db.delete(schema.sessions)
      .where(eq(schema.sessions.userId, user.id));
    
    // Re-create current session
    const expiresAt = getExpiryDate(24);
    await db.insert(schema.sessions).values({
      token: currentToken,
      userId: user.id,
      expiresAt,
      ipAddress: request.ip,
      userAgent: request.headers['user-agent'],
    });
    
    // Log audit
    await logAudit(
      user.id,
      user.username,
      'REVOKE_ALL_SESSIONS',
      'SESSION',
      undefined,
      undefined,
      request.ip,
      request.headers['user-agent']
    );
    
    return { ok: true };
  });

  // ============ DELETE ACCOUNT ============
  app.delete('/api/account', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;
    const { confirmation } = request.body as { confirmation: string };
    
    if (confirmation !== user.username) {
      return reply.status(400).send({ ok: false, msg: 'Please type your username to confirm' });
    }
    
    // Log audit before deletion
    await logAudit(
      user.id,
      user.username,
      'DELETE_ACCOUNT',
      'USER',
      user.id.toString(),
      undefined,
      request.ip,
      request.headers['user-agent']
    );
    
    // Delete user (cascade will handle sessions, files, etc.)
    await db.delete(schema.users)
      .where(eq(schema.users.id, user.id));
    
    return { ok: true };
  });
}
