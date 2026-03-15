import { FastifyInstance } from 'fastify';
import { db, schema } from '../db/index.js';
import { eq, desc, sql, count, sum, and, gte } from 'drizzle-orm';
import { authenticate, AuthenticatedRequest } from '../middleware/auth.js';
import {
  getVirusTotalApiKey,
  setVirusTotalApiKey,
  listVirusTotalKeys,
  addVirusTotalKey,
  updateVirusTotalKey,
  removeVirusTotalKey,
  getVirusTotalUsageSummary,
} from '../lib/virustotal.js';
import {
  getMalwareBazaarApiKeyMasked,
  setMalwareBazaarApiKey,
} from '../lib/malwarebazaar.js';
import { getStats } from '../lib/storage.js';
import { getClientIp } from '../lib/clientIp.js';
import { z } from 'zod';

// Admin middleware - checks if user is admin
async function requireAdmin(request: AuthenticatedRequest, reply: any) {
  await authenticate(request, reply);
  
  if (!request.user?.isAdmin) {
    return reply.status(403).send({ ok: false, msg: 'Admin access required' });
  }
}

// Audit log helper function
export async function logAudit(
  userId: number | null,
  username: string,
  action: string,
  resourceType?: string,
  resourceId?: string,
  details?: Record<string, any>,
  ipAddress?: string,
  userAgent?: string
) {
  try {
    await db.insert(schema.auditLogs).values({
      userId,
      username,
      action,
      resourceType,
      resourceId,
      details: details ? JSON.stringify(details) : null,
      ipAddress,
      userAgent,
    });
  } catch (error) {
    console.error('Failed to log audit:', error);
  }
}

const suspendUserSchema = z.object({
  suspended: z.boolean(),
});

const updateQuotaSchema = z.object({
  quota: z.number().min(0),
});

const adminSettingsSchema = z.object({
  virusTotalApiKey: z.string().max(500).optional(),
});

const addVirusTotalKeySchema = z.object({
  key: z.string().min(10).max(500),
  label: z.string().max(100).optional(),
});

const updateVirusTotalKeySchema = z.object({
  enabled: z.boolean().optional(),
  label: z.string().max(100).optional(),
});

export async function adminRoutes(app: FastifyInstance): Promise<void> {
  
  // ============ ADMIN SETTINGS (VirusTotal etc.) ============
  app.get('/api/admin/settings', { preHandler: requireAdmin }, async (_request: AuthenticatedRequest, reply) => {
    const [vtKey, mb] = await Promise.all([
      getVirusTotalApiKey(),
      getMalwareBazaarApiKeyMasked(),
    ]);
    return {
      ok: true,
      virusTotalConfigured: !!(vtKey && vtKey.length > 0),
      malwareBazaarConfigured: mb.configured,
      malwareBazaarMaskedKey: mb.maskedKey,
    };
  });

  app.patch('/api/admin/settings', { preHandler: requireAdmin }, async (request: AuthenticatedRequest, reply) => {
    const body = adminSettingsSchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ ok: false, msg: 'Invalid request' });
    }
    if (body.data.virusTotalApiKey !== undefined) {
      await setVirusTotalApiKey(body.data.virusTotalApiKey?.trim() || null);
    }
    const apiKey = await getVirusTotalApiKey();
    return {
      ok: true,
      virusTotalConfigured: !!(apiKey && apiKey.length > 0),
    };
  });

  // ============ VIRUSTOTAL API KEY MANAGEMENT ============
  app.get('/api/admin/virustotal-keys', { preHandler: requireAdmin }, async (_request: AuthenticatedRequest, _reply) => {
    const keys = await listVirusTotalKeys();
    const usage = await getVirusTotalUsageSummary();
    return { ok: true, keys, usage };
  });

  app.post('/api/admin/virustotal-keys', { preHandler: requireAdmin }, async (request: AuthenticatedRequest, reply) => {
    const body = addVirusTotalKeySchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ ok: false, msg: 'Invalid request' });
    }
    await addVirusTotalKey(body.data.key, body.data.label);
    const keys = await listVirusTotalKeys();
    const usage = await getVirusTotalUsageSummary();
    return { ok: true, keys, usage };
  });

  app.patch('/api/admin/virustotal-keys/:id', { preHandler: requireAdmin }, async (request: AuthenticatedRequest, reply) => {
    const { id } = request.params as { id: string };
    const body = updateVirusTotalKeySchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ ok: false, msg: 'Invalid request' });
    }
    const updated = await updateVirusTotalKey(id, body.data);
    if (!updated) {
      return reply.status(404).send({ ok: false, msg: 'API key not found' });
    }
    const keys = await listVirusTotalKeys();
    const usage = await getVirusTotalUsageSummary();
    return { ok: true, keys, usage };
  });

  app.delete('/api/admin/virustotal-keys/:id', { preHandler: requireAdmin }, async (request: AuthenticatedRequest, reply) => {
    const { id } = request.params as { id: string };
    const removed = await removeVirusTotalKey(id);
    if (!removed) {
      return reply.status(404).send({ ok: false, msg: 'API key not found' });
    }
    const keys = await listVirusTotalKeys();
    const usage = await getVirusTotalUsageSummary();
    return { ok: true, keys, usage };
  });

  // ============ MALWARE BAZAAR API KEY ============
  app.get('/api/admin/malwarebazaar', { preHandler: requireAdmin }, async (_request: AuthenticatedRequest, reply) => {
    const mb = await getMalwareBazaarApiKeyMasked();
    return { ok: true, configured: mb.configured, maskedKey: mb.maskedKey };
  });

  const setMalwareBazaarKeySchema = z.object({
    apiKey: z.string().max(500),
  });

  app.post('/api/admin/malwarebazaar', { preHandler: requireAdmin }, async (request: AuthenticatedRequest, reply) => {
    const body = setMalwareBazaarKeySchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ ok: false, msg: 'Invalid request' });
    }
    await setMalwareBazaarApiKey(body.data.apiKey.trim() || null);
    const mb = await getMalwareBazaarApiKeyMasked();
    return { ok: true, configured: mb.configured, maskedKey: mb.maskedKey };
  });

  app.delete('/api/admin/malwarebazaar', { preHandler: requireAdmin }, async (_request: AuthenticatedRequest, reply) => {
    await setMalwareBazaarApiKey(null);
    return { ok: true, configured: false, maskedKey: null };
  });

  // ============ ADMIN DASHBOARD STATS ============
  app.get('/api/admin/stats', { preHandler: requireAdmin }, async (request: AuthenticatedRequest, reply) => {
    // Get total users count
    const [usersResult] = await db.select({ count: count() }).from(schema.users);
    const totalUsers = usersResult?.count || 0;
    
    // Get total storage used
    const [storageResult] = await db.select({ 
      total: sum(schema.users.storageUsed) 
    }).from(schema.users);
    const totalStorage = Number(storageResult?.total) || 0;
    
    // Get active sessions (not expired)
    const now = new Date();
    const [sessionsResult] = await db.select({ count: count() })
      .from(schema.sessions)
      .where(gte(schema.sessions.expiresAt, now));
    const activeSessions = sessionsResult?.count || 0;
    
    // Get total files count
    const [filesResult] = await db.select({ count: count() })
      .from(schema.files)
      .where(eq(schema.files.isDeleted, false));
    const totalFiles = filesResult?.count || 0;
    
    // Get suspended users count
    const [suspendedResult] = await db.select({ count: count() })
      .from(schema.users)
      .where(eq(schema.users.isSuspended, true));
    const suspendedUsers = suspendedResult?.count || 0;

    // Backend filesystem capacity (total storage follows disk/mount)
    const storageBackend = await getStats();

    return {
      ok: true,
      stats: {
        totalUsers,
        totalStorage,
        activeSessions,
        totalFiles,
        suspendedUsers,
        storageBackend: storageBackend ? { total: storageBackend.total, free: storageBackend.free } : null,
      },
    };
  });
  
  // ============ LIST ALL USERS ============
  app.get('/api/admin/users', { preHandler: requireAdmin }, async (request: AuthenticatedRequest, reply) => {
    const { page = '1', limit = '20', search = '' } = request.query as { 
      page?: string; 
      limit?: string;
      search?: string;
    };
    
    const pageNum = parseInt(page);
    const limitNum = parseInt(limit);
    const offset = (pageNum - 1) * limitNum;
    
    const users = await db.query.users.findMany({
      orderBy: (users: any, { desc }: any) => [desc(users.createdAt)],
      limit: limitNum,
      offset,
    });
    
    const [totalResult] = await db.select({ count: count() }).from(schema.users);
    const total = totalResult?.count || 0;
    
    return {
      ok: true,
      users: users.map((u: any) => ({
        id: u.id,
        username: u.username,
        isAdmin: u.isAdmin,
        isSuspended: u.isSuspended,
        suspendedAt: u.suspendedAt,
        storageUsed: u.storageUsed,
        storageQuota: u.storageQuota,
        totpEnabled: u.totpEnabled,
        createdAt: u.createdAt,
      })),
      pagination: {
        page: pageNum,
        limit: limitNum,
        total,
        totalPages: Math.ceil(total / limitNum),
      },
    };
  });
  
  // ============ SUSPEND/UNSUSPEND USER ============
  app.patch('/api/admin/users/:userId/suspend', { preHandler: requireAdmin }, async (request: AuthenticatedRequest, reply) => {
    const admin = request.user!;
    const { userId } = request.params as { userId: string };
    const userIdNum = parseInt(userId);
    
    const body = suspendUserSchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ ok: false, msg: 'Invalid request' });
    }
    
    const { suspended } = body.data;
    
    // Prevent self-suspension
    if (userIdNum === admin.id) {
      return reply.status(400).send({ ok: false, msg: 'Cannot suspend yourself' });
    }
    
    const user = await db.query.users.findFirst({
      where: eq(schema.users.id, userIdNum),
    });
    
    if (!user) {
      return reply.status(404).send({ ok: false, msg: 'User not found' });
    }
    
    await db.update(schema.users)
      .set({
        isSuspended: suspended,
        suspendedAt: suspended ? new Date() : null,
      })
      .where(eq(schema.users.id, userIdNum));
    
    // If suspending, delete all their sessions
    if (suspended) {
      await db.delete(schema.sessions).where(eq(schema.sessions.userId, userIdNum));
    }
    
    // Log audit
    await logAudit(
      admin.id,
      admin.username,
      suspended ? 'USER_SUSPENDED' : 'USER_UNSUSPENDED',
      'USER',
      userId,
      { targetUsername: user.username },
      getClientIp(request),
      request.headers['user-agent']
    );
    
    return { ok: true, suspended };
  });
  
  // ============ UPDATE USER QUOTA ============
  app.patch('/api/admin/users/:userId/quota', { preHandler: requireAdmin }, async (request: AuthenticatedRequest, reply) => {
    const admin = request.user!;
    const { userId } = request.params as { userId: string };
    const userIdNum = parseInt(userId);
    
    const body = updateQuotaSchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ ok: false, msg: 'Invalid request' });
    }
    
    let { quota } = body.data;

    const user = await db.query.users.findFirst({
      where: eq(schema.users.id, userIdNum),
    });

    if (!user) {
      return reply.status(404).send({ ok: false, msg: 'User not found' });
    }

    // Cap quota by filesystem: don't allow more than (free + this user's current used)
    const backendStats = await getStats();
    if (backendStats) {
      const maxAssignable = backendStats.free + (user.storageUsed ?? 0);
      if (quota > maxAssignable) {
        quota = maxAssignable;
      }
    }

    await db.update(schema.users)
      .set({ storageQuota: quota })
      .where(eq(schema.users.id, userIdNum));

    // Log audit
    await logAudit(
      admin.id,
      admin.username,
      'USER_QUOTA_UPDATED',
      'USER',
      userId,
      { targetUsername: user.username, oldQuota: user.storageQuota, newQuota: quota },
      getClientIp(request),
      request.headers['user-agent']
    );
    
    return { ok: true, quota };
  });
  
  // ============ GET AUDIT LOGS ============
  app.get('/api/admin/audit-logs', { preHandler: requireAdmin }, async (request: AuthenticatedRequest, reply) => {
    const { page = '1', limit = '50', action = '', username = '' } = request.query as {
      page?: string;
      limit?: string;
      action?: string;
      username?: string;
    };
    
    const pageNum = parseInt(page);
    const limitNum = parseInt(limit);
    const offset = (pageNum - 1) * limitNum;
    
    const logs = await db.query.auditLogs.findMany({
      orderBy: (logs: any, { desc }: any) => [desc(logs.createdAt)],
      limit: limitNum,
      offset,
    });
    
    const [totalResult] = await db.select({ count: count() }).from(schema.auditLogs);
    const total = totalResult?.count || 0;
    
    return {
      ok: true,
      logs: logs.map((log: any) => ({
        id: log.id,
        userId: log.userId,
        username: log.username,
        action: log.action,
        resourceType: log.resourceType,
        resourceId: log.resourceId,
        details: log.details ? JSON.parse(log.details) : null,
        ipAddress: log.ipAddress,
        userAgent: log.userAgent,
        createdAt: log.createdAt,
      })),
      pagination: {
        page: pageNum,
        limit: limitNum,
        total,
        totalPages: Math.ceil(total / limitNum),
      },
    };
  });
  
  // ============ GET USER SESSIONS (Admin) ============
  app.get('/api/admin/users/:userId/sessions', { preHandler: requireAdmin }, async (request: AuthenticatedRequest, reply) => {
    const { userId } = request.params as { userId: string };
    const userIdNum = parseInt(userId);
    
    const sessions = await db.query.sessions.findMany({
      where: eq(schema.sessions.userId, userIdNum),
      orderBy: (sessions: any, { desc }: any) => [desc(sessions.createdAt)],
    });
    
    const now = new Date();
    
    return {
      ok: true,
      sessions: sessions.map((s: any) => ({
        id: s.id,
        deviceInfo: s.deviceInfo,
        ipAddress: s.ipAddress,
        userAgent: s.userAgent,
        createdAt: s.createdAt,
        lastActive: s.lastActive,
        expiresAt: s.expiresAt,
        isActive: s.expiresAt > now,
      })),
    };
  });
  
  // ============ REVOKE USER SESSION (Admin) ============
  app.delete('/api/admin/sessions/:sessionId', { preHandler: requireAdmin }, async (request: AuthenticatedRequest, reply) => {
    const admin = request.user!;
    const { sessionId } = request.params as { sessionId: string };
    const sessionIdNum = parseInt(sessionId);
    
    const session = await db.query.sessions.findFirst({
      where: eq(schema.sessions.id, sessionIdNum),
      with: { user: true },
    });
    
    if (!session) {
      return reply.status(404).send({ ok: false, msg: 'Session not found' });
    }
    
    await db.delete(schema.sessions).where(eq(schema.sessions.id, sessionIdNum));
    
    // Log audit
    await logAudit(
      admin.id,
      admin.username,
      'SESSION_REVOKED',
      'SESSION',
      sessionId,
      { targetUserId: session.userId },
      getClientIp(request),
      request.headers['user-agent']
    );
    
    return { ok: true };
  });
}
