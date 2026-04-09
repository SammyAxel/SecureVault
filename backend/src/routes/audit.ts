import type { FastifyInstance } from 'fastify';
import { and, count, eq } from 'drizzle-orm';
import { db, schema } from '../db/index.js';
import { authenticate, type AuthenticatedRequest } from '../middleware/auth.js';
import { demoSessionFilter } from '../lib/demo.js';

export async function auditRoutes(app: FastifyInstance): Promise<void> {
  // ============ GET MY AUDIT LOGS (Activity timeline) ============
  app.get('/api/audit-logs', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const { page = '1', limit = '30' } = request.query as {
      page?: string;
      limit?: string;
    };

    const pageNum = Math.max(1, parseInt(page) || 1);
    const limitNum = Math.min(100, Math.max(1, parseInt(limit) || 30));
    const offset = (pageNum - 1) * limitNum;

    const user = request.user!;
    const dsid = demoSessionFilter(request);

    const logs = await db.query.auditLogs.findMany({
      where: and(
        eq(schema.auditLogs.userId, user.id),
        dsid != null ? eq(schema.auditLogs.demoSessionId, dsid) : undefined
      ),
      orderBy: (logs: any, { desc }: any) => [desc(logs.createdAt)],
      limit: limitNum,
      offset,
    });

    const [totalResult] = await db
      .select({ count: count() })
      .from(schema.auditLogs)
      .where(
        and(
          eq(schema.auditLogs.userId, user.id),
          dsid != null ? eq(schema.auditLogs.demoSessionId, dsid) : undefined
        )
      );
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
}

