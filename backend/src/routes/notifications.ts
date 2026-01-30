import type { FastifyInstance } from 'fastify';
import { db, schema } from '../db/index.js';
import { eq, and, desc, count } from 'drizzle-orm';
import type { AuthenticatedRequest } from '../middleware/auth.js';
import { authenticate } from '../middleware/auth.js';

export default async function notificationRoutes(app: FastifyInstance) {
  // ============ GET NOTIFICATIONS ============
  app.get('/api/notifications', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;
    const { unread_only, limit = '50' } = request.query as { unread_only?: string; limit?: string };
    
    const limitNum = Math.min(parseInt(limit), 100); // Max 100
    
    const where = unread_only === 'true' 
      ? and(eq(schema.notifications.userId, user.id), eq(schema.notifications.read, false))
      : eq(schema.notifications.userId, user.id);
    
    const notifications = await db.query.notifications.findMany({
      where,
      orderBy: (notifications: any, { desc }: any) => [desc(notifications.createdAt)],
      limit: limitNum,
    });
    
    // Get unread count
    const [unreadResult] = await db
      .select({ count: count() })
      .from(schema.notifications)
      .where(and(
        eq(schema.notifications.userId, user.id),
        eq(schema.notifications.read, false)
      ));
    
    return {
      ok: true,
      notifications,
      unreadCount: unreadResult?.count || 0,
    };
  });

  // ============ MARK NOTIFICATION AS READ ============
  app.patch('/api/notifications/:id/read', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;
    const { id } = request.params as { id: string };
    const notificationId = parseInt(id);
    
    const notification = await db.query.notifications.findFirst({
      where: and(
        eq(schema.notifications.id, notificationId),
        eq(schema.notifications.userId, user.id)
      ),
    });
    
    if (!notification) {
      return reply.status(404).send({ ok: false, msg: 'Notification not found' });
    }
    
    await db.update(schema.notifications)
      .set({ read: true })
      .where(eq(schema.notifications.id, notificationId));
    
    return { ok: true };
  });

  // ============ MARK ALL AS READ ============
  app.patch('/api/notifications/read-all', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;
    
    await db.update(schema.notifications)
      .set({ read: true })
      .where(and(
        eq(schema.notifications.userId, user.id),
        eq(schema.notifications.read, false)
      ));
    
    return { ok: true };
  });

  // ============ DELETE NOTIFICATION ============
  app.delete('/api/notifications/:id', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;
    const { id } = request.params as { id: string };
    const notificationId = parseInt(id);
    
    const notification = await db.query.notifications.findFirst({
      where: and(
        eq(schema.notifications.id, notificationId),
        eq(schema.notifications.userId, user.id)
      ),
    });
    
    if (!notification) {
      return reply.status(404).send({ ok: false, msg: 'Notification not found' });
    }
    
    await db.delete(schema.notifications)
      .where(eq(schema.notifications.id, notificationId));
    
    return { ok: true };
  });

  // ============ CLEAR ALL NOTIFICATIONS ============
  app.delete('/api/notifications', { preHandler: authenticate }, async (request: AuthenticatedRequest, reply) => {
    const user = request.user!;
    
    await db.delete(schema.notifications)
      .where(eq(schema.notifications.userId, user.id));
    
    return { ok: true };
  });
}

// ============ HELPER FUNCTION ============
export async function createNotification(
  userId: number,
  type: string,
  title: string,
  message: string,
  actionUrl?: string,
  metadata?: Record<string, any>
) {
  await db.insert(schema.notifications).values({
    userId,
    type,
    title,
    message,
    actionUrl: actionUrl || null,
    metadata: metadata ? JSON.stringify(metadata) : null,
  });
}
