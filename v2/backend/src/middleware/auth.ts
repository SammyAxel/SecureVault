import { FastifyRequest, FastifyReply } from 'fastify';
import { db, schema } from '../db/index.js';
import { eq, and, gt } from 'drizzle-orm';

export interface AuthenticatedRequest extends FastifyRequest {
  user?: schema.User;
  session?: schema.Session;
}

/**
 * Authentication middleware - verifies session token
 */
export async function authenticate(
  request: AuthenticatedRequest,
  reply: FastifyReply
): Promise<void> {
  const token = request.headers.authorization?.replace('Bearer ', '');
  
  if (!token) {
    return reply.status(401).send({ ok: false, msg: 'No authorization token provided' });
  }
  
  // Find valid session
  const session = await db.query.sessions.findFirst({
    where: and(
      eq(schema.sessions.token, token),
      gt(schema.sessions.expiresAt, new Date())
    ),
    with: { user: true },
  });
  
  if (!session) {
    return reply.status(401).send({ ok: false, msg: 'Invalid or expired session' });
  }
  
  // Check if user is suspended
  if (session.user.isSuspended) {
    return reply.status(403).send({ ok: false, msg: 'Account is suspended' });
  }
  
  // Update last active
  await db.update(schema.sessions)
    .set({ lastActive: new Date() })
    .where(eq(schema.sessions.id, session.id));
  
  // Attach user and session to request
  request.user = session.user;
  request.session = session;
}

/**
 * Admin middleware - checks if user is admin
 */
export async function requireAdmin(
  request: AuthenticatedRequest,
  reply: FastifyReply
): Promise<void> {
  if (!request.user?.isAdmin) {
    return reply.status(403).send({ ok: false, msg: 'Admin access required' });
  }
}

/**
 * Optional auth - doesn't fail if not authenticated
 */
export async function optionalAuth(
  request: AuthenticatedRequest,
  reply: FastifyReply
): Promise<void> {
  const token = request.headers.authorization?.replace('Bearer ', '');
  
  if (!token) return;
  
  const session = await db.query.sessions.findFirst({
    where: and(
      eq(schema.sessions.token, token),
      gt(schema.sessions.expiresAt, new Date())
    ),
    with: { user: true },
  });
  
  if (session && !session.user.isSuspended) {
    request.user = session.user;
    request.session = session;
  }
}
