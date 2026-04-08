import { FastifyRequest, FastifyReply } from 'fastify';
import { db, schema } from '../db/index.js';
import { eq, and, gt } from 'drizzle-orm';
import { hashSHA256 } from '../lib/crypto.js';

export interface AuthenticatedRequest extends FastifyRequest {
  user?: schema.User;
  session?: schema.Session;
  /** The raw Bearer token (unhashed). Needed for "isCurrent" checks. */
  rawToken?: string;
}

export async function authenticate(
  request: AuthenticatedRequest,
  reply: FastifyReply
): Promise<void> {
  const rawToken = request.headers.authorization?.replace('Bearer ', '');

  if (!rawToken) {
    return reply.status(401).send({ ok: false, msg: 'No authorization token provided' });
  }

  const tokenHash = hashSHA256(rawToken);

  const session = await db.query.sessions.findFirst({
    where: and(
      eq(schema.sessions.token, tokenHash),
      gt(schema.sessions.expiresAt, new Date())
    ),
    with: { user: true },
  });

  if (!session) {
    return reply.status(401).send({ ok: false, msg: 'Invalid or expired session' });
  }

  if (session.user.isSuspended) {
    return reply.status(403).send({ ok: false, msg: 'Account is suspended' });
  }

  await db.update(schema.sessions)
    .set({ lastActive: new Date() })
    .where(eq(schema.sessions.id, session.id));

  request.user = session.user;
  request.session = session;
  request.rawToken = rawToken;
}

export async function requireAdmin(
  request: AuthenticatedRequest,
  reply: FastifyReply
): Promise<void> {
  if (!request.user?.isAdmin) {
    return reply.status(403).send({ ok: false, msg: 'Admin access required' });
  }
}

export async function optionalAuth(
  request: AuthenticatedRequest,
  reply: FastifyReply
): Promise<void> {
  const rawToken = request.headers.authorization?.replace('Bearer ', '');

  if (!rawToken) return;

  const tokenHash = hashSHA256(rawToken);

  const session = await db.query.sessions.findFirst({
    where: and(
      eq(schema.sessions.token, tokenHash),
      gt(schema.sessions.expiresAt, new Date())
    ),
    with: { user: true },
  });

  if (session && !session.user.isSuspended) {
    request.user = session.user;
    request.session = session;
    request.rawToken = rawToken;
  }
}
