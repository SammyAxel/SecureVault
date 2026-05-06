import { FastifyRequest, FastifyReply } from 'fastify';
import { db, schema } from '../db/index.js';
import { eq, and, gt } from 'drizzle-orm';
import { hashSHA256, generateToken } from '../lib/crypto.js';
import { getClientIp } from '../lib/clientIp.js';
import { config } from '../config.js';
import {
  getSessionTokenFromRequest,
  setSessionAndCsrfCookies,
} from '../lib/sessionCookies.js';

export interface AuthenticatedRequest extends FastifyRequest {
  user?: schema.User;
  session?: schema.Session;
  /** The raw session token (unhashed). Needed for "isCurrent" checks and logout. */
  rawToken?: string;
}

function ipv4Prefix24(ip: string): string | null {
  const p = ip.split('.');
  if (p.length === 4 && p.every((x) => /^\d{1,3}$/.test(x) && Number(x) <= 255)) {
    return `${p[0]}.${p[1]}.${p[2]}`;
  }
  return null;
}

function sessionBindingMatches(
  storedIp: string | null,
  currentIp: string,
  storedUa: string | null,
  currentUa: string | undefined
): boolean {
  const ua = (currentUa ?? '').trim() || 'unknown';
  const sUa = (storedUa ?? '').trim() || 'unknown';
  if (sUa !== ua && sUa !== 'unknown') return false;
  if (!storedIp || storedIp === 'unknown') return true;
  if (storedIp === currentIp) return true;
  if (config.SESSION_BIND_IPV4_SUBNET) {
    const a = ipv4Prefix24(storedIp);
    const b = ipv4Prefix24(currentIp);
    if (a && b && a === b) return true;
  }
  return false;
}

export async function authenticate(
  request: AuthenticatedRequest,
  reply: FastifyReply
): Promise<void> {
  let rawToken = getSessionTokenFromRequest(request);

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

  if (config.SESSION_BIND_IP_UA) {
    const ip = getClientIp(request);
    const ua = request.headers['user-agent'];
    if (!sessionBindingMatches(session.ipAddress ?? null, ip, session.userAgent ?? null, ua)) {
      await db.delete(schema.sessions).where(eq(schema.sessions.id, session.id));
      return reply.status(401).send({
        ok: false,
        msg: 'Session no longer valid (network or device changed). Please sign in again.',
        code: 'SESSION_BINDING',
      });
    }
  }

  const rotateHours = config.SESSION_ROTATE_HOURS;
  if (rotateHours > 0) {
    const rotatedAt = session.tokenRotatedAt ?? session.createdAt ?? new Date();
    const intervalMs = rotateHours * 3600 * 1000;
    if (Date.now() - rotatedAt.getTime() >= intervalMs) {
      const newToken = generateToken();
      const newHash = hashSHA256(newToken);
      await db
        .update(schema.sessions)
        .set({ token: newHash, tokenRotatedAt: new Date() })
        .where(eq(schema.sessions.id, session.id));
      rawToken = newToken;
      session.token = newHash;
      setSessionAndCsrfCookies(reply, request, newToken, session.expiresAt);
    }
  }

  await db
    .update(schema.sessions)
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
  _reply: FastifyReply
): Promise<void> {
  const rawToken = getSessionTokenFromRequest(request);

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
