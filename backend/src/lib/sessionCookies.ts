import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { generateToken } from './crypto.js';
import { config } from '../config.js';

export const SESSION_COOKIE_NAME = 'sv_sid';
export const CSRF_COOKIE_NAME = 'sv_csrf';
export const CSRF_HEADER_NAME = 'x-csrf-token';

/** Unauthenticated POST/PUT/PATCH/DELETE paths that skip CSRF double-submit. */
const CSRF_SKIP_PREFIXES = [
  '/api/register',
  '/api/setup/admin',
  '/api/auth/challenge',
  '/api/auth/verify',
  '/api/auth/device-link/challenge',
  '/api/auth/device-link/verify',
] as const;

export function isRequestHttps(request: FastifyRequest): boolean {
  const xf = request.headers['x-forwarded-proto'];
  const proto = (Array.isArray(xf) ? xf[0] : xf)?.split(',')[0]?.trim();
  if (proto === 'https') return true;
  return request.protocol === 'https';
}

function cookieSecure(request: FastifyRequest): boolean {
  if (config.SESSION_COOKIE_SECURE === 'true') return true;
  if (config.SESSION_COOKIE_SECURE === 'false') return false;
  return isRequestHttps(request);
}

function sameSitePolicy(): 'strict' | 'lax' | 'none' {
  const v = config.SESSION_COOKIE_SAMESITE;
  if (v === 'strict' || v === 'lax' || v === 'none') return v;
  return 'lax';
}

function cookieBaseOpts(request: FastifyRequest, maxAgeSec: number) {
  const secure = cookieSecure(request);
  const sameSite = sameSitePolicy();
  if (sameSite === 'none' && !secure) {
    throw new Error('SESSION_COOKIE_SAMESITE=none requires HTTPS (Secure cookies)');
  }
  return {
    path: '/',
    maxAge: maxAgeSec,
    secure,
    sameSite,
  } as const;
}

export function setSessionAndCsrfCookies(
  reply: FastifyReply,
  request: FastifyRequest,
  sessionToken: string,
  expiresAt: Date
): void {
  const maxAgeSec = Math.max(
    60,
    Math.floor((expiresAt.getTime() - Date.now()) / 1000)
  );
  const base = cookieBaseOpts(request, maxAgeSec);
  reply.setCookie(SESSION_COOKIE_NAME, sessionToken, {
    ...base,
    httpOnly: true,
  });
  const csrf = generateToken(24);
  reply.setCookie(CSRF_COOKIE_NAME, csrf, {
    ...base,
    httpOnly: false,
  });
}

export function clearSessionAndCsrfCookies(reply: FastifyReply, request: FastifyRequest): void {
  const base = cookieBaseOpts(request, 0);
  reply.clearCookie(SESSION_COOKIE_NAME, { path: '/', secure: base.secure, sameSite: base.sameSite });
  reply.clearCookie(CSRF_COOKIE_NAME, { path: '/', secure: base.secure, sameSite: base.sameSite });
}

export function getSessionTokenFromRequest(request: FastifyRequest): string | undefined {
  const fromCookie = request.cookies?.[SESSION_COOKIE_NAME];
  if (fromCookie) return fromCookie;
  if (config.LEGACY_BEARER_AUTH) {
    const h = request.headers.authorization;
    if (h?.startsWith('Bearer ')) return h.slice(7);
  }
  return undefined;
}

function requestPath(request: FastifyRequest): string {
  const u = request.url.split('?')[0];
  return u || '';
}

export function shouldSkipCsrfCheck(request: FastifyRequest): boolean {
  const m = request.method;
  if (m === 'GET' || m === 'HEAD' || m === 'OPTIONS') return true;
  const path = requestPath(request);
  for (const p of CSRF_SKIP_PREFIXES) {
    if (path === p || path.startsWith(`${p}/`)) return true;
  }
  return false;
}

export function registerCsrfHook(app: FastifyInstance): void {
  app.addHook('preHandler', async (request, reply) => {
    if (!requestPath(request).startsWith('/api')) return;
    if (shouldSkipCsrfCheck(request)) return;
    const cookieVal = request.cookies?.[CSRF_COOKIE_NAME];
    const headerVal = request.headers[CSRF_HEADER_NAME];
    const headerStr = Array.isArray(headerVal) ? headerVal[0] : headerVal;
    if (!cookieVal || !headerStr || cookieVal !== headerStr) {
      return reply.status(403).send({ ok: false, msg: 'Invalid or missing CSRF token' });
    }
  });
}
