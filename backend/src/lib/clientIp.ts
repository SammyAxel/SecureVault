/**
 * Get the client (source) IP for logging and rate limiting.
 * When the app is behind a reverse proxy (nginx, Cloudflare, etc.), request.ip
 * is often the proxy's IP (e.g. 127.0.0.1). We use X-Forwarded-For, X-Real-IP,
 * or CF-Connecting-IP when the direct connection is from a trusted/local source.
 */

import type { FastifyRequest } from 'fastify';

const LOCALHOST_IPV4 = '127.0.0.1';
const LOCALHOST_IPV6 = '::1';
const LOCALHOST_IPV6_MAPPED = '::ffff:127.0.0.1';

function isLocalOrPrivate(ip: string): boolean {
  if (!ip) return false;
  const trimmed = ip.trim().toLowerCase();
  if (trimmed === LOCALHOST_IPV4 || trimmed === LOCALHOST_IPV6 || trimmed === LOCALHOST_IPV6_MAPPED) {
    return true;
  }
  // Private ranges: 10.x, 172.16-31.x, 192.168.x
  if (trimmed.startsWith('10.')) return true;
  if (trimmed.startsWith('192.168.')) return true;
  if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(trimmed)) return true;
  return false;
}

/**
 * Returns the client IP, preferring proxy headers when the direct connection
 * is from localhost/private (i.e. we're behind a reverse proxy).
 */
export function getClientIp(request: FastifyRequest): string {
  const directIp = (request.ip ?? '').trim();

  if (isLocalOrPrivate(directIp)) {
    const forwarded = request.headers['x-forwarded-for'];
    if (forwarded) {
      const first = (typeof forwarded === 'string' ? forwarded : forwarded[0])?.split(',')[0]?.trim();
      if (first) return first;
    }
    const realIp = request.headers['x-real-ip'];
    if (realIp) {
      const ip = typeof realIp === 'string' ? realIp : realIp[0];
      if (ip?.trim()) return ip.trim();
    }
    const cf = request.headers['cf-connecting-ip'];
    if (cf) {
      const ip = typeof cf === 'string' ? cf : cf[0];
      if (ip?.trim()) return ip.trim();
    }
  }

  return directIp || 'unknown';
}
