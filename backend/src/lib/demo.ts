import type { AuthenticatedRequest } from '../middleware/auth.js';

export const DEMO_MODE = process.env.DEMO_MODE === 'true';
export const DEMO_USERNAME = process.env.DEMO_USERNAME || 'demo_admin';
export const DEMO_SESSION_UPLOAD_LIMIT = 25 * 1024 * 1024; // 25 MB per session

/** True when the current request comes from the shared demo admin account. */
export function isDemoAdmin(request: AuthenticatedRequest): boolean {
  return DEMO_MODE && request.user?.username === DEMO_USERNAME;
}

/**
 * If the current request is from the demo admin, return their session id so
 * callers can scope file queries to this session. Returns null otherwise.
 */
export function demoSessionFilter(request: AuthenticatedRequest): number | null {
  if (!isDemoAdmin(request)) return null;
  return request.session?.id ?? null;
}
