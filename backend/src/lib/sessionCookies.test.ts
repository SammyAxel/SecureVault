import { describe, it, expect } from 'vitest';
import type { FastifyRequest } from 'fastify';
import { shouldSkipCsrfCheck } from './sessionCookies.js';

function req(method: string, url: string): FastifyRequest {
  return { method, url } as FastifyRequest;
}

describe('shouldSkipCsrfCheck', () => {
  it('allows safe methods without CSRF', () => {
    expect(shouldSkipCsrfCheck(req('GET', '/api/files'))).toBe(true);
    expect(shouldSkipCsrfCheck(req('HEAD', '/api/upload'))).toBe(true);
    expect(shouldSkipCsrfCheck(req('OPTIONS', '/api/files/x'))).toBe(true);
  });

  it('requires CSRF for authenticated mutating routes', () => {
    expect(shouldSkipCsrfCheck(req('POST', '/api/upload'))).toBe(false);
    expect(shouldSkipCsrfCheck(req('DELETE', '/api/files/550e8400-e29b-41d4-a716-446655440000'))).toBe(false);
  });

  it('skips CSRF only for the public share access recorder POST', () => {
    expect(shouldSkipCsrfCheck(req('POST', '/api/public/abc-123/access'))).toBe(true);
    expect(shouldSkipCsrfCheck(req('POST', '/api/public/abc-123/access?x=1'))).toBe(true);
    expect(shouldSkipCsrfCheck(req('POST', '/api/public/abc-123/other'))).toBe(false);
    expect(shouldSkipCsrfCheck(req('PUT', '/api/public/abc-123/access'))).toBe(false);
  });

  it('skips CSRF for auth registration and challenge routes', () => {
    expect(shouldSkipCsrfCheck(req('POST', '/api/register'))).toBe(true);
    expect(shouldSkipCsrfCheck(req('POST', '/api/auth/challenge'))).toBe(true);
  });
});
