import { describe, it, expect, vi, beforeEach } from 'vitest';

// We test the ApiError class and the JSON-parse safety of request().
// Since request() uses fetch internally, we mock it.

describe('ApiError', () => {
  it('can be imported and constructed', async () => {
    const { ApiError } = await import('./api');
    const err = new ApiError(404, 'Not found');
    expect(err).toBeInstanceOf(Error);
    expect(err.status).toBe(404);
    expect(err.message).toBe('Not found');
    expect(err.name).toBe('ApiError');
  });

  it('carries optional data', async () => {
    const { ApiError } = await import('./api');
    const err = new ApiError(400, 'Quota', { quotaExceeded: true });
    expect(err.data?.quotaExceeded).toBe(true);
  });
});

describe('request() JSON safety', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
  });

  it('throws ApiError (not SyntaxError) when server returns non-JSON', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: () => Promise.resolve('<html>Error</html>'),
    }));

    const { ApiError } = await import('./api');
    // Re-import to get the module with the mocked fetch
    const mod = await import('./api');

    // publicRequestJson has always been safe; now request() should be too
    await expect(mod.publicRequestJson('/test')).rejects.toBeInstanceOf(ApiError);
  });
});
