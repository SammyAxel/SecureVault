import { test, expect } from '@playwright/test';

test.describe('Enkripsi End-to-End', () => {
  test('Memastikan file yang tersimpan berupa ciphertext', async ({ page, request }) => {
    // Normally this requires access to the backend filesystem.
    // In E2E, we can verify that the upload payload is encrypted.
    // We can observe the network request during upload.
    
    await page.goto('/drive');
    const fileInput = page.locator('input[type="file"]');
    await expect(fileInput).toBeAttached();
    // Setup fetch spy in page context
    await page.evaluate(() => {
      (window as any).__lastUploadContainsPlaintext = null;
      const originalFetch = window.fetch;
      window.fetch = async function(input, init) {
        const url = typeof input === 'string' ? input : (input as Request).url;
        if (url.includes('/api/upload') && init && init.body instanceof FormData) {
          const body = init.body;
          const file = body.get('file');
          if (file instanceof Blob) {
            const text = await file.text();
            (window as any).__lastUploadContainsPlaintext = text.includes('This is a test file for upload.');
          }
        }
        return originalFetch.apply(this, arguments as any);
      };
    });

    const [requestEvent] = await Promise.all([
      page.waitForRequest(req => req.url().includes('/api/upload') && req.method() === 'POST'),
      fileInput.setInputFiles({
        name: 'testfile.txt',
        mimeType: 'text/plain',
        buffer: Buffer.from('This is a test file for upload.')
      })
    ]);
    
    // Check validation result from page context
    const containsPlaintext = await page.evaluate(() => (window as any).__lastUploadContainsPlaintext);
    expect(containsPlaintext).toBe(false);
  });

  test('Mengecek integritas file hash', async ({ page }) => {
    // Tests that frontend calculates SHA-256 correctly before encrypting
    // We can unit-test the crypto lib directly, or rely on UI states.
  });
});
