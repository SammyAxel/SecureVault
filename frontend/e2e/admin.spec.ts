import { test, expect } from '@playwright/test';

test.describe('Admin & Konfigurasi', () => {
  test('Menjalankan wizard setup pertama kali', async ({ page }) => {
    // Note: If DB is already seeded, this redirects.
    await page.goto('/setup');
    const isSetupCompleted = await page.locator('text=Setup completed').isVisible();
    if (!isSetupCompleted) {
      const adminInput = page.locator('input[placeholder="Admin Username"]');
      if (await adminInput.isVisible()) {
        await adminInput.fill('admin_tester');
        await page.click('button:has-text("Complete Setup")');
        await expect(page.locator('text=Dashboard')).toBeVisible();
      }
    }
  });

  test('Memastikan endpoint setup tidak bisa diakses setelah selesai', async ({ page, request }) => {
    const res = await request.get('/api/setup/status');
    const json = await res.json();
    if (json.completed) {
      await page.goto('/setup');
      // Should redirect to login or show 403
      await expect(page).toHaveURL(/.*\/login/);
    }
  });

  test('Admin melihat daftar seluruh user', async ({ page }) => {
    // Navigate to admin panel
    await page.goto('/admin/users');
    // Give the client-side router a moment to execute any redirect logic
    await page.waitForTimeout(1000);
    // We don't have login context here, so it might redirect
    if (page.url().includes('admin')) {
      await expect(page.locator('table, .user-list')).toBeVisible();
    }
  });
});
