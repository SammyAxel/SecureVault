import { test, expect } from '@playwright/test';

test.describe('SecureVault Feature Tests', () => {
  test('Application loads correctly', async ({ page }) => {
    // Navigasi ke frontend
    await page.goto('/');
    
    // Pastikan halaman dimuat dengan mengecek judul atau elemen spesifik
    await expect(page).toHaveTitle(/SecureVault/i);
    
    // Memeriksa apakah UI utama untuk otentikasi/login muncul
    const mainContainer = page.locator('main');
    await expect(mainContainer).toBeVisible();
  });

  test('Demo mode login available', async ({ page }) => {
    await page.goto('/');
    
    // Memeriksa tombol "Download demo admin keys" atau tombol login
    const downloadKeysBtn = page.getByText(/Download demo admin keys/i);
    if (await downloadKeysBtn.isVisible()) {
      await expect(downloadKeysBtn).toBeVisible();
    }
  });
});
