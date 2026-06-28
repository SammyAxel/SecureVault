import { test, expect } from '@playwright/test';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Menonaktifkan storageState bawaan agar kita bisa mengetes Login & Register dari kondisi unauthenticated
test.use({ storageState: { cookies: [], origins: [] } });

test.describe('Autentikasi & Akun', () => {
  const testUser = `testuser_${Date.now()}`;

  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('Registrasi akun baru dengan generate keypair', async ({ page }) => {
    // Navigasi ke halaman Register
    if (page.url().includes('login')) {
      const registerBtn = page.locator('button:has-text("Register")');
      if (await registerBtn.isVisible()) {
        await registerBtn.click();
      }
    } else if (!page.url().includes('register')) {
      await page.goto('/register');
    }

    await page.fill('input[placeholder="Username"], input[id="register-username"]', testUser);
    
    // Listen for file download event
    const downloadPromise = page.waitForEvent('download');
    await page.click('button[type="submit"]:has-text("Register")');
    
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toContain(testUser);
    
    const keyPath = path.join(__dirname, `.auth/${testUser}_key.json`);
    await download.saveAs(keyPath);
    
    // Login
    await page.fill('input[id="login-username"], input[placeholder="Username"]', testUser);
    await page.setInputFiles('input[type="file"]', keyPath);
    await page.click('button[type="submit"]:has-text("Login")');
    
    // Verify redirected to home
    await expect(page.locator('text="Home"').or(page.locator('text="My Drive"')).first()).toBeVisible({ timeout: 15000 });
  });

  test('Login menggunakan key file yang salah atau milik user lain', async ({ page }) => {
    await page.goto('/login');
    await page.fill('input[placeholder="Username"]', 'nonexistent_user');
    
    // Memberikan file acak sebagai file key yang salah
    await page.setInputFiles('input[type="file"]', 'playwright.config.ts');
    await page.click('button[type="submit"]:has-text("Login")');
    
    // Harap ada error
    const errorMsg = page.locator('.text-red-500, .bg-red-500, [role="alert"]');
    await expect(errorMsg).toBeVisible();
  });

  test('Mengakses halaman yang membutuhkan login tanpa session aktif', async ({ page }) => {
    await page.goto('/home');
    // Karena session kosong, sistem harus menendang kembali ke Login
    await expect(page).toHaveURL(/.*\/login/);
  });
});
