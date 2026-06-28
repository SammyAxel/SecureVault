import { test as setup, expect } from '@playwright/test';
import { fileURLToPath } from 'url';
import * as path from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const authFile = path.join(__dirname, '.auth/user.json');

setup('Register, Login, and save session', async ({ page }) => {
  await page.goto('/');

  // Navigasi ke halaman Register
  if (page.url().includes('login')) {
    const registerBtn = page.locator('button:has-text("Register")');
    if (await registerBtn.isVisible()) {
      await registerBtn.click();
    }
  } else if (!page.url().includes('register')) {
    await page.goto('/register');
  }

  const botUsername = `bot_tester_${Date.now()}`;
  await page.fill('input[placeholder="Choose a username"], input[id="register-username"]', botUsername);

  // Klik Create Account dan tangkap unduhan key file
  const downloadPromise = page.waitForEvent('download');
  await page.click('button[type="submit"]:has-text("Create Account")');
  const download = await downloadPromise;

  const keyPath = path.join(__dirname, `.auth/${botUsername}_key.json`);
  await download.saveAs(keyPath);

  // Aplikasi akan otomatis navigate ke /login setelah register sukses.
  // Sekarang lakukan proses Login

  // Sekarang lakukan proses Login
  await page.fill('input[id="login-username"], input[placeholder="Enter your username"]', botUsername);
  
  // Unggah key file
  await page.setInputFiles('input[type="file"]', keyPath);
  
  // Klik tombol Login (biasanya teksnya "Login" atau "Sign In")
  await page.click('button[type="submit"]:has-text("Login")');

  // Tunggu masuk ke Home
  await expect(page.locator('text="Home"').or(page.locator('text="My Drive"')).first()).toBeVisible({ timeout: 15000 });

  // Simpan state session
  await page.context().storageState({ path: authFile });
});
