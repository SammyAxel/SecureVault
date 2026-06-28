import { test, expect, Page } from '@playwright/test';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Menonaktifkan storageState bawaan agar kita bisa mendaftarkan 2 akun segar secara paralel
test.use({ storageState: { cookies: [], origins: [] } });

async function setupAndLogin(page: Page, username: string) {
  await page.goto('/register');
  await page.fill('input[id="register-username"]', username);
  
  const downloadPromise = page.waitForEvent('download');
  await page.click('button[type="submit"]:has-text("Create Account")');
  const download = await downloadPromise;
  
  const keyPath = path.join(__dirname, `.auth/${username}_key.json`);
  await download.saveAs(keyPath);
  
  // Aplikasi auto-navigate ke login
  await page.waitForURL('**/login');
  await page.fill('input[id="login-username"], input[placeholder="Enter your username"]', username);
  await page.setInputFiles('input[type="file"]', keyPath);
  await page.click('button[type="submit"]:has-text("Login")');
  
  await expect(page.locator('text="Home"').or(page.locator('text="My Drive"')).first()).toBeVisible({ timeout: 15000 });
}

test.describe('Skenario Multi-User & Race Condition', () => {
  test('Menguji 2 koneksi bersamaan & upload file paralel (Isolasi & Race Condition)', async ({ browser }) => {
    test.setTimeout(90000); // Waktu ekstra karena 2 bot mendaftar live
    
    // Buka dua konteks browser incognito secara terpisah
    const contextA = await browser.newContext();
    const contextB = await browser.newContext();
    
    const pageA = await contextA.newPage();
    const pageB = await contextB.newPage();
    
    const timestamp = Date.now();
    const userA = `user_A_${timestamp}`;
    const userB = `user_B_${timestamp}`;
    
    // 1. Eksekusi Registrasi & Login secara berurutan agar CPU tidak spike (karena generate key RSA sangat berat)
    await setupAndLogin(pageA, userA);
    await setupAndLogin(pageB, userB);

    // 2. Navigasi ke My Drive (karena tombol Upload hanya ada di Dashboard My Drive, bukan di halaman Home)
    await Promise.all([
      pageA.click('text="My Drive"'),
      pageB.click('text="My Drive"')
    ]);
    await Promise.all([
      pageA.waitForURL('**/drive'),
      pageB.waitForURL('**/drive')
    ]);

    // 3. Persiapkan data file yang berbeda untuk masing-masing user
    const filePayloadA = {
      name: `file_rahasia_A_${timestamp}.txt`,
      mimeType: 'text/plain',
      buffer: Buffer.from('Ini adalah data file rahasia milik User A.')
    };

    const filePayloadB = {
      name: `file_rahasia_B_${timestamp}.txt`,
      mimeType: 'text/plain',
      buffer: Buffer.from('Ini adalah data file rahasia milik User B.')
    };

    // 3. Trigger Upload secara SIMULTAN (Race Condition Test)
    // Menggunakan FileChooser native browser agar event onChange SolidJS 100% terpicu
    const [fileChooserA, fileChooserB] = await Promise.all([
      pageA.waitForEvent('filechooser'),
      pageB.waitForEvent('filechooser'),
      pageA.click('label[aria-label="Upload files"]'),
      pageB.click('label[aria-label="Upload files"]')
    ]);

    await Promise.all([
      fileChooserA.setFiles(filePayloadA),
      fileChooserB.setFiles(filePayloadB)
    ]);

    // 4. Verifikasi bahwa tidak ada crash dan file masing-masing masuk
    await expect(pageA.locator(`text="${filePayloadA.name}"`).first()).toBeVisible({ timeout: 10000 });
    await expect(pageB.locator(`text="${filePayloadB.name}"`).first()).toBeVisible({ timeout: 10000 });

    // 5. Data Leak / Isolation Check
    // Pastikan User A TIDAK melihat file B, dan User B TIDAK melihat file A!
    await expect(pageA.locator(`text="${filePayloadB.name}"`)).not.toBeVisible();
    await expect(pageB.locator(`text="${filePayloadA.name}"`)).not.toBeVisible();
    
    await contextA.close();
    await contextB.close();
  });
});
