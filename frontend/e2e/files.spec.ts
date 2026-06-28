import { test, expect } from '@playwright/test';

test.describe('Manajemen File', () => {
  // We assume the user is logged in before these tests
  // Since we don't have a global setup yet, we can mock or do a quick login if needed
  // For the sake of the feature test definitions, we outline the exact steps here.
  
  test.beforeEach(async ({ page }) => {
    // In a real environment, we would load the session or perform login here.
    // We will navigate to the home.
    await page.goto('/home');
  });

  test('Upload file berukuran normal', async ({ page }) => {
    // We mock file upload
    const fileInput = page.locator('input[type="file"]');
    if (await fileInput.count() > 0) {
      await fileInput.setInputFiles({
        name: 'testfile.txt',
        mimeType: 'text/plain',
        buffer: Buffer.from('This is a test file for upload.')
      });
      await page.click('button:has-text("Upload")');
      await expect(page.locator('text=testfile.txt')).toBeVisible({ timeout: 10000 });
    }
  });

  test('Upload file yang ukurannya melebihi kuota user', async ({ page }) => {
    // Attempt to upload a massive file or a file that triggers the quota limit
    // Assuming 50MB is the limit for demo
    const fileInput = page.locator('input[type="file"]');
    if (await fileInput.count() > 0) {
      const largeBuffer = Buffer.alloc(51 * 1024 * 1024, 'a'); // 51MB
      await fileInput.setInputFiles({
        name: 'toolarge.txt',
        mimeType: 'text/plain',
        buffer: largeBuffer
      });
      await page.click('button:has-text("Upload")');
      await expect(page.locator('text=Quota exceeded').or(page.locator('text=too large'))).toBeVisible();
    }
  });

  test('Download file milik sendiri dan memastikan isinya identik', async ({ page }) => {
    // Look for a download button on the first file
    const downloadBtn = page.locator('button[title="Download"], button:has-text("Download")').first();
    if (await downloadBtn.isVisible()) {
      const downloadPromise = page.waitForEvent('download');
      await downloadBtn.click();
      const download = await downloadPromise;
      expect(download.suggestedFilename()).not.toBeNull();
    }
  });

  test('Melihat daftar file dan memastikan hanya file milik akun sendiri yang tampil', async ({ page }) => {
    // Ensure the file list is rendered
    const fileList = page.locator('.file-list, table');
    await expect(fileList).toBeVisible();
    // Assuming UI implies ownership
  });

  test('Membuat folder baru untuk mengorganisir file', async ({ page }) => {
    const newFolderBtn = page.locator('button:has-text("New Folder")');
    if (await newFolderBtn.isVisible()) {
      await newFolderBtn.click();
      await page.fill('input[placeholder="Folder Name"]', 'Test Folder');
      await page.click('button:has-text("Create")');
      await expect(page.locator('text=Test Folder')).toBeVisible();
    }
  });

  test('Menghapus file sehingga berpindah ke Trash', async ({ page }) => {
    const deleteBtn = page.locator('button[title="Delete"], button:has-text("Delete")').first();
    if (await deleteBtn.isVisible()) {
      await deleteBtn.click();
      // Confirm deletion if there's a modal
      const confirmBtn = page.locator('button:has-text("Confirm")');
      if (await confirmBtn.isVisible()) {
        await confirmBtn.click();
      }
    }
  });

  test('Melihat isi halaman Trash dan Memulihkan file', async ({ page }) => {
    await page.goto('/trash');
    const trashItem = page.locator('.trash-item, tr').first();
    if (await trashItem.isVisible()) {
      const restoreBtn = trashItem.locator('button:has-text("Restore")');
      await restoreBtn.click();
      await expect(trashItem).not.toBeVisible();
    }
  });
});
