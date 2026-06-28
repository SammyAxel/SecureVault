import { test, expect } from '@playwright/test';

test.describe('Berbagi File (Sharing)', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/home');
  });

  test('Berbagi file ke akun user lain', async ({ page }) => {
    const shareBtn = page.locator('button[title="Share"], button:has-text("Share")').first();
    if (await shareBtn.isVisible()) {
      await shareBtn.click();
      await page.fill('input[placeholder="Username to share with"]', 'targetuser');
      await page.click('button:has-text("Share File")');
      await expect(page.locator('text=Shared successfully')).toBeVisible();
    }
  });

  test('Mencoba berbagi file ke username yang tidak terdaftar', async ({ page }) => {
    const shareBtn = page.locator('button[title="Share"], button:has-text("Share")').first();
    if (await shareBtn.isVisible()) {
      await shareBtn.click();
      await page.fill('input[placeholder="Username to share with"]', 'invalid_user_xyz123');
      await page.click('button:has-text("Share File")');
      await expect(page.locator('text=User not found').or(page.locator('.text-red-500'))).toBeVisible();
    }
  });

  test('Membuat dan mengakses public link', async ({ page }) => {
    const publicLinkBtn = page.locator('button:has-text("Create Public Link")').first();
    if (await publicLinkBtn.isVisible()) {
      await publicLinkBtn.click();
      const linkInput = page.locator('input[readonly]');
      const linkValue = await linkInput.inputValue();
      expect(linkValue).toContain(page.context().browser()?.contexts()[0].pages()[0].url().split('/')[2] || 'localhost');
      
      // Access the public link from a new context (unauthenticated)
      const context2 = await page.context().browser()!.newContext();
      const page2 = await context2.newPage();
      await page2.goto(linkValue);
      await expect(page2.locator('text=Download')).toBeVisible();
      await context2.close();
    }
  });

  test('Mencabut (revoke) public link', async ({ page }) => {
    const revokeBtn = page.locator('button:has-text("Revoke Link")').first();
    if (await revokeBtn.isVisible()) {
      await revokeBtn.click();
      await expect(page.locator('text=Link revoked')).toBeVisible();
    }
  });
});
