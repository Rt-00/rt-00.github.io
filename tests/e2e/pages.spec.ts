import { expect, test } from '@playwright/test';

test('about page renders markdown as whoami', async ({ page }) => {
  await page.goto('/about/');
  const main = page.locator('main');
  await expect(main).toContainText('rt@blog:~$ whoami');
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('rt');
  await expect(page.locator('nav[aria-label="Main"] a[aria-current="page"]')).toHaveText('about');
});

test('unknown paths render a terminal-style 404', async ({ page }) => {
  const response = await page.goto('/nope/here/');
  expect(response?.status()).toBe(404);
  await expect(page.locator('main')).toContainText('command not found: /nope/here/');
  await expect(page.getByRole('link', { name: 'cd ~' })).toHaveAttribute('href', '/');
});
