import { expect, test } from '@playwright/test';

test('tags index lists tags with counts, most used first', async ({ page }) => {
  await page.goto('/tags/');
  const main = page.locator('main');
  await expect(main).toContainText('rt@blog:~$ ls tags/');
  const items = main.getByRole('listitem');
  // `meta` is used by two published posts and one draft: drafts must not count
  await expect(items.first()).toHaveText(/^\s*2\s+meta\s*$/);
  await expect(main.getByRole('link', { name: 'astro' })).toHaveAttribute('href', '/tags/astro/');
});

test('tag page lists only posts with that tag', async ({ page }) => {
  await page.goto('/tags/astro/');
  const main = page.locator('main');
  await expect(main).toContainText('grep -l "#astro" posts/*');
  await expect(main.getByRole('link', { name: 'Hello, world' })).toBeVisible();
  await expect(main.getByRole('link', { name: 'Guia de escrita' })).toHaveCount(0);
});
