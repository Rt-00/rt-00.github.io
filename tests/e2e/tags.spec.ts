import { expect, test } from '@playwright/test';

test('tags index lists tags with counts, most used first', async ({ page }) => {
  await page.goto('/tags/');
  const main = page.locator('main');
  await expect(main).toContainText('rt@blog:~$ ls tags/');
  const items = main.getByRole('listitem');
  // `csapp` is used by two published posts and one draft: drafts must not count
  await expect(items.filter({ hasText: 'csapp' })).toHaveText(/^\s*2\s+csapp\s*$/);
  // ties are broken alphabetically
  await expect(items.first()).toHaveText(/^\s*2\s+c\s*$/);
  await expect(main.getByRole('link', { name: 'csapp' })).toHaveAttribute('href', '/tags/csapp/');
});

test('tag page lists only posts with that tag', async ({ page }) => {
  await page.goto('/tags/csapp/');
  const main = page.locator('main');
  await expect(main).toContainText('grep -l "#csapp" posts/*');
  await expect(main.getByRole('link', { name: /Bits \+ context:/ })).toBeVisible();
  await expect(main.getByRole('link', { name: /Bits \+ contexto:/ })).toBeVisible();
  await expect(main.getByRole('link', { name: 'Draft example' })).toHaveCount(0);
});
