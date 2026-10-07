import { expect, test } from '@playwright/test';

test('tags index lists tags with counts, most used first', async ({ page }) => {
  await page.goto('/tags/');
  const main = page.locator('main');
  await expect(main).toContainText('rt@blog:~$ ls tags/');
  const items = main.getByRole('listitem');
  // `csapp` is used by four published posts and one draft: drafts must not count
  await expect(items.filter({ hasText: 'csapp' })).toHaveText(/^\s*4\s+csapp\s*$/);
  // ties are broken alphabetically
  await expect(items.first()).toHaveText(/^\s*4\s+c\s*$/);
  await expect(main.getByRole('link', { name: 'csapp' })).toHaveAttribute('href', '/tags/csapp/');
});

test('tag page lists only posts with that tag', async ({ page }) => {
  await page.goto('/tags/compilers/');
  const main = page.locator('main');
  await expect(main).toContainText('grep -l "#compilers" posts/*');
  await expect(main.getByRole('link', { name: /^CSAPP §1\.2/ })).toHaveCount(2);
  await expect(main.getByRole('link', { name: /^CSAPP §1\.1/ })).toHaveCount(0);
  await expect(main.getByRole('link', { name: 'Draft example' })).toHaveCount(0);
});
