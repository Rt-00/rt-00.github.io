import { expect, test } from '@playwright/test';

test.describe('search', () => {
  test('finds english posts and highlights matches', async ({ page }) => {
    await page.goto('/search/');
    await expect(page.locator('main')).toContainText('grep -ri');
    await page.getByRole('searchbox').fill('meaning');
    const result = page.getByRole('listitem').filter({ hasText: 'Bits + context' });
    await expect(result).toBeVisible();
    await expect(result.locator('mark').first()).toHaveText(/meaning/i);
    await expect(result.getByRole('link')).toHaveAttribute(
      'href',
      '/posts/csapp-1-1-bits-and-context/',
    );
  });

  test('searches portuguese posts in the same index', async ({ page }) => {
    await page.goto('/search/');
    await page.getByRole('searchbox').fill('significado');
    await expect(page.getByRole('listitem').filter({ hasText: 'Bits + contexto' })).toBeVisible();
  });

  test('reads the query from ?q= and reports no matches', async ({ page }) => {
    await page.goto('/search/?q=zzzyxnotaword');
    await expect(page.getByRole('searchbox')).toHaveValue('zzzyxnotaword');
    await expect(page.locator('main')).toContainText('0 matches');
  });

  test('does not index non-post pages', async ({ page }) => {
    // pagefind matches fuzzily, so assert on the page itself rather than on the count
    await page.goto('/search/?q=elsewhere');
    const main = page.locator('main');
    await expect(main).toContainText(/\d+ match/);
    await expect(main.locator('a[href="/about/"]')).toHaveCount(0);
  });
});
