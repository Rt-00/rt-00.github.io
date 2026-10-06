import { expect, test } from '@playwright/test';

test.describe('search', () => {
  test('finds english posts and highlights matches', async ({ page }) => {
    await page.goto('/search/');
    await expect(page.locator('main')).toContainText('grep -ri');
    await page.getByRole('searchbox').fill('dijkstra');
    const result = page.getByRole('listitem').filter({ hasText: 'Hello, world' });
    await expect(result).toBeVisible();
    await expect(result.locator('mark').first()).toHaveText(/dijkstra/i);
    await expect(result.getByRole('link')).toHaveAttribute('href', '/posts/hello-world/');
  });

  test('searches portuguese posts in the same index', async ({ page }) => {
    await page.goto('/search/');
    await page.getByRole('searchbox').fill('rascunhos');
    await expect(page.getByRole('listitem').filter({ hasText: 'Guia de escrita' })).toBeVisible();
  });

  test('reads the query from ?q= and reports no matches', async ({ page }) => {
    await page.goto('/search/?q=zzzyxnotaword');
    await expect(page.getByRole('searchbox')).toHaveValue('zzzyxnotaword');
    await expect(page.locator('main')).toContainText('0 matches');
  });

  test('does not index non-post pages', async ({ page }) => {
    await page.goto('/search/?q=craft');
    await expect(page.locator('main')).toContainText('0 matches');
  });
});
