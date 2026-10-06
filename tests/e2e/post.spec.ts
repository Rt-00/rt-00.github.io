import { expect, test } from '@playwright/test';

test.describe('post page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/posts/hello-world/');
  });

  test('shows cat command, title and metadata', async ({ page }) => {
    const main = page.locator('main');
    await expect(main).toContainText('rt@blog:~$ cat posts/hello-world.md');
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('Hello, world');
    await expect(main).toContainText('2026-10-06');
    await expect(main).toContainText('[en]');
    await expect(main).toContainText(/\d+ min read/);
    await expect(main).toContainText(/\d+ words/);
    await expect(main.getByRole('link', { name: '#astro' })).toHaveAttribute(
      'href',
      '/tags/astro/',
    );
  });

  test('has a table of contents linking to headings', async ({ page }) => {
    const toc = page.getByRole('navigation', { name: 'Table of contents' });
    await toc.getByRole('link', { name: 'Code' }).click();
    await expect(page).toHaveURL(/#code$/);
  });

  test('highlights code in grayscale with dual themes', async ({ page }) => {
    const code = page.locator('pre.astro-code');
    await expect(code).toBeVisible();
    const style = await code.locator('span[style*="--shiki-dark"]').first().getAttribute('style');
    expect(style).toContain('--shiki-light');
  });

  test('renders optimized co-located images', async ({ page }) => {
    const img = page.getByRole('img', { name: /terminal window/ });
    await expect(img).toHaveAttribute('src', /\/_astro\//);
  });

  test('sets the document language from the post', async ({ page }) => {
    await expect(page.locator('html')).toHaveAttribute('lang', 'en');
    await page.goto('/posts/guia-de-escrita/');
    await expect(page.locator('html')).toHaveAttribute('lang', 'pt');
  });

  test('drafts are not built', async ({ page }) => {
    const response = await page.goto('/posts/draft-example/');
    expect(response?.status()).toBe(404);
  });
});
