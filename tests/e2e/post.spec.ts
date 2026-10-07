import { expect, test } from '@playwright/test';

test.describe('post page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/posts/csapp-1-1-bits-and-context/');
  });

  test('shows cat command, title and metadata', async ({ page }) => {
    const main = page.locator('main');
    await expect(main).toContainText('rt@blog:~$ cat posts/csapp-1-1-bits-and-context.md');
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(
      'CSAPP §1.1 — Bits + context: what hello.c teaches about meaning',
    );
    await expect(main).toContainText('2026-10-07');
    await expect(main).toContainText('[en]');
    await expect(main).toContainText(/\d+ min read/);
    await expect(main).toContainText(/\d+ words/);
    await expect(main.getByRole('link', { name: '#csapp' }).first()).toHaveAttribute(
      'href',
      '/tags/csapp/',
    );
  });

  test('has a table of contents linking to headings', async ({ page }) => {
    const toc = page.getByRole('navigation', { name: 'Table of contents' });
    await toc.getByRole('link', { name: 'Checking it myself' }).click();
    await expect(page).toHaveURL(/#checking-it-myself$/);
  });

  test('highlights code in grayscale with dual themes', async ({ page }) => {
    const code = page.locator('pre.astro-code').first();
    await expect(code).toBeVisible();
    const style = await code.locator('span[style*="--shiki-dark"]').first().getAttribute('style');
    expect(style).toContain('--shiki-light');
  });

  test('renders optimized co-located images', async ({ page }) => {
    const img = page.getByRole('img', { name: /same four bytes/ });
    await expect(img).toHaveAttribute('src', /\/_astro\//);
  });

  test('sets the document language from the post', async ({ page }) => {
    await expect(page.locator('html')).toHaveAttribute('lang', 'en');
    await page.goto('/posts/csapp-1-1-bits-e-contexto/');
    await expect(page.locator('html')).toHaveAttribute('lang', 'pt');
  });

  test('series posts link to the next part', async ({ page }) => {
    await page.locator('main').getByRole('link', { name: '1.2', exact: true }).click();
    await expect(page).toHaveURL(/\/posts\/csapp-1-2-programs-translated\/$/);
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(/^CSAPP §1\.2/);
  });

  test('drafts are not built', async ({ page }) => {
    const response = await page.goto('/posts/draft-example/');
    expect(response?.status()).toBe(404);
  });
});
