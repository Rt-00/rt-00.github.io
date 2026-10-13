import { expect, test, type Page } from '@playwright/test';

const POST = '/posts/csapp-1-6-memory-hierarchy/'; // has wide tables, code blocks and a figure

async function contentWidth(page: Page) {
  return page.evaluate(() => {
    const style = getComputedStyle(document.body);
    return (
      document.body.getBoundingClientRect().width -
      parseFloat(style.paddingLeft) -
      parseFloat(style.paddingRight)
    );
  });
}

test.describe('wide screens', () => {
  test.use({ viewport: { width: 1440, height: 900 } });

  test('posts use a wide reading column', async ({ page }) => {
    await page.goto(POST);
    expect(await contentWidth(page)).toBeGreaterThanOrEqual(880);
  });

  test('home titles get the full row, with tags below', async ({ page }) => {
    await page.goto('/');
    const row = page.locator('main').getByRole('listitem').first();
    const title = row.locator('a[href^="/posts/"]');
    const lineHeight = await title.evaluate((el) => parseFloat(getComputedStyle(el).lineHeight));
    const box = await title.boundingBox();
    expect(box?.height).toBeLessThan(lineHeight * 1.5);
    const tags = await row.locator('.tags').boundingBox();
    expect(tags?.y).toBeGreaterThan(box?.y ?? 0);
  });
});

test.describe('narrow screens', () => {
  test.use({ viewport: { width: 375, height: 800 } });

  test('home titles start at the left edge, below date and lang', async ({ page }) => {
    await page.goto('/');
    const row = page.locator('main').getByRole('listitem').first();
    const date = await row.locator('time').boundingBox();
    const title = await row.locator('a[href^="/posts/"]').boundingBox();
    expect(title?.x).toBeLessThanOrEqual((date?.x ?? 0) + 1);
    expect(title?.y).toBeGreaterThan(date?.y ?? 0);
  });

  for (const path of ['/', POST, '/tags/', '/search/', '/about/']) {
    test(`no horizontal page scroll on ${path}`, async ({ page }) => {
      await page.goto(path);
      const overflow = await page.evaluate(
        () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
      );
      expect(overflow).toBe(0);
    });
  }
});
