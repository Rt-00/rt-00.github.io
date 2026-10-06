import { expect, test } from '@playwright/test';

test('rss feed lists published posts with absolute links', async ({ request }) => {
  const response = await request.get('/rss.xml');
  expect(response.ok()).toBe(true);
  const xml = await response.text();
  expect(xml).toContain('<title>Hello, world</title>');
  expect(xml).toContain('<link>https://rt-00.github.io/posts/hello-world/</link>');
  expect(xml).toContain('<category>astro</category>');
  expect(xml).not.toContain('Draft example');
});

test('sitemap includes posts and excludes drafts', async ({ request }) => {
  const index = await request.get('/sitemap-index.xml');
  expect(index.ok()).toBe(true);
  const xml = await (await request.get('/sitemap-0.xml')).text();
  expect(xml).toContain('https://rt-00.github.io/posts/hello-world/');
  expect(xml).not.toContain('draft-example');
});
