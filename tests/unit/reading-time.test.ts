import { describe, expect, test } from 'vitest';
import { readingStats } from '../../src/lib/reading-time';

describe('readingStats', () => {
  test('counts plain words', () => {
    expect(readingStats('one two three').words).toBe(3);
  });

  test('ignores markdown syntax, link urls and html tags', () => {
    const md = '# Title\n\nSome **bold** [link](https://example.com/a-b) <br/> `code`';
    expect(readingStats(md).words).toBe(5);
  });

  test('counts hyphenated words once and ignores list markers and rules', () => {
    expect(readingStats('- well-known fact\n\n---\n\n+ item').words).toBe(3);
  });

  test('ignores fenced code blocks', () => {
    const md = 'before\n\n```ts\nconst a = 1;\nconst b = 2;\n```\n\nafter';
    expect(readingStats(md).words).toBe(2);
  });

  test('ignores image alt text and import/export lines in mdx', () => {
    const md = "import X from './x.astro';\n\n![alt text](./img.png)\n\nhello";
    expect(readingStats(md).words).toBe(1);
  });

  test('minutes round up at 220 wpm with a minimum of one', () => {
    expect(readingStats('').minutes).toBe(1);
    expect(readingStats('word '.repeat(220)).minutes).toBe(1);
    expect(readingStats('word '.repeat(221)).minutes).toBe(2);
  });
});
