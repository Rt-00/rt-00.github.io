import { describe, expect, test } from 'vitest';
import { countTags, postsWithTag } from '../../src/lib/tags';
import { post } from './fixtures';

const posts = [
  post('a', '2026-01-01', { tags: ['vim', 'tools'] }),
  post('b', '2026-02-01', { tags: ['vim'] }),
  post('c', '2026-03-01', { tags: ['astro'] }),
];

describe('countTags', () => {
  test('counts tags, most used first then alphabetical', () => {
    expect(countTags(posts)).toEqual([
      { tag: 'vim', count: 2 },
      { tag: 'astro', count: 1 },
      { tag: 'tools', count: 1 },
    ]);
  });
});

describe('postsWithTag', () => {
  test('filters posts by tag, newest first', () => {
    expect(postsWithTag(posts, 'vim').map((p) => p.id)).toEqual(['b', 'a']);
  });

  test('returns empty list for unknown tag', () => {
    expect(postsWithTag(posts, 'nope')).toEqual([]);
  });
});
