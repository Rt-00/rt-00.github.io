import { describe, expect, test } from 'vitest';
import { groupByYear, publishedPosts, sortByDateDesc } from '../../src/lib/posts';
import { post } from './fixtures';

describe('publishedPosts', () => {
  const posts = [post('a', '2026-01-01'), post('b', '2026-02-01', { draft: true })];

  test('hides drafts by default', () => {
    expect(publishedPosts(posts).map((p) => p.id)).toEqual(['a']);
  });

  test('includes drafts when asked', () => {
    expect(publishedPosts(posts, { includeDrafts: true }).map((p) => p.id)).toEqual(['a', 'b']);
  });
});

describe('sortByDateDesc', () => {
  test('orders newest first without mutating the input', () => {
    const posts = [post('old', '2025-01-01'), post('new', '2026-05-01'), post('mid', '2025-09-01')];
    expect(sortByDateDesc(posts).map((p) => p.id)).toEqual(['new', 'mid', 'old']);
    expect(posts.map((p) => p.id)).toEqual(['old', 'new', 'mid']);
  });

  test('orders posts from the same day by time', () => {
    const posts = [
      post('morning', '2026-10-07T09:00:00Z'),
      post('evening', '2026-10-07T18:00:00Z'),
    ];
    expect(sortByDateDesc(posts).map((p) => p.id)).toEqual(['evening', 'morning']);
  });

  test('breaks ties by id for stable output', () => {
    const posts = [post('b', '2026-01-01'), post('a', '2026-01-01')];
    expect(sortByDateDesc(posts).map((p) => p.id)).toEqual(['a', 'b']);
  });
});

describe('groupByYear', () => {
  test('groups sorted posts by UTC year, newest year first', () => {
    const posts = [post('x', '2025-12-31'), post('y', '2026-01-01'), post('z', '2026-03-01')];
    expect(groupByYear(posts).map(({ year, posts }) => [year, posts.map((p) => p.id)])).toEqual([
      [2026, ['z', 'y']],
      [2025, ['x']],
    ]);
  });

  test('returns empty list for no posts', () => {
    expect(groupByYear([])).toEqual([]);
  });
});
