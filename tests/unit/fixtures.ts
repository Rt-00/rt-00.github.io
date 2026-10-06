import type { PostLike } from '../../src/lib/posts';

export function post(
  id: string,
  date: string,
  overrides: Partial<PostLike['data']> = {},
): PostLike {
  return {
    id,
    data: { date: new Date(date), draft: false, tags: [], ...overrides },
  };
}
