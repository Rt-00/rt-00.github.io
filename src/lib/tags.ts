import { sortByDateDesc, type PostLike } from './posts';

export function countTags(posts: PostLike[]): { tag: string; count: number }[] {
  const counts = new Map<string, number>();
  for (const tag of posts.flatMap((post) => post.data.tags)) {
    counts.set(tag, (counts.get(tag) ?? 0) + 1);
  }
  return [...counts]
    .map(([tag, count]) => ({ tag, count }))
    .sort((a, b) => b.count - a.count || a.tag.localeCompare(b.tag));
}

export function postsWithTag<T extends PostLike>(posts: T[], tag: string): T[] {
  return sortByDateDesc(posts.filter((post) => post.data.tags.includes(tag)));
}
