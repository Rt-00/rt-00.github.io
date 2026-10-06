/** Minimal shape shared by collection entries, so helpers stay testable without Astro. */
export interface PostLike {
  id: string;
  data: { date: Date; draft: boolean; tags: string[] };
}

export function publishedPosts<T extends PostLike>(
  posts: T[],
  { includeDrafts = false }: { includeDrafts?: boolean } = {},
): T[] {
  return includeDrafts ? posts : posts.filter((post) => !post.data.draft);
}

export function sortByDateDesc<T extends PostLike>(posts: T[]): T[] {
  return [...posts].sort(
    (a, b) => b.data.date.getTime() - a.data.date.getTime() || a.id.localeCompare(b.id),
  );
}

export function groupByYear<T extends PostLike>(posts: T[]): { year: number; posts: T[] }[] {
  const groups = new Map<number, T[]>();
  for (const post of sortByDateDesc(posts)) {
    const year = post.data.date.getUTCFullYear();
    groups.set(year, [...(groups.get(year) ?? []), post]);
  }
  return [...groups].map(([year, posts]) => ({ year, posts }));
}
