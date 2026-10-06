import { getCollection } from 'astro:content';
import { publishedPosts, sortByDateDesc } from './posts';

/** Published posts, newest first. Drafts are only visible in `astro dev`. */
export async function getPosts() {
  const posts = await getCollection('posts');
  return sortByDateDesc(publishedPosts(posts, { includeDrafts: import.meta.env.DEV }));
}
