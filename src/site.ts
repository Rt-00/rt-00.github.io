export const SITE = {
  title: 'rt@blog',
  description: 'Notes on software, tools and whatever else — written in a terminal.',
  author: 'rt',
  url: 'https://rt-00.github.io',
  prompt: 'rt@blog:~$',
} as const;

export const NAV = [
  { href: '/', label: 'posts' },
  { href: '/tags/', label: 'tags' },
  { href: '/about/', label: 'about' },
  { href: '/search/', label: 'search' },
] as const;
