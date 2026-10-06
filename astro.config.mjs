// @ts-check
import { defineConfig } from 'astro/config';
import mdx from '@astrojs/mdx';
import sitemap from '@astrojs/sitemap';
import { monoDark, monoLight } from './src/shiki/mono';

// https://astro.build/config
export default defineConfig({
  site: 'https://rt-00.github.io',
  trailingSlash: 'always',
  integrations: [mdx(), sitemap()],
  markdown: {
    shikiConfig: {
      themes: { light: monoLight, dark: monoDark },
      defaultColor: false,
    },
  },
});
