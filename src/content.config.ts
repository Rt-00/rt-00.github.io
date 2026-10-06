import { defineCollection } from 'astro:content';
import { glob } from 'astro/loaders';
import { z } from 'astro/zod';

const posts = defineCollection({
  loader: glob({ base: './src/content/posts', pattern: '**/*.{md,mdx}' }),
  schema: ({ image }) =>
    z.object({
      title: z.string(),
      description: z.string(),
      date: z.coerce.date(),
      updated: z.coerce.date().optional(),
      lang: z.enum(['pt', 'en']),
      tags: z
        .array(z.string().regex(/^[a-z0-9-]+$/, 'tags must be lowercase kebab-case'))
        .default([]),
      draft: z.boolean().default(false),
      cover: image().optional(),
    }),
});

export const collections = { posts };
