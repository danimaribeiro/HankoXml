import { defineCollection, z } from 'astro:content';
import { glob } from 'astro/loaders';

const withNav = {
  title: z.string(),
  description: z.string().optional(),
  order: z.number().default(0),
};

const guide = defineCollection({
  loader: glob({ pattern: '**/*.md', base: './src/content/guide' }),
  schema: z.object(withNav),
});

const reference = defineCollection({
  loader: glob({ pattern: '**/*.md', base: './src/content/reference' }),
  schema: z.object(withNav),
});

const examples = defineCollection({
  loader: glob({ pattern: '**/*.md', base: './src/content/examples' }),
  schema: z.object(withNav),
});

export const collections = { guide, reference, examples };
