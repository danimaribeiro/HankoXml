// @ts-check
import { defineConfig } from 'astro/config';

import tailwindcss from '@tailwindcss/vite';

import { satteri } from '@astrojs/markdown-satteri';

import baseLinks from './src/base-links.mjs';

// Published to GitHub Pages at https://danimar.dev/HankoXml/ by
// .github/workflows/pages.yml. Internal links go through withBase()
// (src/url.ts) or, in Markdown, through baseLinks.
const site = 'https://danimar.dev';
const base = '/HankoXml';

// https://astro.build/config
export default defineConfig({
  // Layout.astro needs `site` to emit an absolute og:image URL; social
  // scrapers reject relative ones.
  site,
  base,
  markdown: {
    processor: satteri({ mdastPlugins: [baseLinks(base)] }),
  },
  vite: {
    plugins: [tailwindcss()]
  }
});
