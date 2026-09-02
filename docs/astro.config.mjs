// @ts-check
import { defineConfig } from 'astro/config';

import tailwindcss from '@tailwindcss/vite';

// https://astro.build/config
export default defineConfig({
  // Set this to the deployed origin (e.g. 'https://danimaribeiro.github.io/HankoXml').
  // Layout.astro needs it to emit an absolute og:image URL; social scrapers
  // reject relative ones.
  // site: 'https://example.com',
  vite: {
    plugins: [tailwindcss()]
  }
});