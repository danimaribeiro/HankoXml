// The site is served under a base path on GitHub Pages
// (https://danimar.dev/HankoXml/, set by `base` in astro.config.mjs), so every
// internal link and asset must go through here instead of starting at "/".
const base = import.meta.env.BASE_URL.replace(/\/$/, '');

// Prefixes a site-root-relative path ("guide/errors" or "/guide/errors") with
// the base path.
export function withBase(path: string): string {
  return `${base}/${path.replace(/^\//, '')}`;
}

// The first path segment after the base, e.g. "guide" for /HankoXml/guide/errors.
export function sectionOf(pathname: string): string {
  const rest = pathname.startsWith(base) ? pathname.slice(base.length) : pathname;
  return rest.split('/')[1] ?? '';
}
