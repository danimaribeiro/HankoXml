// Markdown content links to other pages with site-root paths such as
// "/guide/errors". Under the GitHub Pages base path those must become
// "/HankoXml/guide/errors", so prefix every root-relative link with `base`.
export default function baseLinks(base) {
  const prefix = base.replace(/\/$/, '');

  return {
    name: 'base-links',
    link(node, ctx) {
      if (/^\/(?!\/)/.test(node.url)) {
        ctx.setProperty(node, 'url', `${prefix}${node.url}`);
      }
    },
  };
}
