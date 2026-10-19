import { withBase } from './url';

export const guideNav = [
  { slug: 'getting-started', title: 'Getting Started' },
  { slug: 'nokogiri-api', title: 'Nokogiri API' },
  { slug: 'module-api', title: 'Module API' },
  { slug: 'xsw-defense', title: 'XSW Defense' },
  { slug: 'trust-anchors', title: 'Trust Anchors & Verification' },
  { slug: 'keys-and-certificates', title: 'Keys & Certificates' },
  { slug: 'errors', title: 'Errors' },
  { slug: 'xades', title: 'XAdES' },
  { slug: 'comparison-signxml', title: 'Comparison with SignXML' },
];

// `yard` is the path to the generated YARD HTML for this class, served
// statically from `public/api` (regenerate with `npm run docs:api`).
export const referenceNav = [
  { slug: 'signer', title: 'Signer', yard: withBase('api/HankoXml/Signer.html') },
  { slug: 'verifier', title: 'Verifier', yard: withBase('api/HankoXml/Verifier.html') },
  { slug: 'verification', title: 'Verification', yard: withBase('api/HankoXml/Verification.html') },
  { slug: 'key', title: 'Key', yard: withBase('api/HankoXml/Key.html') },
  { slug: 'policy', title: 'Policy', yard: withBase('api/HankoXml/Policy.html') },
  { slug: 'algorithms', title: 'Algorithms', yard: withBase('api/HankoXml/Algorithms.html') },
  { slug: 'placement', title: 'Placement', yard: withBase('api/HankoXml/Placement.html') },
  { slug: 'signed-document', title: 'SignedDocument', yard: withBase('api/HankoXml/SignedDocument.html') },
  { slug: 'xades', title: 'Xades', yard: withBase('api/HankoXml/Xades.html') },
];

export const yardIndexUrl = withBase('api/HankoXml.html');

export const examplesNav = [
  { slug: 'simplest', title: 'The Simplest Thing' },
  { slug: 'nfe-brazil', title: 'NFe-shaped fixture' },
];
