---
title: XSW Defense
description: How HankoXml defeats XML Signature Wrapping attacks.
order: 4
---

# Defending against XML Signature Wrapping (XSW)

A signature is only secure if it actually signed the data you are looking at. Attackers often wrap
or move the `<Signature>` block to trick naive verifiers into trusting content that was never
covered by the digest. HankoXml provides a structural `signed?` check on the verification result to
prove a specific node was cryptographically covered.

```ruby
result = HankoXml.verify!(doc, certificate: cert)

# Find the critical data in your document
payload = doc.at_xpath("//Invoice")

# Ensure the attacker didn't move it outside the signed block
unless result.signed?(payload)
  raise "XSW Attack Detected: The invoice was tampered with!"
end
```

## `#signed?` semantics — normative

`verification.signed?(node)` returns `true` if and only if **all** of:

1. `verification.valid?` is `true`. On an invalid verification, `#signed?` is always `false`; it
   never raises.
2. `node` belongs to `verification.document` — the same object identity, not an equal document. A
   node from a re-parse of the same bytes returns `false`. This is deliberate: "is this node, the
   one I am about to read values out of, covered" is the only question that prevents XSW.
3. `node` is the target of some reference in `verification.references`, or a descendant of one.
4. `node` is **not** inside a subtree removed by that reference's transforms — for example, not
   inside the `<ds:Signature>` element excised by an `enveloped-signature` transform.

## The shorter, safer read: `#at_signed`

```ruby
# Unsafe, and the shortest thing to write in every other library:
assertion = doc.at_xpath("//saml:Assertion", ns)

# Safe, and now shorter still:
assertion = result.at_signed("//saml:Assertion", ns)
```

`#at_signed` performs the XPath *and* the `#signed?` check, raising `HankoXml::NotSignedError` if
the node it found is not covered — so forgetting the check is no longer possible by omission, only
by deliberately using `doc.at_xpath` instead. Ergonomics is a security control: a defence that costs
an extra line gets skipped, and one that saves a line gets adopted.

## Structural hardening via `Policy`

Several `HankoXml::Policy` fields exist specifically to close XSW-adjacent holes before any
cryptography runs:

- **`require_signed_root: true`** (default) — the document element must be inside signed material.
  This kills naive signature-wrapping outright. It also breaks SAML-style protocols that legitimately
  sign a fragment — use `HankoXml::Policy.fragment` for those, and rely on `#signed?`/`#at_signed`
  as described above.
- **`reject_duplicate_ids: true`** (default) — two elements sharing the same `Id` make
  `URI="#x"` resolution ambiguous, which is the mechanism behind several XSW variants.
- **`allow_external_references: false`** (default) — blocks the SSRF/file-read surface of XML-DSig
  outright; any reference whose URI is not `""` or `#fragment` is rejected before libxmlsec1 ever
  sees it.

See the [Policy reference](/reference/policy) for the full field list, and
[Trust Anchors & Verification](/guide/trust-anchors) for how certificate trust interacts with all
of this.
