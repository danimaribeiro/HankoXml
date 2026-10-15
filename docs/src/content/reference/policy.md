---
title: Policy
description: HankoXml::Policy — the frozen allowlist enforced before any cryptography runs.
order: 5
---

# `HankoXml::Policy`

A frozen allowlist, enforced **in Ruby, before anything reaches libxmlsec1**, on both signing and
verification.

```ruby
HankoXml::Policy.strict        # default everywhere
HankoXml::Policy.fragment      # strict, minus require_signed_root — for protocols
                               # that sign a fragment (SAML assertions)
HankoXml::Policy.legacy_sha1   # strict + SHA-1 digest and RSA-SHA1 signature
HankoXml::Policy.xades         # strict + RSA-PSS (MGF1), SHA-3 / ECDSA-SHA3 and XPath Filter 2.0
HankoXml::Policy.interop       # fragment + SHA-1 with RSA or DSA, 1024-bit RSA, XPath Filter 2.0 — for
                               # legacy foreign signatures (W3C interop vectors), never a default
HankoXml::Policy.permissive    # allows everything Ruby checks. Documented as unsafe. The native
                               # layer still refuses XPath/XSLT transforms and never fetches a URI.

policy = HankoXml::Policy.strict.with(
  digest_methods:    %i[sha1 sha256],
  max_references:    4,
  max_document_size: 8 * 1024 * 1024,
)
```

## Full field list, with `strict` defaults

```ruby
HankoXml::Policy.new(
  # --- algorithm allowlists (Symbols or URI Strings) ---------------------
  signature_methods:        %i[rsa_sha256 rsa_sha384 rsa_sha512
                               ecdsa_sha256 ecdsa_sha384 ecdsa_sha512],
  digest_methods:           %i[sha256 sha384 sha512],
  canonicalization_methods: %i[c14n exc_c14n c14n11
                               c14n_with_comments exc_c14n_with_comments],
  transforms:               %i[enveloped_signature base64
                               c14n exc_c14n c14n11
                               c14n_with_comments exc_c14n_with_comments],

  # --- reference resolution ----------------------------------------------
  allow_external_references: false,  # URI="http://…", "file:…", or any non-#fragment
  allow_retrieval_method:    false,  # <ds:RetrievalMethod> in KeyInfo → network/file fetch
  allow_same_document_xpointer: false, # URI="#xpointer(…)"
  max_references:            8,
  require_references:        true,   # a <SignedInfo> with zero <Reference> is rejected

  # --- structural hardening ----------------------------------------------
  require_signed_root:       true,   # the document element must be inside signed material
  reject_duplicate_ids:      true,   # two elements with the same Id → reject
  max_document_size:         16 * 1024 * 1024,
  max_transforms_per_reference: 4,

  # --- keys ---------------------------------------------------------------
  min_rsa_key_bits:          2048,
  min_ec_key_bits:           256,
  min_dsa_key_bits:          2048,
  allow_hmac:                false,
  check_certificate_validity: true,  # notBefore / notAfter against Time.now
  clock_skew:                60,     # seconds of tolerance for the above
  require_signing_key_usage: true,   # store: only -- see below

  # --- structure -----------------------------------------------------------
  schema:                    :default, # Verifier XSD check of <Signature>; nil skips it
)
```

## Notes on the non-obvious fields

- **`require_signing_key_usage: true`.** Applies to `store:` verification only.
  If the signing certificate has a KeyUsage extension, it must include
  `digitalSignature` or `nonRepudiation`; otherwise verification fails with
  `UntrustedCertificate`. A certificate with no KeyUsage extension is accepted
  (RFC 5280: no extension means no restriction). `nonRepudiation` alone is
  enough because qualified signing certificates (eIDAS/XAdES) often carry only
  that bit; SignXML, by contrast, requires `digitalSignature`. Pinned trust
  (`certificate:`, `certificates:`, `key:`, `keys:`) is not checked: the caller
  already chose that exact key. `Policy.permissive` turns it off.

- **`allow_hmac: false`** — An HMAC `SignatureMethod` combined with certificate-based trust is a
  classic confusion attack: the attacker replaces an RSA signature with an HMAC one keyed on public
  data. With `allow_hmac: false` any HMAC `SignatureMethod` is a `PolicyError`, even if a custom
  `signature_methods` list names it. HankoXml has no HMAC secret-key API, so `allow_hmac: true`
  (as in `Policy.permissive`) does not make HMAC signatures verifiable; it only stops the policy
  from rejecting them. Trust stays pinned to the caller's certificate or key either way.
- **`Policy.xades`** is `Policy.strict` plus RSA-PSS (RFC 6931 `sha*-rsa-MGF1`) and SHA-3 digest
  / ECDSA-SHA3 methods. It does not change XAdES structure or make `Xades::Signer` default to it.
  libxmlsec1 1.3 (vendored / platform gems) implements these URIs; xmlsec 1.2 (Ubuntu) does not,
  and `Native.sign` / `Native.verify` then fail closed.
- **`:xpath_filter2`** (`Policy.xades`, `Policy.interop`) is XPath Filter 2.0 in the one shape EU
  DSS writes for enveloped XAdES (#85): a whole-document reference (`URI=""`, or `#xpointer(/)` under
  `allow_same_document_xpointer`) whose first transform is the only Filter 2.0 transform, holding a
  single `subtract` of `/descendant::P:Signature` (every signature) or `/*/P:Signature` (the root's
  signature children), with `P` bound to the XML-DSig namespace where the expression sits. Any other
  filter, expression or binding (`intersect`, `union`, `name()='ds:Signature'`, a second XPath) is a
  `PolicyError`, because `#signed?` couldn't say what it signs. xmlsec runs the transform, and
  `Native.verify` enables it only when the policy allows `:xpath_filter2`. `#signed?` leaves out the
  subtracted signatures, including any `<ds:Signature>` an attacker adds later: the digest never saw
  its contents.
- **`require_signed_root: true`** is the structural half of the XSW defence — see
  [XSW Defense](/guide/xsw-defense).
- **`reject_duplicate_ids: true`** is enforced on the native layer's parse of the same bytes xmlsec
  verifies (`Native.scan`), with or without Nokogiri, matching ID attributes by local name as
  `xmlSecAddIDs` registers them. Duplicate IDs make `URI="#x"` resolution ambiguous, and "which `x` did xmlsec pick" is the mechanism behind
  several XSW variants.
- **`allow_external_references: false`** blocks the SSRF/file-read surface of XML-DSig outright. Any
  reference whose URI is not `""` or `#fragment` is rejected in Ruby before xmlsec sees it.

Violations raise `HankoXml::PolicyError` from `verify!`/`sign`, and appear in
`Verification#errors` with `#valid?` false from `#verify` / `#valid?`. Error messages always name the
offending value and field, and the escape hatch to use if the document genuinely requires it (for
example `HankoXml::Policy.legacy_sha1` or `HankoXml::Policy.xades`).

## Why `require_signed_root` defaults to `true`

`true` means the document element must be inside signed material. It kills signature-wrapping
outright, but breaks SAML, where the signature legitimately covers an `<Assertion>` inside an
unsigned `<Response>`. The opt-out is made safe, not just available, by three things:

1. **A named preset, not a boolean** — `policy: HankoXml::Policy.fragment` reads as a deliberate
   protocol decision, not a flag someone flipped to silence an error.
2. **`Verification#partial?`** is `true` for every such verification, so the condition is
   inspectable, loggable, and assertable in tests.
3. **`Verification#at_signed`** makes the safe read shorter than the unsafe one, so under a fragment
   policy the path of least resistance is the correct one.

See [Trust Anchors & Verification](/guide/trust-anchors) for how `Policy` interacts with certificate
trust, and [Errors](/guide/errors) for `HankoXml::PolicyError`.
