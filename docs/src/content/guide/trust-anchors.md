---
title: Trust Anchors & Verification Options
description: Verifying against multiple certificates, CA stores, schemas, and validation times.
order: 5
---

# Trust Anchors & Verification Options

You can verify signatures against multiple certificates, strict schemas, or specific validation
times.

```ruby
HankoXml.verify!(
  doc,
  # Pass a single cert, an array of certs, an OpenSSL::X509::Store, or a mapping of <KeyName>s
  store: my_trusted_ca_store,

  # Ensure the certificate was valid at a specific time
  verification_time: Time.parse("2023-01-01"),

  # Pre-validate the <Signature> structure against the W3C XSD to prevent parser exploits
  schema: :default,

  # Enforce strict security policies (no SHA-1, no external references)
  policy: HankoXml::Policy.strict
)
```

## Trust sources

Trust sources are mutually exclusive: passing more than one of `certificate:`, `certificates:`,
`store:`, `key:`, `keys:` — or omitting all of them — raises `HankoXml::ConfigurationError` at
construction.

| Keyword | Behaviour |
| --- | --- |
| `store:` | Extracts the `<X509Certificate>` from `KeyInfo`, validates the chain with `OpenSSL::X509::Store#verify`, then hands libxmlsec1 only the validated leaf. Chain policy (CRLs, purpose, time) is OpenSSL's and fully configurable. |
| `certificates:` | The signature must verify against one of these exact certificates. |
| `certificate:` | Pinned to exactly one certificate. |
| `key:` | Bare public key; `KeyInfo` is ignored entirely. |
| `keys:` | A `KeyName => key-or-certificate` map. The document's `<ds:KeyName>` selects which one to verify against; an unrecognized name fails as `UntrustedCertificate` rather than falling back to trying every key. |

Verifying against the operating system's CA bundle is spelled out explicitly rather than hidden
behind an empty array:

```ruby
store = OpenSSL::X509::Store.new.tap(&:set_default_paths)
HankoXml::Verifier.new(store: store)
```

## `verification_time:`

Certificate validity (`notBefore`/`notAfter`) is checked against this `Time` instead of `Time.now`.
Without it, every archived document becomes unverifiable the day its signing certificate expires —
which is wrong: the question is whether the certificate was valid *when the document was signed*.
Long-lived archives (invoices, SAML assertions, contracts) whose signing certificate has since
expired need this.

```ruby
HankoXml::Verifier.new(store: store, verification_time: archived_at)
```

Setting `policy: policy.with(check_certificate_validity: false)` skips the window entirely.

## `schema:`

An OpenSSL-independent structural check: the `<ds:Signature>` subtree is validated against the
bundled `xmldsig-core-schema.xsd` (or a caller-supplied `Nokogiri::XML::Schema`) **before** any
cryptography. A structurally malformed `<SignedInfo>` is rejected without reaching libxmlsec1's
parser at all. `schema: :default` uses the bundled XSD; `nil` (the default) skips it.
`Policy.strict` sets `schema: :default`.

## `referenced_documents:`

A `URI => document` map for references that point outside the document — the *only* way a
non-fragment reference can resolve. `allow_external_references` stays `false`, nothing is fetched,
and a reference whose URI is not a key in this map raises `HankoXml::ReferenceError`.

## Selecting which signature to verify

```ruby
verifier = HankoXml::Verifier.new(certificate: cert, signature: :only)
```

| Value | Meaning |
| --- | --- |
| `:first` (default) | verify the first `<ds:Signature>` in document order |
| `:only` | as `:first`, but raise `MultipleSignatures` if more than one is present |
| `Integer` | the nth signature, document order, 0-based |
| `String` | an XPath selecting exactly one `<ds:Signature>` |

See the [`Verifier` reference](/reference/verifier) and [`Policy` reference](/reference/policy) for
the complete configuration surface.
