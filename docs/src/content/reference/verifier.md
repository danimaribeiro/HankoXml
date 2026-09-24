---
title: Verifier
description: HankoXml::Verifier — configure and run signature verification.
order: 2
---

# `HankoXml::Verifier`

```ruby
verifier = HankoXml::Verifier.new(
  certificate:   cert,             # pin exactly this certificate
  # or
  certificates:  [cert_a, cert_b], # any one of these
  # or
  store:         OpenSSL::X509::Store.new, # full chain validation
  # or
  key:           OpenSSL::PKey::RSA,       # bare public key, no certificate
  # or
  keys:          { "key-name-1" => cert_a, "key-name-2" => key_b },
                 # select by the <ds:KeyName> the document declares

  policy:        HankoXml::Policy.strict,  # default
  id_attributes: %w[Id ID id],
  namespaces:    {},
  signature:     nil,      # nil (default) | :first | :only | Integer index | XPath String

  verification_time:    nil,   # Time — evaluate certificate validity as of then
  schema:               nil,   # validate <Signature> against an XSD first
  referenced_documents: {},    # URI => document, for non-fragment references
  certificate_subject:  nil,   # store: only — String CN or OpenSSL::X509::Name
)
```

Trust sources are mutually exclusive: passing more than one of `certificate:`, `certificates:`,
`store:`, `key:`, `keys:` — or omitting all of them — raises `HankoXml::ConfigurationError` at
construction. See [Trust Anchors & Verification](/guide/trust-anchors) for a full discussion of
each keyword.

`certificate_subject:` only works with `store:`. After the chain validates, a `String` must be the
signing certificate's only `CN` (exact match), and an `OpenSSL::X509::Name` must equal its whole
subject; otherwise verification fails with `UntrustedCertificate`. With `store:`, `Policy.strict` also
requires the certificate's KeyUsage, when present, to allow `digitalSignature` or `nonRepudiation`
(`require_signing_key_usage`).

## `signature:` values

| Value | Meaning |
| --- | --- |
| `nil` (default) | as `:only` — one signature verifies as before, several raise `MultipleSignatures` |
| `:first` | verify the first `<ds:Signature>` in document order; ignores any others (unsafe opt-in) |
| `:only` | as `:first`, but raise `MultipleSignatures` if the document has more than one — the safest choice for protocols that expect exactly one |
| `Integer` | the nth signature, document order, 0-based |
| `String` | an XPath selecting exactly one `<ds:Signature>` |

## Methods

```ruby
verifier.verify(xml)      # => HankoXml::Verification. ALWAYS TRUTHY — check #valid?
verifier.verify!(xml)     # => Verification, or raises
verifier.valid?(xml)      # => true / false. Never raises for a signature that
                          #    fails to verify; still raises ParseError /
                          #    KeyLoadError, and MultipleSignatures when the
                          #    document has several and signature: is nil/:only.
verifier.verify_all(xml)  # => Array<Verification>, one per <ds:Signature>
```

`#verify` is the only method that hands back a failed `Verification`, and its documentation and
YARD `@return` both carry the "always truthy" warning. Prefer `#valid?` in conditionals and
`#verify!` in flows that should abort. See [`Verification`](/reference/verification) for the object
`#verify`/`#verify!` return.

## No trust-free verification

There is no way to verify against the certificate the document itself carries: every `Verifier`
needs `certificate:`, `certificates:`, `store:`, `key:` or `keys:`. An explicit integrity-only mode
is planned ([#103](https://github.com/danimaribeiro/HankoXml/issues/103)).
