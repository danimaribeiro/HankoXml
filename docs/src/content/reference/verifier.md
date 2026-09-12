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
  signature:     :first,   # :first | :only | :all | Integer index | XPath String

  verification_time:    nil,   # Time — evaluate certificate validity as of then
  schema:               nil,   # validate <Signature> against an XSD first
  referenced_documents: {},    # URI => document, for non-fragment references
)
```

Trust sources are mutually exclusive: passing more than one of `certificate:`, `certificates:`,
`store:`, `key:`, `keys:` — or omitting all of them — raises `HankoXml::ConfigurationError` at
construction. See [Trust Anchors & Verification](/guide/trust-anchors) for a full discussion of
each keyword.

## `signature:` values

| Value | Meaning |
| --- | --- |
| `:first` (default) | verify the first `<ds:Signature>` in document order |
| `:only` | as `:first`, but raise `MultipleSignatures` if the document has more than one — the safest choice for protocols that expect exactly one |
| `Integer` | the nth signature, document order, 0-based |
| `String` | an XPath selecting exactly one `<ds:Signature>` |

## Methods

```ruby
verifier.verify(xml)      # => HankoXml::Verification. ALWAYS TRUTHY — check #valid?
verifier.verify!(xml)     # => Verification, or raises
verifier.valid?(xml)      # => true / false. Never raises for signature-level
                          #    failures; still raises ParseError / KeyLoadError.
verifier.verify_all(xml)  # => Array<Verification>, one per <ds:Signature>
```

`#verify` is the only method that hands back a failed `Verification`, and its documentation and
YARD `@return` both carry the "always truthy" warning. Prefer `#valid?` in conditionals and
`#verify!` in flows that should abort. See [`Verification`](/reference/verification) for the object
`#verify`/`#verify!` return.

## The unsafe escape hatch

```ruby
HankoXml::Verifier.without_trust_verification(policy: ...)
```

Its `Verification#certificate` is populated, `#trusted?` is `false`, and `#valid?` is `true` only
for integrity. `verify!` on such a verifier still raises unless you also passed
`allow_untrusted: true` — two explicit steps to get to the dangerous outcome.
