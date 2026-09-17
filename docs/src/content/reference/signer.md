---
title: Signer
description: HankoXml::Signer — configure and produce XML-DSig signatures.
order: 1
---

# `HankoXml::Signer`

```ruby
signer = HankoXml::Signer.new(
  key:                     key,                # see Keys & Certificates
  certificate:             cert,               # optional
  certificates:            [cert, intermediate], # chain for <X509Data>, optional
  signature_method:        :rsa_sha256,        # default
  canonicalization_method: :exc_c14n,          # default, applies to <SignedInfo>
  digest_method:           :sha256,            # default for every reference
  references:              [],                 # default = [whole document]
  key_info:                [:x509_certificate], # default
  placement:               :append_to_root,    # default, see Placement
  id_attributes:           %w[Id ID id],
  namespaces:              {},                 # prefix => href, for XPath args
  signature_id:            nil,                # sets <Signature Id="...">
  policy:                  HankoXml::Policy.strict, # default
  template:                :adopt,             # :adopt | :build | :require
)
```

## Block form

For when the reference list is non-trivial:

```ruby
signer = HankoXml::Signer.new(key: key, certificate: cert) do |s|
  s.signature_method = :rsa_sha1
  s.canonicalization_method = :c14n
  s.reference "#NFe3520...", transforms: %i[enveloped_signature c14n], digest_method: :sha1
  s.key_info :x509_certificate
  s.placement = HankoXml::Placement.append_to("/nfe:NFe", namespaces: { "nfe" => NFE_NS })
end
```

The block runs against a mutable builder; `Signer.new` **freezes the instance before returning it**.
A `Signer` is therefore immutable, reusable, and safe to share across threads.

## Exclusive c14n with InclusiveNamespaces (SAML)

```ruby
xs_aware = HankoXml::Transform.exc_c14n(inclusive_prefixes: %w[xs])
# same as HankoXml::Transform.new(:exc_c14n, inclusive_prefixes: %w[xs])

HankoXml::Signer.new(
  key: key, certificate: cert,
  policy: HankoXml::Policy.fragment,
  placement: HankoXml::Placement.after("//saml:Assertion/saml:Issuer", namespaces: SAML_NS),
  references: [HankoXml::Reference.new(uri: "#assertion-1",
                                       transforms: [:enveloped_signature, xs_aware])]
)
```

This emits `<ec:InclusiveNamespaces PrefixList="xs"/>` inside the `<Transform>`. Each listed prefix
(or `"#default"`) is canonicalized the inclusive way: its in-scope declaration is digested even when
it is declared on an ancestor outside the signed element, as SAML's `xsi:type="xs:string"` needs.
`inclusive_prefixes:` on any transform other than `:exc_c14n` / `:exc_c14n_with_comments` raises
`ConfigurationError`.

Verification needs no option. libxmlsec1 reads `InclusiveNamespaces` from a `<Transform>` or from
`<CanonicalizationMethod>`, and the default `schema: :default` accepts both.

## Methods

```ruby
signer.sign(doc_or_xml)   # => HankoXml::SignedDocument, input untouched
signer.sign!(doc)         # => the same Nokogiri::XML::Document, now signed
signer.template(doc)      # => Nokogiri::XML::Element — the unsigned <Signature>
                          #    it would insert. For inspection and testing.
signer.to_h               # => the full effective configuration, resolved URIs
```

`#template` exists because "show me exactly what XML you are about to produce, before any crypto
happens" is the single most useful debugging affordance a signing library can offer, and because it
makes the whole template layer testable with plain XML assertions and no keys.

## Signing a document that already has a `<Signature>` template

Many real documents arrive with the `<Signature>` skeleton already in place — SAML request
templates, ERP envelopes, anything produced by a tool that separates "build the envelope" from
"sign it". This is a first-class mode:

```ruby
Signer.new(key: key, template: :adopt)   # default
Signer.new(key: key, template: :build)   # always build; raise if one exists
Signer.new(key: key, template: :require) # only fill in an existing one; raise if absent
```

Under `:adopt` (the default), `sign`/`sign!` look for `ds:Signature` elements first:

- **none present** → build one from the `Signer` configuration, as described above;
- **one or more present** → adopt them. The template's `<SignedInfo>` is kept as-is. Before
  `Native.sign`, `policy` is enforced on that template (same allowlist as verification) and
  its Reference URIs must match `references`. Empty `references` means whole-document `URI=""`.
  A fragment template therefore needs `references: ["#that-id"]`; a `file://` / SHA-1 template
  is rejected under `Policy.strict`. Only `key`, `certificates`, `key_info` and `id_attributes`
  still apply to the adopted skeleton.

`:require` is also the one signing mode that runs without Nokogiri: nothing has to be constructed,
so no DOM is needed.

A template whose Reference URIs do not match `references` raises `HankoXml::ConfigurationError`.
A template that violates `policy` raises `HankoXml::PolicyError` before any native signing call.

## Signing order for multiple/nested signatures

Follows the rule: **innermost first**, sorted by ancestor depth descending. An outer signature
covering an inner one must be computed after the inner `<SignatureValue>` exists, or the outer
digest covers an empty element.

```ruby
signer.sign!(doc)                   # signs every unsigned <Signature>, innermost first
signer.sign!(doc, force: true)      # re-signs even already-signed ones
signer.sign!(doc, signature: 0)     # only the nth, document order
```

`force:` defaults to `false`: an already-signed `<Signature>` (non-empty `<SignatureValue>`) is left
alone, so signing a partially-signed document is idempotent for the parts already done.

## External signers (HSM, cloud KMS, smartcards)

**Not supported in v1.** The private key does not always exist as bytes you can hand to a library —
AWS KMS, Azure Key Vault, PKCS#11 tokens and Brazilian A3 smartcards all sign *on the device*. A
future version will keep libxmlsec1 doing all reference resolution, transforms, canonicalization and
digesting (where XML-DSig vulnerabilities actually live), and give it a device-backed key handle
through an OpenSSL provider or PKCS#11 engine, rather than reimplementing that logic in Ruby.
`Signer.new` raises `HankoXml::ConfigurationError` if `key:` is anything but key material or an
`HankoXml::Key`.
