---
title: Brazilian NFe
description: Signing and verifying documents for Brazil's Nota Fiscal Eletrônica, the driving use case for HankoXml.
order: 2
---

# Brazilian NFe (the driving use case)

NFe (Nota Fiscal Eletrônica) requires SHA-1 and explicit configuration that differs from the strict,
modern defaults — a good demonstration of overriding [`Policy`](/reference/policy) and
[`Signer`](/reference/signer) options deliberately, rather than reaching for `permissive`.

## Signing

```ruby
require "hanko_xml"

bundle = HankoXml::Key.from_pkcs12("certificado_a1.pfx", password: ENV.fetch("PFX_PASSWORD"))

# NFe requires SHA-1 and explicit configuration
signer = HankoXml::Signer.new(
  key:                     bundle.key,
  certificates:            bundle.certificates,
  signature_method:        :rsa_sha1,
  digest_method:           :sha1,
  canonicalization_method: :c14n,
  id_attributes:           %w[Id],
  key_info:                [:x509_certificate],
  placement:               HankoXml::Placement.after("//ds:Signature")
)

signed = signer.sign(nfe_doc)
```

`HankoXml::Key.from_pkcs12` handles the A1 certificate bundle (key + leaf certificate + CA chain) in
one call — see the [Key reference](/reference/key) for details on PKCS#12 handling.

Because NFe requires legacy SHA-1 algorithms, use `HankoXml::Policy.legacy_sha1` (or an explicit
`Policy#with(...)` override) rather than the default `Policy.strict`, which would reject SHA-1 as a
digest or signature method.

## Verifying a fragment signature (SAML-style, same pattern applies to NFe sub-elements)

```ruby
v = HankoXml::Verifier.new(
  store:         idp_store,
  policy:        HankoXml::Policy.strict.with(require_signed_root: false),
  id_attributes: %w[ID],
  signature:     :only,
).verify(response_doc)

raise "invalid signature" unless v.valid?

assertion = response_doc.at_xpath("//saml:Assertion", "saml" => SAML_NS)

# THE line that C#'s CheckSignature does not make you write, and that every
# SAML XSW CVE is the absence of:
raise "assertion is not covered by the signature" unless v.signed?(assertion)

subject = assertion.at_xpath(".//saml:NameID", "saml" => SAML_NS).text
```

`require_signed_root: false` is necessary here because the signature covers the `<Assertion>`, not
the `<Response>` — precisely the case where [`#signed?`](/reference/verification) becomes mandatory
rather than merely advisory. See [XSW Defense](/guide/xsw-defense) for why this check exists and
what it protects against.
