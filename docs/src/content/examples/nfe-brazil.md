---
title: NFe-shaped fixture
description: A test document in the XML-DSig shape used by Brazilian NF-e (legacy SHA-1, C14N, enveloped).
order: 2
---

# NFe-shaped fixture

HankoXml is a general XML-DSig library. This page is only a **test case**: an XML document whose
signature shape matches Brazilian NF-e (enveloped, RSA-SHA1, SHA-1 digest, C14N 1.0, `Id` on a child
element). The suite keeps a fixture in that shape so the library can sign and verify it. It is not a
product profile and not a reason to treat HankoXml as an NF-e toolkit.

That shape needs SHA-1 and explicit configuration that differs from the strict, modern defaults — a
demonstration of overriding [`Policy`](/reference/policy) and [`Signer`](/reference/signer)
deliberately, rather than reaching for `permissive`.

## Signing

```ruby
require "hanko_xml"

bundle = HankoXml::Key.from_pkcs12("certificado_a1.pfx", password: ENV.fetch("PFX_PASSWORD"))

# This fixture uses SHA-1, C14N 1.0, and a sibling <Signature> — the NF-e XML-DSig subset.
signer = HankoXml::Signer.new(
  key:                     bundle.key,
  certificates:            bundle.certificates,
  signature_method:        :rsa_sha1,
  digest_method:           :sha1,
  canonicalization_method: :c14n,
  id_attributes:           %w[Id],
  key_info:                [:x509_certificate],
  placement:               HankoXml::Placement.after("//ds:Signature"),
  policy:                  HankoXml::Policy.legacy_sha1
)

signed = signer.sign(nfe_shaped_doc)
```

`HankoXml::Key.from_pkcs12` unwraps a PKCS#12 / PFX bundle (key + leaf certificate + CA chain) in
one call — see the [Key reference](/reference/key).

`Policy.strict` rejects SHA-1. Use `HankoXml::Policy.legacy_sha1` (or an explicit `Policy#with(...)`)
when a document genuinely uses that subset.

## Verifying a fragment signature

The same APIs apply to any fragment signature (SAML assertions, a signed child element, this
fixture’s inf\* node):

```ruby
v = HankoXml::Verifier.new(
  store:         idp_store,
  policy:        HankoXml::Policy.fragment,
  id_attributes: %w[ID],
  signature:     :only,
).verify(response_doc)

raise "invalid signature" unless v.valid?

assertion = response_doc.at_xpath("//saml:Assertion", "saml" => SAML_NS)

raise "assertion is not covered by the signature" unless v.signed?(assertion)

subject = assertion.at_xpath(".//saml:NameID", "saml" => SAML_NS).text
```

`Policy.fragment` drops `require_signed_root` because the signature covers a child, not the document
element — precisely the case where [`#signed?`](/reference/verification) is mandatory. See
[XSW Defense](/guide/xsw-defense).
