---
title: Nokogiri API
description: Sign and verify directly on Nokogiri::XML::Document.
order: 2
---

# The Nokogiri API (Recommended)

HankoXml can extend Nokogiri directly, making signing and verifying incredibly ergonomic. The
extension is opt-in: `require "hanko_xml"` alone leaves Nokogiri's classes untouched, and
`require "hanko_xml/nokogiri_ext"` adds these methods to `Nokogiri::XML::Document` and `Node`:

| Method | Same as |
| --- | --- |
| `doc.sign(**opts)` | `HankoXml.sign(doc, **opts)`, a new `SignedDocument`; `doc` is untouched |
| `doc.sign!(**opts)` | `HankoXml.sign!(doc, **opts)`, signs in place and returns `doc` |
| `doc.signature_valid?(**opts)` | `HankoXml.valid?(doc, **opts)`, `true` / `false` |
| `doc.signatures` | the `<ds:Signature>` elements, a `NodeSet` |
| `doc.signature_present?` | `HankoXml.signature_present?(doc)`, structural, no crypto |

```ruby
require "nokogiri"
require "hanko_xml"
require "hanko_xml/nokogiri_ext"

doc = Nokogiri::XML(File.read("document.xml"))
private_key = File.read("private.pem")
certificate = File.read("public.crt")

# Sign the document in place
doc.sign!(key: private_key, certificate: certificate)

# Safely serialize without destroying the signature bytes
File.write("signed.xml", doc.to_xml(save_with: Nokogiri::XML::Node::SaveOptions::AS_XML))

# Verify it later
signed_doc = Nokogiri::XML(File.read("signed.xml"))
if signed_doc.signature_valid?(certificate: certificate)
  puts "Signature is valid!"
end
```

## Why `save_with: AS_XML`?

Re-serializing a signed document with the wrong options can silently change whitespace or attribute
quoting, invalidating the byte-exact canonicalization the signature relies on. Always serialize a
signed document with `Nokogiri::XML::Node::SaveOptions::AS_XML` (no formatting, no entity
substitution) so the bytes you write are the bytes that were actually signed.

## Every keyword from `Signer`/`Verifier` is accepted

The extension's methods forward every keyword accepted by `HankoXml::Signer.new` /
`HankoXml::Verifier.new` — see the [API Reference](/reference/signer) for the full list, including
`policy:`, `placement:`, `signature_method:`, and trust options like `store:`.

```ruby
doc.sign!(key: key, certificate: certificate, signature_method: :rsa_sha256, policy: HankoXml::Policy.strict)

doc.signature_valid?(store: my_trusted_ca_store, verification_time: Time.parse("2023-01-01"))
```

Next: the [Module API](/guide/module-api) for non-Nokogiri-mutating equivalents, or
[XSW Defense](/guide/xsw-defense) for the security model behind `signed?`.
