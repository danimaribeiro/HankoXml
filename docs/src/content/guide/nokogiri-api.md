---
title: Nokogiri API
description: Sign and verify directly on Nokogiri::XML::Document.
order: 2
---

# The Nokogiri API (Recommended)

HankoXml extends Nokogiri directly, making signing and verifying incredibly ergonomic. This is the
recommended way to use the library for most applications.

```ruby
require "nokogiri"
require "hanko_xml"

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

The monkey-patched methods forward every keyword accepted by `HankoXml::Signer.new` /
`HankoXml::Verifier.new` — see the [API Reference](/reference/signer) for the full list, including
`policy:`, `placement:`, `signature_method:`, and trust options like `store:`.

```ruby
doc.sign!(key: key, certificate: certificate, signature_method: :rsa_sha256, policy: HankoXml::Policy.strict)

doc.signature_valid?(store: my_trusted_ca_store, verification_time: Time.parse("2023-01-01"))
```

Next: the [Module API](/guide/module-api) for non-Nokogiri-mutating equivalents, or
[XSW Defense](/guide/xsw-defense) for the security model behind `signed?`.
