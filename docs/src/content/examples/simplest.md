---
title: The Simplest Thing
description: Sign and verify a document with zero configuration.
order: 1
---

# The Simplest Thing

```ruby
require "hanko_xml"

key  = OpenSSL::PKey::RSA.new(File.read("signer.key"))
cert = OpenSSL::X509::Certificate.new(File.read("signer.crt"))

signed = HankoXml.sign(HankoXml.parse(File.read("doc.xml")), key: key, certificate: cert)
File.binwrite("signed.xml", HankoXml.serialize(signed))

HankoXml.valid?(signed, certificate: cert)  # => true
```

Enveloped, whole document, RSA-SHA256, exclusive C14N, `<Signature>` appended to the root. No
template, no keys manager, no algorithm URIs — these are all sensible defaults from
[`Signer`](/reference/signer).

See [Getting Started](/guide/getting-started) for the equivalent using the Nokogiri monkey-patches
(`doc.sign!` / `doc.signature_valid?`), which most applications should prefer.
