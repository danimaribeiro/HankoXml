---
title: Module API
description: The top-level HankoXml module, for use without the Nokogiri monkey-patches.
order: 3
---

# The Module API

If you prefer not to use the Nokogiri monkey-patches, you can use the top-level `HankoXml` module
directly. It is the 90% case: constructor + single call, nothing more.

```ruby
require "hanko_xml"

# Sign. Returns a NEW HankoXml::SignedDocument; `doc` is untouched.
signed = HankoXml.sign(doc, key: key, certificate: cert)
signed.to_xml   # signature-safe serialization; #to_s and #write_to too

# Sign in place. Returns the same object you passed, now containing <Signature>.
HankoXml.sign!(doc, key: key, certificate: cert)

# Verify — predicate. Safe to use directly in a conditional.
HankoXml.valid?(xml, certificate: cert)        # => true / false

# Verify — raising. Returns a Verification; raises on anything but success.
HankoXml.verify!(xml, certificate: cert)       # => Verification, or raises

# Is there a signature at all? (structural, no crypto)
HankoXml.signature_present?(xml)               # => true / false
```

Every one of these needs Nokogiri loaded (`require "nokogiri"`) in 0.1.0; without it they raise
`HankoXml::NokogiriRequired`.

## Verification

```ruby
require "hanko_xml"
require "pathname"

xml = File.read("signed.xml")

# Raises HankoXml::VerificationError if the signature is invalid or tampered with
result = HankoXml.verify!(xml, certificate: Pathname("public.crt"))

puts result.valid? # => true
```

## Signing (immutable)

```ruby
# Returns a safe `SignedDocument` wrapper without mutating the original
# A String is PEM content, not a filename: pass files as Pathname (or File.read them).
signed_doc = HankoXml.sign(xml, key: Pathname("private.pem"), certificate: Pathname("public.crt"))

puts signed_doc.to_s
```

## There is deliberately no `HankoXml.verify`

Only `sign` / `sign!` and `verify!` / `valid?` / `signature_present?` are exposed at the module level. There is
no `HankoXml.verify` returning a rich object: a `Verification` instance is always truthy, so
`if HankoXml.verify(doc, ...)` would be a security bug that reads like correct code. The rich
`Verification` object (see [Reference: Verification](/reference/verification)) is reachable only
through `verify!` (which raises on failure) or `HankoXml::Verifier#verify`, where the object's role
is explicit. This asymmetry is intentional — see [XSW Defense](/guide/xsw-defense) for why it matters.

For fine-grained control over algorithms, placement, and trust sources, construct a
[`Signer`](/reference/signer) or [`Verifier`](/reference/verifier) directly.
