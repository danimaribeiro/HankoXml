---
title: Verification
description: HankoXml::Verification — the anti-XSW result object, and its Reference type.
order: 3
---

# `HankoXml::Verification`

This is the most important type in the library. It answers "what was actually signed", not "did
something verify".

```ruby
v = verifier.verify(doc)

v.valid?             # => true / false — the single crypto verdict
v.errors             # => Array<HankoXml::Error>  (built, not raised)

# --- What was covered -----------------------------------------------------
v.signed?(node)      # => true / false. THE question you should be asking.
v.signed_nodes       # => Array<Nokogiri::XML::Node> actually covered
v.references         # => Array<Verification::Reference>
v.covers_root?       # => true when the document element is inside signed material
v.partial?           # => true when it does not (a fragment signature)

# --- Reading signed data safely -------------------------------------------
v.at_signed(xpath, ns = {})   # => Node, or raises HankoXml::NotSignedError
v.signed(xpath, ns = {})      # => Array<Node>, all of which are covered;
                              #    raises if ANY match is not covered

# --- Authenticated metadata (read from <SignedInfo>, which is signed) -----
v.signature_method        # => :rsa_sha256
v.canonicalization_method # => :exc_c14n
v.digest_methods          # => [:sha256]
v.signed_info             # => HankoXml::SignedInfo (frozen value object)

# --- Who signed -----------------------------------------------------------
v.certificate        # => OpenSSL::X509::Certificate that trust resolved to, or nil
v.certificate_chain  # => Array<OpenSSL::X509::Certificate> as validated
v.key_info           # => HankoXml::KeyInfo::Parsed — what the document *claimed*

# --- Provenance -----------------------------------------------------------
v.signature_node     # => Nokogiri::XML::Element, the <ds:Signature> verified
v.document           # => the Nokogiri document these nodes belong to
```

Metadata accessors (`signature_method`, `references`, …) are populated on both valid and invalid
verifications, because "what did it claim" is exactly what you want when debugging a failure.
Everything on a `Verification` whose `valid?` is `false` is **unauthenticated**.

## `#signed?` semantics — normative

See [XSW Defense](/guide/xsw-defense) for the full explanation. In short, `v.signed?(node)` is
`true` only if the verification is valid, the node belongs to `v.document` by identity, the node is
covered by some reference, and it wasn't excised by a transform (like `enveloped-signature`).

## `#reference` {#reference}

`Verification::Reference` is frozen:

```ruby
ref.uri            # => "#infNFe01"
ref.node           # => Nokogiri::XML::Node the URI resolved to, or nil for URI=""
ref.digest_method  # => :sha1
ref.transforms     # => [:enveloped_signature, :c14n]
ref.enveloped?     # => true
ref.valid?         # => false — THIS reference's digest did not match
ref.errors         # => [#<HankoXml::DigestMismatch reference_uri="#infNFe01">]
```

Per-reference validity matters because "the digest of reference 2 does not match" and "the
signature over `<SignedInfo>` does not match" are completely different bugs — the first means the
data changed, the second means the key or the canonicalization is wrong. Per-reference status is
recovered from the captured xmlsec error log; when it cannot be attributed to a specific reference,
`ref.errors` is empty and the failure appears only at `v.errors`.

## `#at_signed` — making the safe read shorter than the unsafe one

```ruby
# Unsafe, and the shortest thing to write in every other library:
assertion = doc.at_xpath("//saml:Assertion", ns)

# Safe, and now shorter still:
assertion = v.at_signed("//saml:Assertion", ns)
```

`#at_signed` needs a DOM and raises `HankoXml::NokogiriRequired` without one — never `false`, and
never a node it could not check.
