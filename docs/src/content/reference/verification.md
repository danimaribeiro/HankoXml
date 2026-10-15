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
v.signed_info             # => SignatureInfo once valid?, else nil

# --- Who signed -----------------------------------------------------------
v.certificate        # => OpenSSL::X509::Certificate that trust resolved to, or nil
v.certificate_chain  # => [leaf, ..., anchor] for store:, [certificate] when pinned,
                     #    [] for a bare key, an untrusted result, or unless valid?
v.trusted?           # => valid? and the key came from trust you supplied; false for
                     #    Verifier.without_trust_verification

# --- What the document claimed (untrusted) --------------------------------
v.key_info           # => KeyInfo::Parsed: #key_names, #certificates (PEM), or nil when no
                     #    <SignedInfo> was read (e.g. no signature). Never picks the key.

# --- Provenance -----------------------------------------------------------
v.signature_node     # => Nokogiri::XML::Element, the <ds:Signature> verified
v.document           # => the Nokogiri document these nodes belong to
```

Metadata accessors (`signature_method`, `references`, …) are populated on both valid and invalid
verifications, because "what did it claim" is exactly what you want when debugging a failure.
Everything on a `Verification` whose `valid?` is `false` is **unauthenticated**. `#signed_info`
is the exception that proves the rule: it is nil until the signature holds, so code that reads it
can't act on a claim by mistake. `#key_info` is the opposite: always the document's claim, never
authenticated, useful for logging who the document *says* signed it.

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
data changed, the second means the key or the canonicalization is wrong. Per-reference status comes
from `Native.verify`'s `reference_valid`, xmlsec's own per-`<Reference>` status (S-09), never from
parsing its error log. `ref.errors` holds a `DigestMismatch` only when xmlsec reported that
reference's digest as wrong; when verification stopped before xmlsec reached a reference,
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
