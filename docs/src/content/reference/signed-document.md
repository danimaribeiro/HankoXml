---
title: SignedDocument
description: HankoXml::SignedDocument — a document you cannot mis-serialize.
order: 8
---

# `HankoXml::SignedDocument`

`Signer#sign` and `HankoXml.sign` do **not** return a bare `Nokogiri::XML::Document`. A bare
document's `#to_xml` defaults to `FORMAT | AS_XML`, which reindents the tree and invalidates the
signature that was just computed — a footgun that fires silently, produces valid-looking XML, and is
discovered by the counterparty.

```ruby
signed = HankoXml.sign(doc, key: key, certificate: cert)
# => #<HankoXml::SignedDocument signatures=1>

signed.to_xml                       # => String, always AS_XML. Safe.
signed.to_s                         # => same
signed.to_xml(declaration: false)   # => same, minus <?xml …?>
signed.write_to(io)                 # => streams the safe serialization
signed.bytes                        # => the String, binary encoding

signed.document                     # => the underlying Nokogiri::XML::Document,
                                    #    for callers who want it. Escape hatch,
                                    #    documented as "you own the consequences".
signed.signatures                   # => NodeSet of <ds:Signature>
signed.valid?(certificate: cert)    # => self-check round trip
```

## Read-only delegation

`SignedDocument` delegates read-only Nokogiri methods (`#at_xpath`, `#xpath`, `#root`, `#encoding`,
`#errors`, …) to the wrapped document, so it is a drop-in for reading.

## Mutators raise on purpose

It deliberately does **not** delegate mutators — `#add_child`, `#remove`, `#content=` and friends
raise `HankoXml::FrozenSignatureError` with a message pointing at `#document` for callers who
genuinely mean it. Any mutation invalidates the signature; failing loudly at the mutation beats
failing mysteriously at the counterparty.

Nodes returned by the readers are still the live tree, so `SignedDocument` records its serialization
when it is created. `#to_xml`, `#to_s`, `#bytes` and `#write_to` raise `FrozenSignatureError` if the
document has changed since, whether through a reader's node or through `#document`. To write out a
document you changed on purpose, use `HankoXml.serialize(signed.document)`.

## `sign` vs `sign!`

`sign!` still returns the caller's own `Nokogiri::XML::Document`, unwrapped, because the caller
already holds that object and wrapping it would be a lie about what they have. The asymmetry:

- **`sign`** is safe by construction — returns a `SignedDocument`.
- **`sign!`** is in-place, returns the plain `Nokogiri::XML::Document`, and expects the caller to
  serialize with `save_with: Nokogiri::XML::Node::SaveOptions::AS_XML` — see the
  [Nokogiri API guide](/guide/nokogiri-api).
