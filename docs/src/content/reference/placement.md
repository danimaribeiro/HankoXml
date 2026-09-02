---
title: Placement
description: HankoXml::Placement — where the <Signature> element goes.
order: 7
---

# `HankoXml::Placement`

Where the `<Signature>` element goes when signing. A frozen value object; symbols coerce.

```ruby
HankoXml::Placement.append_to_root            # :append_to_root  (default)
HankoXml::Placement.prepend_to_root           # :prepend_to_root
HankoXml::Placement.append_to(node_or_xpath, namespaces: {})
HankoXml::Placement.prepend_to(node_or_xpath, namespaces: {})
HankoXml::Placement.after(node_or_xpath, namespaces: {})
HankoXml::Placement.before(node_or_xpath, namespaces: {})
HankoXml::Placement.detached                  # build <Signature> but insert nothing;
                                              # Signer#template returns it, sign raises
HankoXml::Placement.custom { |doc, signature| ... }  # you insert it; return value ignored
```

An XPath that matches zero or more than one node raises `HankoXml::PlacementError` before any
crypto runs. The `custom` block is the full escape hatch — the rare case, not the default.

## Ordering matters

Signature placement happens **before** digest computation, which is why it is part of the `Signer`
and not a post-processing step: for an enveloped signature, where the element sits changes what
gets canonicalized.

```ruby
HankoXml::Signer.new(
  key: key,
  certificates: certs,
  placement: HankoXml::Placement.after("//ds:Signature")
)
```

See [`Signer`](/reference/signer) for how `placement:` is used during signing.
