---
title: Keys & Certificates
description: Loading keys, certificates, and PKCS#12 bundles with HankoXml::Key.
order: 6
---

# Keys & Certificates

Coercion is uniform, and applies to `key:`, `certificate:`, `certificates:` everywhere in the API.

`key:` accepts:

- `OpenSSL::PKey::PKey` (RSA, EC, DSA) — used directly
- a `String` of PEM (encrypted PEM requires `key_password:`)
- a `Pathname` / `File` / anything responding to `#to_path` — read from disk
- `HankoXml::Key` — the explicit wrapper

`certificate:` / `certificates:` accept the same, plus `OpenSSL::X509::Certificate`.

## Convenience constructors

All pure Ruby over `OpenSSL`:

```ruby
HankoXml::Key.from_pem(pem, password: nil)
HankoXml::Key.from_der(der)
HankoXml::Key.from_file(path, password: nil)
```

## PKCS#12 bundles

The common case for Brazilian NFe A1 certificates and for Windows-exported keys. Returns key + leaf
certificate + CA chain in one go.

```ruby
bundle = HankoXml::Key.from_pkcs12("cert.pfx", password: ENV["PFX_PASSWORD"])
bundle.key           # => OpenSSL::PKey::RSA
bundle.certificate   # => OpenSSL::X509::Certificate
bundle.certificates  # => [leaf, *ca_chain]

signer = HankoXml::Signer.new(**bundle.to_h)   # key:, certificate:, certificates:
```

## Everything crossing into Rust is PEM

No `key_format` parameter exists in the public API or in the native contract: Ruby normalizes with
`OpenSSL::PKey#to_pem` / `OpenSSL::X509::Certificate#to_pem`, which is unambiguous, covers PKCS#1 and
PKCS#8, and means decryption and PKCS#12 unwrapping happen in Ruby with OpenSSL rather than in Rust
with xmlsec's format enum.

## Key material handling

`HankoXml::Key` holds PEM bytes in a Ruby `String`. Ruby strings are GC-managed and not zeroized, and
this cannot be promised otherwise. What is promised:

- the native layer copies what it needs and retains nothing after the call returns;
- `Key#dispose!` overwrites the Ruby-side buffer in place and marks the key unusable, for callers who
  want to bound the window;
- a `Key` never appears in `#inspect`, `#to_s`, or an exception message —
  `Signer#inspect` shows `#<HankoXml::Signer key=[FILTERED] …>`.

See the [`Key` reference](/reference/key) for the full API surface.
