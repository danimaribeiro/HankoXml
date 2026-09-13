---
title: Key
description: HankoXml::Key — loading keys, certificates, and PKCS#12 bundles.
order: 4
---

# `HankoXml::Key`

Coercion is uniform, and applies to `key:`, `certificate:`, `certificates:` throughout the public
API.

`key:` accepts:

- `OpenSSL::PKey::PKey` (RSA, EC, DSA) — used directly
- a `String` of PEM (encrypted PEM requires `key_password:`)
- a `Pathname` / `File` / anything responding to `#to_path` — read from disk
- `HankoXml::Key` — the explicit wrapper

`certificate:` / `certificates:` accept the same, plus `OpenSSL::X509::Certificate`.

## Constructors

```ruby
HankoXml::Key.from_pem(pem, password: nil)
HankoXml::Key.from_der(der)
HankoXml::Key.from_file(path, password: nil)

# PKCS#12 / PFX — Windows-exported keys and A1-style software certificates.
# Returns key + leaf certificate + CA chain in one go.
bundle = HankoXml::Key.from_pkcs12("cert.pfx", password: ENV["PFX_PASSWORD"])
bundle.key           # => OpenSSL::PKey::RSA
bundle.certificate   # => OpenSSL::X509::Certificate
bundle.certificates  # => [leaf, *ca_chain]
signer = HankoXml::Signer.new(**bundle.to_h)   # key:, certificate:, certificates:
```

## PEM normalization

Everything crossing into Rust is **PEM**, always. No `key_format` parameter exists in the public API
or in the native contract: Ruby normalizes with `OpenSSL::PKey#to_pem` /
`OpenSSL::X509::Certificate#to_pem`, which is unambiguous, covers PKCS#1 and PKCS#8, and means
decryption and PKCS#12 unwrapping happen in Ruby with OpenSSL rather than in Rust with xmlsec's
format enum.

## Instance methods

```ruby
key.dispose!   # overwrites the Ruby-side buffer in place and marks the key unusable
```

## Safety

- The native layer copies what it needs and retains nothing after the call returns.
- A `Key` never appears in `#inspect`, `#to_s`, or an exception message —
  `Signer#inspect` shows `#<HankoXml::Signer key=[FILTERED] …>`.
- `HankoXml::Error` and subclasses never carry key material.

Ruby strings are GC-managed and not zeroized, so `#dispose!` is a best-effort way to bound the
window a key's bytes remain in memory, not a hard guarantee.
