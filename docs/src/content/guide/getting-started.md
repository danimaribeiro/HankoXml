---
title: Getting Started
description: Install HankoXml and sign/verify your first document.
order: 1
---

# Getting Started

HankoXml is a high-performance, strictly secure XML Digital Signature (XML-DSig) library for Ruby.
It is backed by a native Rust extension that binds directly to [libxmlsec1](https://www.aleksey.com/xmlsec/)
using [Magnus](https://github.com/matsadler/magnus). It is designed to be completely byte-faithful,
blazingly fast, and natively immune to XML Signature Wrapping (XSW) attacks.

It tightly integrates with Nokogiri, allowing you to sign and verify documents directly in memory
without fragile re-serialization.

## Features

- **Full XML-DSig Support** — Sign and verify Enveloped, Enveloping, and Detached signatures.
- **Nokogiri Native, Nokogiri Optional** — Signs and verifies the Nokogiri documents you already hold, with
  opt-in `doc.sign!` / `doc.signature_valid?` shorthands (`require "hanko_xml/nokogiri_ext"`), and verifies
  Strings, files and IOs without Nokogiri.
- **XSW Defense** — Provides a robust `Policy` engine and structural `signed?(node)` checks to defeat
  XML Signature Wrapping (XSW) attacks.
- **Rust-Backed** — Memory-safe FFI boundaries, zero shell-outs to CLI binaries, and massive performance
  gains over pure-Ruby cryptography.

## Requirements

- Ruby 3.1+

Precompiled platform gems are published for `x86_64-linux`, `aarch64-linux`, `arm64-darwin` and
`x64-mingw-ucrt`. They bundle libxmlsec1, libxml2 and OpenSSL, so on those platforms you need nothing
else.

### Building from source (fallback)

On any other platform RubyGems installs the source gem, which compiles the Rust extension against the
local `libxmlsec1` (`>= 1.2.30, < 1.4`). That needs:

- Rust toolchain (stable)
- `libxmlsec1` and `libxml2` development headers, `pkg-config`, and libclang:
  - **macOS:** `brew install libxmlsec1 libxml2 pkg-config`
  - **Debian/Ubuntu:** `apt install libxmlsec1-dev libxml2-dev pkg-config libclang-dev`

> **Note (macOS):** Homebrew's `libxml2` is keg-only. HankoXml's `build.rs` automatically works around
> this by resolving absolute library paths during compilation.

## Installation

Add this line to your application's Gemfile:

```ruby
gem "hanko_xml"
```

Then run `bundle install`, or install it directly with `gem install hanko_xml`.

Nokogiri is optional. Add `gem "nokogiri"` for signing and the Nokogiri API; without it,
verification still works on a String, a path or an IO, and so does signing a document that
already holds its `<Signature>` template. Building a template raises
`HankoXml::NokogiriRequired`.

## Your first signature

The `doc.sign!` / `doc.signature_valid?` shorthands below come from the opt-in Nokogiri extension,
`require "hanko_xml/nokogiri_ext"`. Without it, use [`HankoXml.sign!` and `HankoXml.valid?`](/guide/module-api).

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

Continue to the [Nokogiri API](/guide/nokogiri-api) or [Module API](/guide/module-api) guides for the
full picture, or jump straight to [XSW Defense](/guide/xsw-defense) to understand the security model.
