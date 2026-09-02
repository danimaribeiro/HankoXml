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
- **Nokogiri Native** — Directly patches `Nokogiri::XML::Document` for seamless `.sign!` and `.verify!` calls.
- **XSW Defense** — Provides a robust `Policy` engine and structural `signed?(node)` checks to defeat
  XML Signature Wrapping (XSW) attacks.
- **Rust-Backed** — Memory-safe FFI boundaries, zero shell-outs to CLI binaries, and massive performance
  gains over pure-Ruby cryptography.

## Requirements

- Ruby 3.0+
- Rust toolchain (stable)
- `libxmlsec1` development headers:
  - **macOS:** `brew install xmlsec1`
  - **Debian/Ubuntu:** `apt install libxmlsec1-dev pkg-config`

> **Note (macOS):** Homebrew's `libxml2` is keg-only. HankoXml's `build.rs` automatically works around
> this by resolving absolute library paths during compilation.

## Installation

Add this line to your application's Gemfile:

```ruby
gem "hanko_xml", git: "https://github.com/danimaribeiro/HankoXml"
```

Then run `bundle install`.

## Your first signature

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

Continue to the [Nokogiri API](/guide/nokogiri-api) or [Module API](/guide/module-api) guides for the
full picture, or jump straight to [XSW Defense](/guide/xsw-defense) to understand the security model.
