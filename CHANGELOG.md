# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the gem version
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html) **over the
Ruby API only** — the libxmlsec1 version the extension is built against is
tracked separately, and is reported by `HankoXml::NativeVersion.build_versions`.

## [Unreleased]

### Fixed

- **#158:** Without Nokogiri, `Signer#sign!` and `Signer#template` given a String
  now raise `NokogiriRequired` naming themselves instead of `HankoXml.parse`.

## [0.1.0] - 2026-10-15

First release.

- **XML-DSig signing and verification** of enveloped, enveloping and detached
  signatures, through libxmlsec1: canonicalization, digests, signature math and
  reference resolution all happen in xmlsec, never in Ruby.
- **Secure by default.** `Policy.strict` denies SHA-1, HMAC, XSLT, XPath and
  external references, requires 2048-bit RSA and DSA and 256-bit EC keys, and
  checks the signing certificate's key usage. Opt-in presets cover other needs:
  `Policy.fragment` (SAML-style signed fragments), `Policy.legacy_sha1`,
  `Policy.xades` (RSA-PSS, SHA-3, ECDSA-SHA3) and `Policy.interop` for older
  signatures.
- **The caller chooses the key.** Verification uses the certificate, key or
  `OpenSSL::X509::Store` you pass, never one selected by the document's
  `<KeyInfo>`, and `Verification` reports which references were signed, so
  XML Signature Wrapping is caught.
- **XAdES-B** signing (`Xades::Signer`) and verification (`Xades::Verifier`),
  including XAdES 1.2.2 and 1.1.1 signed properties, tested against SignXML
  and the EU DSS corpus.
- **Works without Nokogiri.** Signing and verification run on Strings, files
  and IOs. With Nokogiri, the documents you already hold can be signed in
  place, and `require "hanko_xml/nokogiri_ext"` adds `doc.sign!` and
  `doc.signature_valid?`.
- **Detailed results.** `Verification` exposes the certificate chain,
  `SignedInfo`, `KeyInfo` and per-reference status, with
  `Verifier.without_trust_verification` for integrity-only checks.
- **External references** are served only from `referenced_documents:`: the
  library never reads files or opens network connections.
- **Precompiled gems** for `x86_64-linux`, `aarch64-linux`, `arm64-darwin` and
  `x64-mingw-ucrt`, with libxml2 2.15.4, xmlsec1 1.3.12 and OpenSSL 3.5.9
  statically linked and isolated from Nokogiri's libxml2. Other platforms build
  the source gem against the system libraries (libxmlsec1 `>= 1.2.30, < 1.4`).
- **Ruby 3.1 to 3.4**, with RBS signatures in `sig/`.
