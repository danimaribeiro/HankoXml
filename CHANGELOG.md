# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the gem version
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html) **over the
Ruby API only** — the libxmlsec1 version the extension is built against is
tracked separately, and is reported by `HankoXml::NativeVersion.build_versions`.

## [Unreleased]

### Added

- **#162:** XAdES-T signing. `Xades::Signer.new(timestamper: ->(request_der) { response_der })`
  adds a `<xades:SignatureTimeStamp>`: an RFC 3161 token over the
  `<ds:SignatureValue>`, canonicalized by xmlsec (#161). The callable does the
  TSA exchange, so the library never opens a connection. The response must
  grant the timestamp and carry the request's imprint and nonce, otherwise
  signing raises `SigningError`. `timestamp_digest_method:` (default: the
  Signer's `digest_method:`) and `timestamp_canonicalization_method:` (default
  `:exc_c14n`) go through the Signer's policy.
- **#163:** XAdES-T verification. `Xades::Verifier` checks every
  `<xades:SignatureTimeStamp>` of the signature against the TSA trust in
  `tsa_store:` or `tsa_certificates:`, which is kept separate from the signer's.
  OpenSSL verifies the token, and its imprint must cover the `<ds:SignatureValue>`
  as xmlsec canonicalizes it. `Xades::Verification#signature_timestamps` lists
  them (time, serial, TSA certificate) and `#timestamp_time` gives the earliest.
  `timestamps: :require` also fails a signature without one (S-22).
- **#167:** XAdES-LT validation data. `Xades::Augmenter` adds unsigned
  properties to an existing, signed XAdES signature: a `SignatureTimeStamp`
  (`timestamper:`, B to T) and `CertificateValues` / `RevocationValues`
  (`validation_data:`, T to LT), leaving everything signed byte-identical.
  `Xades::Signer` takes `validation_data:` too, with `timestamper:`.
  `Xades::ValidationData` holds caller-supplied certificates, CRLs and OCSP
  responses, type-checked only; the library never fetches them, and nothing
  embedded is trusted yet (#168).
- **#168:** XAdES-LT verification. When a signature embeds `CertificateValues`
  or `RevocationValues`, `Xades::Verifier` validates the signing certificate
  at the time of its earliest verified SignatureTimeStamp: XML-DSig trust at
  that time (an expired certificate still verifies; embedded certificates may
  complete a `store:` chain), then embedded OCSP responses or CRLs for every
  certificate below the anchor, verified by OpenSSL against the same anchor
  and issued no earlier than that time (`revocation_grace:` widens it).
  `long_term: :verify | :require | :ignore`; the result is
  `Xades::Verification#long_term_validation`. Fail closed (S-23).
- **#169:** XAdES-LTA. `Xades::Augmenter.new(timestamper:, archive_timestamp: true)`
  appends a `<xades141:ArchiveTimeStamp>` over the EN 319 132-1 input (the
  References' data as xmlsec digested it, SignedInfo, SignatureValue, KeyInfo,
  every unsigned property before it and the other `ds:Object`s); running it
  again renews it. `Xades::Verifier` verifies every ArchiveTimeStamp against
  the TSA trust, failing closed, and lists them in
  `Xades::Verification#archive_timestamps`. `Native.reference_data` returns
  each Reference's digested octets from xmlsec. SignXML's DSS-produced
  HU_POL-3 ArchiveTimeStamp verifies.

### Changed

- **#163:** `Xades::Verifier` no longer ignores unsigned SignatureTimeStamps.
  A signature that carries one now fails verification unless the timestamp
  verifies, which needs `tsa_store:` or `tsa_certificates:`. Pass
  `timestamps: :ignore` to keep the XAdES-B-only behavior.
- **#168:** `Xades::Verifier` no longer ignores embedded `CertificateValues` /
  `RevocationValues`. A signature that carries them is validated at its
  timestamp time and fails when that evidence does not hold, which can also
  make a signature fail that verified before (and one whose certificate has
  expired pass). Pass `long_term: :ignore` to keep the XAdES-T behavior.
- **#169:** `Xades::Verifier` no longer ignores `xades141:ArchiveTimeStamp`s:
  one that does not verify, or one present without TSA trust, fails the
  signature. `timestamps: :ignore` leaves them unread.

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
