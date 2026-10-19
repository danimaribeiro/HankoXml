---
title: Xades
description: HankoXml::Xades — Signer, Augmenter, ValidationData, Verifier and Verification for XAdES-B, -T, -LT and -LTA.
order: 9
---

# `HankoXml::Xades`

XAdES baseline signatures (ETSI EN 319 132-1, namespace `http://uri.etsi.org/01903/v1.3.2#`), built
on [`Signer`](/reference/signer) and [`Verifier`](/reference/verifier). xmlsec still does every
digest, canonicalization and signature; this layer adds the qualifying properties and checks them.
Every class here needs Nokogiri. For what each level is for, read the
[XAdES guide](/guide/xades).

| Class | Does |
|---|---|
| `Xades::Signer` | Signs XAdES-B, and T or LT in the same call |
| `Xades::Augmenter` | Adds T, LT or LTA to a signature that already exists |
| `Xades::ValidationData` | The certificates, CRLs and OCSP responses LT embeds |
| `Xades::Verifier` | Verifies B, T, LT and LTA, failing closed |
| `Xades::Verification` | The result, with the signed properties and the timestamps |

## `Xades::Signer`

Takes every `Signer` keyword, plus:

```ruby
signer = HankoXml::Xades::Signer.new(
  key: key, certificate: cert,          # certificate: is required
  signing_time:       nil,              # Time; nil = when #sign runs, written in UTC
  signature_policy:   nil,              # Xades::SignaturePolicy / Hash / :implied
                                        #   { identifier: "urn:oid:…", digest_value: "<Base64>",
                                        #     digest_method: :sha256, description: nil }
  claimed_roles:      [],               # SignerRoleV2/ClaimedRoles
  data_object_format: nil,              # Xades::DataObjectFormat / Hash: mime_type:, description:, encoding:
  signature_id:       nil,              # generated when nil; QualifyingProperties targets it
  timestamper:        nil,              # XAdES-T: ->(request_der) { response_der }
  timestamp_digest_method:           nil,        # imprint digest; nil = digest_method:
  timestamp_canonicalization_method: :exc_c14n,  # how SignatureValue is canonicalized
  validation_data:    nil,              # XAdES-LT: Xades::ValidationData / Hash; needs timestamper:
)
signer.sign(xml)   # => SignedDocument
```

- It always builds a new `<Signature>`: `template:` other than `:build` raises `ConfigurationError`.
- `<SignedInfo>` gets a last Reference over `<xades:SignedProperties>`, which holds `SigningTime`,
  `SigningCertificateV2` (with `IssuerSerialV2`) and the optional properties. The output conforms
  to the XAdES 1.3.2 schema and still verifies with a plain `Verifier` under `Policy.strict`.
- With `timestamper:`, a `<xades:SignatureTimeStamp>` is added over the canonicalized
  `<ds:SignatureValue>`. The library never opens a connection: the callable gets the RFC 3161
  request DER and returns the response DER. The response must be granted and carry the request's
  imprint, digest algorithm and nonce, or signing raises `SigningError` before anything is written.
  The TSA's signature is not checked when signing; that belongs to verification.
- Both imprint algorithms go through the registry and the Signer's `policy:`, so a SHA-1 imprint
  needs `Policy.legacy_sha1`.
- With `validation_data:` too, `CertificateValues` and `RevocationValues` follow the timestamp.

## `Xades::Augmenter`

Adds unsigned properties to an existing, signed XAdES signature, without touching anything a
Reference or the SignatureValue covers.

```ruby
augmenter = HankoXml::Xades::Augmenter.new(
  timestamper:       nil,        # adds a SignatureTimeStamp (B to T)
  timestamp_digest_method:           :sha256,
  timestamp_canonicalization_method: :exc_c14n,
  validation_data:   nil,        # adds CertificateValues / RevocationValues (T to LT)
  archive_timestamp: false,      # true: adds an ArchiveTimeStamp (LT to LTA); needs timestamper:
  archive_canonicalization_method:   :c14n,
  policy:            HankoXml::Policy.strict)   # imprint algorithms, max_document_size
augmenter.augment(xml, signature: nil)          # => SignedDocument (a copy)
```

- At least one of `timestamper:` and `validation_data:` is required. The Augmenter is frozen, and
  `#inspect` shows no material.
- `signature:` is the document-order index of the `<ds:Signature>`; `nil` needs exactly one. It
  must be signed and carry one 1.3.2 QualifyingProperties targeting it, or the call raises
  `ConfigurationError` / `XadesError`.
- Validation data needs a SignatureTimeStamp, already there or added by `timestamper:` in the same
  call.
- With `archive_timestamp: true`, `<xades141:ArchiveTimeStamp>` is appended last, over every part
  EN 319 132-1 §5.5.2.2 lists. `timestamper:` then adds a SignatureTimeStamp only when there is
  none, and the signature must carry LT values (or get them from `validation_data:`). Running it
  again renews the archive: each new ArchiveTimeStamp covers the earlier ones.
- `archive_canonicalization_method:` other than `:c14n` is refused for a signature whose References
  leave a node set, as `Xades::Signer`'s enveloped one does.
- The caller's document is not modified. The Augmenter does not verify the signature it extends,
  and embedding vouches for nothing: verify first.

## `Xades::ValidationData`

```ruby
HankoXml::Xades::ValidationData.new(
  certificates:   [],   # X509 / PEM / Key: the chain, TSA certificates…
  crls:           [],   # OpenSSL::X509::CRL, PEM or DER
  ocsp_responses: [],   # OpenSSL::OCSP::Response or DER OCSPResponse
)                       # a Hash of these keywords works wherever it is taken
```

You collect the material; the library never fetches it. Each entry is only type-checked
(certificates, CRLs, OCSPResponses with a successful `responseStatus`), otherwise
`ConfigurationError`. None of it is trusted. It is frozen.

## `Xades::Verifier`

Takes every `Verifier` keyword, except that trust must be `certificate:`, `certificates:` or
`store:`, since the signed properties commit to a certificate. Plus:

```ruby
verifier = HankoXml::Xades::Verifier.new(
  store: roots,
  signature_policy: nil,     # the SignaturePolicyIdentifier the signature must carry
  timestamps:       :verify, # :verify | :require | :ignore
  tsa_store:        nil,     # OpenSSL::X509::Store trusting the TSAs, or
  tsa_certificates: nil,     # trusted TSA certificates (PEM / X509 / Key); not both
  long_term:        nil,     # :verify | :require | :ignore; nil = :verify, or :ignore with timestamps: :ignore
  revocation_grace: 0,       # seconds an embedded CRL / OCSP response may predate the validation time
)
verifier.verify(xml)   # => Xades::Verification
```

After the XML-DSig signature verifies:

- **B.** There is exactly one SignedProperties Reference, and the element xmlsec digested for it is
  the SignedProperties of this signature's single QualifyingProperties, never a decoy elsewhere.
  `SigningCertificateV2` (or v1 `SigningCertificate`) must list a digest of the certificate that
  verified. The XAdES 1.2.2 and 1.1.1 namespaces are read too.
- **T.** Every SignatureTimeStamp, found by path and never by search, is verified by OpenSSL against
  the TSA trust, over the SignatureValue as xmlsec canonicalizes it. One present with no TSA trust
  fails. `:require` also fails a signature without one; `:ignore` reads no unsigned property.
- **LT.** With `CertificateValues` or `RevocationValues`, the signature is verified at the earliest
  timestamp time, and every certificate below the anchor needs embedded OCSP or CRL evidence that
  verifies against the same anchor, issued no earlier than that time minus `revocation_grace:`,
  and showing no revocation at or before it.
- **LTA.** Every ArchiveTimeStamp is verified against the TSA trust, over the input recomputed by
  xmlsec from the verified signature. Properties after an ArchiveTimeStamp are outside it.

Any failure is a `HankoXml::XadesError` (a `PolicyError` for a disallowed algorithm) in `#errors`.
TSA chains are checked at the current time: an ArchiveTimeStamp is not yet used to validate an
expired TSA certificate at a past time (#173).

## `Xades::Verification`

A [`Verification`](/reference/verification) whose `#valid?`, `#signed?` and `#at_signed` also fail
closed on the XAdES checks. Each reader is `nil` unless the verification is valid.

| Reader | Returns |
|---|---|
| `#signed_properties` | `Xades::SignedProperties(signing_time:, signature_policy:, claimed_roles:, data_object_formats:)` |
| `#signature_timestamps` | `Xades::SignatureTimeStamp(id:, time:, serial_number:, tsa_certificate:, digest_method:, policy_id:)`s in document order; empty when there are none, `nil` with `timestamps: :ignore` |
| `#timestamp_time` | The earliest SignatureTimeStamp `time`, or `nil` |
| `#long_term_validation` | `Xades::LongTermValidation(time:, certificate_chain:, revocation:)`, with one `Xades::RevocationStatus(certificate:, source:, issued_at:, status:)` per certificate below the anchor; `nil` without LT values |
| `#archive_timestamps` | `Xades::SignatureTimeStamp`s for the ArchiveTimeStamps, in document order; empty when there are none |

All of them are frozen.
