---
title: "XAdES: Signatures That Outlive Certificates"
description: How XAdES and timestamps keep an XML signature verifiable for decades, from XAdES-B to the renewable ArchiveTimeStamp of XAdES-LTA.
order: 8
---

# XAdES: signatures that outlive their certificates

This guide shows how XAdES and timestamps keep an XML signature verifiable for decades. It starts
from what a plain signature can prove and adds one layer per section, ending at the renewable
ArchiveTimeStamp of XAdES-LTA. Every option is listed in the [XAdES reference](/reference/xades).

XAdES needs Nokogiri: `Xades::Signer`, `Xades::Augmenter` and `Xades::Verifier` raise
`NokogiriRequired` without it.

## The problem: a signature is checked today, but was made in the past

A digital signature proves that someone holding a private key signed some bytes. To know *who* that
was, the verifier uses a **certificate**: a document from a certificate authority (CA) saying "this
public key belongs to Maria Silva, valid from 2024-05-01 to 2027-05-01".

Picture a contract signed in March 2025, and three questions about it in 2030:

- **The certificate expired in 2027.** A normal verifier checks the certificate against *today's*
  date, so the signature now fails, though nothing about the contract changed.
- **Was the key stolen?** If Maria reported her key stolen in 2026, the CA *revoked* the
  certificate. A signature from 2025 is still good; one made by the thief in 2026 is not. Without a
  reliable date on the signature, the verifier can't tell them apart.
- **Can the verifier still ask the CA?** CAs stop publishing the status of expired certificates,
  and some CAs close down entirely.

A long-lived signature needs two things a plain signature lacks: **trustworthy proof of when it
existed**, and **the evidence about the certificate, saved from that time**. XAdES (ETSI EN 319
132-1) is the standard for adding both to an XML signature.

## XML-DSig in one paragraph

XAdES builds on XML-DSig. A `<ds:Signature>` has three main parts:

1. **SignedInfo** lists *References*. Each Reference points at some data, says how to transform it,
   and stores a digest of the result.
2. **SignatureValue** is the signature over the canonical form of SignedInfo. Since SignedInfo holds
   the digests, signing it signs all the data.
3. **KeyInfo** usually carries the signer's certificate. It is *not* signed by default: anyone can
   edit it.

**Canonicalization (c14n)** turns XML into one exact byte sequence, so harmless differences such as
attribute order don't change a hash. *Inclusive* c14n (`:c14n`) and *exclusive* c14n (`:exc_c14n`)
differ in how they copy namespace declarations from parent elements, which matters for
[XAdES-LTA](#xades-lta-a-timestamp-over-everything-renewed).

Verifying means recomputing every digest, checking the SignatureValue with the public key, and
checking that the certificate chains to a **trust anchor** you chose. In HankoXml that is
`HankoXml::Verifier`, and xmlsec does all the cryptography.

## What XAdES adds: signed and unsigned properties

XAdES adds a `<xades:QualifyingProperties>` block inside a `<ds:Object>` of the signature. Its two
halves are the key idea of this guide.

**SignedProperties** are what the signer commits to. SignedInfo gets an extra Reference to
`<xades:SignedProperties>`, so they are signed like the document:

- **SigningCertificateV2** holds a digest of the signer's certificate. This closes the KeyInfo gap:
  an attacker can't swap in another certificate for the same key, because the signed digest would
  no longer match.
- **SigningTime** is the time the signer *claims*. It is only the signer's word, written by the
  signer's own computer; a thief with a stolen key can write any date there.
- Optional: signature policy, claimed roles, data object format.

**UnsignedProperties** are added afterwards: timestamps and validation data, often years later and
often by someone other than the signer. No Reference covers them.

> **The rule that follows:** anything in UnsignedProperties is attacker-controlled until it proves
> itself. A timestamp must verify against a timestamp authority you trust; an OCSP response must
> verify against your CA. HankoXml never trusts embedded material because it is there
> (`SECURITY_REVIEW.md` S-22, S-23, S-24).

The shape of a full XAdES-LTA signature, with the level that adds each part:

```text
<ds:Signature Id="sig">
├── <ds:SignedInfo>             B    References: the document, and the SignedProperties
├── <ds:SignatureValue>         B    the signature over SignedInfo
├── <ds:KeyInfo>                     the certificate, unsigned
└── <ds:Object>
    └── <xades:QualifyingProperties Target="#sig">
        ├── <xades:SignedProperties>          B    SigningTime, SigningCertificateV2, …
        └── <xades:UnsignedProperties>
            └── <xades:UnsignedSignatureProperties>
                ├── <xades:SignatureTimeStamp>       T    a TSA's token over the SignatureValue
                ├── <xades:CertificateValues>        LT   the certificate chain
                ├── <xades:RevocationValues>         LT   CRLs and OCSP responses
                └── <xades141:ArchiveTimeStamp>      LTA  a TSA's token over everything above
```

## The four levels

The ETSI baseline profiles name four levels. Each keeps everything from the one before and adds one
thing, and each answers "how long can this signature still be verified?" with a longer time.

| Level | Adds | Proves | Good until |
|---|---|---|---|
| **B** (Basic) | SignedProperties | Who signed, bound to one certificate | The signing certificate expires |
| **T** (Timestamp) | SignatureTimeStamp | The signature existed at a trusted time | The TSA's certificate expires |
| **LT** (Long Term) | CertificateValues, RevocationValues | The certificate was good at that time | The TSA's certificate expires |
| **LTA** (Long Term with Archive) | ArchiveTimeStamp, renewable | All of the evidence existed while it was sound | Renewed for as long as you keep renewing |

In HankoXml, `Xades::Signer` produces B, T or LT in one call, `Xades::Augmenter` raises an existing
signature to T, LT or LTA later, and `Xades::Verifier` checks whatever level it finds.

```ruby
signed = HankoXml::Xades::Signer.new(key: key, certificate: cert).sign(xml)   # XAdES-B
result = HankoXml::Xades::Verifier.new(certificate: cert).verify(signed.to_s)
result.valid?                          # => true
result.signed_properties.signing_time  # what the signer claimed
```

## What a timestamp is

A **Time-Stamp Authority (TSA)** is a service, defined by RFC 3161, that signs statements of the
form "these bytes existed at 2025-03-14 10:22:07 UTC". It never sees the bytes, only their hash.

| Request | Token (TimeStampToken) |
|---|---|
| `messageImprint`: the hash algorithm and the hash of your bytes | The same `messageImprint` |
| `nonce`: a random number, so an old reply can't be replayed | The same `nonce` |
| `certReq`: "include your certificate" | `genTime` (the time), `serialNumber`, `policy`, all signed by the TSA, whose certificate is marked for *timeStamping* |

To check a token later you recompute the hash of the bytes and compare it to `messageImprint`,
verify the TSA's signature on the token, and check that the TSA's certificate chains to a TSA root
*you* trust and may issue timestamps. If all three hold, those exact bytes existed at `genTime`, by
the TSA's clock rather than the signer's. That is the difference from SigningTime.

HankoXml never opens a connection. You pass a `timestamper:`, any callable that takes the request
DER and returns the response DER, so you decide how to reach the TSA (HTTP, a proxy, a stub in
tests). HankoXml builds the request, checks the response answers it (status, imprint, algorithm,
nonce), and writes the token in.

```ruby
tsa = lambda do |request_der|
  Net::HTTP.post(URI("https://tsa.example/"), request_der,
                 "Content-Type" => "application/timestamp-query").body
end
```

## XAdES-T: timestamping the signature

XAdES timestamps the canonicalized **SignatureValue**. It depends on SignedInfo, which depends on
every digest, so it fingerprints the whole signed content. A timestamp over it proves the complete
signature existed at that time, so the private key was used no later than that.

The token goes into `<xades:SignatureTimeStamp>`, with a `CanonicalizationMethod` that says how the
SignatureValue became bytes. xmlsec does that canonicalization, both when signing and when
verifying.

```ruby
# Sign and timestamp in one call
signed = HankoXml::Xades::Signer.new(key: key, certificate: cert, timestamper: tsa).sign(xml)

# Or add the timestamp to an existing XAdES-B signature later
t = HankoXml::Xades::Augmenter.new(timestamper: tsa).augment(b_signed_xml)
```

`Xades::Verifier` then:

1. verifies the XML-DSig signature and the signed properties, as for B;
2. finds each SignatureTimeStamp by its exact path in this signature's QualifyingProperties, never
   by searching the document, where an attacker could plant decoys;
3. canonicalizes the SignatureValue with the stated method, through xmlsec;
4. verifies the token with OpenSSL against **your TSA trust**, kept separate from the signer's: the
   TSA's signature, its chain, its timeStamping purpose, and that the imprint is the hash of step 3.

```ruby
verifier = HankoXml::Xades::Verifier.new(store: roots, tsa_certificates: tsa_roots)
result = verifier.verify(xml)
result.valid?                      # => true
result.signature_timestamps.first  # id, time, serial_number, tsa_certificate, …
result.timestamp_time              # the earliest verified time
```

`timestamps:` sets the strictness. `:verify` (the default) checks every timestamp present,
`:require` also fails a signature with none, and `:ignore` doesn't read them (the XAdES-B
behavior). A timestamp present with no TSA trust configured fails, because an unverifiable
timestamp is not evidence.

T alone doesn't say whether Maria's certificate was still good in March 2025. That needs revocation
data.

## Revocation: was the certificate still good?

A CA **revokes** a certificate when its key is compromised or its holder leaves the organization.
There are two ways to learn about it:

| | CRL | OCSP response |
|---|---|---|
| What it is | A list of every revoked serial number, published regularly | An answer about one certificate: good, revoked or unknown |
| Signed by | The CA that issued the certificate (with the *cRLSign* key usage) | The CA, or a responder it delegated (with the *OCSPSigning* purpose) |
| Its date | `thisUpdate`, when it was issued | `thisUpdate` per answer, and `producedAt` for the response |
| Revocation | Each entry has a revocation date | A revoked answer carries the revocation date |

Both are signed objects, so they can be stored and checked later, offline. That is what LT does.

Evidence speaks only about the moment it was issued: a CRL from January says nothing about
February. So to show the certificate was good at the timestamp's time, the evidence must be issued
**at or after** that time. A revocation **after** that time doesn't hurt: if Maria's key was stolen
in 2026, the 2025 signature was made before the theft, and the timestamp proves it.

## XAdES-LT: saving the evidence inside the signature

LT adds two properties after the SignatureTimeStamp:

- `<xades:CertificateValues>`: the certificates of the chain, so it can be built without fetching
  anything;
- `<xades:RevocationValues>`: CRLs and OCSP responses, collected *after* the timestamp so they are
  fresh.

You collect them, typically a few minutes after timestamping, and pass them in as
`validation_data:`. HankoXml only checks that each one parses as its type; it never fetches
anything, and nothing embedded is trusted until it verifies.

```ruby
lt = HankoXml::Xades::Augmenter.new(
  validation_data: { certificates: [cert, intermediate, root],
                     ocsp_responses: [ocsp_for_cert, ocsp_for_intermediate] }
).augment(t_signed_xml)
```

`Xades::Signer` takes `validation_data:` too, together with `timestamper:`, to write LT in one call.

When a signature carries LT values, `Xades::Verifier`:

1. verifies the SignatureTimeStamps; the earliest verified time is the **validation time**;
2. verifies the XML-DSig signature **as of the validation time**, so an expired signing certificate
   passes if it was valid then. Embedded certificates may fill the middle of a `store:` chain, but
   never act as its anchor: the root still comes from your `store:`;
3. finds usable evidence for every certificate below the anchor: an OCSP response that verifies
   against your root (its responder chain also checked at its `producedAt`), or a CRL signed by the
   certificate's issuer;
4. requires that evidence to be issued no earlier than the validation time minus
   `revocation_grace:`, and not in the future;
5. fails on a revocation at or before the validation time, even beside good evidence. A later one
   is reported as `:revoked_later`.

```ruby
result.long_term_validation.time        # the validation time
result.long_term_validation.revocation  # per certificate: source (:ocsp / :crl), issued_at, status
```

`long_term:` works like `timestamps:`: `:verify` (the default) checks LT values when present,
`:require` also needs them, and `:ignore` skips them.

> **A real-world example.** In the HU_POL-3 sample from SignXML's test suite, produced by EU DSS,
> one OCSP response is dated **one second before** the signature timestamp. The default,
> `revocation_grace: 0`, rejects it as stale; `revocation_grace: 1` accepts it, and the full LT
> check then passes on a real three-certificate chain. The default is strict on purpose: you
> choose how much slack to allow.

## XAdES-LTA: a timestamp over everything, renewed

LT still has a weak point: the **TSA's own certificate**. It expires too, typically after 5 to 10
years, and the TSA's key could be compromised. Hash and signature algorithms also weaken over time
(SHA-1 went from standard to broken in about 20 years). Once the SignatureTimeStamp can't be
trusted, its validation time is gone, and LT falls with it.

The fix is an **ArchiveTimeStamp** (`<xades141:ArchiveTimeStamp>`, namespace
`http://uri.etsi.org/01903/v1.4.1#`). It timestamps *everything*: the signed data, the signature,
the SignatureTimeStamp and all the LT evidence. While it is trusted, it proves all that material
existed at its time, when the older TSA was still sound. Before its own TSA certificate expires,
you add a new one over everything, including the old one, so each layer protects the one beneath:

```text
ArchiveTimeStamp 2036                       TSA certificate valid to 2042
└── ArchiveTimeStamp 2031                   TSA certificate valid to 2037
    └── CertificateValues + RevocationValues   collected 2025
        └── SignatureTimeStamp 2025         TSA certificate valid to 2032
            └── Signature and signed data   2025, signing certificate valid to 2027
```

```ruby
# LT to LTA. The signature needs CertificateValues or RevocationValues already,
# or validation_data: in the same call.
lta = HankoXml::Xades::Augmenter.new(timestamper: tsa, archive_timestamp: true).augment(lt_xml)

# Years later, renew it: the new ArchiveTimeStamp covers the old one.
renewed = HankoXml::Xades::Augmenter.new(timestamper: tsa, archive_timestamp: true).augment(lta.to_s)
```

### Which bytes it covers

EN 319 132-1 §5.5.2.2 defines the input as these parts, concatenated in order:

1. each Reference's data, exactly as it was digested. HankoXml takes these bytes from xmlsec
   (`Native.reference_data`) instead of re-running transforms in Ruby;
2. `SignedInfo`, `SignatureValue` and `KeyInfo`;
3. every unsigned signature property before this ArchiveTimeStamp, earlier ArchiveTimeStamps
   included;
4. every other `ds:Object` (not the one holding QualifyingProperties).

Parts 2 to 4 are canonicalized by xmlsec with the ArchiveTimeStamp's own CanonicalizationMethod.
The standard can be read several ways here. Four readings were tried against a real
ArchiveTimeStamp made by EU DSS (in the HU_POL-3 sample); only this one matched its hash, and that
timestamp now verifies through HankoXml.

### Why the default is inclusive c14n

Some References don't end in a canonicalization step, such as the enveloped `URI=""` one
`Xades::Signer` writes. Their result is a set of XML nodes, not bytes. XML-DSig turns such a set
into bytes with *inclusive* c14n before hashing, and xmlsec does so; the archive rule says to use
the ArchiveTimeStamp's method. The two agree only when that method is inclusive c14n, so
`archive_canonicalization_method:` defaults to `:c14n`, and any other method is refused for such a
signature, both when adding and when verifying.

### How it is verified

Each ArchiveTimeStamp is checked like a SignatureTimeStamp, but over the input above, recomputed by
xmlsec from the verified signature. Changing any covered byte (an OCSP response, KeyInfo, another
Object) makes it fail. Properties added *after* an ArchiveTimeStamp are outside it, which is what
lets renewal work. The results are in `result.archive_timestamps`.

## Over twenty years

The same contract, signed in March 2025, verified at different dates, with a 3-year signing
certificate, TSA certificates of about 6 years and ArchiveTimeStamps renewed every 5 years. Move the
verification date and compare the levels, under the ETSI validation model and under what HankoXml
does today. The two part ways after 2032, for the reason in the next section.

| Verified in | B | T | LT | LTA (ETSI model) | LTA (HankoXml today) |
|---|---|---|---|---|---|
| 2026 | valid | valid | valid | valid | valid |
| 2030 | fails: the certificate expired in 2027 | at risk: revocation data must be fetched now, and the CA may no longer publish it | valid, as of March 2025 with the saved evidence | valid | valid |
| 2033 | fails | fails: the 2025 TSA certificate expired in 2032 | fails, for the same reason | valid: the newest ArchiveTimeStamp vouches for every layer below | fails: the old TSA chain is checked at today's date |
| 2040 | fails | fails | fails | valid, as long as renewal continued | fails |

HankoXml checks B and T without LT data at today's date, so in 2030 its T fails outright rather than
being "at risk".

## What is not done yet

> **Past-signature validation.** HankoXml verifies every ArchiveTimeStamp, but does not yet *use*
> one to validate older material at an earlier date. TSA certificate chains, including the
> SignatureTimeStamp's, are checked at **today's** date, because OpenSSL's timestamp verification
> takes no verification time.

So once the SignatureTimeStamp's TSA certificate expires, HankoXml rejects the signature, even if it
carries valid ArchiveTimeStamps covering that period. Closing the gap means the validation algorithm
of ETSI EN 319 102-1: walk the ArchiveTimeStamps from newest to oldest, and validate each layer at
the time the one above proves, including the TSA chains, their revocation evidence, and whether the
algorithms were still acceptable then. It is tracked in
[#173](https://github.com/danimaribeiro/HankoXml/issues/173).

HankoXml's LTA is still worth producing today. The signatures it writes are standard, so EU DSS and
other validators can do the long-term validation, and HankoXml will too once that work lands.

Also not supported: distributed timestamps (`xades:Include`, `ReferenceInfo`), `XMLTimeStamp`,
indirect CRLs and CRL distribution-point scoping.

## Cheat sheet

| Level | HankoXml |
|---|---|
| B | `Xades::Signer.new(key:, certificate:)` |
| T | `timestamper:` on `Xades::Signer` or `Xades::Augmenter` |
| LT | `validation_data:` on `Xades::Signer` (with `timestamper:`) or `Xades::Augmenter` |
| LTA | `Xades::Augmenter.new(timestamper:, archive_timestamp: true)`, again to renew |

| Verifier option | Values | Meaning |
|---|---|---|
| `tsa_store:` / `tsa_certificates:` | Store, or certificates | The TSA roots you trust. Needed whenever a timestamp is present. |
| `timestamps:` | `:verify` · `:require` · `:ignore` | SignatureTimeStamps and ArchiveTimeStamps |
| `long_term:` | `:verify` · `:require` · `:ignore` | The LT checks; `:ignore` by default with `timestamps: :ignore` |
| `revocation_grace:` | Seconds, default `0` | How much earlier than the validation time CRL / OCSP evidence may be |

| Term | Meaning |
|---|---|
| c14n | Canonicalization: the one exact byte form of some XML that gets hashed |
| Trust anchor | A root certificate you chose to trust; every chain must end at one |
| TSA | Time-Stamp Authority: signs "these bytes existed at time X" (RFC 3161) |
| Imprint | The hash of the timestamped bytes, inside the token |
| CRL | Certificate Revocation List, signed by the issuing CA |
| OCSP | Online Certificate Status Protocol: a signed answer about one certificate |
| Validation time | The earliest verified SignatureTimeStamp; LT checks the certificate as of then |
| Renewal | Adding a new ArchiveTimeStamp before the previous TSA certificate expires |
| Past-signature validation | Validating old timestamps at the time a newer one proves; not done yet |
