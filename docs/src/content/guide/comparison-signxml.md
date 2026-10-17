---
title: Comparison with SignXML
description: Feature and security comparison of HankoXml and SignXML, plus a plan to close the remaining gaps (XAdES first).
order: 8
---

# Comparison with SignXML

This page compares HankoXml `0.1.0` with [SignXML](https://pypi.org/project/signxml/) `5.1.0`, the Python XML Signature and XAdES library. Both implement W3C XML-DSig. Neither implements XML Encryption.

| | HankoXml | SignXML |
|---|---|---|
| Language | Ruby 3.1+ | Python 3.9–3.13+, PyPy |
| Engine | Rust FFI → libxmlsec1 + OpenSSL, Nokogiri DOM | Pure Python: `lxml` + `cryptography` |
| Standard | XML-DSig (sign/verify) | XML-DSig 1.1 required + most recommended, plus XAdES |
| License | MIT | Apache-2.0 |
| Age / volume | First release 2026 (`0.1.0`) | Since 2014; high PyPI volume |
| Default verify posture | Fail closed: exactly one trust source required | Fail open: system CA store if you pass no trust args |

HankoXml is a general Ruby XML-DSig library with a strict policy and an XSW API. One spec fixture is NFe-shaped (legacy SHA-1 enveloped) so that XML subset is proven to sign and verify. SignXML’s README lists SAML 2.0, XAdES, EBICS, and WS-Security as *applications of XML-DSig*, not as first-class protocol stacks. See [What each library is actually for](#what-each-library-is-actually-for) and [Plan to close the gap](#plan-to-close-the-gap-with-signxml).

## Feature comparison

| Feature | HankoXml | SignXML |
|---|---|---|
| Enveloped / enveloping / detached | Yes | Yes |
| Signature placement | Fine-grained (`append_to_root`, `before`/`after` XPath, SAML-style placeholders, custom) | Placeholder `<ds:Signature/>` and `method=` |
| “See what is signed” | `Verification#signed?(node)`, `#at_signed`, `#covers_root?` | Return `VerifyResult.signed_xml` / `signed_data`; caller must use only that |
| Algorithm policy | Frozen `Policy` allowlist on sign **and** verify | `SignatureConfiguration` on verify |
| Trust model | Exactly one of `certificate` / `certificates` / `store` / `key` / `keys` | Optional `x509_cert`, `ca_pem_file`, `cert_subject_name`, `cert_resolver`, `hmac_key`; **none → system CAs** |
| Chain validation | `store:` via `OpenSSL::X509::Store` | cryptography `x509.verification`, plus hostname/CN check |
| KeyUsage `digitalSignature` | `store:` under `Policy.strict`: KeyUsage, when present, must allow `digitalSignature` or `nonRepudiation` | Enforced on end-entity by default |
| HMAC | Registered (`hmac-sha256`) but **no HMAC key API**; blocked by default `signature_methods` | First-class `hmac_key=` |
| RSA-PSS (MGF1), SHA3, ECDSA-SHA3 | Built in; `Policy.xades` (not `Policy.strict`) | Built in and allowed by default |
| InclusiveNamespaces PrefixList | `Transform.exc_c14n(inclusive_prefixes:)`; verified on `Transform` and `CanonicalizationMethod` | First-class (`inclusive_ns_prefixes`) |
| XPath / XSLT / XPointer transforms | Registered as insecure; **denied by `Policy.strict`** | Disabled by default (no network, XSLT, or XPath) |
| External references | Denied by default; native URI types limited to empty/same-document | Only if you pass `uri_resolver` |
| Schema check of `<ds:Signature>` | On by default (`Policy.strict.schema == :default`); `schema: nil` opts out | `validate_schema=True` by default |
| XAdES | XAdES-B signing and verification (`Xades::Signer` / `Xades::Verifier`) | Yes (`XAdESSigner` / `XAdESVerifier`) — see [XAdES](#xades) |
| XML Encryption | No | No |
| PKCS#12 / A1 bundles | `Key.from_pkcs12` | PEM / cryptography objects |
| Historical signature time | `verification_time:` on every trust source; `clock_skew` on pinned trust | `SignatureConfiguration(verification_time=...)` |
| Interop tests | Internal RSpec + self-roundtrip fixtures, plus merlin-twenty-three and phaos-three under `Policy.interop` | XMLDSig interoperability vectors — see [Interop tests](#interop-tests) |
| Native ABI risk | Bindgen vs system libxmlsec1; checked at require | None (pure Python) |

### Algorithms (defaults)

**HankoXml `Policy.strict`:** RSA/ECDSA SHA-256/384/512; SHA-256/384/512 digests; c14n / exclusive c14n / c14n11 (± comments); transforms: enveloped, base64, those c14n methods. SHA-1 only via `Policy.legacy_sha1`. HMAC, DSA, XPath, XSLT, RIPEMD off.

**SignXML `SignatureConfiguration` defaults:** RSA PKCS#1 v1.5, RSA-PSS/MGF1, ECDSA (SHA-2 and SHA-3), DSA-SHA256, **HMAC SHA-224/256/384/512**; SHA-2 and SHA-3 digests. SHA-1 families off unless you add them. HMAC methods sit in the default *allowlist*, but `require_x509=True` still blocks HMAC until you turn that off.

## Security comparison

### Where HankoXml is stricter

1. **Trust is explicit.** `Verifier.new` raises `ConfigurationError` unless you pass exactly one trust source. SignXML’s documented default is: any signature whose cert chains to the **system CA store** is accepted — “anyone can get an SSL certificate and generate a signature that you will trust.”
2. **KeyInfo cannot become the verification key.** Every trusted PEM is pinned as xmlsec `signKey`. A document-supplied `<KeyValue>` / `<DEREncodedKeyValue>` / `<RetrievalMethod>` cannot replace the caller’s key. SignXML compares KeyValue vs X509Data when both are present (`ignore_ambiguous_key_info=False`), but `require_x509=False` without `hmac_key` still accepts any valid key.
3. **XSW is a first-class API.** `signed?(node)` / `at_signed` maps xmlsec’s ID table back onto the caller’s Nokogiri node. SignXML’s correct pattern is “only consume `signed_xml`” plus `location=`; the default `location='.//'` searches the whole tree.
4. **Policy runs before crypto.** External `file://` / `http://` references are rejected in Ruby, and the native context only enables empty and same-document URIs. SignXML is also safe here if you leave `uri_resolver` unset.
5. **HMAC confusion is hard to hit.** Default `signature_methods` exclude HMAC, and there is no `hmac_key` path. SignXML `<4.0.4` had [CVE-2025-48994](https://github.com/XML-Security/signxml/security/advisories/GHSA-6vx8-pcwv-xhf4) (HMAC algorithm confusion) and [CVE-2025-48995](https://github.com/XML-Security/signxml/security/advisories/GHSA-gmhf-gg8w-jw42) (HMAC timing). Current 5.1.0 restricts algorithms when `hmac_key` is set.
6. **Parser posture.** `HankoXml.parse` is `strict.nonet`, never `NOENT` / `RECOVER` / `HUGE`. SignXML uses lxml with `resolve_entities=False`.

### Where SignXML is stronger

1. **XML-DSig 1.1 defaults.** SignXML allows RSA-PSS, SHA-3 and ECDSA-SHA3 by default. HankoXml registers them but keeps them behind `Policy.xades` (#60). HMAC and archival XAdES remain SignXML-only.
2. **Certificate path policy.** SignXML supports `ee_policy` / `ca_policy`. HankoXml’s `store:` checks KeyUsage (`require_signing_key_usage`) and exact subject matching (`certificate_subject:`), but has no equivalent of arbitrary end-entity/CA policy objects beyond what `OpenSSL::X509::Store` configures.
3. **Comment / c14n truncation.** SignXML documents comment-induced truncation and excises comments from `signed_xml` when they were not signed. HankoXml leaves “read the node you checked with `signed?`” to the caller.
4. **Maturity.** Years of interop vectors and two published HMAC CVEs that were fixed. HankoXml is new and has no foreign interop corpus yet (below).

Neither library is immune to XSW if the application reads unsigned nodes. HankoXml makes the safe read shorter (`at_signed`). SignXML makes the safe read the return value (`signed_xml`). Skipping either pattern reopens wrapping.

### Remaining HankoXml gaps

Every finding in `SECURITY_REVIEW.md` (S-01 to S-21) is fixed. What remains are design choices and missing features:

| Gap | Practical impact |
|---|---|
| `signature: :first` is still available | The default (`nil`) fails closed on more than one `<Signature>`, but an explicit `:first` ignores extra wrapping signatures. SignXML’s `location` is the analogous footgun. |
| `#signed?` under `Policy.permissive` | XPath/XSLT/Manifest are not modeled. Safe under `Policy.strict`, which denies those transforms. |
| No HMAC key API | `allow_hmac` only gates the `SignatureMethod`; HMAC interop is not possible. |
| `clock_skew` on `store:` | `OpenSSL::X509::StoreContext` has no skew, so `clock_skew` applies only to pinned trust. |

### Remaining SignXML gaps (5.1.0)

| Gap | Practical impact |
|---|---|
| Default `verify()` trusts system CAs | Public TLS cert → trusted XML signature unless you pass `x509_cert` / `ca_pem_file` / `cert_subject_name`. |
| Default `location='.//'` | Signature may be found anywhere; wrapping is an application bug if you don’t constrain location and you don’t consume only `signed_xml`. |
| `require_x509=False` without `hmac_key` | Any key that produces a valid signature is accepted; you must inspect `VerifyResult.signature_key`. |
| HMAC still in default `signature_methods` | Fine while `require_x509=True`; dangerous if someone copies a “disable x509” snippet. |
| `always_add_key_value=True` | Documented hazard (KeyValue vs X509Data). |
| No structural `signed?(node)` | Easy to verify, then XPath to an unsigned sibling. The library’s own docs warn about this. |
| `<4.0.4` | CVE-2025-48994 (HMAC confusion), CVE-2025-48995 (HMAC timing). Stay on 4.0.4+. |

---

## Interop tests

The table cell “Internal RSpec vs XMLDSig interoperability suite” is true, but it collapses two different questions: *does this library accept signatures produced by other implementations?* versus *does this library’s own sign/verify round-trip work?*

### What SignXML actually runs

SignXML vendors the classic W3C/IETF vectors and a few later libraries under `test/interop/`:

- **merlin-xmldsig-twenty-three** — the W3C “Y2” set (detached / enveloped / enveloping, transforms, Manifest, X.509 chains)
- **phaos-xmldsig-three** — the W3C “Y3” set
- **aleksey-xmldsig-01** — vectors from Aleksey Sanin (author of libxmlsec)
- **xml-crypto** (Node), **pyXMLSecurity**, **TR2012**, plus some WS-Security samples

The test runner *verifies foreign files*. It does not claim every vector must pass: XPath, XSLT, XPointer, several X509Data variants, and a “bad_interop_cases” list are skipped. SHA-1 vectors are accepted only because the suite passes a looser `SignatureConfiguration`. That is the honest shape of “we run the interop suite”: consume other people’s signatures, with an explicit skip list for transforms you refuse to implement.

### What HankoXml actually runs

HankoXml’s suite is RSpec around **self-produced** fixtures:

- six templates and their signed forms (`c14n`, `exc_c14n`, `sha512`, enveloping, detached, NF-e SHA-1)
- one RSA-2048 signer and one “other” cert
- security regressions (KeyInfo pinning, policy-before-crypto, ID resolution vs DTD/`xml:id`)

Since #62 it also verifies the merlin/phaos corpus (see below). `SIGNING_TEST_COVERAGE.md` already records that ECDSA, PKCS#12, chains, HMAC, and most algorithm matrix cells are untested.

### Why this is not “xmlsec already did it”

HankoXml delegates canonicalization and crypto to libxmlsec1, and xmlsec *was* one of the original W3C interop reporters. Algorithm-level merlin failures are therefore unlikely. The remaining risk is **HankoXml’s Ruby layer**:

- `Policy.strict` rejecting a signature another library would accept (SHA-1, HMAC, extra transforms)
- ID-attribute registration and `#signed?` mapping disagreeing with how the foreign document named its nodes
- KeyInfo pinning rejecting `X509IssuerSerial` / `X509SKI` shapes that xmlsec would have resolved
- `HankoXml.serialize` / write-back changing bytes that xmlsec digested
- Nokogiri parse options vs the xmlsec parse of the same bytes

Those bugs only show up when the input was **not** signed by HankoXml.

### What would be a useful HankoXml interop target

Not “pass every merlin file under `Policy.strict`.” That would force XPath/XSLT/XPointer back on. A useful bar:

1. Vendor merlin-twenty-three and phaos-three (and maybe aleksey-enveloped) under `spec/interop/`.
2. Verify them with an explicit `Policy.interop` (or `legacy_sha1` plus HMAC/DSA as needed), **not** `Policy.strict`.
3. Skip the same dangerous transforms SignXML skips (XPath, XSLT, XPointer), and treat those skips as documented non-goals.
4. Fail the spec on `PolicyError` vs `VerificationError` vs success — the interesting cases are “xmlsec would have accepted this, HankoXml’s policy or ID table did not.”
5. Keep `Policy.strict` as the production default. Interop coverage is a *verifier compatibility* test, not a reason to loosen defaults.

### Where HankoXml stands (#62)

`spec/interop/` vendors merlin-xmldsig-twenty-three and phaos-xmldsig-three from the pinned xmlsec1 1.3.12 tarball and pins every vector's outcome under `Policy.interop`, next to xmlsec's own expectation:

- **Valid (29 of 44):** merlin enveloped/enveloping DSA and RSA (keys from `<KeyValue>`), phaos DSA and RSA enveloped/enveloping (through a CA `store:` and against the pinned leaf certificate), the 11 phaos signatures over a `<Manifest>` (Manifest references are not resolved, #75, so the Manifest element is what is signed), and the 10 detached or external signatures, whose data is served through `referenced_documents:` (#74).
- **Refused by policy, by design:** HMAC (7; there is no HMAC key API), RetrievalMethod (3), XPath transform (1), more than 8 references (1).
- **Refused, as xmlsec also refuses them:** the bad digest and bad signature vectors.
- **Schema:** merlin `signature.xml` puts a no-namespace element where the XML-DSig schema's `##other` wildcard does not allow one.

No vector showed HankoXml's Ruby layer rejecting a signature that xmlsec accepts, outside those explicit policy choices.

---

## XAdES

SignXML implements a **baseline XAdES** wrapper (`XAdESSigner` / `XAdESVerifier`): extra `ds:Object` / `QualifyingProperties` references, `SignaturePolicyIdentifier`, `ClaimedRoles`, `DataObjectFormat`. It is not a full archival profile (XAdES-A / T / C / XL with RFC 3161 timestamps, OCSP, and certificate values).

HankoXml signs XAdES-B with `HankoXml::Xades::Signer` (#57): `QualifyingProperties` with `SigningTime`, `SigningCertificateV2`, `SignaturePolicyIdentifier`, `SignerRoleV2` and `DataObjectFormat`, and a second reference over `SignedProperties`, conforming to the ETSI XAdES 1.3.2 schema. `HankoXml::Xades::Verifier` (#58) checks them on verification, reading only the SignedProperties xmlsec digested and binding `SigningCertificate(V2)` to the certificate that verified; it verifies SignXML's real-world XAdES samples, reads the older XAdES 1.2.2 and 1.1.1 namespaces too (#86), and refuses the EU DSS signature-wrapping attacks. SignXML's own `XAdESSigner` output verifies under `Policy.strict` (#59). RSA-PSS, SHA-3 and ECDSA-SHA3 are first-class `Algorithms` entries behind `Policy.xades` (#60). XAdES-T signing (`timestamper:`, a caller-supplied TSA exchange, #162) has landed; verifying the timestamp (#163) and XAdES-LT/LTA (#82) are still open.

### XAdES is an overlay, not a different crypto

[ETSI EN 319 132-1](https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.01.00_30/en_31913201v010100v.pdf) builds on XML-DSig. The extra work is:

- a `QualifyingProperties` object (signing time, signing certificate digest, optional policy, roles, data-object format)
- a **second** `<Reference>` whose URI points at `SignedProperties` (so those properties are themselves signed)
- later levels add *unsigned* properties: signature timestamps, revocation values, archive timestamps

The digest/signature algorithms stay XML-DSig. A library that can already emit two references and an `<Object>` is most of the way to XAdES-B. Timestamps and revocation are a different product.

### Does the NFe-shaped fixture need it? No.

Brazilian NF-e / NFC-e / CT-e / MDF-e use a **tiny XML-DSig subset**, not XAdES:

- enveloped signature
- RSA-SHA1 + SHA-1 digest (legacy; still mandated by the schema)
- C14N 1.0 (not exclusive)
- `X509Data` with the **end-entity only** (`EndCertOnly`)
- signature placed after the infNFe / equivalent node (`Id` on that node)

Nothing in that XML subset asks for `SignedProperties`, a signature policy OID, or a timestamp token.

### Where XAdES *does* matter

| Context | Uses XAdES? |
|---|---|
| EU eIDAS advanced / qualified electronic signatures | Yes — this is the point of XAdES |
| European e-invoicing (some EN 16931 / national profiles) | Often yes |
| ICP-Brasil DOC-ICP-15 (AD-RB … AD-RA) | Yes, for some Brazilian *electronic documents* (contracts), not the NF-e XML-DSig subset |
| SAML 2.0 | No — XML-DSig over `Assertion` |
| WS-Security / SOAP | No — XML-DSig over the body / timestamp |
| EBICS | XML-DSig; XAdES only if a specific order type says so |

SignXML listing XAdES as a target is real for EU legal signatures. **XAdES is the largest feature gap versus SignXML.** SAML, WS-Security, and the NFe-shaped fixture do not need it.

---

## What each library is actually for

SignXML’s README sentence — “used to provide payload security in SAML 2.0, XAdES, EBICS, and WS-Security” — describes **where XML-DSig shows up in the world**, not four protocol implementations. SignXML does not parse SAML metadata, speak EBICS order types, or wrap SOAP `wsse:Security` headers. It signs and verifies the XML those protocols embed.

HankoXml is the same kind of library: general XML-DSig. The NFe-shaped spec fixture exists so a legacy enveloped SHA-1 / C14N 1.0 / sibling-`<Signature>` document round-trips. That is a test-case requirement, not the product.

| XML shape | What XML-DSig must do | HankoXml today | SignXML today |
|---|---|---|---|
| **NFe-shaped fixture** | Enveloped, RSA-SHA1, SHA-1, C14N, `X509Data` end-entity only, `Id` on a child, PKCS#12 | Supported (`Policy.legacy_sha1`, `Key.from_pkcs12`, `Placement.after`) | Possible with a SHA-1 `SignatureConfiguration` |
| **SAML 2.0** | Enveloped **fragment** (Assertion, not Response), exclusive c14n, often **InclusiveNamespaces PrefixList**, Assertion `ID` | `Policy.fragment` + `#at_signed` + `Transform.exc_c14n(inclusive_prefixes:)` | Documented; InclusiveNamespaces first-class; `location=` for the Assertion |
| **WS-Security** | Sign SOAP Body / Timestamp; `wsu:Id`; sometimes STR-Transform / `BinarySecurityToken` | Custom `id_attributes` might cover `wsu:Id`; STR-Transform no | Some interop fixtures; not a WSS stack |
| **EBICS** | XML-DSig over order data + X.509 | Generic XML-DSig | Generic XML-DSig |
| **XAdES / eIDAS / ICP-Brasil AD-\*** | Extra signed properties, later timestamps/revocation | XAdES-B (#57–#59); archival no | Baseline XAdES yes; archival incomplete |

### Practical takeaway

- **Ruby XML-DSig with pinned trust and `#signed?(node)`:** HankoXml. Use `signature: :only` (or `verify_all`) and `result.at_signed(...)` rather than trusting `valid?` alone.
- **Python, HMAC, or archival XAdES:** SignXML. Always pass an explicit trust anchor, set `expect_config=SignatureConfiguration(location=...)`, and only consume `verify().signed_xml`.
- **Do not treat either as a drop-in for the other.** HankoXml has XAdES-B and RSA-PSS/SHA-3 behind `Policy.xades`, and no HMAC key. SignXML has no Ruby/Nokogiri integration and a much looser default trust story. SignXML's `XAdESVerifier` defaults to `expect_references=3` because `XAdESSigner` also signs `<KeyInfo>`; HankoXml signs two references (payload + SignedProperties), so the reverse check passes `expect_references=2`.

---

## Plan to close the gap with SignXML

The main **feature** gap was XAdES-B. SignXML can emit and verify baseline qualifying properties; HankoXml now does too (#57–#59). RSA-PSS/SHA-3 sit behind `Policy.xades` (#60). Archival XAdES-T/LT/LTA is out of scope.

Stay at **XAdES-B** (BES / baseline B) to match what SignXML actually ships. Do not start with XAdES-T/C/XL/A (RFC 3161 timestamps, OCSP, archive timestamps) — that is a PKI-lifetime product, not SignXML parity.

### Phase 1 — XAdES-B sign and verify (parity with `XAdESSigner` / `XAdESVerifier`)

1. Add `HankoXml::XAdES` (or `HankoXml::Xades::Signer` / `Verifier`) as a thin layer over `Signer` / `Verifier`, not a second crypto stack. libxmlsec1 already does the digests; Ruby builds the `xades:QualifyingProperties` `ds:Object` and the extra `ds:Reference` whose URI is `#…-signedprops`.
2. Signed properties to implement, matching SignXML: `SigningTime`, `SigningCertificate` / `SigningCertificateV2` (cert digest), optional `SignaturePolicyIdentifier`, `SignerRole/ClaimedRoles`, `DataObjectFormat`.
3. Policy: `max_references` already allows 8; XAdES-B needs at least two (payload + SignedProperties). Default `Policy.strict` must accept that extra same-document reference without `Policy.permissive`. `require_signed_root` stays a separate concern (payload may still be the root).
4. Verification: check the SignedProperties digest, parse the signed properties into a result object (SignXML’s `XAdESVerifyResult.signed_properties`), and fail if the signing-certificate digest does not match the cert used to verify.
5. Tests: round-trip HankoXml → HankoXml; **verify a document produced by SignXML’s `XAdESSigner`** (#59); sign in HankoXml and verify in SignXML (`expect_references=2`) when `python3` can import `signxml`. No NF-e fixtures in this suite.

### Phase 2 — Algorithms XAdES documents actually use (done, #60)

SignXML’s default allowlist includes RSA-PSS (MGF1) and SHA-3. EU XAdES profiles often want RSA-PSS SHA-256, not PKCS#1 v1.5.

1. `:rsa_pss_sha256` (and SHA-384/512), SHA-3 digests, and ECDSA-SHA3 are first-class `Algorithms` entries.
2. They stay **out** of `Policy.strict` until opted in (`Policy.xades` or `Policy.strict.with(signature_methods: …)`), same pattern as `legacy_sha1`.
3. libxmlsec1 1.3 implements these URIs (vendored xmlsec 1.3.12 / platform gems). xmlsec 1.2 does not; signing then fails closed. Specs that exercise crypto skip unless `NativeVersion.build_versions[:xmlsec] >= 1.3`.

### Phase 3 — InclusiveNamespaces (done)

`Transform.exc_c14n(inclusive_prefixes:)` emits `ec:InclusiveNamespaces PrefixList` (#61), and a SAML-shaped fixture with it on both `CanonicalizationMethod` and the Reference transform verifies under `Policy.fragment`.

### Phase 4 — Foreign-signature interop (not a protocol)

Vendor merlin-twenty-three / phaos-three under `spec/interop/`. Verify with `Policy.interop` (or `legacy_sha1` plus HMAC/DSA as needed). Skip XPath / XSLT / XPointer the way SignXML does. Keep `Policy.strict` as the production default.

### Out of scope for SignXML parity

| Item | Why not in this plan |
|---|---|
| XAdES-T / C / XL / A | SignXML does not really ship archival XAdES either |
| HMAC `key:` path | SignXML has it; HankoXml’s default deny is a security choice, not a missing XAdES feature |
| SOAP / EBICS / SAML stacks | Neither library is a protocol implementation |
| `lib/hanko_xml/profiles/nfe.rb` | Do not add an NF-e product profile. The existing XML fixture is enough |

### Suggested order of PRs

1. XAdES-B types + template (`QualifyingProperties` + second Reference) + sign/verify round-trip — done (#57, #58)
2. Cross-check against SignXML-produced XAdES-B XML — done (#59)
3. RSA-PSS (and SHA-3 if xmlsec supports it) behind `Policy.xades` — done (#60)
4. merlin/phaos interop corpus under `Policy.interop` — done (#62)
