# XML Signing Test Coverage: Gaps and Specs to Add

Date: 2026-09-12 (originally against commit `3af4155`; `bundle exec rspec` =
179 examples. Re-checked after PR #30: trust-source specs T1–T4 now live in
`spec/hanko_xml/verifier_spec.rb`. S-01 group K lives in
`spec/hanko_xml/key_value_trust_spec.rb`.)

**Status after #52 (2026-09-17):** groups A–H are now specs:
`spec/hanko_xml/signer_sign_spec.rb` (A, D, G, H, N3),
`signer_algorithms_spec.rb` (B), `signer_references_spec.rb` (C),
`signer_key_info_spec.rb` (E, F) and `key_spec.rb` (F2/F3). Writing them
fixed four bugs: the pass-phrase prompt on an encrypted key without
`password:`, the empty `<KeyValue/>` (E6), the no-op X509Data clauses (E8)
and the `:detached` `TypeError` (G6). The rest were `pending` specs with their
own issues, all since fixed: E7 `<KeyName/>` (#67), C6 `[href, name]` on the
Signer (#68), F9 Ed25519 (#69), B6 EC key with the default method (#70), C14
an apostrophe in an Id (#71), and E4 a stale adopted certificate (#72). The
tables below
keep their original "Expected today" column as a record of what the review
predicted.

This document inventories what the suite currently exercises on the *signing*
side of HankoXml, lists the scenarios it does not, and specifies the specs that
should be written. It covers functional gaps as well as security regressions;
security items cross-reference `SECURITY_REVIEW.md` (S-xx). Dispositions in
that file are the source of truth after PR #30.

Legend for the **Expected today** column:

- `pass` -- the spec should pass against the current code (pure coverage gap).
- `FAIL` -- the spec documents a bug/finding and is expected to fail until the
  code is fixed. Write it anyway (pending or `xit` with the S-id in the
  description) so the fix has a target.
- `?` -- outcome unknown; the spec answers a question the review could not.

---

## 1. What is covered today

Signing is exercised in exactly three places:

| Spec | What it proves |
|------|----------------|
| `spec/hanko_xml/native_spec.rb` `.sign` | `Native.sign` on the six `template_*.xml` fixtures produces output that `Native.verify` accepts with `signer.crt`; `ParseError` on garbage XML; `KeyLoadError` on a bad key. |
| `spec/hanko_xml/nokogiri_ext_spec.rb` | `doc.sign` returns a `SignedDocument` and `doc.sign!` mutates in place -- both then `signature_valid?`. Detached templates pass `references: ["#payload-1"]` (S-05). |
| `spec/hanko_xml/signer_spec.rb` | Configuration only: defaults, coercion, block form, freezing, `#to_h`, `#inspect`, two `ConfigurationError`s. Never calls `#sign`. |
| `spec/hanko_xml/signer_policy_spec.rb` | S-05: Policy and reference-URI checks run before `Native.sign` on adopted and built templates (R3/R4/R5/H7). |

Adjacent but not signing: `template_spec.rb` (unsigned tree shape),
`placement_spec.rb` (insertion modes on a bare node), `reference_spec.rb`,
`transform_spec.rb`, `key_spec.rb`, `xml_spec.rb` (byte-faithful serialize).

Consequences: `Signer#sign!`'s multi-signature loop, `force:`, `signature:`,
`template: :build/:require`, `write_back_signature` for anything other than
`DigestValue`/`SignatureValue`/one `X509Certificate`, every algorithm choice
made through the Ruby API, every `Placement` mode *through the Signer*, every
key type other than the 2048-bit RSA fixture, and every error path except two
are untested.

Fixtures: one RSA-2048 signer, one RSA-2048 "other", six templates and their
signed forms (`c14n`, `exc_c14n`, `sha512`, `enveloping`, `detached`, `nfe`
SHA-1). No ECDSA, no encrypted key, no PKCS#12, no chain (intermediate + root),
no expired cert, no weak key, no non-UTF-8 document, no `xml:id`, no DTD.

There is no coverage tool in the Gemfile. Recommendation: add `simplecov` as a
development dependency, enable it in `spec_helper.rb` behind `ENV["COVERAGE"]`,
and set a `minimum_coverage` for `lib/hanko_xml/signer.rb`,
`verifier.rb`, `verification.rb`, `policy.rb` once the specs below land.

---

## 2. Specs to add: functional signing scenarios

### A. `Signer#sign` / `#sign!` end-to-end (new `spec/hanko_xml/signer_sign_spec.rb`)

| # | Scenario | Assert | Expected today |
|---|----------|--------|----------------|
| A1 | Sign a String, verify with `signer.crt` | `valid? == true`; output contains one `<ds:Signature>` appended to root | pass |
| A2 | Sign a `Nokogiri::XML::Document` via `#sign` | input untouched (no `<ds:Signature>` in original), result is `SignedDocument`, `result.document != input` | pass |
| A3 | `#sign!` on a Document | same object returned, mutated; `SignatureValue` non-empty; verifies | pass |
| A4 | Sign a `Pathname` / `File` / IO | all coerce and verify | pass |
| A5 | Round trip through `SignedDocument#to_xml` then `Nokogiri::XML(...)` then verify | still valid (write-back + AS_XML serialization agree with what xmlsec signed) | pass |
| A6 | Round trip through **default** `doc.to_xml` (FORMAT) | signature **invalid** -- documents why `SignedDocument` exists | pass |
| A7 | `sign` twice with the same frozen `Signer` on different docs | both verify; Signer is reusable/thread-safe (also run under `Thread.new` x8) | pass |
| A8 | Idempotence: `#sign!` on an already-signed doc | no second signature, bytes unchanged (`force: false` skips) | pass |
| A9 | `force: true` re-signs an already-signed template | `SignatureValue` changes; still verifies | pass |
| A10 | Sign a document that already has a *different* valid signature | new signature added by `:adopt`? or only unsigned templates signed? -- pin down the semantics | ? |
| A11 | Signing when Nokogiri is not loaded | `NokogiriRequired` from `sign!`; `capabilities[:sign] == :template_only` | pass |
| A12 | Output encoding: document declared `ISO-8859-1` with non-ASCII content | signs and verifies; write-back preserves declaration | ? |
| A13 | Document with default namespace on root (`<Envelope xmlns="urn:…">`) | `<Signature>` gets the ds namespace, not the parent default | pass (fixtures do this) |
| A14 | Document with `<?xml-stylesheet?>` PI, comments, CDATA before/after root | verifies; comments outside root untouched | pass |
| A15 | Document with an internal DTD subset | signs; verifies; DOCTYPE preserved | pass (see H-group for the attack side) |
| A16 | Very deep nesting (250 levels) and a 15 MiB payload | no stack overflow in `collect_signature_nodes`; completes | ? |

### B. Algorithms through the Ruby API

For each cell: sign with the Ruby `Signer`, inspect `<SignedInfo>`, then verify
with `Native.verify` **and** `Verifier#verify` (strict or `legacy_sha1`).

| # | `signature_method` | `digest_method` | `canonicalization_method` | Expected today |
|---|--------------------|-----------------|---------------------------|----------------|
| B1 | `:rsa_sha256` | `:sha256` | `:exc_c14n` (defaults) | pass |
| B2 | `:rsa_sha1` | `:sha1` | `:c14n` (NF-e) with `Policy.legacy_sha1` | pass |
| B3 | `:rsa_sha384` | `:sha384` | `:c14n11` | pass |
| B4 | `:rsa_sha512` | `:sha512` | `:c14n_with_comments` | pass |
| B5 | `:rsa_sha224` | `:sha224` | `:exc_c14n_with_comments` | pass (strict rejects sha224 -- assert `PolicyError`) |
| B6 | `:ecdsa_sha256` with a P-256 key + cert | `:sha256` | `:exc_c14n` | ? (no EC fixture; add `ec_signer.key/crt`) |
| B7 | `:ecdsa_sha384` P-384 | `:sha384` | `:c14n` | ? |
| B8 | `:hmac_sha256` | -- | -- | should raise (no HMAC key path exists); pin the error class |
| B9 | `:dsa_sha1` | -- | -- | ? (xmlsec may reject; pin the error) |
| B10 | Unknown Symbol / arbitrary URI string as `signature_method` | `Template` emits the URI verbatim; `Native.sign` raises `SigningError` | ? |
| B11 | `Algorithms.register` a custom transform then sign with it | `SigningError` from xmlsec (unknown transform) rather than a crash | ? |
| B12 | `:rsa_pss_sha256` under `Policy.xades` | pass on xmlsec ≥ 1.3; `SigningError` on 1.2; `PolicyError` under strict | pass (gated) |
| B13 | `:sha3_256` digest under `Policy.xades` | same as B12 | pass (gated) |
| B14 | `:ecdsa_sha3_256` with a P-256 key under `Policy.xades` | same as B12 | pass (gated) |

### C. References and transforms

| # | Scenario | Assert | Expected today |
|---|----------|--------|----------------|
| C1 | Default: single `URI=""` with `enveloped-signature` | as fixture | pass |
| C2 | `references: ["#id1"]` fragment, element **not** root | verifies; `Verification#references[0].node` is that element; `covers_root? == false` | pass |
| C3 | `references: ["#rootId"]` where the **root** carries the Id | verifies? (S-20: `xmlSecAddIDs` may skip the root's own attributes) | ? |
| C4 | Two references (`#a`, `#b`) | two `<Reference>`s, both digests filled, `signed?(a) && signed?(b)`, `!signed?(c)` | pass |
| C5 | Fragment whose Id attribute is `ID` and `id` (each of the default `id_attributes`) | verifies | pass |
| C6 | Custom `id_attributes: ["wsu:Id"]`-style namespaced `[ns, name]` pairs on the Signer | `Native.sign` receives local names only; verify with the same setting | ? (Signer passes `@id_attributes` straight to native; an Array entry raises `NativeError` "array element is not a String") |
| C7 | Fragment target does not exist (`"#nope"`) | `SigningError`/`ReferenceError` with `reference_uri`, not a silent empty digest | ? |
| C8 | Duplicate Id for the target | error (or documented first-wins) -- pin it | ? |
| C9 | Transforms `[:enveloped_signature, :exc_c14n]` vs `[:exc_c14n, :enveloped_signature]` order | both verify; c14n output differs | pass |
| C10 | `:xpath` transform with an XPath body | `<XPath>` text emitted; xmlsec signs; strict verify → `PolicyError` (xpath not allowed) | pass |
| C11 | `:xpath_filter2` / `:xslt` | sign result or error pinned; verify under strict → `PolicyError` | ? (xslt available only on libxslt builds -- S-10) |
| C12 | `:base64` transform over an `<Object>` in an enveloping signature | verifies | ? |
| C13 | Reference with `id:`/`type:` set | attributes present in output; survive write-back | pass |
| C14 | Reference `URI` with characters needing escaping (`#a b`, `#a&b`, `#a'b`) | template escapes; native resolves or errors cleanly; no XPath injection (`verification_spec` covers verify side only) | pass |
| C15 | External `URI="file://…"`/`http://…` in a **Signer-configured** reference | `Signer` refuses under strict policy | **pass** (S-05) |
| C16 | Enveloping signature built through the Ruby API (`<Object Id>` + `URI="#object"`) | currently impossible without a hand template? -- pin either support or the error | ? |

### D. Template modes and multiple signatures

| # | Scenario | Assert | Expected today |
|---|----------|--------|----------------|
| D1 | `template: :build` on an unsigned doc | builds and signs | pass |
| D2 | `template: :build` on a doc with an existing `<Signature>` | `ConfigurationError` | pass |
| D3 | `template: :require` on a doc without `<Signature>` | `ConfigurationError` | pass |
| D4 | `template: :require` on a doc with an empty template | signs it | pass |
| D5 | `template: :adopt` (default) with two unsigned templates | both signed, innermost first; both verify with `verify_all` | pass |
| D6 | Nested signatures (outer envelopes inner `<Signature>`) | inner signed first, then outer covers it; both verify | pass (depth sort exists for this; untested) |
| D7 | `signature: 0` selects which template to sign | document-order index, agreeing with Verifier's `signature: n` (S-11) | pass |
| D8 | `signature: 99` out of range | `ConfigurationError` (S-11) | pass |
| D9 | Adopted template whose algorithms differ from the Signer's configuration | Signer's `signature_method: :rsa_sha256` but template says rsa-sha1 → `PolicyError` under strict | **pass** (S-05 R4) |
| D10 | Adopted template with `KeyInfo` shapes: none / `X509Data` empty / `X509Data` with stale cert / `KeyValue` / `KeyName` | see E-group | mixed |

### E. `write_back_signature` fidelity

The Ruby DOM is patched from the natively signed bytes. Every leaf xmlsec can
fill must be copied back or the caller's document diverges from what was
signed.

| # | Leaf | Expected today |
|---|------|----------------|
| E1 | `DigestValue` for every `<Reference>` (1, 2, N) | pass |
| E2 | `SignatureValue` | pass |
| E3 | `X509Certificate` appended to an empty `<X509Data/>` | pass |
| E4 | Existing `X509Certificate` text replaced | pass |
| E5 | `certificates:` chain (leaf + intermediate) → N `X509Certificate` children | ? (order and count) |
| E6 | `key_info: [:key_value]` → `<RSAKeyValue>` written back | **FAIL** -- write-back copies only `X509Certificate`; Ruby output has an empty `<KeyValue/>` (confirmed) while `Native.sign` output has the key |
| E7 | `key_info: [:key_name]` → `<KeyName>` text (xmlsec fills from key name if set; likely stays empty) | ? -- pin the semantics |
| E8 | `:x509_subject_name`, `:x509_issuer_serial`, `:x509_ski` clauses | `Template` only emits `<X509Data/>` for these; xmlsec fills the sub-elements only if the template contains them → clauses are silently no-ops | FAIL (functional) |
| E9 | Whitespace/pretty-printing inside `<Signature>` after write-back | serialization of the written-back DOM still verifies | pass (A5) |
| E10 | Template signed with `Signature/@Id` (`signature_id:`) | attribute preserved | pass |

### F. Keys, certificates, and inputs

| # | Scenario | Assert | Expected today |
|---|----------|--------|----------------|
| F1 | `key:` as `OpenSSL::PKey::RSA`, PEM String, `Pathname`, `HankoXml::Key` | all sign identically | pass |
| F2 | Encrypted PEM key with `Key.from_pem(pem, password:)` | signs | pass |
| F3 | Encrypted PEM key passed as a raw String to `Signer.new` (no password) | `KeyLoadError`, message never contains the PEM | pass |
| F4 | `Key.from_pkcs12` bundle → `Signer.new(**bundle.to_h)` | signs; certificate chain emitted | ? |
| F5 | `key:` is a **public** key | `KeyLoadError`/`SigningError` at sign time (not a silent bad signature); ideally `ConfigurationError` at construction | pass (S-15, `ConfigurationError` at construction) |
| F6 | `key:` and `certificate:` do not match | `ConfigurationError` at construction | pass (S-14, `spec/hanko_xml/signer_spec.rb`) |
| F7 | `certificate:` given as a private key PEM | `ConfigurationError` | pass (S-15) |
| F8 | RSA-1024 key | strict `Signer` refuses (`min_rsa_key_bits`) | pass (S-06, `Policy#enforce_key_size!`) |
| F9 | EC P-256 / P-384 / Ed25519 keys | ECDSA signs; Ed25519 raises a clear error (no XML-DSig URI registered) | ? |
| F10 | `Key#dispose!` then `sign` | `KeyLoadError "disposed"` | pass |
| F11 | `certificates:` with an expired intermediate | sign succeeds (signing does not validate the chain) -- document it | ? |
| F12 | `Signer#inspect`, `#to_h[:key].inspect`, exception messages from a bad key | never contain PEM bytes (`spec` exists for `#inspect` only) | pass |

### G. Placement through the Signer

`placement_spec.rb` tests `Placement#insert` on a bare node. Add one
`Signer.new(placement: …).sign` per mode and assert *the signature verifies*
(placement affects the enveloped-signature transform and c14n):

| # | Placement | Expected today |
|---|-----------|----------------|
| G1 | `:append_to_root` (default) | pass |
| G2 | `:prepend_to_root` | pass |
| G3 | `Placement.after("//n:infNFe", namespaces:)` (NF-e shape: signature is a sibling, reference is `#Id`) | pass |
| G4 | `Placement.before(...)` | pass |
| G5 | `Placement.append_to`/`prepend_to` a nested element | pass |
| G6 | `Placement.detached` with `references: ["#x"]` -- where does the `<Signature>` go? `Signer#sign!` calls `insert`, which is a no-op for `:detached`, so the built template is never in the doc and `find_or_build_signatures` returns a node xmlsec cannot find | ? / likely FAIL |
| G7 | `Placement.custom { |doc, sig| … }` | pass |
| G8 | XPath matching 0 / 2 nodes | `PlacementError` before any crypto | pass |

### H. Error paths

| # | Scenario | Expected class | Expected today |
|---|----------|----------------|----------------|
| H1 | Malformed XML String | `ParseError` | pass |
| H2 | Empty document / no root | `ParseError` | ? |
| H3 | xmlsec failure mid-sign (e.g. unknown algorithm URI) | `SigningError` with non-empty `xmlsec_errors` | FAIL (S-13: `xmlsec_errors` always `[]` because the buffer is drained twice) |
| H4 | `NativeError` from a non-String `id_attributes` entry | `NativeError` message "array element is not a String" | pass |
| H5 | Unsupported `doc_or_xml` type | `ArgumentError` | pass |
| H6 | Concurrency: 8 threads signing simultaneously with distinct Signers | no crash, all verify (GVL + `Once` init) | pass |
| H7 | `HankoXml.sign` with `Policy` violation in configured references | `PolicyError` before native call | **pass** (S-05) |

---

## 3. Specs to add: security regressions (from `SECURITY_REVIEW.md`)

Each of these should be written now and marked pending until fixed. Group by
finding so a fix PR can flip its group to passing.

### S-01 KeyValue trust (Critical, **fixed**)

K1–K8 pass in `spec/hanko_xml/key_value_trust_spec.rb`. `key:` / `store:`
already rejected this forged document after #30; cert PEMs and empty trust
now do too.

| # | Spec | Level |
|---|------|-------|
| K1 | Template with `<KeyInfo><KeyValue/></KeyInfo>` signed by `other.key` → `Native.verify(xml, [signer.crt], [], ids, 0)[:status] != :succeeded` | Native |
| K2 | Same with `trusted = []` → not `:succeeded` | Native |
| K3 | `Verifier.new(certificate: signer_crt).verify(forged).valid? == false` and `errors` contains `UntrustedCertificate` (or a new `UntrustedKey`) | Verifier |
| K4 | Forged doc with **both** attacker `X509Certificate` and attacker `KeyValue` → invalid | Verifier |
| K5 | Forged doc with `<DEREncodedKeyValue>` (dsig11) → invalid | Native |
| K6 | Forged doc with `<RetrievalMethod URI="#k">` pointing at an in-document `<KeyValue>` → invalid | Native |
| K7 | Legit doc whose `<KeyInfo>` is **absent** but `trusted = [signer.crt]` → valid (pinning must still work without KeyInfo) | Native |
| K8 | Legit doc with `X509Certificate` = signer, trusted = `[other.crt]` → invalid (already covered; keep) | Native |

### S-02 / S-08 trust sources (**fixed** in #30)

T1–T4 (and T5 for public-key values) now pass in
`spec/hanko_xml/verifier_spec.rb`. T6 and T7 (exactly one trust source) also
pass there. Cert-valued `keys:` is covered under S-01 group K.

| # | Spec | After #30 |
|---|------|-----------|
| T1 | `store:` containing `signer.crt` accepts the genuine fixture (`valid? == true`) | pass |
| T2 | `store:` containing only `other.crt` rejects it | pass |
| T3 | `key:` = signer public key accepts; `key:` = other public key rejects | pass |
| T4 | `keys: { "name" => signer_public_key }` with `<KeyName>name</KeyName>` accepts; with `other` key rejects; with unknown name → `UntrustedCertificate` | pass |
| T5 | `keys:` where the document's `KeyName` names a trusted entry but the **signature** was made with a different key → invalid (name is unauthenticated) | pass (public-key values) |
| T6 | Passing two trust sources → `ConfigurationError` | pass (`verifier_spec` "trust source selection") |
| T7 | Passing **no** trust source → `ConfigurationError` | pass (`verifier_spec` "trust source selection") |

### S-03 ID resolution / XSW

| # | Spec |
|---|------|
| X1 | DTD `<!ATTLIST Invoice Id ID #IMPLIED>` + earlier `<Order Id="inv-1">`: `valid?` must be false **or** `signed?(order) == false` and `references[0].node` must be the node xmlsec digested | **pass** (`id_resolution_spec`) |
| X2 | Prefix variant (`<!ATTLIST n:Invoice …>`, attacker `<x:Invoice xmlns:x=same-ns>`): `at_signed("//n:Invoice")` never returns the attacker node | still open |
| X3 | `xml:id="inv-1"` on an attacker element vs `Id="inv-1"` on the signed one, both orders → consistent resolution or rejection | **pass** (`id_resolution_spec`; xml:id on signed element) |
| X4 | Namespaced attacker attribute `<Evil p:Id="inv-1">` before the legit element → consistent or rejected |
| X5 | Duplicate plain `Id` (attacker first / attacker last) → with `reject_duplicate_ids: true` the result is invalid with a `PolicyError`; with the field false, `signed?` agrees with xmlsec |
| X6 | Classic XSW: move the signed element under a wrapper and put a forged copy at the original path → `valid? == true` but `signed?(forged) == false`, `at_signed(original_xpath)` raises `NotSignedError` (this is the documented defence; it has **no spec today**) |
| X7 | Enveloped `URI=""` signature: `signed?(any node) == true` except nodes inside `<Signature>`; `covers_root? == true` |
| X8 | Fragment signature: `covers_root? == false`, `partial? == true`, and under `Policy.strict` (`require_signed_root`) `valid? == false` |
| X9 | `resolver:` + `id_attributes` disagreement (exists) -- extend with the DTD case |
| X10 | Document parsed **with** an internal subset that declares an external entity (`<!ENTITY x SYSTEM "file:///etc/hostname">`) → `ParseError` or entity not expanded; no file read |

### S-04 / S-05 / S-10 external references, transforms, ordering

S-04 verify-side ordering and URI fetch are **fixed** in
`spec/hanko_xml/policy_ordering_spec.rb`. S-05 Signer `:adopt` policy and
reference-URI matching are **fixed** in `spec/hanko_xml/signer_policy_spec.rb`.
Native transform allowlisting is S-10 (fixed, PR #64); R6 only asserts the Ruby
policy gate, and the S-10 native spec cannot tell the allow-list apart from a
digest mismatch.

| # | Spec | After S-05 |
|---|------|------------|
| R1 | Verifier: `<Reference URI="file:///tmp/probe">` under strict → `PolicyError` **and** the file was not opened | **pass** |
| R2 | Verifier: same under `Policy.permissive` → Ruby allows Native.verify; native still does not fetch; `valid? == false` | **pass** (no libxml2 fetch; `referenced_documents:` is the supported path) |
| R3 | Signer `:adopt` with a template containing a `file://` reference → `PolicyError` before `Native.sign`; file not read | **pass** |
| R4 | Signer `:adopt` with a template using rsa-sha1 while Signer is strict → `PolicyError` | **pass** |
| R5 | Signer `:adopt` with a template referencing `#attacker-node` not in `Signer#references` → `ConfigurationError`; opt-in via `references: ["#id"]` | **pass** |
| R6 | Verifier: XSLT transform present under strict → `PolicyError` **before** `Native.verify` | **pass** |
| R7 | Verifier: `Native.verify` is not invoked when `inspect_sig` output already violates policy | **pass** (same specs as R1/R6/R8) |
| R8 | `max_transforms_per_reference` exceeded → rejected before native | **pass** |

### S-06 policy fields (fixed; see `spec/hanko_xml/policy_enforcement_spec.rb` and `spec/hanko_xml/policy_spec.rb`)

| Field | Spec | Status |
|-------|------|--------|
| `require_signed_root` | fragment-only signature under strict → `PolicyError`; `Policy.fragment` / whole-document accepts | pass (Verifier only -- Signer deliberately does not check it, R5) |
| `reject_duplicate_ids` | duplicate ID attribute value anywhere in the document → `PolicyError` at sign and verify time | pass |
| `max_document_size` | serialized document over the configured limit → `PolicyError` before `Native.*` | pass |
| `min_rsa_key_bits` | RSA-1024 signing/trust key → `PolicyError`; RSA-2048 passes | pass (`Policy#enforce_key_size!`, separate from `#violations`/`#enforce!` -- needs real key material) |
| `min_ec_key_bits` | same mechanism as `min_rsa_key_bits`, untested with an actual weak EC key (OpenSSL build-dependent) | pass (code path shared with `min_rsa_key_bits`; no dedicated weak-EC-key spec) |
| `allow_hmac` | `hmac-sha256` SignatureMethod → `PolicyError` under strict regardless of `signature_methods` | pass |
| `allow_retrieval_method` | `<RetrievalMethod>` in KeyInfo → `PolicyError` | pass (native `inspect_document` reports `has_retrieval_method`) |
| `allow_same_document_xpointer` | `URI="#xpointer(/)"` → `PolicyError` | pass |
| `check_certificate_validity` / `clock_skew` | expired signing cert: strict → `CertificateExpired`; `clock_skew: 60` accepts a cert that expired 30s ago, rejects one expired 30min ago. `store:` honors `check_certificate_validity` via `StoreContext` (#30); `certificate:` path fixed under S-07. | pass |
| `schema` | `Policy.strict.schema == :default` → `Verifier` validates the `<Signature>` against the XSD without the caller passing `schema:`; explicit `schema: nil` still opts out | pass |

### S-07 `verification_time` (fixed; see `spec/hanko_xml/policy_enforcement_spec.rb`)

| # | Spec | Status |
|---|------|--------|
| V1 | Signing cert valid 2020-2021, `verification_time: 2020-06-01` → **valid** | pass |
| V2 | Same, `verification_time: nil` (now) → `CertificateExpired` | pass -- was the actual bug: `check_certificate_validity` had no effect without an explicit `verification_time:`, so an expired cert verified fine by default |
| V3 | Trusted anchor expired but signing cert fine, `verification_time` within the anchor's window → valid; outside → `CertificateExpired` naming which cert | not separately spec'd -- on `certificate:`/`certificates:` trust the trusted anchor *is* the signing cert (S-01 signKey pinning), so this collapses into V1/V2 |

### S-11 multiple signatures (fixed; see `spec/hanko_xml/multi_signature_spec.rb`)

| # | Spec | Status |
|---|------|--------|
| M1 | Default `signature:` (`nil`) with two signatures raises `MultipleSignatures` instead of silently verifying only the first | pass |
| M2 | `signature: :only` with two → `MultipleSignatures` | pass |
| M3 | `signature: 1` selects the right one (document order) | pass |
| M4 | `verify_all` returns one `Verification` per signature, in document order | pass |
| M5 | Signer `signature: n` and Verifier `signature: n` refer to the same node | pass |
| M6 | `signature: :first` remains available as an explicit, unsafe opt-in | pass |

### S-12 / S-13 native robustness

| # | Spec | Status |
|---|------|--------|
| N1 | `Native.sign`/`verify` with a String of length `2**31` (skip unless `ENV["HANKO_BIG"]`) → `ParseError`/`ArgumentError`, never a truncated parse | pass (S-12, `document_size_spec.rb`, opt-in; `ffi_len` unit test always runs) |
| N2 | `SigningError#xmlsec_errors` is non-empty when xmlsec logged errors | pass (S-13, `native_errors_spec.rb`) |
| N3 | Exception messages never include the private key PEM (grep `-----BEGIN`) for every error path in section H | ? (S-13 made native messages fixed strings; no spec over section H yet) |
| N4 | Unsafe-budget spec: extend to assert `dsig.rs` has a `// SAFETY:` comment within 3 lines above every `unsafe` | ? |

---

## 4. Fixtures to add

- `ec_signer.key` / `ec_signer.crt` (P-256), `ec384_signer.*` (P-384)
- `weak_signer.key` / `weak_signer.crt` (RSA-1024)
- `expired_signer.crt` (same key as `signer.key`, notAfter in the past)
- `intermediate.crt` + `root.crt` + `leaf.key/crt` chain
- `encrypted_signer.key` (AES-256, known password) and `signer.p12`
- `template_keyvalue.xml`, `template_keyname.xml`, `template_two_signatures.xml`,
  `template_nested_signatures.xml`, `template_external_ref.xml`
- `signed_with_keyvalue_only.xml` (attacker-signed; **must** be rejected)
- `xsw_dtd_id.xml`, `xsw_xmlid.xml`, `xsw_wrapped.xml`
- `latin1_document.xml`

Generate the certificates with a checked-in `spec/support/gen_fixtures.rb`
rather than committing opaque binaries only, so expiry dates and key sizes are
auditable (the current `signer.crt` is valid 2026-08-31 → 2036-08-28).

---

## 5. Suggested spec layout

```
spec/hanko_xml/signer_sign_spec.rb        # groups A, D, E, G, H
spec/hanko_xml/signer_algorithms_spec.rb  # group B
spec/hanko_xml/signer_references_spec.rb  # group C
spec/hanko_xml/signer_keys_spec.rb        # group F
spec/security/key_value_trust_spec.rb     # K*
spec/security/trust_sources_spec.rb       # T*
spec/security/xsw_spec.rb                 # X*
spec/security/policy_ordering_spec.rb     # R*
spec/security/policy_fields_spec.rb       # S-06 table
spec/security/verification_time_spec.rb   # V*
spec/security/multiple_signatures_spec.rb # M*
spec/security/native_robustness_spec.rb   # N*
```

Run the `spec/security` directory in CI as its own job so a red security spec
is visible at a glance, and tag the pending ones with the finding id
(`pending "S-01"`) so `rspec --tag` can list what is still open.