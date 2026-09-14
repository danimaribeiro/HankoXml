# HankoXml Security Review

Date: 2026-09-12 (re-checked after S-05 / #36)
Original scope: the whole repository at commit `3af4155` -- the Rust extension
(`ext/hanko_xml`), the Ruby layer (`lib/hanko_xml`), the build/vendoring
pipeline, CI/release workflows, and the specs.

This document is the follow-up tracker. Remaining findings are filed as GitHub
issues (#33–#51); the checklist below links each open item.

Follow-up commit `fdcf06e` (PR #30) wired `store:` / `key:` and pinned
`signKey` for key PEMs. S-01 remaining surface (certificate PEMs / empty trust)
is closed by pinning every trusted PEM as `signKey`. Findings that still hold
were judged to still make sense; S-01, S-02, S-03, S-04, S-05, and S-08 are closed as
originally stated.

Each finding is tagged with how it was established:

- **[confirmed]** -- reproduced by running code against this checkout
  (system libxmlsec1 1.2.39, Ruby 3.2.3, Nokogiri 1.18). Reproduction steps
  are given inline so another agent can turn them into specs.
- **[code review]** -- established from reading the source plus knowledge of
  libxmlsec1/libxml2 behaviour, not executed. Treat as a strong hypothesis
  that needs a reproducing spec before (and after) it is fixed.

Disposition after the re-check:

- **open** -- still holds; needs a fix.
- **partial** -- PR #30 narrowed it; the remaining surface is still a bug.
- **fixed** -- original report no longer holds.

Severity reflects impact on a consumer that uses the library the way the
README recommends: verify with a pinned certificate, then trust the document.

---

## Summary

| ID | Severity | Area | Finding | Disposition | Evidence |
|----|----------|------|---------|-------------|----------|
| S-01 | **Critical** | Verifier / native | `<KeyValue>` supplied by the document is accepted as the verification key. After #30 this was still true for `certificate:` / `certificates:` / cert-valued `keys:` / `Native.verify` with cert PEMs or empty trust. Every trusted PEM is now pinned as `signKey`; empty trust fails closed. | **fixed** | confirmed, then re-checked |
| S-02 | **High** | Verifier | `store:` and `key:` trust sources are accepted, documented, and silently ignored (empty trust set) | **fixed** (#30) | confirmed, then re-checked |
| S-03 | **High** | Verification | Fragment-reference resolution disagrees between xmlsec (libxml2 ID table: DTD- and `xml:id`-aware, namespace-agnostic) and `Verification#signed?` (XPath over configured attribute names, no-namespace only). A DTD internal subset lets an attacker make `signed?` bless an unsigned node while the signature stays valid | **fixed** (#28/#34) | confirmed (spec X1/X3) |
| S-04 | **High** | Verifier / native | Policy is enforced *after* `Native.verify`, so external `Reference URI="file://…"`/`http://…` are dereferenced by xmlsec before `allow_external_references: false` rejects them (local-file digest oracle, SSRF) | **fixed** | confirmed (spec R1/R2/R6/R8) |
| S-05 | **High** | Signer | `Signer#sign!` (default `template: :adopt`) signs any pre-existing `<Signature>` template in the input with the caller's key and never enforces `Signer#policy`: a signing oracle for attacker-chosen algorithms, references and external URIs | **fixed** | confirmed (spec R3/R4/R5) |
| S-06 | **Medium** | Policy | 11 of 18 `Policy` fields were declared and documented as enforced but never checked. After #30, `check_certificate_validity` is honored on the `store:` path only; the other ten fields are still unread. | **partial** (#30) | confirmed (grep), re-checked |
| S-07 | **Medium** | Verifier | `verification_time:` validates only the *trusted* certificates' validity window, never the signing certificate; `check_certificate_validity: false` has no effect. After #30, `store:` applies both knobs to the signing cert via `StoreContext`; `certificate:` is unchanged. | **partial** (#30) | confirmed, re-checked |
| S-08 | **Medium** | Verifier | `keys:` with a public key (not a certificate) produces an empty trust set. After #30, key-valued entries pass `to_pem` and pin `signKey`. Cert-valued entries still hit S-01. | **fixed** (#30) | confirmed, then re-checked |
| S-09 | **Medium** | Verification | `Reference#valid?` is just `Verification#valid?`; per-reference status, `Manifest`, `RetrievalMethod` and `Object` semantics are not surfaced, so `signed?` over-approximates for anything but the simplest shapes | **fixed** | code review |
| S-10 | **Medium** | Native | Transform surface is whatever libxmlsec1 was built with; the source gem on a host whose xmlsec links libxslt (this checkout does) enables the XSLT transform, and policy blocks it only after it has run (S-04) | **open** | confirmed (ldd) |
| S-11 | **Medium** | Verifier | `signature: :first` default: with several `<Signature>` elements only the first is verified and the result is reported for the whole document | **open** | code review |
| S-12 | **Low** | Native | `xml.len() as i32` in `OwnedXmlDoc::parse` truncates documents over 2 GiB; no size guard before the FFI boundary and `max_document_size` is unenforced | **open** | code review |
| S-13 | **Low** | Native / Ruby | Exceptions are classified by substring (`msg.contains("key")`, `contains("parse")`); xmlsec error text (with attacker-controlled URIs/paths) is echoed verbatim into Ruby exception messages | **open** | code review |
| S-14 | **Low** | Signer | A mismatched `key:`/`certificate:` pair is accepted at sign time; the output verifies with neither certificate | **open** | confirmed, re-checked |
| S-15 | **Low** | Key | `Key#dispose!` claims in-place zeroization but only nils the reference; `Key#private_key?` is true for public-only `PKey`s; PEM-vs-cert detection is a substring heuristic | **open** | code review |
| S-16 | **Low** | Algorithms | `Algorithms.register(..., replace: true)` is process-global and can re-point a Symbol used by `Policy.strict` (e.g. `:sha256`) at another URI, silently changing what "strict" means | **open** | code review |
| S-17 | **Low** | SignedDocument | `#document` exposes the mutable Nokogiri document; `FrozenSignatureError` exists but is never raised | **open** | code review |
| S-18 | **Low** | Build | `build/vendor.rs` shells out to `curl`/`tar`/`configure`/`make` and hand-parses `dependencies.yml`; SHA-256 pinning is good, but `HANKO_XML_VENDOR_CACHE` and `tmp/vendor-build/.stamp-complete` are trusted build-time inputs | **open** | code review |
| S-19 | **Low** | CI | Actions pinned by major tag, not commit SHA; `main.yml` has no top-level `permissions:` | **open** | code review |
| S-20 | **Info** | Native | Whether the root element's own `Id` is registered by `xmlSecAddIDs(doc, root, ids)` depends on xmlsec walking `cur` or `cur->children`; `URI="#rootId"` is untested | **open** | code review |
| S-21 | **Info** | Docs | README passes file *paths* as `key:`/`certificate:` Strings (`key: "private.pem"`); `Key.coerce(String)` treats them as PEM and raises `KeyLoadError`. Fails closed, but misleading | **open** | code review, re-checked |

What is done well (so the fixing agent does not undo it): PEM-only FFI
boundary with every Ruby argument copied before the native call; RAII wrappers
around every libxml2/xmlsec resource; `unsafe` confined to `dsig.rs`/`errors.rs`
with a spec guarding that budget; xmlsec stderr replaced by a captured error
callback; `HankoXml.parse` is strict + `nonet`, never `NOENT`/`HUGE`/`RECOVER`;
AS_XML-only serialization; SHA-256 pinned vendored tarballs with hidden
visibility and `--exclude-libs,ALL` plus a symbol-leak spec; XPath fragment
lookup uses variable bindings (no injection); RubyGems trusted publishing with
`rubygems_mfa_required`; ABI-compatibility check at require time. After #30:
`store:` / `key:` / `certificate:` / `certificates:` / `keys:` honor
`API_CONTRACT.md` §5.6 and pin `signKey` so KeyInfo is ignored. Empty
trust fails closed (`Native.verify` → `:invalid`; `Verifier.new` without a
trust source → `ConfigurationError`).

## Open work

- [x] **S-01** (#33) remaining: pin `signKey` for `certificate:` /
      `certificates:` / cert-valued `keys:` / `Native.verify` with cert
      PEMs; empty trust fails closed
- [x] **S-03** (#34) ID resolution mismatch — fixed via native
      `reference_element_indexes` (#28)
- [x] **S-04** (#35) policy before crypto; do not dereference external URIs first
- [x] **S-05** (#36) `template: :adopt` signing oracle; enforce Signer policy
- [ ] **S-06** (#37) remaining unenforced Policy fields
- [ ] **S-07** (#38) remaining: `certificate:` path + native `certsVerificationTime`
- [x] **S-09** (#39) per-reference validity / `signed?` over-approximation
- [ ] **S-10** (#40) restrict transforms/URIs regardless of host xmlsec build
- [x] **S-11** (#41) `signature: :first` and Signer/Verifier index disagreement
- [ ] **S-12** (#42) `xml.len() as i32` + `max_document_size`
- [ ] **S-13** (#43) error classification and xmlsec log in messages
- [ ] **S-14** (#44) reject mismatched `key:` / `certificate:` at sign time
- [ ] **S-15** (#45) `Key#dispose!` / `private_key?` / PEM heuristic
- [ ] **S-16** (#46) freeze or snapshot `Algorithms.register`
- [ ] **S-17** (#47) `SignedDocument` mutability / unused `FrozenSignatureError`
- [ ] **S-18** (#48) document vendored cache/stamp as trusted inputs
- [ ] **S-19** (#49) pin Actions to SHAs; `permissions:` on `main.yml`
- [ ] **S-20** (#50) spec (and fix if needed) root-element `Id` registration
- [ ] **S-21** (#51) README path Strings vs PEM `Key.coerce`
- [x] **S-02** `store:` / `key:` ignored — fixed in #30 (also closed #12)
- [x] **S-08** `keys:` public key empty trust set — fixed in #30

Signing/verification coverage gaps: #52 (`SIGNING_TEST_COVERAGE.md`).

---

## Findings in detail

### S-01 -- `<KeyValue>` from the document is trusted as the verification key  [confirmed, Critical, **fixed**]

**Disposition:** closed. `verify_document` now loads every trusted PEM as a
public key (certificate PEMs via `xmlSecKeyDataFormatCertPem`) and pins
`ctx.signKey`, so xmlsec never reads the document's KeyInfo for the
verification key. Several cert PEMs are tried in order (`certificates:`).
An empty trust list returns `:invalid` with `no trusted key or certificate
provided`. `Verifier` requires exactly one trust source at construction.
Regression specs: `spec/hanko_xml/key_value_trust_spec.rb` (K1–K8).

Historical reproduction (pre-fix, at `3af4155` / after #30): a template with
`<KeyInfo><KeyValue/></KeyInfo>` signed by `other.key` verified as
`:succeeded` against `signer.crt` and against an empty trust list, because
`xmlSecKeysMngrGetKey` prefers a complete `<RSAKeyValue>` from the document
over the KeysMngr. `key:` / `store:` were already pinned by #30; the leftover
was cert PEMs going into KeysMngr as CA anchors.

Do not re-open. Chain validation remains a Ruby `store:` concern — Native no
longer treats trusted cert PEMs as CA anchors.

### S-02 -- `store:` and `key:` are ignored  [confirmed, High, **fixed**]

**Disposition:** closed by PR #30 (`fdcf06e`). Do not re-open as originally
stated.

`store:` identifies the KeyInfo end-entity (the cert that issued nobody else
in the set; document order is not a leaf indicator), validates it with
`OpenSSL::X509::StoreContext` (no mutation of the caller's store), and pins
the leaf **public key** as xmlsec `signKey`. Passing the leaf certificate as
`xmlSecKeyDataTypeTrusted` does not pin it: xmlsec still X509-verifies every
KeyInfo cert and rejects `CA:FALSE` EEs.

`key:` passes a public-key PEM into `Native.verify`, which classifies
non-`BEGIN CERTIFICATE` PEMs and pins `signKey` so KeyInfo is ignored
(`API_CONTRACT.md` §5.6).

Re-checked after #30:

```
good doc, store: with signer.crt -> valid?: true
good doc, key: signer public key  -> valid?: true
good doc, key: other public key   -> valid?: false
FORGED (KeyValue) doc, store:     -> valid?: false (no X509Certificate)
FORGED (KeyValue) doc, key: signer pubkey -> valid?: false
```

The Copilot branch `origin/copilot/fix-verifier-store-and-key-usage` (PR #27)
is superseded by #30.

### S-03 -- ID resolution mismatch between xmlsec and `Verification#signed?`  [confirmed, High, **fixed**]

**Disposition:** fixed. `Native.verify` returns `reference_element_indexes`
from libxml2's ID table (`xmlGetID`) after verification; `Verification` maps
those indexes onto the caller's DOM. Specs X1 (DTD) and X3 (`xml:id`) in
`spec/hanko_xml/id_resolution_spec.rb` pass. Remaining related work: S-20
(root-element Id registration, #50) and unused `reject_duplicate_ids` (S-06).

Two independent resolvers ~~decide~~ decided which node `URI="#id"` denotes:

- **Native** (`register_id_attributes` → `xmlSecAddIDs`): libxml2's ID table.
  It already contains every `xml:id` and every attribute the document's
  **internal DTD subset** declares as type `ID` (`xmlIsID` consults
  `doc->intSubset`, matching element/attribute *QNames including prefix*).
  `xmlSecAddIDsWalk` then adds attributes matched by **local name only,
  ignoring namespace**, first in document order wins, and duplicates are
  logged through the error callback but do not fail the operation.
- **Ruby** (`Verification#resolve_by_id_attributes`):
  `//*[@*[local-name()=$n and namespace-uri()='' and .=$id]]`, i.e. the first
  element in document order carrying a *no-namespace* attribute named in
  `id_attributes`. It knows nothing about the DTD or `xml:id`.

Both parsers accept an internal subset (`HankoXml.parse` is `strict.nonet`,
which does not disable it; `OwnedXmlDoc::parse` uses options `0`), and
`HankoXml.serialize` preserves the `<!DOCTYPE>` across the round trip.

Attack sketch (fragment signature over `<n:Invoice Id="inv-1">`, verified with
`Policy.fragment`):

```xml
<!DOCTYPE Root [<!ATTLIST n:Invoice Id ID #IMPLIED>]>
<Root xmlns:n="urn:nfe">
  <x:Invoice xmlns:x="urn:nfe" Id="inv-1"><x:Amount>1</x:Amount></x:Invoice>   <!-- attacker -->
  <n:Invoice Id="inv-1"><n:Amount>100</n:Amount></n:Invoice>                    <!-- signed, untouched -->
  <Signature>…URI="#inv-1"…</Signature>
</Root>
```

Expected: libxml2 registers `inv-1` → the *legit* `n:Invoice` at parse time
(the ATTLIST names the literal QName `n:Invoice`, so `x:Invoice` is not an ID
attribute); `xmlSecAddIDs` then sees the attacker's `Id` as a duplicate and
skips it. xmlsec digests the legit node, `valid? == true`. Ruby's XPath returns
the first `Id="inv-1"` in document order, the attacker's node, so
`signed?(attacker_node) == true` and `at_signed("//n:Invoice")` returns the
attacker's node. This defeats the library's headline XSW defence.

A plainer variant with `<!ATTLIST Invoice Id ID #IMPLIED>` and an attacker
`<Order Id="inv-1">` needs no namespaces. Also relevant: `reject_duplicate_ids`
is a no-op (S-06) and the xmlsec "duplicate ID" diagnostics are discarded when
verification succeeds (`errors` is only read on failure).

Remediation direction: resolve fragments in Ruby through the same mechanism
xmlsec used, or make the mismatch impossible: reject documents with an internal
subset / `xml:id` / duplicate IDs before verification (`reject_duplicate_ids`,
a new `allow_dtd` field), strip `namespace-uri()=''` asymmetry by registering
only no-namespace attributes natively (or matching any namespace in Ruby), and
fail verification when the native error log contains `xmlSecAddIDs` duplicate
warnings. Specs: `SIGNING_TEST_COVERAGE.md`, group H.

### S-04 -- Policy runs after cryptography; external references are dereferenced first  [confirmed, High, **fixed**]

**Disposition:** closed. `Verifier#verify_single` runs `@policy.enforce!` on
`inspect_sig` output **before** `Native.verify`. `DsigCtx::for_signing`
(sign and verify) sets `enabledReferenceUris` and
`transformCtx.enabledUris` to
`xmlSecTransformUriTypeEmpty | xmlSecTransformUriTypeSameDocument`, so
`file://` / `http://` References are not fetched even if Ruby is bypassed.
`Policy.permissive` (`allow_external_references: true`) skips the Ruby
check but still does not fetch — `referenced_documents:` remains the only
supported non-fragment path. Specs: `spec/hanko_xml/policy_ordering_spec.rb`
(R1, R2, R6, R7, R8).

Signer `:adopt` now enforces the same policy before `Native.sign` (S-05).
The native URI restriction is defense in depth on that path too.

Do not re-open the verify-side fetch.

### S-05 -- Signer adopts hostile templates and never enforces its policy  [confirmed, High, **fixed**]

**Disposition:** closed. `Signer#sign!` runs `@policy.enforce!` on
`inspect_sig` output **before** `Native.sign`, for templates the Signer
just built and for `:adopt`/`:require` skeletons already in the input.
Adopted templates must also have Reference URIs matching `Signer#references`;
empty `references` means whole-document `URI=""`, so a fragment template
needs an explicit `references: ["#id"]` opt-in.

Default is still `template: :adopt` (the skeleton-already-present mode).
That is no longer a signing oracle: SHA-1, `file://`/`http://`, XSLT, and
`#attacker-node` fail closed under `Policy.strict` without calling
`Native.sign`. Specs: `spec/hanko_xml/signer_policy_spec.rb` (R3, R4, R5,
H7, C15).

`Native.sign` itself remains callable without the Ruby policy gate; URI
fetch is still blocked natively (S-04). Transform registration on a direct
`Native.sign` call remains S-10.

Do not re-open the adopt-side oracle.

### S-06 -- Unenforced `Policy` fields  [confirmed, Medium, **partial**]

**Disposition:** `check_certificate_validity` is now read on the `store:`
path (`StoreContext` + `V_FLAG_NO_CHECK_TIME`). Every other listed field is
still unread. `Policy#violations` is unchanged.

`Policy#violations` checks `signature_methods`, `canonicalization_methods`,
`digest_methods`, `transforms`, `max_references`, `require_references`,
`max_transforms_per_reference`, `allow_external_references`. It never reads:

`allow_retrieval_method`, `allow_same_document_xpointer`,
`require_signed_root`, `reject_duplicate_ids`, `max_document_size`,
`min_rsa_key_bits`, `min_ec_key_bits`, `allow_hmac`,
`clock_skew`, `schema`.

`check_certificate_validity` is no longer "only in `policy.rb`": `Verifier`
uses it for `store:`. Effects a consumer would reasonably rely on and does
not get: a 1024-bit RSA key verifies under `Policy.strict`; a fragment-only
signature verifies under `Policy.strict` (`require_signed_root: true`) unless
the caller checks `covers_root?` themselves; `Policy.strict.schema == :default`
does not turn on XSD validation (only `Verifier.new(schema: :default)` does);
duplicate IDs are never rejected (S-03); `max_document_size` never bounds the
FFI input (S-12); `check_certificate_validity: false` still cannot disable
xmlsec's time check on the `certificate:` path (S-07).

`Policy.permissive`'s doc comment ("Everything libxmlsec1 supports") and the
docs site reference pages describe these as live controls.

### S-07 -- `verification_time:` checks the wrong certificates  [confirmed, Medium, **partial**]

**Disposition:** `store:` now applies `verification_time` (and
`check_certificate_validity`) to the **signing** cert via
`OpenSSL::X509::StoreContext`. The `certificate:` / `certificates:` path still
iterates the caller's trusted anchors. xmlsec `certsVerificationTime` is still
0. `clock_skew` is still unused.

`verify_single` iterates `trusted` (the caller's own anchors) and raises
`CertificateExpired` when `verification_time` falls outside *their* window.
On the `certificate:` path the signing certificate embedded in the document
is checked by xmlsec against `certsVerificationTime = 0` (wall clock)
regardless.

```
expired signing cert, verify now                              -> valid? false
expired signing cert, verification_time inside its validity   -> valid? false
expired signing cert, Policy.permissive (check_certificate_validity: false) -> valid? false
good doc, verification_time before TRUSTED cert notBefore     -> [CertificateExpired]
```

So the documented use case (verify an old NF-e as of its signing date) is
impossible, and `clock_skew` is meaningless. Fix by setting
`ctx.keyInfoReadCtx.certsVerificationTime` from Ruby's `verification_time`.

### S-08 -- `keys:` with a public key gives an empty trust set  [confirmed, Medium, **fixed**]

**Disposition:** closed by PR #30 for public-key (and private-key) map
values. `keys_trust` now always does `Key.coerce(...).to_pem`; a key PEM
pins `signKey`. Do not re-open the empty-trust-set bug.

Leftover from S-01 is closed: a certificate in the `keys:` map is now a
cert PEM that Native pins as `signKey`. The `KeyName` looked up is still
the document's unauthenticated string; that is intended `keys:` semantics
once each value is a pinned key.

Re-checked after S-01:

```
good doc, keys: {alice => signer_pubkey}  -> valid?: true
forged KeyValue, keys: {alice => signer_pubkey} -> valid?: false
forged KeyValue, keys: {alice => signer.crt}    -> valid?: false
```

### S-09 -- Per-reference validity and non-trivial shapes  [code review, Medium, **fixed**]

**Disposition:** fixed for the headline complaint (per-reference validity is
now real); the non-trivial-shape half is unchanged because it was already
fail-safe, not fail-open.

`verify_document` now reads `xmlSecDSigCtx.signedInfoReferences` after
`xmlSecDSigCtxVerify` and returns each `<SignedInfo><Reference>`'s own digest
status (`reference_valid: Array<true|false|nil>`, same indexing as the
existing `reference_element_indexes`) alongside the overall result --
independent of it, since xmlsec digest-checks every Reference before it
evaluates `SignatureValue`. `Verification#build_references` now sets
`valid?` from that per-reference status (falling back to the overall
`valid?` only when there is no real answer: a `Verification` built directly,
or a reference xmlsec never reached because verification aborted earlier),
instead of copying the overall result onto every `Reference`. A
harmless-fragment Reference and a tampered payload Reference in the same
`SignedInfo` now disagree correctly.

The second remaining-work item -- `Manifest`, `RetrievalMethod`,
`#xpointer(...)` and external references -- is unchanged: `resolve_reference`
still only handles `""` and `#id`, so those still resolve to `node: nil`.
That was already the safe direction (`signed?` treats `node: nil` as "covers
nothing," so it cannot be used to over-claim coverage), just not an accurate
one; genuine support for those shapes remains future work, now tracked
separately if picked up.

### S-10 -- Transform/URI surface depends on the host build  [confirmed by `ldd`, Medium, **open**]

**Disposition:** still open. Source gem still inherits distro xmlsec.

`lib/hanko_xml/hanko_xml.so` in this checkout links `libxslt.so.1` via the
system `libxmlsec1`, so the XSLT transform is registered. The vendored builds
pass `--without-libxslt`, `--without-http`, `--without-ftp`-equivalents, but
the source gem inherits the distro's configuration. `dsig.rs` now restricts
`enabledUris` (S-04) but still does not restrict `enabledTransforms`, so an
XSLT transform is registered whenever the host xmlsec was built with libxslt.
Ruby Policy rejects it before `Native.verify` (R6) and `Native.sign` (S-05);
the remaining gap is a direct `Native.verify` / `Native.sign` call, and
host-dependent registration.

### S-11 -- Multiple signatures and `signature: :first`  [code review, Medium, **fixed**]

**Disposition:** fixed. `Verifier#initialize` now defaults `signature:` to
`nil`, which behaves like `:only`: with a single `<Signature>` it verifies as
before, but with more than one it raises `MultipleSignatures` instead of
silently verifying just the first. `signature: :first` remains as an
explicit, unsafe opt-in for callers who intentionally want the old default.
`Signer#sign!(signature: n)` now indexes document order (matching the
`all_sigs_in_order` xpath), the same as the Verifier's `Integer` index,
instead of the depth-sorted signing-order array; an out-of-range index raises
`ConfigurationError` instead of silently returning the document unmodified.
Signing order for the unqualified (sign-everything) case is still
depth-first/innermost-first, unaffected. `require_signed_root` enforcement
remains tracked separately under S-06.

### S-12 -- Length truncation at the FFI boundary  [code review, Low, **open**]

**Disposition:** still open. `xml.len() as i32` is unchanged.

`sys::xmlReadMemory(xml.as_ptr().cast(), xml.len() as i32, …)`: a `Vec<u8>`
longer than `i32::MAX` wraps (negative → parse failure; ≥ 4 GiB → parses only
the low 32 bits' worth of bytes). Ruby strings can be that large. Guard with a
checked conversion and honour `max_document_size` before copying.

### S-13 -- Error classification and message content  [code review, Low, **open**]

**Disposition:** still open. Substring mapping and xmlsec log-in-message
unchanged.

`lib.rs` maps errors with `msg.contains("parse")`, `contains("key")`,
`contains("certificate")`; `format_error` appends the full xmlsec log
(`func=…:file=…:line=…:msg=…`) which includes attacker-controlled URIs, node
names and file paths and ends up in `VerificationError#message`. Applications
that log or display exception messages leak those. Also, `native_sign` drains
the error buffer a second time after `format_error` already did, so
`SigningError#xmlsec_errors` is always empty.

### S-14 -- Key/certificate mismatch accepted at sign time  [confirmed, Low, **open**]

**Disposition:** still open. Re-checked after #30: `sign(key: other.key,
certificate: signer.crt)` succeeds; `verify` with either cert is false.

`HankoXml.sign(xml, key: other.key, certificate: signer.crt)` succeeds; the
output verifies with neither `signer.crt` nor `other.crt`. `Signer#initialize`
should check `certificate.to_openssl.check_private_key(key.to_openssl)`.

### S-15 -- `Key` hygiene  [code review, Low, **open**]

**Disposition:** still open. The `private_key?` heuristic no longer gates
S-08 (that path uses `to_pem` unconditionally), but the three hygiene bugs
remain.

`Key#dispose!` documents "Overwrites the Ruby-side PEM buffer in place" but
only sets `@material = nil`; every `to_pem` call materialises an unencrypted
PEM String in the Ruby heap and none are cleared. `Key#private_key?` returns
true for public-only `PKey`s (used by S-08's `certificate?` branch by
implication). `from_pem` decides cert-vs-key by `include?("CERTIFICATE") &&
!include?("PRIVATE KEY")`, so a bundle PEM (cert + key) is parsed as a key and
its certificate silently dropped.

### S-16 -- Mutable global algorithm registry  [code review, Low, **open**]

**Disposition:** still open.

`HankoXml::Algorithms.register(:digest, :sha256, "…#sha1", secure: true,
replace: true)` re-points the Symbol `Policy.strict` compares through
`uri_for`, so any code in the process (a plugin, a test helper) can widen
"strict" without touching a Policy object. Freeze the built-in tables or have
Policy snapshot URIs at construction.

### S-17 -- `SignedDocument` is not actually immutable  [code review, Low, **open**]

**Disposition:** still open.

`attr_reader :document` hands out the live Nokogiri document; `FrozenSignatureError`
is never raised. `#valid?` only accepts trust keywords and cannot pass
`policy:`/`schema:`/`signature:`, so callers get strict-policy verification
with no way to tighten or loosen from that entry point.

### S-18 -- Vendored build trust  [code review, Low, **open**]

**Disposition:** still open as a threat-model / CI residual, not a runtime
bypass. SHA-256 pinning stays; document that cache and stamp are trusted
inputs. Dependabot PR #29 (bindgen 0.73) is still open.

Good: SHA-256 of every tarball is verified before extraction, every time.
Watch-items: `HANKO_XML_VENDOR_CACHE` and `tmp/vendor-build/…/.stamp-complete`
let a pre-populated directory skip the download *and* (for the stamp) the whole
build; `tar -xf` extracts upstream archives without `--no-same-owner`/path
checks; `curl -L` follows redirects from the mirror. Acceptable for CI, but the
threat model should say so. Also `Cargo.toml` pins `bindgen = "0.72"` while
`Cargo.lock` and a Dependabot branch move to 0.73 -- fine, just keep the lock
committed.

### S-19 -- CI hardening  [code review, Low, **open**]

**Disposition:** still open. `release.yml` / `vendored-deps.yml` already set
`permissions:`; `main.yml` does not.

`actions/checkout@v7`, `oxidize-rb/actions/*@v1`, `ruby/setup-ruby@v1`,
`actions/upload-artifact@v7`, `actions/download-artifact@v8` are tag-pinned;
pin to commit SHAs for the release path at least. `main.yml` inherits default
`GITHUB_TOKEN` permissions; add `permissions: contents: read`. The release job
correctly uses OIDC trusted publishing and `environment: rubygems`.

### S-20 -- Root-element `Id` registration  [code review, Info, **open**]

**Disposition:** still open. Spec gap; related to S-03.

`register_id_attributes(root, …)` calls `xmlSecAddIDs(doc, root, ids)`. In
xmlsec, `xmlSecAddIDs` walks the *children* of `cur`, so an `Id` on the root
element itself may not be registered and `URI="#rootId"` may fail natively
while Ruby's `//*` XPath resolves it. Needs a spec either way.

### S-21 -- README examples fail closed  [code review, Info, **open**]

**Disposition:** still open. Re-checked: `Key.coerce("public.crt")` raises
`KeyLoadError`.

`HankoXml.sign(xml, key: "private.pem", certificate: "public.crt")` and
`HankoXml.verify!(xml, certificate: "public.crt")`: `Key.coerce(String)` calls
`from_pem`, which raises `KeyLoadError`. Use `Pathname` in the examples or
accept path Strings explicitly.

---

## Suggested remediation order

S-01, S-02, S-03, S-04, S-05, and S-08 are done. Remaining, in order:

1. S-10 -- restrict `enabledTransforms` natively regardless of host xmlsec.
2. S-06, S-07 -- make every documented knob real or remove it from the API
   and docs, including the `certificate:` time path.
3. S-11, S-14, S-09, S-12, S-13 -- correctness and robustness.
4. S-15 through S-21 -- hygiene.

Companion document: `SIGNING_TEST_COVERAGE.md` lists the specs that should
exist for the signing path and for each finding above. Specs T1–T4 for S-02 /
S-08 live in `spec/hanko_xml/verifier_spec.rb`. S-01 group K lives in
`spec/hanko_xml/key_value_trust_spec.rb`. S-04 group R lives in
`spec/hanko_xml/policy_ordering_spec.rb`. S-05 group R3–R5 / H7 lives in
`spec/hanko_xml/signer_policy_spec.rb`.
