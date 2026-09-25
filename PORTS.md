# HankoXml Ports: Rust and Python

How HankoXml could ship as a Rust crate and a Python package that share one
security core with the Ruby gem. This is a plan, not a record of work done:
nothing below is implemented yet. When a phase lands, mark it done here and
cite the PR.

## Why this is cheaper than it sounds

The hard part of HankoXml is already written in Rust and has nothing Ruby-specific
in it:

| File | Lines | What it does | Ruby-specific? |
|---|---|---|---|
| `ext/hanko_xml/src/dsig.rs` | ~1,500 | Parses, inspects, signs and verifies through xmlsec | No |
| `ext/hanko_xml/src/errors.rs` | ~100 | Captures xmlsec's error log | No |
| `ext/hanko_xml/src/sys.rs` | ~40 | bindgen output | No |
| `ext/hanko_xml/build.rs` | ~270 | System or vendored libxml2 2.14.6, xmlsec1 1.3.12, OpenSSL 3.5.8, pinned by SHA-256 | No |
| `ext/hanko_xml/src/lib.rs` | ~390 | Magnus glue: the five `HankoXml::Native` functions | **Yes** |

The boundary is already the right shape for other languages. Every call is bytes
in, bytes or plain data out (`sign`, `verify`, `inspect_sig`, `versions`,
`check_version`), and no `xmlDocPtr` ever crosses it (API_CONTRACT.md §3.1,
VENDORING.md). A PyO3 binding would be a sibling of `lib.rs`, not a rewrite.

## The catch: most of the security logic is in Ruby

API_CONTRACT.md §3 sets the rule "policy in Ruby, crypto in Rust". About 4,000
lines of `lib/` sit on the Ruby side of that line, and much of it is security
logic, not convenience:

- `Policy`: the algorithm allowlist, reference and URI rules, the checks that the
  root is signed (`require_signed_root`) and that IDs are unique, and the
  document and key size limits (S-04, S-06, S-12).
- `Signer`: key type checks, the S-05 checks on adopted templates, and
  write-back into the caller's DOM.
- `Verifier`: when XSD validation runs, trust collection, chain validation through
  `OpenSSL::X509::Store`, and the signing certificate's key usage and subject.
- `Verification`: the anti-XSW view (`#signed?`, `#at_signed`), built from
  `reference_element_indexes` and `reference_valid` (S-09).
- `Xades::Verifier`: the XAdES-B checks (#58).

If each port re-implements those in its own language, three copies of the
security rules drift apart, and every `S-xx` fix has to land three times. **The
plan is therefore to move the language-neutral security logic into the Rust core
first, and have the Ruby gem become the first thin binding over it.** The ports
come after that.

This reverses part of the API_CONTRACT.md §3 rule. That was decided on
2026-09-24 (see "Decisions"), and API_CONTRACT.md §3 is rewritten in Phase 0.

## Target architecture

```
┌─────────────────────┐ ┌─────────────────────┐ ┌─────────────────────┐
│ Ruby gem hanko_xml  │ │ Python hanko-xml    │ │ Rust crate          │
│ Nokogiri write-back,│ │ lxml write-back,    │ │ hanko-xml           │
│ idiomatic API       │ │ idiomatic API       │ │ (the core's API)    │
├─────────────────────┤ ├─────────────────────┤ │                     │
│ ext/: Magnus glue   │ │ PyO3 glue           │ │                     │
└──────────┬──────────┘ └──────────┬──────────┘ └──────────┬──────────┘
           └───────────── bytes in, data out ──────────────┘
┌──────────────────────────────────────────────────────────────────────┐
│ hanko-xml (core): Policy, Signer, Verifier, Verification data,       │
│ templates via xmlsec's template API, XAdES, trust-chain validation.  │
│ #![forbid(unsafe_code)] outside its FFI module.                      │
├──────────────────────────────────────────────────────────────────────┤
│ hanko-xml-sys: bindgen bindings + build.rs vendoring, links = xmlsec1│
└──────────────────────────────────────────────────────────────────────┘
```

Repository layout (one repo, one Cargo workspace):

```
crates/hanko-xml-sys/   bindgen, build.rs, dependencies.yml (moved from ext/)
crates/hanko-xml/       the core: dsig.rs, errors.rs and the ported security logic
ext/hanko_xml/          Magnus glue only, depends on crates/hanko-xml
python/                 PyO3 glue (src/), Python layer (hanko_xml/), pytest suite
conformance/            shared cases every binding must pass (see below)
```

### What stays in each language

- **Taking and returning the host DOM.** Nokogiri in Ruby, lxml in Python. The
  binding serializes to bytes, calls the core, and writes the results back into
  the caller's own nodes, as `Signer#write_back_signature` does today. The rule
  that only bytes cross the FFI matters even more in Python: lxml wheels bundle
  their own libxml2, just as precompiled Nokogiri does.
- **Mapping `Verification` to host nodes.** The core returns document-order
  element indexes per reference. The binding turns them into Nokogiri or lxml
  nodes for `#signed?` and `#at_signed`.
- **Key input coercion.** `OpenSSL::PKey` objects in Ruby, `cryptography` key
  objects in Python. Each is converted to PEM and handed to the core, as
  `Key#to_pem` does today.
- **Error classes.** The core returns a typed error kind, fixed messages and the
  captured xmlsec log (S-13). Each binding maps them to its own exception
  hierarchy. Messages never contain key material.

### What moves into the core

- **Policy**: the presets (`strict`, `fragment`, `legacy_sha1`, `xades`,
  `interop`, `permissive`) and every violation check. Most of these are string
  comparisons over the `inspect_sig` result and port directly. The DOM-dependent
  ones (`require_signed_root`, `reject_duplicate_ids`) run on the core's own
  libxml2 parse of the same bytes, which is also what xmlsec resolves against.
- **The algorithm registry** (`Algorithms`) and its URIs.
- **Template building**, through xmlsec's own template API
  (`xmlSecTmplSignatureCreate`, `xmlSecTmplSignatureAddReference`, …) rather
  than hand-built nodes, per the "let xmlsec1 do the security work" rule.
- **Signer checks**: key type and size, the key matching the certificate, and
  the S-05 template checks before signing.
- **Verifier**: XSD validation (the bundled `xmldsig-core-schema.xsd`), policy
  before verify (S-04), key pinning as `signKey` (S-01), and per-reference
  digest status (S-09).
- **Trust-chain validation**, now done by `OpenSSL::X509::Store`. See
  "Decisions", item 3.
- **XAdES-B**: the signed-properties checks and `SigningCertificate(V2)`
  matching.

## Shared conformance suite

Each port's own tests aren't enough to prove the ports behave the same. Add a
`conformance/` directory with a manifest (JSON), where each case gives:

- the input document, keys, certificates and policy preset;
- the operation (`sign`, `verify`, `inspect`);
- the expected result: validity, the error kind, which references are signed, and
  the `S-xx` finding the case guards, if any.

Seed it from the existing fixtures (`spec/fixtures`, `spec/interop`) and from
`spec/hanko_xml/adversarial_spec.rb` (tampering, signature wrapping, key
substitution, XXE, entity expansion, weak keys). RSpec, pytest and `cargo test`
each run the whole manifest. A case that passes in one language and fails in
another is a bug in a binding, and CI names the case.

This is also where the ASSURANCE.md property and fuzz targets belong: fuzz the
core once, and all three packages benefit.

## Phases

Each phase is one or more PRs and leaves the Ruby gem shippable. The Ruby spec
suite is the safety net throughout: it must pass unchanged, except for specs
that assert where code lives.

### Phase 0: Contract update and conformance seed

- Rewrite API_CONTRACT.md §3 for "security in the core, ergonomics in the
  binding" (Decisions, item 2).
- Check that `hanko-xml` is free on crates.io and PyPI (Decisions, item 5).
- Decide the repo's visibility before the first crate or wheel is published
  (Decisions, item 1).
- Create `conformance/` and a Ruby runner for it, seeded from the existing
  fixtures and adversarial cases, passing against today's gem. This pins current
  behavior before anything moves.

### Phase 1: Split the crate (no behavior change)

- Move bindgen, `build.rs` and `dependencies.yml` into `crates/hanko-xml-sys`,
  and `dsig.rs` and `errors.rs` into `crates/hanko-xml`. `ext/hanko_xml` keeps
  only the Magnus glue.
- Move the `unsafe` confinement check to crate level: `#![forbid(unsafe_code)]`
  on everything except the core's FFI module, and update
  `spec/hanko_xml/native_spec.rb` to match.
- Check that platform gems still build (`cross-gem.yml`) and that
  `HANKO_XML_VENDOR=1` and the system-library builds both pass.

### Phase 2: Move the security logic into the core

In this order, each step a PR, and each deleting the Ruby it replaces:

1. The algorithm registry and the policy checks that only read `inspect_sig`
   output.
2. The DOM-dependent policy checks (`require_signed_root`,
   `reject_duplicate_ids`), running on the core's parse.
3. Verifier orchestration: size limit, inspect, policy, verify, per-reference
   status. This returns a `Verification` data record that Ruby wraps.
4. Signer: template building through xmlsec's API, key checks, S-05. Ruby keeps
   `Placement` resolution and write-back.
5. Trust-chain validation, depending on the decision below.
6. XAdES-B.

API_CONTRACT.md, SECURITY_REVIEW.md citations and the RBS signatures are updated
in the same PR as each step. The public Ruby API doesn't change.

### Phase 3: Rust crate

- A public API for `hanko-xml`: a `Signer` builder, `Verifier`, `Policy`
  presets, and a `Verification` with the signed-reference view. It works on
  bytes, with an optional DOM-free "verify and return the signed bytes" helper
  for callers that have no DOM.
- Cargo features: `vendored` (the default, statically linked, like the platform
  gems) and `system` (pkg-config).
- rustdoc, examples, and publishing to crates.io with trusted publishing.

### Phase 4: Python package

- PyO3 glue with abi3 wheels built by maturin, for the platforms the gem ships:
  x86_64-linux and aarch64-linux (manylinux and musllinux), arm64-darwin and
  x86_64-windows, with the static vendored build.
- A Python layer shaped like the Ruby one: `hanko_xml.sign`, `hanko_xml.is_valid`,
  `Signer`, `Verifier`, `Verification` with `signed` and `at_signed`, and lxml as
  the optional DOM. Type hints ship with it (`py.typed`).
- An interop check against SignXML both ways, like
  `spec/interop/xades_signxml_produced_spec.rb` does today. The SignXML
  comparison guide in the docs gets a Python version.
- Publishing to PyPI with trusted publishing.

### Phase 5: Docs and release

- The docs site gets a language switcher on guide and reference pages, plus
  rustdoc and Python API references next to the YARD one.
- RELEASING.md covers all three packages.

## Decisions

Settled on 2026-09-24:

1. **One repository for all three packages.** Phase 2 moves checks from Ruby into
   the core one PR at a time, and the Ruby specs have to prove each move in that
   same PR. Split repos would turn every step into a core release plus a version
   bump in the gem. The core's `S-xx` findings, SECURITY_REVIEW.md, the fuzz
   targets and the conformance suite stay in one place, and the conformance
   suite runs against all three bindings in one CI run. polars, pydantic-core,
   tokenizers and cryptography publish a Rust core and bindings from one repo
   the same way.
   - **CI:** every workflow filters on paths, so a Python-only change doesn't
     build gems (as `pages.yml` already does). A change under `crates/` runs
     all three bindings, since all three depend on the core.
   - **Tags:** one prefix per package: `gem-v*`, `crate-v*` and `py-v*`. Each
     release workflow triggers only on its own prefix.
   - **Discoverability:** the README lists all three packages, and the
     crates.io and PyPI metadata link to the package's subdirectory.
   - **Visibility:** the repo is private today. Publishing works from a private
     repo, but docs.rs and PyPI would link to source nobody can open. Decide
     before Phase 3.
   - A binding can still move out later, once the core API is stable, if it gets
     its own maintainers or pace. Splitting later is easy; merging repos back
     together is not.
2. **Policy moves into Rust.** The reason for the ports is to reuse the security
   rules, so they live in the core. This replaces "policy in Ruby, crypto in
   Rust" (API_CONTRACT.md §3) with "security in the core, ergonomics in the
   binding". §3 argued that Ruby is memory-safe while Rust grows `unsafe` with
   every feature. That still holds if the ported logic is safe Rust and `unsafe`
   stays in the FFI module, which Phase 1 enforces at compile time.
3. **Certificate chains: xmlsec's X.509 store, called directly, with our checks on
   top. Recommended, pending the conformance suite.** Both options run OpenSSL's
   own `X509_verify_cert` underneath, so neither validates chains better. The
   question is which wrapper, and what each costs:
   - **xmlsec's normal path conflicts with S-01.** xmlsec validates chains while
     resolving `<KeyInfo>`/`<X509Data>` through a keys manager. That is the path
     where the document chooses the key, which S-01 forbids. So the core would
     call `xmlSecOpenSSLX509StoreVerify` directly (public in xmlsec1 1.3.12),
     with the certificates from `<KeyInfo>` as untrusted input and the trusted
     roots in the store. The leaf's public key is then still pinned as
     `signKey`, as `store:` does today.
   - **Some checks aren't xmlsec features, so they stay in the core either way:**
     rejecting a `<KeyInfo>` where more than one certificate chains to the store
     (xmlsec returns the first certificate that verifies), requiring
     `digitalSignature` or `nonRepudiation` in KeyUsage (#63), and
     `certificate_subject:` matching.
   - **System and vendored builds may disagree.** xmlsec1 1.3 added X.509 strict
     checks and `XMLSEC_KEYINFO_FLAGS_X509DATA_SKIP_TIME_CHECKS`. Check whether
     the system 1.2.39 build can express `check_certificate_validity: false`
     and a fixed verification time (`certsVerificationTime`) with the same
     results. If it can't, trust results would depend on the build, which the
     rule "must pass on both" doesn't allow.
   - **Revocation:** both options support CRLs only, not OCSP. There's no
     difference here.
   - **Fallback:** the `openssl` crate's `X509Store`, linked to the same vendored
     OpenSSL, keeps today's semantics exactly. Use it if the conformance suite
     shows a trust case where xmlsec's store differs and can't be configured to
     match, or if the 1.2.39 gap is real.
4. **Each package has its own version and its own changelog.** A core change is
   released in each binding that ships it. The changelog entry in that binding
   names the core change, so no package gets an empty release. Every release
   records the core version it bundles (for Ruby, in `NativeVersion`).
   `CHANGELOG.md` stays the gem's, and each other package gets a `CHANGELOG.md`
   in its own directory. The `**#NN:**` tagging rule applies to all of them.

Still open:

5. **Package names.** `hanko-xml` on crates.io and PyPI, imported as `hanko_xml`
   in Python. Check both are free in Phase 0.
6. **CI cost.** CI is paused for budget reasons. The Python wheel matrix and a
   Rust test job add to that cost. Once CI resumes, consider running the full
   matrix only on release tags, with a small Linux job on PRs.

## Risks

- **Behavior drift during Phase 2.** Code that moves from Ruby into Rust can
  change behavior in ways the Ruby specs don't notice. The Phase 0 conformance
  seed is what catches this, which is why it comes first.
- **Two libxml2 versions in Python.** lxml bundles its own. Bytes-only crossing
  handles this, as it does for Nokogiri, but the Python layer must never be
  "optimized" into sharing pointers.
- **System library differences.** The system build (libxml2 2.9.14, xmlsec1
  1.2.39) behaves differently from the vendored one: XSD integer limits, the
  text node size limit, ECKeyValue. Python and Rust users on the `system`
  feature inherit the same gaps, so the conformance suite needs the same
  capability gating that `HankoXml::NativeVersion.build_versions` gives the
  Ruby specs.
- **Scope.** Phase 2 is most of the work. Phases 3 and 4 are mostly packaging
  once it's done, and neither should start before Phase 2 is complete.
