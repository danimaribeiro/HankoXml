# HankoXml Ports: Rust and Python

How HankoXml could ship as a Rust crate and a Python package that share one
security core with the Ruby gem. This is a plan, not a record of work done:
nothing below is implemented yet. When a phase lands, mark it done here and
cite the PR.

The plan was reviewed twice on 2026-09-24. The problems those reviews found,
with one or more ways to solve each, are under "Problems and options" (P1 to
P10). The rest of the plan points to them. The second pass added P1 option C,
moved the P2 recommendation to option B, and added the pregenerated bindings
(P7), the gemspec allowlist (Phase 1), the XSD skip flag (Phase 2) and the fork
note (P9). The options were then decided the same day (Decisions, item 7).

The Rust crate and the Python package will get names of their own (Decisions,
item 6). Until they are chosen, `hanko-xml` and `hanko_xml` below stand in for
them wherever the text means the crate or the Python package rather than the
gem.

## Ground rules for the ports

Settled on 2026-09-24. Three libraries in three languages can't keep every rule
the Ruby gem was built under, so:

- **No existing rule is a hard constraint.** That includes CLAUDE.md,
  API_CONTRACT.md §3 and the `unsafe` budget. When a rule gets in the way of a
  port, change it, and record the change and the reason here.
- **Move to Rust what is easy to share; rewrite in each language what isn't.**
  Duplicated logic across the bindings is acceptable. The shared conformance
  suite, not a single copy of the code, is what keeps the copies in agreement.
- **More `unsafe` is acceptable.** Keep it in FFI modules and reduce it as we go.

What doesn't change are the security properties the packages promise:
`Policy.strict` is the default and fails closed, the trusted key is pinned and
`<KeyInfo>` never selects it (S-01), only bytes cross the FFI (two libxml2
builds in one process, see VENDORING.md), and error messages never contain key
material. The conformance suite checks these in every package.

## Why this is cheaper than it sounds

The hard part of HankoXml is already written in Rust and has little that is
Ruby-specific:

| File | Lines | What it does | Ruby-specific? |
|---|---|---|---|
| `ext/hanko_xml/src/dsig.rs` | ~1,500 | Parses, inspects, signs and verifies through xmlsec | No |
| `ext/hanko_xml/src/errors.rs` | ~100 | Captures xmlsec's error log | No |
| `ext/hanko_xml/src/sys.rs` | ~40 | bindgen output | No |
| `ext/hanko_xml/build.rs`, `build/vendor.rs` | ~270 + ~820 | System or vendored libxml2 2.14.6, xmlsec1 1.3.12, OpenSSL 3.5.8, pinned by SHA-256 | Partly: `RUBY_TARGET` switches vendoring on (P7) |
| `ext/hanko_xml/src/lib.rs` | ~390 | Magnus glue: the six `HankoXml::Native` functions | **Yes** |

The boundary is already the right shape for other languages. Every call is bytes
in, bytes or plain data out (`sign`, `verify`, `inspect_sig`, `versions`,
`check_version`, `abi_compatible?`), and no `xmlDocPtr` ever crosses it
(API_CONTRACT.md §3.1, VENDORING.md). A PyO3 binding would be a sibling of
`lib.rs`, not a rewrite.

## Where the security logic lives

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

If each port re-implemented all of that, three copies of the rules would drift
apart and every `S-xx` fix would land three times. So the parts that are easy to
share move into the Rust core first, and the Ruby gem becomes the first binding
over it. The parts tied to a host library (the DOM, a caller's
`OpenSSL::X509::Store`) stay in each binding and are duplicated, and the
conformance suite checks that the copies agree. The ports come after the move.

This replaces the API_CONTRACT.md §3 rule, which is rewritten in Phase 0.

## Target architecture

```
┌─────────────────────┐ ┌─────────────────────┐ ┌─────────────────────┐
│ Ruby gem hanko_xml  │ │ Python hanko-xml    │ │ Rust crate          │
│ Nokogiri parse,     │ │ lxml parse,         │ │ hanko-xml           │
│ node mapping,       │ │ node mapping,       │ │ (the core's API,    │
│ write-back, store:  │ │ write-back          │ │ bytes in/bytes out) │
├─────────────────────┤ ├─────────────────────┤ │                     │
│ ext/: Magnus glue   │ │ PyO3 glue           │ │                     │
└──────────┬──────────┘ └──────────┬──────────┘ └──────────┬──────────┘
           └───────────── bytes in, data out ──────────────┘
┌──────────────────────────────────────────────────────────────────────┐
│ hanko-xml (core): Policy, verify and sign orchestration, template    │
│ fragments, chain validation from bytes, XAdES verification, and the  │
│ FFI layer. unsafe only in FFI modules (P3).                          │
├──────────────────────────────────────────────────────────────────────┤
│ hanko-xml-sys: bindgen bindings + build.rs vendoring, links = xmlsec1│
└──────────────────────────────────────────────────────────────────────┘
```

Repository layout (one repo, one Cargo workspace):

```
crates/hanko-xml-sys/   bindgen, build.rs, build/vendor.rs, dependencies.yml
                        (moved from ext/ and the repo root)
crates/hanko-xml/       the core: dsig.rs, errors.rs, the FFI wrappers and the
                        ported security logic
ext/hanko_xml/          Magnus glue only, depends on crates/hanko-xml
python/                 PyO3 glue (src/), Python layer (hanko_xml/), pytest suite
conformance/            shared cases every binding must pass (see below)
```

### What moves into the core

- **The algorithm registry** (`Algorithms`) and its URIs.
- **Policy**: the presets (`strict`, `fragment`, `legacy_sha1`, `xades`,
  `interop`, `permissive`) and every violation check. Most of these are string
  comparisons over the `inspect_sig` result and port directly. The DOM-dependent
  ones (`require_signed_root`, `reject_duplicate_ids`) read facts that the
  core's inspect collects from its own libxml2 parse of the same bytes, the
  parse xmlsec resolves against.
- **Verifier orchestration**: the size limit, XSD validation against the bundled
  `xmldsig-core-schema.xsd`, policy before verify (S-04), key pinning as
  `signKey` (S-01), and per-reference digest status (S-09).
- **Signer checks**: key type and size, the key matching the certificate, and
  the S-05 template checks before signing.
- **Template fragments**, built with xmlsec's own template API
  (`xmlSecTmplSignatureCreate`, `xmlSecTmplSignatureAddReference`, …) rather
  than by hand (P5).
- **Chain validation from bytes**: trust anchors, intermediates and CRLs (P1,
  P2, Decisions, item 3).
- **XAdES-B verification**: the signed-properties checks and
  `SigningCertificate(V2)` matching. The core finds `<SignedProperties>` through
  its own reference resolution, so it needs no host DOM. XAdES signing stays in
  Ruby until another package needs it.
- **The FFI layer**: the RAII wrappers now in `dsig.rs`, a small safe DOM layer
  (P6), X.509 wrappers if P2 option A is chosen, and error capture.

### What each binding keeps

Some of this is security logic, duplicated on purpose (P4). Every item needs
conformance cases.

- **Parsing into the host DOM**, Nokogiri in Ruby and lxml in Python, with the
  API_CONTRACT.md §6.3 parse rules (strict, no network, no entity substitution,
  no huge mode) and the size check before parsing (S-12). lxml's parser defaults
  aren't Nokogiri's, so the Python layer sets every option explicitly.
- **Mapping the core's answers to host nodes.** The core returns document-order
  element indexes per reference. The binding turns them into Nokogiri or lxml
  nodes for `#signed?` and `#at_signed`, and checks them against its own ID
  resolution (`detect_resolution_mismatches`, S-09).
- **Write-back and placement.** The binding serializes to bytes, calls the core,
  and writes the results back into the caller's own nodes, as
  `Signer#write_back_signature` does today. The rule that only bytes cross the
  FFI matters even more in Python: lxml wheels bundle their own libxml2, just as
  precompiled Nokogiri does.
- **Key input coercion.** `OpenSSL::PKey` objects in Ruby, `cryptography` key
  objects in Python. Each is converted to PEM and handed to the core, as
  `Key#to_pem` does today.
- **Host objects the core can't read**: Ruby's `store:` (an
  `OpenSSL::X509::Store`, P1), a caller's own `schema:` object, and `resolver:`.
- **Error classes.** The core returns a typed error kind, a fixed message and
  the captured xmlsec log (S-13). Each binding maps them to its own exception
  hierarchy. Messages never contain key material.

The Rust crate has no host DOM. It works on bytes and inserts the core's
template fragments itself (P5).

## Shared conformance suite

Each port's own tests aren't enough to prove the ports behave the same, and with
logic duplicated on purpose (P1, P4) they matter more. Add a `conformance/`
directory with a manifest (JSON), where each case gives:

- the input document, keys, certificates, policy preset and options;
- the operation (`sign`, `verify`, `inspect`);
- the expected result: validity, the error kind, which references are signed
  (as element indexes), and the `S-xx` finding the case guards, if any.

The manifest's vocabulary (error kinds, options, fixed times) is defined in
Phase 0; see P8.

Seed it from the existing fixtures (`spec/fixtures`, `spec/interop`) and from
`spec/hanko_xml/adversarial_spec.rb` (tampering, signature wrapping, key
substitution, XXE, entity expansion, weak keys). The binding obligations above
each need cases: XXE and entity expansion against the host parser, oversized
input, signature wrapping and ID collisions against the node mapping, and
write-back for each placement. RSpec, pytest and `cargo test` each run the whole
manifest. A case that passes in one language and fails in another is a bug in a
binding, and CI names the case.

This is also where the ASSURANCE.md property and fuzz targets belong: fuzz the
core once, and all three packages benefit.

## Problems and options

Found in the 2026-09-24 reviews. The recommended option is marked, and each
was decided on 2026-09-24 (Decisions, item 7): P1 C, P2 B, P3 A, P4 A, P5 A,
P7 A, P9 A, and P10 resolved by the crate's own name, plus the single fixes for
P6 and P8. The problems and the options stay here as the record of why.

### P1. Host objects can't cross the FFI

`Verifier.new(store:)` takes an `OpenSSL::X509::Store` the caller built, and
callers put CRLs and verification flags into it (`spec/interop/interop_spec.rb`,
"revokes the signer through a CRL in store:"). Ruby's openssl can't list what a
store holds, so the core can't rebuild it from bytes. The same goes for
`schema:`, which accepts any object with `#validate`, and `resolver:`, which is
a Proc.

- **Option A: the core validates chains from bytes, and Ruby keeps
  `store:`.** The core takes trust anchors, intermediates, CRLs, a verification
  time and a flag to skip time checks (how it calls OpenSSL is P2). Rust and
  Python only offer this API. Ruby keeps its `store:` path working as it does
  today, and gains `trust_anchors:` and `crls:` keywords that go to the core.
  The leaf rule, the ambiguity rule, KeyUsage (#63) and `certificate_subject:`
  then exist twice, in Ruby for `store:` and in the core for everything else,
  and conformance cases pin both. `store:` can be deprecated later or kept.
  That duplicate is the first item under "Risks"; option C removes it.
- **Option B: no chain validation in the core.** Each binding validates with its
  host library (Ruby's `OpenSSL::X509::Store`, Python's
  `cryptography.x509.verification`, the `openssl` crate in Rust) and hands the
  verified leaf's public key to the core, which pins it as `signKey`, as
  `Verifier#store_trust` does today. That is three copies, and Python's verifier
  isn't OpenSSL: it builds paths its own way and, as of this writing, doesn't
  check revocation. Confirm its CRL support before picking this.
- **Option C (recommended): the core owns the rules, and Ruby's `store:` path
  runs only the verify call.** The one host-bound step in
  `Verifier#store_trust` is `OpenSSL::X509::StoreContext#verify`. The leaf
  rule, the ambiguity rule, KeyUsage (#63) and `certificate_subject:` are logic
  over certificate bytes, so the core exposes them as two calls: "candidate
  leaves for this `<KeyInfo>`", which applies the leaf rule and returns each
  candidate with the rest of the set as its chain, and "judge these verified
  leaves", which applies the ambiguity rule, KeyUsage and the subject check and
  returns the key to pin as `signKey` (S-01). Ruby's `store:` path runs
  `StoreContext#verify` per candidate between the two calls, with the time and
  flag handling it has today. The `trust_anchors:` and `crls:` keywords of
  option A run the same two calls around the core's own `X509_verify_cert`
  (P2), and Rust and Python only offer that path. One copy of each rule,
  `store:` keeps working, at the cost of a second FFI round-trip. Passing
  `store:` together with `trust_anchors:` is a `ConfigurationError`.

Whichever option wins, the core validates against the bundled schema, and a
caller's own `schema:` object or `resolver:` stays in the binding. The core's
verify therefore takes a flag to skip its XSD step, and the binding runs the
caller's schema at the same point in the order (size, XSD, policy, verify).

### P2. The planned single-OpenSSL build doesn't work

The earlier Decision 3 pointed `openssl-sys` at hanko-xml-sys's OpenSSL by
setting `OPENSSL_DIR` from hanko-xml-sys's build. A build script can't set
environment variables for another crate's build script, and `openssl-sys` would
build first anyway. The plan also relied on `symbols_spec.rb` and
`packaging_spec.rb` to catch a second copy, but the first only checks exported
symbols and the second only checks gem contents. Neither would see a second,
hidden static copy.

- **Option A: bindgen the X.509 functions from the libcrypto xmlsec already
  links.** Add `X509_STORE`, `X509_STORE_CTX`, `X509_verify_cert`,
  `X509_check_private_key` and the PEM/DER readers to the bindgen allowlist,
  and wrap them in the FFI layer. The OpenSSL pin stays in `dependencies.yml`
  with its SHA-256, and the system path gets OpenSSL's headers from
  pkg-config, which already reports them for `xmlsec1-openssl`. The cost is
  more `unsafe`, which the ground rules accept. "One OpenSSL by construction"
  holds for the gem and the wheel, which are self-contained cdylibs, but not
  for the Rust crate: the sys crate would link a libcrypto without going
  through `openssl-sys`, whose `links = "openssl"` is what gives Cargo one
  OpenSSL per build graph. A downstream program that also pulls in
  `openssl-sys`, through reqwest with native-tls for example, links two
  libcryptos into one binary. Hidden visibility guards against a second
  dynamic copy, not against two static archives resolved by one linker, so
  the outcome is duplicate-symbol errors or a silent mix of object files from
  two versions. That rules A out for the crate, and using A for the gem and B
  for the crate would be two OpenSSL build paths to keep in step.
- **Option B (recommended): the `openssl` crate, with `openssl-sys` owning
  OpenSSL.** The sys crate depends on `openssl-sys` and forwards its
  `vendored` feature, which builds OpenSSL through `openssl-src`, and
  hanko-xml-sys configures xmlsec against the paths `openssl-sys` passes to
  the crates that depend on it (`DEP_OPENSSL_INCLUDE`, and its install root
  when vendored), the way curl-sys and libgit2-sys share one OpenSSL. Every
  Cargo graph then has one OpenSSL, the API is safe, chain validation uses the
  `openssl` crate rather than new X.509 wrappers (most of that item in P6 goes
  away), and `openssl-src` also embeds OpenSSL's source for crates.io (P7).
  The pin moves from `dependencies.yml` to an `openssl-src` version
  (VENDORING.md changes), and `openssl-src`'s configure flags differ from
  `vendor.rs`'s, which deliberately leaves out `no-legacy` and builds with
  hidden visibility, so the algorithm set has to be checked again. Keep the
  hidden-visibility flags: `openssl-src` compiles through the `cc` crate,
  which honors `CFLAGS`, and `spec/symbols_spec.rb` keeps guarding the
  result. Add a spec that the built library holds exactly one OpenSSL, for
  example by comparing the version each side reports at runtime.

### P3. `forbid(unsafe_code)` can't exclude one module

A crate-level `#![forbid(unsafe_code)]` can't be relaxed by an `allow` inside a
module (rustc error E0453), so "forbid outside the FFI module" can't be written.
The Magnus glue also has one `unsafe` today, the `RString::as_slice` copy in
`lib.rs`, which `native_spec.rb` allows.

- **Option A (recommended for now): deny, then allow per module.**
  `#![deny(unsafe_code)]` at each crate root and `#[allow(unsafe_code)]` on the
  FFI modules only. It is a lint rather than a guarantee, but every exception is
  one greppable attribute, and `native_spec.rb` is rewritten to list the modules
  that carry it.
- **Option B (later): a separate FFI crate.** Move the safe wrappers (the RAII
  types from `dsig.rs`, `errors.rs`, the DOM and X.509 wrappers) into their own
  crate and forbid `unsafe` in all of `hanko-xml`. Worth doing once the wrapper
  API stops changing.

### P4. Some security logic has to stay in each binding

Every binding parses its input with its host parser before the core sees any
bytes, and maps the core's answers back to host nodes. That work can't move into
the core: the parse rules (API_CONTRACT.md §6.3, `HankoXml.parse`), the size
check before parsing (S-12, `HankoXml.coerce_document`), the element-index to
host-node mapping (S-09, which depends on the host parser and the core agreeing
on element order), `detect_resolution_mismatches`, and write-back.

- **Option A (recommended): each binding implements them.** They are listed
  under "What each binding keeps", and the conformance suite has cases for each.
- **Option B (add if Python needs it): the core goes first on raw input.** For
  String or IO input, the binding hands the raw bytes to the core first (size
  check, parse, policy, verify) and only then parses them into the host DOM for
  the `Verification` view, so hostile input is rejected before any host parse.
  The node mapping then relies on the host parsing the same raw bytes the same
  way, which needs its own conformance cases.

### P5. Templates built in the core don't fit write-back

Ruby inserts the template into the caller's own DOM (`Placement#insert`) and
after signing copies only the values back (`Signer#write_back_signature`). That
is the write-back guarantee of API_CONTRACT.md §6.4, and `Signer#template(doc)`
is public API that returns a node. The Rust crate has no host DOM, so it needs
templates built in the core anyway.

- **Option A (recommended): the core returns a template fragment.** The core
  builds a standalone `<Signature>` with xmlSecTmpl* and returns it as bytes.
  The Rust crate inserts it itself. Python, and Ruby when convenient, parse the
  fragment and insert it with Placement, then carry on as today. S-05 checks
  every template in the core before signing, so the host-side insert isn't a
  security step.
- **Option B: each binding keeps its own builder.** Ruby keeps `Template`,
  Python ports it to lxml, and only the Rust crate uses the core's builder. For
  the same S-05 reason, drift between builders is an interop problem, not a
  security one.

### P6. `unsafe` grows

Walking the DOM for `require_signed_root` and duplicate IDs, xmlSecTmpl*,
`xmlSchema*` for XSD validation, XPath for placement and XAdES, and the X.509
wrappers of P2 option A are all new FFI. API_CONTRACT.md §3's promise that a new
algorithm, document shape or trust mode adds no `unsafe` no longer holds. The
DOM walk has a start: `collect_reference_element_indexes` in `dsig.rs` already
walks the document in order and calls `xmlGetID`, and under P2 option B the
X.509 wrappers aren't needed.

The ground rules accept this. Two things keep it manageable, and both should
happen:

- A small safe DOM layer in the FFI modules: node handles tied to the lifetime
  of `OwnedXmlDoc`, with children, attributes, namespaces, text and ID lookup.
  It grows as features need it, so most new code is safe Rust on top of it.
- Bring two ASSURANCE.md items forward to before Phase 2 step 2, when the first
  DOM FFI lands: the ASan/LSan run of the suite and the `cargo-fuzz` verify
  target.

### P7. Publishing the sys crate

The gem's build works because CI builds it. A crate on crates.io and a Python
sdist get built by strangers:

- `vendor.rs` downloads the tarballs during the build. docs.rs builds without
  network access, and offline builds fail.
- `HANKO_XML_VENDOR` or `RUBY_TARGET` switches vendoring on, and neither is set
  in a Cargo or maturin build.
- bindgen needs libclang and the headers. docs.rs has neither xmlsec nor our
  pinned libraries, and every `cargo build` and sdist install would need
  libclang too.
- The vendored build is autotools plus MinGW. Rust's default Windows target and
  python.org's CPython are MSVC.

The Cargo features are the same under both options: `vendored` and `system`
take precedence over the environment variables, which stay for the gem. The
crate defaults to `system`, as `openssl-sys` does, and the wheels and platform
gems build with `vendored`. The options are about sources and Windows:

- **Option A (recommended first): keep downloading, and use MinGW on Windows.**
  `vendored` keeps downloading, checked against `dependencies.yml`, and the
  crate documents that it needs network access. `vendored` uses bindings
  generated ahead of time and checked in, one file per target, since the
  pinned libraries have a fixed ABI; bindgen becomes an opt-in
  `buildtime-bindgen` feature for regenerating them. On docs.rs (the `DOCS_RS`
  variable) the build skips the C libraries and uses the same files. `system`
  keeps running bindgen at build time, because xmlsec 1.2 and 1.3 differ in
  struct layout. Windows wheels and the crate's `vendored` feature target
  `x86_64-pc-windows-gnu`, reusing the MinGW path the gem already has. PyO3 and
  maturin support that target; confirm the wheel loads in python.org's CPython.
  MSVC Rust users get `system` only.
- **Option B (later): embed sources, and build natively with MSVC.** The crate
  ships the pinned tarballs (or depends on `-src` crates) within crates.io's
  10 MB limit. libxml2 and xmlsec1 fit, and OpenSSL needs `openssl-src` (P2
  option B) or a trimmed tarball. `vendor.rs` gains an MSVC path: CMake for
  libxml2, xmlsec's `win32/configure.js` with nmake, and OpenSSL's `VC-WIN64A`
  target.

### P8. The conformance manifest needs a shared vocabulary

The core has four error kinds (`Parse`, `KeyLoad`, `Signing`, `Native`), while
Ruby raises about fifteen error classes. Policy presets alone don't cover what
the specs configure (`Policy#with` overrides, `id_attributes:`, `signature:`,
`referenced_documents:`, `certificate_subject:`), and the fixtures'
certificates expire.

Fix, in Phase 0, as part of the manifest schema:

- a list of neutral error kinds (`policy`, `parse`, `schema`, `reference`,
  `untrusted_certificate`, `certificate_expired`, `signature_missing`,
  `verification_failed`, `configuration`, …), with each binding's mapping to
  its own classes;
- an options object that mirrors the `Signer` and `Verifier` keywords;
- a fixed `verification_time` on every case;
- signed references as document-order element indexes, which every binding can
  compute.

### P9. Threading without the GVL

`errors.rs`, the referenced-documents map in `dsig.rs` and API_CONTRACT.md §9
argue their safety from "the GVL is held". A Rust caller can call from any
thread, and Python may release the GIL or not have one (free-threaded 3.13t and
later, which abi3 wheels don't cover).

- **Option A (recommended first): hold the GIL, and restate the contract per
  thread.** The Python glue holds the GIL for every core call, as Ruby holds the
  GVL, and ships abi3 wheels for GIL builds only. For Rust, calls are synchronous
  and each runs on one thread from start to finish. The thread-locals are per OS
  thread, so they stay correct for concurrent calls on different threads, and
  the comments in `errors.rs`, `dsig.rs` and API_CONTRACT.md §9 are rewritten
  in those terms. Rust users will call concurrently from day one, so a
  concurrent-calls stress test under ASan and TSan runs before the crate is
  published. API_CONTRACT.md §9's advice to initialize in the parent before
  forking carries over to Python's `multiprocessing` with the fork start
  method, and the Python docs say so.
- **Option B (later): release the GIL.** Release it around sign and verify for
  parallelism, and add free-threaded wheels, once that stress test passes.

### P10. Crate names collide

The gem's extension package is named `hanko_xml`. If the core were also called
`hanko-xml`, Cargo and crates.io, which treat `-` and `_` as the same, would
see two crates named `hanko_xml` in one workspace.

- **Option A: rename the extension crate.** This is less free than it looks.
  rb_sys builds the Makefile so that `RUSTLIB` is `lib<target>.so`, where
  `<target>` is the argument to `create_rust_makefile` in `extconf.rb`, and
  copies it to `<target>.so`. So the crate's library name and the installed
  file name must match, and renaming the crate means renaming the whole
  chain: the package, the extconf target (`hanko_xml/hanko_xml_ruby`),
  `#[magnus::init(name = "hanko_xml_ruby")]` (Magnus supports `name` and emits
  `Init_hanko_xml_ruby`, which Ruby expects for that file name), the two
  `require_relative` lines in `lib/hanko_xml.rb`, the Rakefile's extension
  task, the artifact list in `spec/symbols_spec.rb` and the cross-gem install
  check.
- **Option B: rename the core's library instead.** Keep the extension as is and
  give the core crate a different library name. Rust users then import a name
  that doesn't match the package.
- **Resolved by Decisions, item 6:** the Rust crate gets a name of its own, so
  there is no collision and the extension keeps `hanko_xml`. Option A stays
  here as the recipe should the extension ever need renaming. The PyO3 module
  gets a private name under the Python package, such as `<package>._native`.

## Phases

Each phase is one or more PRs and leaves the Ruby gem shippable. The Ruby spec
suite is the safety net throughout: it must pass unchanged, except for specs
that assert where code lives.

### Phase 0: Contract update, open decisions and conformance seed

- Rewrite API_CONTRACT.md §3 for "shared rules in the core, host-bound checks
  and ergonomics in each binding" (Ground rules, Decisions, item 2).
- The options for P1 to P10 are decided (Decisions, item 7); Phase 1 builds on
  P2 and P3.
- Choose the names of the Rust crate and the Python package (Decisions,
  item 6), and check they are free on crates.io and PyPI before anything is
  named after them.
- Define the manifest vocabulary (P8), then create `conformance/` and a Ruby
  runner for it, seeded from the existing fixtures and adversarial cases, and
  passing against today's gem. This pins current behavior before anything
  moves. While CI is paused, it runs locally like everything else (Decisions,
  item 5).

### Phase 1: Split the crate (no behavior change)

- Move bindgen, `build.rs` and `build/vendor.rs` into `crates/hanko-xml-sys`,
  along with `dependencies.yml` from the repo root, since `cargo package` only
  ships files inside the crate's directory. Add `crates/` to the allowlist in
  `hanko_xml.gemspec` (today `lib/`, `ext/`, `sig/` plus the root Cargo files
  and `dependencies.yml`), or the source gem can't compile the extension.
  Update the paths in the Rakefile, `.github/workflows/vendored-deps.yml`,
  `spec/packaging_spec.rb`, `spec/symbols_spec.rb` and VENDORING.md. Move
  `dsig.rs` and `errors.rs` into `crates/hanko-xml`. `ext/hanko_xml` keeps
  only the Magnus glue, under its current name (P10).
- Confine `unsafe` per P3, and update `spec/hanko_xml/native_spec.rb` to match.
- If P2 option B is picked, switch the OpenSSL build over here, since it
  changes the build graph.
- Check that the platform gems still build (`cross-gem.yml`, run locally while
  CI is paused) and that the `HANKO_XML_VENDOR=1` and system-library builds both
  pass.

### Phase 2: Move the easy-to-share security logic into the core

The ASan run and the `cargo-fuzz` verify target (P6) come first. Then, in this
order, each step a PR. Each step deletes the Ruby it replaces, unless Ruby keeps
a copy on purpose (P1, P5):

1. The algorithm registry and the policy checks that only read `inspect_sig`
   output.
2. The DOM-dependent policy checks. The core's inspect also returns the facts
   they need (the root's ID values, duplicate ID values, which elements the
   references resolve to), so `require_signed_root` and `reject_duplicate_ids`
   become checks over one record with no second parse, and Policy stays a pure
   function that is easy to property-test. The safe DOM layer (P6) starts
   here, from the walk `collect_reference_element_indexes` already does.
3. Verifier orchestration: size limit, XSD validation against the bundled
   schema, inspect, policy, verify, per-reference status. The core takes trust
   that's already resolved (pinned keys and certificates), so Ruby's trust
   collection, including `store:`, keeps working in front of it. The key size
   and certificate date checks (S-06, S-07) stay in Ruby until step 5 brings
   X.509 parsing into the core. The verify call takes a flag to skip the XSD
   step for callers with their own `schema:` object (P1). This returns a
   `Verification` data record that Ruby wraps.
4. Signer: key type and size, the key matching the certificate, and S-05 in the
   core, plus the template-fragment builder (P5). Ruby keeps `Placement`
   resolution and write-back.
5. Chain validation from bytes, with the key size and certificate date checks,
   per Decisions, item 3 (P1, P2). Under P1 option C this lands as the two
   calls (candidate leaves, judge verified leaves), and Ruby's `store:` path
   switches to them in the same PR so only one copy of the rules remains.
6. XAdES-B verification.

API_CONTRACT.md, SECURITY_REVIEW.md citations and the RBS signatures are updated
in the same PR as each step. Nothing is removed from the public Ruby API. New
keywords, such as `trust_anchors:` and `crls:` under P1 option A, may be added.

### Phase 3: Rust crate

Starts once Phase 2 is complete and the repo is public.

- A public API for `hanko-xml`: a `Signer` builder, `Verifier`, `Policy`
  presets, and a `Verification` with the signed-reference view. It works on
  bytes, with an optional DOM-free "verify and return the signed bytes" helper
  for callers that have no DOM. Placement for the core's template fragments:
  append to the root, or before or after an element found by ID or XPath (XPath
  through libxml2).
- Cargo features, docs.rs and Windows per P7.
- Hooks that only the Ruby and Python glue use are `#[doc(hidden)]` or behind
  an unstable feature, so refactoring a binding doesn't force a major release
  of the crate.
- The concurrent-calls stress test from P9.
- rustdoc, examples, and publishing to crates.io with trusted publishing.

### Phase 4: Python package

Starts once Phase 2 is complete and the repo is public.

- PyO3 glue that holds the GIL during core calls (P9), with abi3 wheels built by
  maturin and the static vendored build: x86_64-linux and aarch64-linux
  (manylinux), arm64-darwin, and x86_64 Windows per P7. The gem ships these,
  apart from Windows, where it ships MinGW `x64-mingw-ucrt`. musllinux would be
  new vendoring work the gem doesn't do; add it when someone asks.
- A Python layer shaped like the Ruby one: `hanko_xml.sign`, `hanko_xml.is_valid`,
  `Signer`, `Verifier`, `Verification` with `signed` and `at_signed`, and lxml as
  the optional DOM, parsed under the P4 rules. Type hints ship with it
  (`py.typed`).
- Chain validation per Decisions, item 3: `trust_anchors=` and `crls=` handed to
  the core (P1 option A or C), or `cryptography`'s verifier (P1 option B).
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
   suite runs against all three bindings in one CI run. polars and tokenizers
   publish a Rust crate and its Python bindings from one repo the same way.
   pydantic-core and cryptography also keep their Rust and Python code in one
   repo, though they don't publish the Rust part as a crate.
   - **CI:** every workflow filters on paths, so a Python-only change doesn't
     build gems (as `pages.yml` already does). A change under `crates/` runs
     all three bindings, since all three depend on the core.
   - **Tags:** one prefix per package: `gem-v*`, `crate-v*` and `py-v*`. Each
     release workflow triggers only on its own prefix.
   - **Discoverability:** the README lists all three packages, and the
     crates.io and PyPI metadata link to the package's subdirectory.
   - **Visibility:** the repo stays private for now and goes public later.
     Phases 0–2 don't depend on it. Phases 3 and 4 wait for it: the crate and
     the wheels are published only once the repo is public, so docs.rs and PyPI
     never link to source nobody can open.
   - A binding can still move out later, once the core API is stable, if it gets
     its own maintainers or pace. Splitting later is easy; merging repos back
     together is not.
2. **Security logic moves into Rust where it's easy to share.** The reason for
   the ports is to reuse the security rules, so the shareable ones live in the
   core, and the ones tied to a host library are duplicated in each binding
   (Ground rules, P4). This replaces "policy in Ruby, crypto in Rust"
   (API_CONTRACT.md §3) with "shared rules in the core, host-bound checks and
   ergonomics in each binding". §3 also argued that Rust grows `unsafe` with
   every feature. That is true (P6), and the ground rules accept it.
3. **Certificate chains: the `openssl` crate over the OpenSSL that
   `openssl-sys` owns (P2 option B), with the rules in the core and Ruby's
   `store:` running only the verify call (P1 option C).** The earlier choice
   was the `openssl` crate pointed at our vendored OpenSSL, which can't be
   built as planned (P2), and a caller's `OpenSSL::X509::Store` can't reach the
   core (P1); item 7 records the evidence. What holds under both:
   - **Not xmlsec's store.** Both P2 options call OpenSSL's `X509_verify_cert`
     directly, which is also what xmlsec's store runs underneath. Going through
     xmlsec's store brings problems:
     - xmlsec validates chains while resolving `<KeyInfo>` through a keys
       manager, the path where the document chooses the key, which S-01
       forbids. Using its store would mean calling
       `xmlSecOpenSSLX509StoreVerify` directly and working around that design.
     - xmlsec1 1.3 changed X.509 behavior (strict checks,
       `XMLSEC_KEYINFO_FLAGS_X509DATA_SKIP_TIME_CHECKS`), so trust results could
       differ between the system 1.2.39 build and the vendored 1.3.12 one.
   - **What carries over from `Verifier#store_trust`:** a leaf is a certificate
     that issued no other certificate in the set, with no reliance on document
     order. A `<KeyInfo>` where more than one leaf chains to the store is
     rejected. `check_certificate_validity: false` maps to
     `X509_V_FLAG_NO_CHECK_TIME`, and `verification_time:` to the store
     context's time. The KeyUsage requirement (#63) and `certificate_subject:`
     still apply. The verified leaf's public key is then pinned as `signKey`
     (S-01). CRLs remain the only revocation input.
4. **Each package has its own version and its own changelog.** A core change is
   released in each binding that ships it. The changelog entry in that binding
   names the core change, so no package gets an empty release. Every release
   records the core version it bundles (for Ruby, in `NativeVersion`).
   `CHANGELOG.md` stays the gem's, and each other package gets a `CHANGELOG.md`
   in its own directory. The `**#NN:**` tagging rule applies to all of them.
5. **CI.** CI stays paused until October 2026 to save Actions budget (see
   CLAUDE.md). Until then, each phase's PRs are checked locally: the full suite,
   rubocop and clippy, on both the system libraries and `HANKO_XML_VENDOR=1`,
   plus `cargo test` for the core crates once they exist. New workflows (core
   crate tests, the Python wheel matrix, the conformance run) are written with
   their automatic triggers commented out as `CI-PAUSED`, like the existing
   ones. When CI resumes, consider running the full wheel matrix only on
   release tags, with a small Linux job on PRs.

6. **Each package gets its own name.** The gem stays `hanko_xml`: hanko is
   Japanese for a seal, a name chosen to sit next to Nokogiri. The Rust crate
   and the Python package get names that fit their own ecosystems, still to be
   chosen; `hanko-xml` and `hanko_xml` in this document are placeholders for
   them. The Rust crate's own name also removes the P10 collision, so the
   extension crate keeps `hanko_xml`. For the record, `hanko-xml`,
   `hanko_xml` and `hanko-xml-sys` were unregistered on crates.io and
   `hanko-xml` on PyPI on 2026-09-24.
7. **The options in "Problems and options"**, decided on 2026-09-24 with what
   was checked for each:
   - **P1, option C.** Needs no outside fact: `Verifier#store_trust` already
     separates the `StoreContext#verify` call from the leaf, ambiguity,
     KeyUsage and subject logic, so the two-call split follows its shape.
   - **P2, option B.** openssl-sys 0.9.117 declares `links = "openssl"`, has a
     `vendored` feature backed by `openssl-src`, and its build script prints
     `cargo:include` always and `cargo:root` when vendored, which is what the
     sys crate needs to configure xmlsec. Whether `openssl-src` honors the
     hidden-visibility `CFLAGS` and matches the current algorithm set is
     checked by the Phase 1 spec, not assumed.
   - **P3, P4 and P9, option A.** Design choices with no open facts. The P9
     stress test still runs before the crate is published.
   - **P5, option A.** xmlsec has `xmlSecTmplSignatureCreateNsPref`, so the
     core can build the fragment with the `ds:` prefix Ruby's template uses.
   - **P7, option A** for Linux and macOS, with the pregenerated bindings.
     Windows is easier than the text above assumed: PyO3 now links
     `python3.dll` through `raw-dylib`, so the GNU target no longer needs the
     import-library machinery. Whether a MinGW abi3 wheel loads in python.org's
     CPython is checked in Phase 4.
   - **P10.** Resolved by item 6. The rb_sys naming rule is recorded under P10
     in case the extension ever needs renaming.
   - **P6 and P8** are fixes, not choices, and stand as written.

Still open:

8. **The names themselves** for the Rust crate and the Python package (item 6).
   Phase 0 needs them before `crates/` and `python/` are created.

## Risks

- **Drift between duplicated copies.** Ruby's `store:` path and the core's chain
  validation (P1 option A; option C removes this one), the template builders
  (P5 option B), and every binding obligation (P4) exist more than once. The conformance suite is the only thing
  that keeps them in agreement, so each duplicate needs cases that exercise both
  copies.
- **Behavior drift during Phase 2.** Code that moves from Ruby into Rust can
  change behavior in ways the Ruby specs don't notice. The Phase 0 conformance
  seed is what catches this, which is why it comes first. Two changes are known
  in advance and each needs a CHANGELOG entry:
  - XSD validation moves from Nokogiri's libxml2 to the core's. With the system
    libraries on Linux, which one ran used to depend on load order, so this
    makes it predictable, but the system libxml2 2.9.14 keeps its XSD integer
    limits.
  - Chain verdicts for the new `trust_anchors:` keyword come from the core's
    OpenSSL (3.5.8 in platform gems) instead of whichever libcrypto Ruby's
    openssl links. Under P1 option A or C the `store:` path keeps running
    Ruby's `StoreContext#verify`, so existing callers see no change; it
    becomes one only if `store:` is deprecated later.
- **Two libxml2 versions in Python.** lxml bundles its own. Bytes-only crossing
  handles this, as it does for Nokogiri, but the Python layer must never be
  "optimized" into sharing pointers.
- **System library differences.** The system build (libxml2 2.9.14, xmlsec1
  1.2.39) behaves differently from the vendored one: XSD integer limits, the
  text node size limit, ECKeyValue. Python and Rust users on the `system`
  feature inherit the same gaps, so the conformance suite needs the same
  capability gating that `HankoXml::NativeVersion.build_versions` gives the
  Ruby specs.
- **A different chain validator in Python.** Under P1 option B, Python's
  verdicts come from `cryptography`, not OpenSSL, and can differ on edge cases
  and revocation.
- **Windows.** Under P7 option A, the Windows wheel is a MinGW build loaded by an
  MSVC-built CPython. If that proves fragile, Windows waits for P7 option B.
- **Scope.** Phase 2 is most of the work. Phases 3 and 4 are packaging plus the
  binding obligations of P4 once it's done, and neither should start before
  Phase 2 is complete. If Phase 2 stalls, there is a shorter route to a Python
  package: after Phases 0 and 1, bind the existing six functions from PyO3,
  duplicate the policy layer in Python, and let the conformance suite show
  which duplicates actually hurt before moving them into the core. That fits
  the ground rule to rewrite what isn't easy to share. Decision 2 chose the
  core-first order, so this is the fallback, not the plan.
