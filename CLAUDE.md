# CLAUDE.md

HankoXml is an XML-DSig library for Ruby. Its native extension (`ext/hanko_xml`,
Rust through Magnus, with bindgen bindings) wraps libxmlsec1 and libxml2.
Nokogiri is the optional DOM layer.

## Workflow

- Never push code straight to `main`. Work on a branch, open a PR, wait for CI
  to go green, then merge it.
- Documentation-only changes (Markdown docs, `CLAUDE.md`, comments in docs) may
  be committed and pushed straight to `main`. Anything touching `lib/`, `ext/`,
  `spec/`, `sig/`, build files or workflows goes through a PR.
- Locally, run only the specs for the code you touched
  (`bundle exec rspec spec/path/to_spec.rb`, plus `bundle exec rubocop` on changed
  files). Leave the full suite and the OS/Ruby matrix to CI.
- If CI fails, fix it on the same branch and wait for green again before merging.
- Every fix or feature gets a spec. A bug found but not fixed yet becomes a
  `pending "#NN: ..."` spec with its own issue.

## Layout

- `lib/hanko_xml/`: the Ruby API. `Signer`, `Verifier` and `Verification` are
  the entry points, `Policy` is the allowlist, and `Template` builds the
  `<Signature>` skeleton.
- `ext/hanko_xml/src/`: `lib.rs` is the Ruby boundary, `dsig.rs` drives xmlsec,
  `errors.rs` captures xmlsec's error log, and `sys.rs` holds the bindgen output.
  `unsafe` belongs only in `dsig.rs`, `errors.rs`, `sys.rs` and the one
  `rstring_to_bytes` copy in `lib.rs`: the crate root denies `unsafe_code` and
  allows it only there, and every `unsafe` block needs a `// SAFETY:` comment
  (`clippy::undocumented_unsafe_blocks`). `spec/hanko_xml/native_spec.rb`
  checks these attributes stay in place.
- `sig/`: RBS signatures. Update them when a public signature changes.
- `lib/hanko_xml/xmldsig-core-schema.xsd`: the W3C schema with local changes,
  each marked with a `HankoXml:` comment.

## Documents to keep in sync

- `API_CONTRACT.md`: the spec for the public API. Change it along with behavior.
- `CHANGELOG.md`: add an entry under `[Unreleased]` for every user-visible
  change, tagged with its issue number (`**#NN:**`).
- `SECURITY.md`: the disclosure policy. Update its supported-versions table
  with each minor release.
- `SECURITY_REVIEW.md`: findings numbered `S-xx`. Cite them in comments and
  specs where a check exists because of one.
- `SIGNING_TEST_COVERAGE.md`, `VENDORING.md`, `RELEASING.md`: update these when
  their subject changes.
- `ASSURANCE.md`: the roadmap for property-based specs, fuzzing and `unsafe`
  checks. When one of its items lands, move it to "In place".
- `PORTS.md`: the plan for Rust and Python ports sharing one core. Mark a phase
  done when it lands.

## Security conventions

- Let xmlsec1 do the security work. The library exists to build on its years of
  hardening, so canonicalization, digests, signature math, reference resolution
  and key handling belong in xmlsec, reached through its own flags and APIs
  (for example `XMLSEC_DSIG_FLAGS_USE_VISA3D_HACK` for bare `#id` lookup). Don't
  reimplement them in Ruby or Rust. Ruby may reject input earlier to give a
  clearer error, like the key-type check before signing, but must never accept
  something xmlsec would reject or make a trust decision xmlsec should make.
  When a fix seems to need new security logic, look for the xmlsec mechanism
  first.
- Fail closed. `Policy.strict` is the default and denies SHA-1, HMAC, RSA-PSS,
  SHA-3, XSLT and XPath transforms, and external references unless a policy
  allows them (`Policy.legacy_sha1`, `Policy.xades`).
- Verification pins the trusted key as xmlsec's `signKey`, and the document's
  `<KeyInfo>` never selects the key (S-01).
- On `:adopt`, check a template against policy and the Signer's references
  before any `Native.sign` (S-05), and don't modify the caller's document until
  those checks pass.
- Only serialized bytes cross the FFI, never an `xmlDocPtr`: Nokogiri and the
  extension may run different libxml2 builds. See `VENDORING.md` and `build.rs`.
- Error messages must never include key material. A misuse is a
  `ConfigurationError` (`PolicyError` for policy); reserve `SigningError` and
  `NativeError` for failures inside xmlsec.

## Builds and library versions

- `bundle exec rake compile` links the system libxml2/xmlsec1.
  `HANKO_XML_VENDOR=1 bundle exec rake compile` builds the pinned vendored copies
  (libxml2 2.15.4, xmlsec1 1.3.12, OpenSSL 3.5.9), as the platform gems do.
- CI's Ubuntu jobs use the system libraries (libxml2 2.9.14, xmlsec1 1.2.39),
  which behave differently from the vendored ones: XSD integer limits, the text
  node size limit, ECKeyValue support. Anything that depends on libxml2 or xmlsec
  behavior must pass on both. Gate a spec on
  `HankoXml::NativeVersion.build_versions` only when the difference is a
  genuine capability gap.
- On Linux with system libraries, whichever of hanko_xml or Nokogiri loads first
  decides which libxml2 the other runs on.
- To reproduce the Ubuntu CI jobs, use an `ubuntu:24.04` container with
  `libxmlsec1-dev libxml2-dev pkg-config libclang-dev ruby-full`. When copying
  sources in, touch them (`tar -xmf`), or cargo keeps a stale build.
