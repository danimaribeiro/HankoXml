# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the gem version
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html) **over the
Ruby API only** — the libxmlsec1 version the extension is built against is
tracked separately, and is reported by `HankoXml::NativeVersion.build_versions`.

## [Unreleased]

### Added

- `HankoXml::NativeVersion.check!` runs at require time and refuses to load
  when the libxmlsec1 present at runtime is not ABI compatible with the headers
  the extension was compiled against. `build.rs` bakes xmlsec's and libxml2's
  struct layouts into the extension via bindgen, and a mismatch is invisible to
  the dynamic linker — every symbol still resolves, and a field is then read at
  the wrong offset. `HANKO_XML_SKIP_VERSION_CHECK` downgrades it to a warning.
- `HankoXml::NativeVersionMismatch`, raised by the above. It subclasses
  `NativeError`, so an existing `rescue HankoXml::Error` still catches it.
- `HankoXml::Native.abi_compatible?`, exposing xmlsec1's
  `xmlSecCheckVersionABICompatible` mode alongside the existing exact-match
  `check_version`.
- Gemspec metadata: `bug_tracker_uri`, `documentation_uri`,
  `rubygems_mfa_required`, and `xmlsec1_version_requirement` (the libxmlsec1
  range these bindings are known to work against).
- A tag-triggered release workflow using RubyGems trusted publishing, which
  builds the gem, installs it into a clean `GEM_HOME` to prove the packaged
  file list is complete, and cuts a GitHub Release. See `RELEASING.md`.
- An opt-in vendored build (`HANKO_XML_VENDOR=1`) that compiles libxml2 and
  xmlsec1 from the source pinned in `dependencies.yml`, verifies their SHA256
  before extracting, and links them statically with hidden visibility. Groundwork
  for precompiled platform gems; the default build still uses system libraries,
  so this path does not run on an ordinary `gem install`. See `VENDORING.md`.
- OpenSSL 3.5.8 (LTS) is vendored statically alongside libxml2 and xmlsec1.
  Linking the system libcrypto could not work for precompiled gems: the build
  container decides the soname the gem records, and it is never the user's --
  a gem built against the container's OpenSSL 1.1 would not load anywhere
  current. The vendored build now has no external crypto dependency at all.
- `spec/symbols_spec.rb`, asserting the extension exports no `xml*`/`xmlSec*`
  symbols. Two statically-linked libxml2 copies in one process (ours and
  Nokogiri's) would otherwise be resolved by load order on Linux, binding our
  calls to the wrong library.

### Fixed

- `Verification#references` (and everything built on it — `#signed?`,
  `#signed_nodes`, `#covers_root?`, `#at_signed`, `#signed`) raised
  `FrozenError` on every call: the object froze itself in `initialize`, but
  `#references` computed and cached itself lazily on first access. Nothing in
  the test suite called it through the public, memoized path, so this went
  uncaught. `#references` is now computed during construction, before the
  object freezes.
- `Verification#resolve_fragment_reference`'s reference resolution replaced a
  hardcoded, string-interpolated XPath (`@Id='#{id}' or ...`) with
  variable-bound XPath, and made the `id_attributes:`/`resolver:` options it
  already accepted actually used, closing an XPath-injection path in the
  anti-XSW reference resolver.
- `Verifier#verify_single` passed `id_attributes:` straight through to
  `Native.verify`, which only accepts plain strings. A namespace-qualified
  `[ns, name]` entry (a Ruby-side-only refinement `Verification` understands)
  crashed with `"array element is not a String"` the moment a caller used it.
  Native calls now go through `#native_id_attributes`, which reduces each
  entry to its local name — the native ID table is namespace-unaware anyway.
- A caller-supplied `resolver:` was never checked against `id_attributes:`
  when both were configured, so `Verification#signed?` could report a node as
  covered based on the resolver's answer while `Native.verify` (which only
  ever sees `id_attributes:`) verified a *different* node with the same ID.
  `HankoXml::ResolutionMismatch` existed for exactly this per
  `API_CONTRACT.md` §5.9 but was never raised. It now is, whenever `resolver:`
  and `id_attributes:` are both non-empty and disagree on a reference's
  target.
- `Verifier` accepted `store:` and `key:` at construction but never used them
  during verification, so documented trust modes failed closed. `store:` now
  identifies the KeyInfo end-entity (not document order), validates that cert
  through `OpenSSL::X509::StoreContext` without mutating the caller's store,
  and hands libxmlsec1 only the validated leaf. `key:` / key-valued `keys:`
  entries pass a public-key PEM into `Native.verify`, which pins it as
  `signKey` so KeyInfo is ignored, matching `API_CONTRACT.md` §5.6.

### Changed

- `SECURITY_REVIEW.md` is the follow-up tracker (GitHub issues could not be
  opened from the cloud agent). It records which findings PR #30 closed
  (S-02, S-08), which it narrowed (S-01, S-06, S-07), and which remain open.
  `SIGNING_TEST_COVERAGE.md` marks trust-source specs T1–T4 as passing.
- `spec.files` is now an allowlist over `git ls-files` rather than a reject
  list. The gem was shipping the entire Astro docs site, `API_CONTRACT.md`, and
  the design assets — 103 files and 734 KB, now 44 files and 169 KB.
- CI runs the matrix on both Ubuntu and macOS across Ruby 3.1–3.4, instead of
  Ruby 3.3.6 on Ubuntu alone.
- `required_ruby_version` is now `>= 3.1.0`. Ruby 3.0 is end-of-life and was
  never in the CI matrix.

## [0.1.0] - 2026-08-31

- Initial release
