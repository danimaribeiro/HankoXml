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
- `spec/symbols_spec.rb`, asserting the extension exports no `xml*`/`xmlSec*`
  symbols. Two statically-linked libxml2 copies in one process (ours and
  Nokogiri's) would otherwise be resolved by load order on Linux, binding our
  calls to the wrong library.

### Changed

- `spec.files` is now an allowlist over `git ls-files` rather than a reject
  list. The gem was shipping the entire Astro docs site, `API_CONTRACT.md`, and
  the design assets — 103 files and 734 KB, now 44 files and 169 KB.
- CI runs the matrix on both Ubuntu and macOS across Ruby 3.1–3.4, instead of
  Ruby 3.3.6 on Ubuntu alone.
- `required_ruby_version` is now `>= 3.1.0`. Ruby 3.0 is end-of-life and was
  never in the CI matrix.

## [0.1.0] - 2026-08-31

- Initial release
