# Releasing hanko_xml

Releases are cut by pushing a `v*` tag. Nothing is published from a laptop, and
there is no RubyGems API key in this repository's secrets — `.github/workflows/release.yml`
authenticates to RubyGems with OIDC (trusted publishing) at the moment of the push.

## Why this gem needs more care than a pure-Ruby one

`ext/hanko_xml/build.rs` runs bindgen against whatever `xmlsec1-openssl.pc` and
`libxml-2.0.pc` resolve to on the build machine. That bakes xmlsec's and
libxml2's **struct layouts** into the compiled extension. So there are three
independent versions in play, and only the first is what users pin:

| | What it is | Where it lives |
|---|---|---|
| Gem version | The Ruby API's SemVer | `lib/hanko_xml/version.rb` |
| Compiled-against xmlsec1 | The headers bindgen saw | `HankoXml::NativeVersion.build_versions` |
| Runtime xmlsec1 | The `.so`/`.dylib` actually loaded | the user's machine |

If 2 and 3 disagree, no symbol fails to resolve and no error is raised — a
field is simply read at the offset our headers claimed rather than the one the
loaded library used. `HankoXml::NativeVersion.check!` runs at require time and
turns that into a `NativeVersionMismatch` instead of a wrong answer from
`verify!`.

For the **source gem** this holds by construction: the machine that compiles
the extension is the machine that loads it. The guard matters for an installed
extension that outlives an OS package upgrade of libxmlsec1. The **platform
gems** (below) avoid the question altogether, because they link their own
static copies.

## Versioning policy

- The gem version is SemVer over the **Ruby API only**. Pre-1.0, a breaking
  change bumps the minor. The gem version never encodes xmlsec's version.
- The supported libxmlsec1 range lives in the gemspec as
  `metadata["xmlsec1_version_requirement"]`. Widening or narrowing it is a
  CHANGELOG-worthy change.
- The vendored versions live in `dependencies.yml`, not in the gem version.
  Bumping any of them (libxml2, xmlsec1, OpenSSL) is at minimum a patch
  release, and a vendored **security** fix is a patch release with the CVE
  named in the CHANGELOG. See "Responding to upstream security fixes" below.

## Stability policy

What a version number promises. Until 1.0, a breaking change bumps the minor
(above). From 1.0 on:

- **Stable:** the public Ruby API as API_CONTRACT.md §5 documents it
  (`HankoXml.sign`, `.valid?`, `.verify!`, `Signer`, `Verifier`,
  `Verification`, `Placement`, `Key`, `Algorithms`, `Policy`, `Xades::*`), the
  error class hierarchy in §5.10, and the RBS signatures in `sig/`. Removing or
  renaming any of it, changing a keyword's meaning, or moving an error to a
  different parent class waits for 2.0.
- **What each `Policy` preset means is stable.** `Policy.strict` stays the
  default, and each preset keeps its purpose: `legacy_sha1` allows SHA-1,
  `xades` allows what XAdES needs, and so on.
- **Defaults can get stricter in a minor release.** When a security fix needs
  it, a preset or default may stop accepting an algorithm, transform or input
  shape it accepted before, for example `Policy.strict` dropping an algorithm
  that has been broken. Callers who still need it opt back in explicitly
  (`Policy#with`, or another preset). The CHANGELOG entry says so under
  `### Security`, with the reason. Defaults never get looser outside a major
  release.
- **Not public:** `HankoXml::Native` (API_CONTRACT.md §7), anything marked
  `@api private` or `private_constant`, error message text, and the exact
  bytes of a signature's serialization beyond what XML-DSig requires. These can
  change in any release.
- **Removed at 1.0:** the deprecated aliases API_CONTRACT.md §10 lists, such as
  `HankoXml.validate`.
- **Supported platforms:** Ruby 3.1 and newer (`required_ruby_version`), and
  for the source gem libxmlsec1 `>= 1.2.30, < 1.4`
  (`metadata["xmlsec1_version_requirement"]`). Dropping a Ruby version that is
  still maintained upstream, or narrowing the libxmlsec1 range, is a major
  change. Dropping an end-of-life Ruby is a minor change, announced in the
  CHANGELOG one release ahead.
- **Security fixes:** the latest minor release always gets them. After 1.0,
  the previous minor also gets them for six months after its successor ships.
  [SECURITY.md](SECURITY.md) keeps the table of supported versions; update it
  with every minor release.

## One-time setup, before the first real release

1. **Register the trusted publisher.** On
   <https://rubygems.org/gems/hanko_xml/trusted_publishers>, add a GitHub
   Actions publisher with repository `danimaribeiro/HankoXml`, workflow
   `release.yml`, and environment `rubygems`. This cannot be done before the
   gem name exists on RubyGems — for a brand-new gem, create a *pending*
   trusted publisher from your profile instead.
2. **Create the `rubygems` environment** in the repository's
   Settings → Environments. Adding yourself as a required reviewer there turns
   every publish into a manual approval, which is worth having for a gem that
   produces signatures.

Until step 1 is done, only run the workflow via `workflow_dispatch` with
`dry_run` left at its default of `true`.

## Cutting a release

1. Move the `## [Unreleased]` entries into a new `## [X.Y.Z] - YYYY-MM-DD`
   section in `CHANGELOG.md`.
2. Bump `HankoXml::VERSION` in `lib/hanko_xml/version.rb`.
3. `bundle exec rake` — the packaging spec checks the two above agree and that
   the file allowlist is complete.
4. Ensure `README.md`'s Installation snippet is `gem "hanko_xml"` (no `git:`
   pin) before cutting the release.
5. Commit, then:

   ```sh
   git tag "v$(ruby -Ilib -rhanko_xml/version -e 'print HankoXml::VERSION')"
   git push origin main --follow-tags
   ```

The workflow then runs the full Ubuntu + macOS × Ruby 3.1–3.4 matrix
(`main.yml`), builds and smoke-tests the four platform gems (`cross-gem.yml`),
verifies the tag matches `HankoXml::VERSION`, builds the source gem, **installs
it into a clean `GEM_HOME` and requires it** (the check that actually proves the
`spec.files` allowlist did not omit anything), pushes the source gem and every
platform gem to RubyGems, and cuts a GitHub Release from the CHANGELOG section
with all the `.gem` files attached.

To rehearse without publishing: Actions → Release → Run workflow, leaving
`dry_run` checked. Everything up to and including the install smoke test runs;
nothing is pushed.

## Platform gems

Each release publishes a source gem and four precompiled platform gems:

| Platform | Built on | Smoke-tested on |
|---|---|---|
| `x86_64-linux` | rake-compiler-dock (rb-sys-dock) | bare `ruby:3.3-slim` container |
| `aarch64-linux` | rake-compiler-dock, cross | bare container on a native arm64 runner |
| `arm64-darwin` | rake-compiler-dock, cross | `macos-latest` runner |
| `x64-mingw-ucrt` | rake-compiler-dock, mingw-w64 cross | `windows-latest` runner |

Each platform gem carries the extension for every supported Ruby ABI (3.1 to
3.4) and links libxml2, xmlsec1 and OpenSSL **statically**, at the versions
pinned in `dependencies.yml` (`HANKO_XML_VENDOR=1`, `ext/hanko_xml/build/vendor.rs`).
`gem install hanko_xml` on these platforms needs no compiler, Rust, libclang,
pkg-config or `libxmlsec1-dev`. Everything else, including `x86_64-darwin`,
falls back to the source gem, which compiles against the system libraries.

`cross-gem.yml` builds them on every pull request and `release.yml` calls it,
so a release ships exactly what the PR matrix tested. The smoke test
(`.github/scripts/smoke_test.sh`) installs each gem with no build tools
present, requires it, checks `NativeVersion.build_versions` reports the pinned
versions, verifies a real signature and rejects a wrong certificate, and, on
Linux and macOS, checks the extension exports no `xml*`/`xmlSec*` symbols and
links none of the vendored libraries dynamically. Windows runners have no
`objdump`, so for `x64-mingw-ucrt` the same check runs on Linux right after the
build (`.github/scripts/check_pe_exports.rb`, #20).

Precompiled gems that dynamically link the *system* libxmlsec1 are not an
option: the binary would be frozen against the builder's headers and shipped to
machines on a different xmlsec1 series, which is precisely what `NativeVersion`
exists to catch. Vendoring makes the compiled-against and runtime versions the
same thing again. VENDORING.md has the design history and the CI failures each
platform went through.

## Responding to upstream security fixes

Vendoring makes this project the distributor of libxml2, xmlsec1 and OpenSSL
for everyone on a platform gem, so their security fixes are ours to ship. The
OS vendor's updates do not reach a statically linked copy.

- `vendored-deps.yml` runs every Monday (and on PRs that touch the pins). It
  reports a newer patch release in a pinned series as actionable, a newer
  minor series as informational, and known advisories against the pinned
  versions via OSV, and opens an issue when something is actionable.
- To bump: change `version`, `url` and `sha256` together in `dependencies.yml`,
  verifying the checksum against two upstream sources (for example the GitHub
  release and the project's own site), update `THIRD_PARTY_LICENSES.md` and
  `spec/packaging_spec.rb`, and run
  `HANKO_XML_VENDOR=1 bundle exec rake compile spec symbols:check`.
- Ship it as a patch release, with the CVEs named in the CHANGELOG entry.
- Also check before every release, not only when the weekly job fires: a
  pinned minor series can stop getting releases while fixes land only in the
  next one, which the patch-level check does not catch (#65 found libxml2 2.14
  in that state).

## OpenSSF Scorecard

`.github/workflows/scorecard.yml` publishes the repository's Scorecard result
on every push to `main` and weekly; the README badge shows it, and the
findings appear under Security → Code scanning. A local run on 2026-10-18
scored 5.2. These checks stay low on purpose or for now, and why:

| Check | Why it stays low | What would change it |
|---|---|---|
| Code-Review, Branch-Protection (approvers, admin enforcement, CODEOWNERS) | One maintainer: GitHub doesn't let you approve your own PR, and requiring approval would block every merge. Admins bypass the PR rule so documentation can go straight to `main` (CLAUDE.md, Workflow). | A second maintainer. |
| Maintained | The repository is younger than 90 days. | Time. |
| CII-Best-Practices | No badge yet (#188). | Filling in the bestpractices.dev questionnaire. |
| Fuzzing | No fuzz target yet. | #184. |
| Signed-Releases | Releases carry no provenance yet. | #179. |
| CI-Tests | Most merged PRs predate CI resuming in October 2026 (#110). | Rises as new PRs merge with CI green. |
| Contributors | Counts organizations, not people. | Outside contributors. |

`codeql.yml` covers SAST, and the docs site's npm lockfile is kept free of
known advisories for the Vulnerabilities check.

## Publishing a security fix

A vulnerability reported through [SECURITY.md](SECURITY.md) arrives as a
private report under Security → Advisories. From there:

1. **Triage.** Acknowledge the report within 7 days. Reproduce it, rate it
   (CVSS, plus the severity scale SECURITY_REVIEW.md uses), and list the
   affected versions.
2. **Draft the advisory.** Accept the report into a draft GitHub Security
   Advisory, or open one yourself under Security → Advisories → New draft.
   Fill in the affected and patched version ranges for the `hanko_xml`
   RubyGems package and credit the reporter unless they asked not to be.
3. **Request a CVE** from the draft (GitHub is a CNA). It is assigned before
   publication and stays private until then.
4. **Fix it privately.** Use the advisory's temporary private fork, so the fix,
   its spec and the review never appear in public PRs. The spec cites the new
   `S-xx` finding, which is added to SECURITY_REVIEW.md in the same change.
   Run the suite on both the system and the vendored builds locally, since the
   public CI does not see the fork.
5. **Release.** Merge the fork, then cut a patch release from this file's
   "Cutting a release". The CHANGELOG entry goes under `### Security` with the
   CVE and the issue or advisory ID. For a supported previous minor, cut its
   patch release from a `X.Y-stable` branch too.
6. **Publish the advisory** once the gems are on RubyGems. GitHub then alerts
   Dependabot users.
7. **ruby-advisory-db.** Open a PR to
   <https://github.com/rubysec/ruby-advisory-db> adding
   `gems/hanko_xml/CVE-YYYY-NNNNN.yml` (`gem`, `cve`, `ghsa`, `url`, `title`,
   `date`, `description`, `cvss_v3`, `patched_versions`), so `bundler-audit`
   warns too.

When the fix is a vendored upstream release instead (libxml2, xmlsec1 or
OpenSSL, see "Responding to upstream security fixes"):

- If the upstream CVE is exploitable through HankoXml as platform gems use it,
  publish a HankoXml advisory naming both CVEs, with the platform gems as the
  affected packages and the source gem left out (it uses the system libraries).
- If it isn't reachable, for example a bug in an OpenSSL API we never call, ship
  the patch release with the CVE in the CHANGELOG and no advisory. Say in the
  CHANGELOG entry why it isn't reachable.

## Trusted build inputs

The SHA-256 pins protect the *download*. They do not protect everything a
vendored build reads, and the rest has to be treated as trusted: whoever can
write to it chooses the OpenSSL, libxml2 and xmlsec1 compiled into the gem.

| Input | Trust | Why |
|---|---|---|
| `dependencies.yml` | **Root of trust** | Its `sha256` fields decide which bytes are accepted. Changing one is trusting a new release; verify it upstream first. |
| Tarball cache: `tmp/vendor-cache/`, or `HANKO_XML_VENDOR_CACHE` | Untrusted, verified | Every tarball, cached or fresh, is hashed and compared before extraction on every build; a mismatch deletes it and fails the build. A shared or mirrored cache is safe. |
| Build prefix: `tmp/vendor-build/<target>/<versions>/`, with `.stamp-complete` | **Trusted, not verified** | If the stamp exists, `vendor.rs` skips download, verification, extraction *and* compilation, and links whatever headers and static libraries are in that prefix. Nothing hashes the installed output. |
| Download hosts (`url`, `mirror`), `curl -L` redirects | Untrusted | Integrity comes only from the SHA-256 check, never from TLS or from which host answered. |
| Tarball contents (`tar -xf`, then `configure` / `make`) | Trusted once the hash matches | Extraction has no `--no-same-owner` or path checks beyond tar's defaults, and the build runs upstream's scripts. This is trusting the pinned upstream release, the same as linking it. |
| Toolchain and environment (`CC`, `AR`, `CFLAGS`, `PATH`, `TARGET`, the rb-sys-dock image) | Trusted | They compile the code. |

Rules that follow:

- Only the account running the build should be able to write to
  `tmp/vendor-build/`. Never restore it from a cache that less-trusted jobs can
  write (for example a CI cache shared with pull requests from forks). CI does
  not cache it, and release builds start from a clean checkout.
- To force a full rebuild from verified sources, delete
  `tmp/vendor-build/<target>/` (or just its `.stamp-complete`).
- `HANKO_XML_VENDOR_CACHE` can point anywhere, including a shared or read-only
  mirror: a wrong or tampered file fails the build instead of being used. It
  must be writable if a tarball is missing, because a failed checksum deletes
  the file.
