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

For today's **source gem** this holds by construction: the machine that
compiles the extension is the machine that loads it. The guard matters for the
precompiled gems below, and for an installed extension that outlives an OS
package upgrade of libxmlsec1.

## Versioning policy

- The gem version is SemVer over the **Ruby API only**. Pre-1.0, a breaking
  change bumps the minor. The gem version never encodes xmlsec's version.
- The supported libxmlsec1 range lives in the gemspec as
  `metadata["xmlsec1_version_requirement"]`. Widening or narrowing it is a
  CHANGELOG-worthy change.
- Once the vendored/precompiled path (below) exists: bumping the vendored
  libxmlsec1 is at minimum a patch release, and a vendored **security** fix is a
  patch release with the CVE named in the CHANGELOG.

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
4. Commit, then:

   ```sh
   git tag "v$(ruby -Ilib -rhanko_xml/version -e 'print HankoXml::VERSION')"
   git push origin main --follow-tags
   ```

The workflow then runs the full Ubuntu + macOS × Ruby 3.1–3.4 matrix, verifies
the tag matches `HankoXml::VERSION`, builds the gem, **installs it into a clean
`GEM_HOME` and requires it** (the check that actually proves the `spec.files`
allowlist did not omit anything), pushes to RubyGems, and cuts a GitHub Release
from the CHANGELOG section.

To rehearse without publishing: Actions → Release → Run workflow, leaving
`dry_run` checked. Everything up to and including the install smoke test runs;
nothing is pushed.

## Not yet done: precompiled platform gems

Today `gem install hanko_xml` compiles on the user's machine and therefore
requires `libxmlsec1-dev`, `pkg-config`, libclang (bindgen needs it), and a
Rust toolchain. The fix is precompiled platform gems with libxmlsec1, libxml2,
and OpenSSL **statically vendored**, built with `oxidize-rb/cross-gem-action`
and `rake-compiler-dock`, keeping the source gem as the fallback.

Precompiled gems that dynamically link the *system* libxmlsec1 are not an
option: the binary would be frozen against the builder's headers and shipped to
machines on a different xmlsec1 series — precisely what `NativeVersion` exists
to catch. Vendoring is what makes the compiled-against and runtime versions the
same thing again.

Worth noting the inversion when that work happens: bindgen-at-build-time is
correct for the source gem, where adapting to whatever xmlsec is installed is
the point, and wrong for a precompiled gem, where the bindings should be
generated once against the pinned vendored source.
