# Vendored precompiled gems for hanko_xml

## Context

`hanko_xml` is unreleased (0.1.0, no tags). Release groundwork already landed this
session: a `spec.files` allowlist, a require-time ABI guard
(`HankoXml::NativeVersion`), an Ubuntu+macOS × Ruby 3.1–3.4 CI matrix, and a
tag-triggered `release.yml` using RubyGems trusted publishing.

Today `gem install hanko_xml` compiles on the user's machine and therefore needs
`libxmlsec1-dev`, `libxml2-dev`, `pkg-config`, libclang (bindgen), and a Rust
toolchain. That is hostile to slim Docker images and to anyone who just wants to
sign an XML document. The goal is **precompiled platform gems with libxml2 and
xmlsec1 statically vendored**, so installing is instant and needs nothing from
the OS but libcrypto.

### Why vendoring is safe here (the load-bearing fact)

The FFI boundary is **serialized bytes, never `xmlDocPtr`**:

- `lib/hanko_xml/signer.rb:153` — `HankoXml.serialize(doc)` → `doc.to_xml(save_with: AS_XML)`; Nokogiri's libxml2 writes bytes.
- `Native.sign(xml_bytes, key_pem, cert_pems, id_attributes, index)` — every argument is a Ruby `String`/`Array`/`Integer`. Rust's `xmlReadMemory` re-parses with **its own** libxml2.
- `lib/hanko_xml/signer.rb:222` `write_back_signature` re-parses the result with **Nokogiri's** libxml2 and copies only `DigestValue`/`SignatureValue`/`X509Certificate` text content back.

Two libxml2 instances, zero shared pointers. Our vendored libxml2 can differ
freely from whatever Nokogiri vendors. **This boundary must never be "optimised"
into passing a raw `xmlDocPtr`** — that would reintroduce the exact bug
documented at length in `ext/hanko_xml/build.rs`.

## Decisions already made

1. **Vendor libxml2 2.14.6 + xmlsec1 1.3.12**, statically, pinned by SHA256:
   - `xmlsec1-1.3.12.tar.gz` — `24045199af12d93fe5fdbbbf7e386e823e4842071e9432e2b90ac108b889a923`
   - `libxml2-2.14.6.tar.xz` — `7ce458a0affeb83f0b55f1f4f9e0e55735dbfc1a9de124ee86fb4a66b597203a`
2. **Vendor OpenSSL 3.5.8 (LTS) statically too.** This started as the
   opposite decision — link the system libcrypto — on the reasoning that
   libxml2 *must* be vendored (`xmlDoc`/`xmlNode`/`xmlAttr` are public structs
   we dereference by field offset, and the same `xmlDocPtr` is shared with
   xmlsec) while OpenSSL is two-party, its 3.x structs opaque, its pointers
   never entering our code. That reasoning was right about safety and wrong
   about feasibility, and CI disproved it three times. See
   [Resolved: OpenSSL is vendored](#resolved-openssl-is-vendored) for the
   evidence and the accepted costs.
3. **Platforms:** `x86_64-linux`, `aarch64-linux`, `arm64-darwin` and
   `x64-mingw-ucrt` all cross-compile and smoke-test green (see the status
   table below). `x86_64-darwin` and `x64-mingw32` are not planned.
4. **Gem version is SemVer over the Ruby API only.** Vendored versions are data,
   never encoded in the gem version (mirroring xmlsec1's number would mean a
   breaking Ruby API change has to wait for xmlsec to bump minor).
5. **The source gem keeps using system libraries by default**; vendoring is
   opt-in via `HANKO_XML_VENDOR=1`, which only CI sets. This inverts nokogiri's
   default deliberately: precompiled gems cover the common cases, so the risky
   vendored path never runs on a user's machine, and source installs stay fast
   and offline-capable. *(Reversible — say so if you'd rather vendor by default.)*

## What the FFI audit found

**The ABI footprint against libxml2 is remarkably small** — six struct fields
total: `xmlNode.{type_, children, next, name, ns}` (`dsig.rs:159-194`) and
`xmlNs.href` (`dsig.rs:198`). `xmlDoc` is never dereferenced at all; it is only
ever passed to functions. That is a narrow surface to keep stable, and it makes
pinning libxml2 2.14.6 low-risk.

**The most ABI-fragile lines in the codebase are the direct field writes
into `xmlSecDSigCtx`** — `signKey`, and (S-04) `enabledReferenceUris` /
`transformCtx.enabledUris`. If xmlsec ever restructures that struct, bindgen
regenerates a different-but-still-valid Rust struct and the breakage is
silent. **Vendoring actively improves this**: headers and archive become the
same pinned source by construction. The only xmlsec field *read* is `.status`.

**`allowlist_var("LIBXML_.*")` couples libxml2's configure flags to the
generated bindings.** It sweeps in every `LIBXML_*_ENABLED` macro, and those
macros gate declarations in headers bindgen parses (e.g. `xmlsec/xmltree.h`).
So disabling a libxml2 feature can change *which functions and types exist* in
`sys.rs`, not merely their values. Consequence for Phase 1: **be conservative
with the disable list, and treat any change to it as requiring a full rebuild
plus the whole suite.** Relatedly, `LIBXML_DOTTED_VERSION` (read at
`dsig.rs:731`) is a compile-time constant, so `versions[:libxml2]` reports the
*header* version — under static vendoring that is finally guaranteed to match
the linked code, which is exactly the property we want.

**Existing tests are a strong regression net.** `spec/hanko_xml/native_spec.rb`
already drives the native layer end to end across every fixture shape — enveloped,
enveloping, detached, plain c14n, exclusive c14n, SHA-256, SHA-512, and an
NFe-shaped document — for both `.sign` (`native_spec.rb:138-150`) and `.verify`
(`native_spec.rb:97-105`), plus negative cases for bad XML and bad keys. If the
vendored build passes that file unchanged, the vendoring is almost certainly
correct. Its "safety budget" example also guards against new `unsafe`/struct-field
creep during the refactor.

*(Minor, optional: `xmlDocDumpFormatMemory`, `xmlNodeListGetString`, and the
`xmlAttr` type are allowlisted in `build.rs` but never used — dead surface that
could be trimmed while we're in there.)*

## Groundwork already verified

- **Symbol hiding will work.** On non-Windows, libxml2's `XMLPUBFUN`
  (`include/libxml/xmlexports.h:29`) and xmlsec1's `XMLSEC_EXPORT`
  (`include/xmlsec/exports.h:56`) both expand to **nothing** — neither forces
  `visibility("default")`, so `-fvisibility=hidden` in `CFLAGS` is not overridden.
  This is the linchpin; without it the whole approach is unsafe.
- **Configure flags exist for everything needed.** xmlsec1 has
  `--disable-crypto-dl`, `--with-openssl=`, `--with-libxml=`,
  `--without-{nss,nspr,gnutls,gcrypt,libxslt}`, `--enable-static`,
  `--disable-shared`, `--with-default-crypto=`. libxml2 has the full
  `--with-{xpath,xptr,c14n,schemas,output,regexps,...}` toggle set.
- **The toolchain is already present.** `rb_sys` 0.9.130's
  `RbSys::ExtensionTask` enables cross-compilation from the `RUBY_TARGET` env var
  (`extensiontask.rb:36`), and its `@cross_compiling_blocks` already strip `.rs`
  files, `Cargo.toml`/`Cargo.lock`, and `extconf.rb` from `gemspec.files` and
  clear `gemspec.extensions` for native gems (`extensiontask.rb:38-50`).
  `rake-compiler-dock` 1.12.0 is already a transitive dependency, and all four
  target platforms are in `rb_sys/toolchain_info/data.rb`.

## Phase 1 — Vendored build on the host — **DONE, verified on arm64-darwin**

Landed as `dependencies.yml`, `ext/hanko_xml/build/vendor.rs` (359 lines), and a
`HANKO_XML_VENDOR` branch in `build.rs` that leaves the system path untouched.
Measured results:

| | System build (default) | Vendored build |
|---|---|---|
| `build_versions[:libxml2]` | 2.15.3 (Homebrew) | **2.14.6** (pinned) |
| Dynamic deps | 7 dylibs incl. libxmlsec1, libxml2, libssl, libxslt | **3**: libSystem, libcrypto, libiconv |
| Suite | 168 examples, 0 failures | **168 examples, 0 failures** |
| Exported symbols | — | **2**: `_Init_hanko_xml`, `_ruby_abi_version` |

The decisive checks both passed:

- **libxml2 reports 2.14.6, not 2.15.3** — the vendored headers won over the
  Homebrew ones, so bindgen's struct layouts match the archive actually linked.
- **Nokogiri co-existence.** In one process, Nokogiri on libxml2 **2.13.9** and
  hanko_xml on vendored **2.14.6**: `doc.sign!` → `to_xml` → `signature_valid?`
  returned `true` for the signing cert and `false` for a different one. Two
  libxml2 versions, no interposition, correct signatures. This is the result the
  whole design rests on.

Implementation notes worth keeping:

- `build.rs` was split into `system_libraries()` / `vendor::build()`, both
  returning a shared `Headers { include_paths, defines }`. The **defines are
  load-bearing** — xmlsec's headers refuse to compile without
  `XMLSEC_CRYPTO_OPENSSL`, and the rest of the `-D` set records which algorithms
  were compiled in (`XMLSEC_NO_MD5`, `XMLSEC_NO_GOST`, …). Dropping them during
  the split broke the build immediately.
- For that reason `vendor.rs` **probes the `.pc` files its own build installed**
  rather than hardcoding defines, so the define set can never drift from the
  configure flags above it.
- `dependencies.yml` is parsed by a ~30-line purpose-built reader instead of
  adding a YAML crate to the build; `spec/packaging_spec.rb` validates the file's
  shape.
- RuboCop needed `target/**/*` excluded: the vendored build extracts xmlsec1's
  sources there, and xmlsec1 ships an RPM `xmlsec1.spec` that RuboCop tries to
  parse as Ruby.

## Phase 2 — Symbol-leak enforcement — **DONE**

`spec/symbols_spec.rb` asserts the built artifact exports no `xml*`/`xmlSec*`
symbols and nothing but `Init_hanko_xml`/`ruby_abi_version`. It runs in
`rake default`, uses `nm -gU` on macOS and `nm -D --defined-only` on Linux, and
skips cleanly where `nm` is unavailable. On a system build it passes trivially
(nothing is statically linked in to leak); it has teeth exactly when it matters.

The rake task from the original design was folded into the spec so a plain
`bundle exec rake` catches a leak with no extra step.

## Resolved: macOS no longer needs a system libcrypto

This was an open question for a while. macOS has shipped no usable system
OpenSSL since Apple deprecated it, so the vendored build linked
`/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib` **by absolute path** — fine
locally, fatal for a distributed gem, since a user without Homebrew's
`openssl@3` at that exact path could not load it.

Vendoring OpenSSL removed it. `otool -L` on the built extension now reports only
`libSystem` and `libiconv` — no libcrypto of any kind, absolute path or
otherwise. The same change unblocks the aarch64 cross-compile, whose failure had
the same root cause: no OpenSSL for the target in the build environment.

## Status of the cross-compile (measured, not predicted)

| Platform | Result |
|---|---|
| `x86_64-linux` | **builds and smoke-tests** — vendored libxml2 2.14.6 + xmlsec1 1.3.12, four Ruby ABIs |
| `aarch64-linux` | **builds and smoke-tests** — on a real `ubuntu-24.04-arm` runner, not emulation |
| `arm64-darwin` | **builds and smoke-tests** — on a real `macos-latest` runner |
| `x64-mingw-ucrt` | **builds and smoke-tests** — on a real `windows-latest` runner; see Phase 5 |
| `x86_64-darwin`, `x64-mingw32` | not planned — see the platform notes above and in Phase 5 |

Four rounds of CI, each failing further along, and every failure was worth
having:

1. `HANKO_XML_VENDOR=1` never reached the build script. No released
   `oxidize-rb/actions` tag implements the `pre-script` input — `v1`, `v1.4.2`
   and `v1.4.4` all set `INPUT_PRE_SCRIPT` and then never reference it; only
   `main` has the conditional that passes it through. The value was accepted
   and silently ignored. Fixed by keying vendoring off `RUBY_TARGET` in
   `build.rs`, which is both more robust and more correct.
2. `curl 403` fetching xmlsec1: `www.aleksey.com` is behind Cloudflare, which
   blocks Actions runners. Switched to the byte-identical GitHub release asset,
   with the original as a fallback mirror.
3. bindgen could not find `openssl/opensslconf.h`. On Debian that header is
   architecture-specific, under `/usr/include/<multiarch triple>`; GCC adds
   that directory implicitly, clang does not — so the C libraries built and
   only binding generation failed.
4. **aarch64 only:** the same header, but now from GCC during xmlsec1's own
   build. The rb-sys-dock image has **no aarch64 OpenSSL at all** — the build
   sees the host's arch-independent `/usr/include/openssl` and no aarch64
   `opensslconf.h` behind it.

### Resolved: OpenSSL is vendored

Decision 2 is reversed. It was right about *safety* and wrong about
*feasibility*, and CI proved it three times — macOS has no system libcrypto,
cross-compiling found no target OpenSSL in the container, and x86_64 built fine
then would not load because the container's OpenSSL is **1.1** while every
current distro ships `libcrypto.so.3`.

The general rule: **the soname a precompiled gem records is decided by whatever
OpenSSL the build container has, which is never the user's.** Vendoring is the
only way to make the two agree. Borrowing the container's `libcrypto.a` instead
of compiling would embed EOL 1.1 crypto into a signing gem; a distro `.deb`
would trade a checksummed upstream tarball for weaker provenance and symbols
compiled without hidden visibility.

Safety is preserved exactly as it is for libxml2: the FFI boundary is PEM
strings, never `EVP_PKEY*`, and hidden visibility plus `--exclude-libs` keeps
our copy private from the libcrypto Ruby's own `openssl` extension has loaded.

Measured on arm64-darwin after the change:

| | Before | After |
|---|---|---|
| Dynamic deps | libSystem, **libcrypto**, libiconv | libSystem, libiconv |
| Exported symbols | 2 | 2 (0 `xml*`/`xmlSec*`/`EVP_*`/`OPENSSL_*`) |
| Cold vendored build | ~50s | **1m13s** (all three libraries) |
| Warm rebuild | — | **7s** |

The build was also moved out of `OUT_DIR` into
`tmp/vendor-build/<target>/<versions>` with a completion stamp. `OUT_DIR`
differs per Ruby ABI, so the old layout rebuilt all three C libraries four
times per platform; none of them depend on the Ruby ABI. A version bump in
`dependencies.yml` changes the key and forces a clean rebuild.

Accepted costs: OpenSSL advisories are now our release obligation, and a
bundled libcrypto bypasses system crypto policy (FIPS and similar), which
matters to regulated users — they should build the source gem, which still
links the system OpenSSL.

*(Possible follow-up: cache `tmp/vendor-build` between CI runs keyed on
`dependencies.yml`. Not done yet — restoring a container-built tree across UID
boundaries can bite, and 1-2 minutes is not yet worth that risk.)*

## Phase 3 — Cross-compilation

- Configure `RbSys::ExtensionTask` in the `Rakefile` with the four platforms and
  Ruby ABIs 3.1–3.4 (one platform gem carrying `lib/hanko_xml/<ABI>/hanko_xml.so`).
- Teach `vendor.rs` to cross-compile: pass `--host=<autotools triple>` derived
  from `TARGET`, and `CC`/`AR`/`RANLIB` from the rake-compiler-dock toolchain.
- **Highest-risk item:** building the vendored C libraries for *darwin* inside the
  Linux dock image (osxcross). Prove this early — if it resists, fall back to
  building the macOS gems on a `macos-latest` runner natively, which is simpler
  and costs only CI minutes.
- `--with-openssl=` must point at the *target* sysroot's OpenSSL, not the host's.

## Phase 4 — Release fan-out — **wired, not yet released**

`release.yml` now calls `cross-gem.yml` as a reusable workflow (`workflow_call`)
so the tag-triggered release builds from the exact same matrix that guards pull
requests, rather than a second copy of it. The `release` job downloads every
`gem-*` artifact `cross-gem.yml` uploaded (`x86_64-linux`, `aarch64-linux`,
`arm64-darwin`) into the same `pkg/` the source gem was built into, and pushes
and releases everything found there together — one `gem push` per file, one
`gh release create` with all of `pkg/*.gem` as assets.

`x86_64-darwin` and `x64-mingw-ucrt` are still absent from the matrix (see
Phase 5), so those users get the source gem — unchanged behavior, since the
source gem is what everyone got before this phase.

Still outstanding before a real (non-dry-run) release:

- RubyGems trusted-publisher registration for `hanko_xml` — required once,
  documented in `release.yml`'s header comment.
- The `spec/packaging_spec.rb` / `native_spec.rb` branching this phase's plan
  called for was **not needed for the wiring above**: those specs run only in
  `main.yml`'s source-gem build, never against the platform gems, which are
  proven instead by `cross-gem.yml`'s own smoke test
  (`.github/scripts/smoke_test.sh`). Revisit only if platform gems start
  running through rspec directly.

**Specs that will conflict and must be branched, not deleted:**

- `spec/packaging_spec.rb:57-59` — `expect(files.grep(/\.(bundle|so|dylib|o|a)\z/)).to be_empty`. Correct for the source gem, false for every native gem.
- `spec/packaging_spec.rb:41-43` — `gemspec.extensions == ["ext/hanko_xml/Cargo.toml"]`. rb_sys clears `extensions` for native gems.
- `spec/hanko_xml/native_spec.rb:23-31` — `.versions` asserts a `\A\d+\.\d+\.\d+` regex. Under vendoring this should assert the *exact* pinned versions (xmlsec 1.3.12 / libxml2 2.14.6), which turns it into a real check that the vendored headers won over any system copy.

Restructure as two contexts — source-gem shape and native-gem shape — driven off
the same gemspec, so both are asserted rather than one being loosened away.

## Phase 5 — Windows — **DONE, x64-mingw-ucrt green in CI**

Decided the way `dependencies.yml`'s header already generalized: vendor OpenSSL
for Windows too, the same as macOS and Linux, rather than link RubyInstaller's
`libcrypto-3-x64.dll` import library. `x64-mingw-ucrt` cross-compiles from the
Linux dock via mingw-w64 and is smoke-tested on a real `windows-latest` runner
(no container exists for Windows, same as arm64-darwin) — installs, loads,
signs and verifies a fixture with no Rust/libxmlsec1-dev/pkg-config present,
across all four Ruby ABIs. `x64-mingw32` (the legacy non-UCRT Windows Ruby) and
32-bit platforms are not planned.

Four rounds of CI, each failing further along -- the same pattern Linux and
Darwin went through:

1. `configure: error: libiconv not found`. `--with-iconv` (no argument) means
   *required*, not *use it if present*, and the mingw dock has no libiconv
   (none is vendored). Switched to `--without-iconv` for the Windows target;
   libxml2 falls back to its own built-in UTF-8/UTF-16/ASCII/ISO-8859-1
   converters, which is what every fixture here needs.
2. xmlsec1's configure auto-detects Windows and builds the CNG/CryptoAPI
   crypto backends alongside OpenSSL unless told not to -- and the first
   attempt to disable them, `--without-mscng --without-mscrypto`, silently did
   nothing: unlike `--without-nss`/`--without-gnutls`, these are
   `AC_ARG_ENABLE` options, not `AC_ARG_WITH`, and an unrecognized
   `--without-*` is accepted and ignored rather than rejected (the same
   mechanism behind the harmless `--with-tree` warning elsewhere in this
   build). The mscng module then failed to compile against the dock's older
   w32api headers. Fixed with the actual flags, `--disable-mscng
   --disable-mscrypto`.
3. `undefined reference to __imp_xmlSecError` (and others) linking
   `libxmlsec1-openssl.a` against `libxmlsec1.a`. Both were compiled without
   `LIBXML_STATIC`/`XMLSEC_STATIC` defined, so `XMLPUBFUN`/`XMLSEC_EXPORT`
   expanded to `__declspec(dllimport)` even for a library's *own* other
   translation units -- every one of them includes the same public headers.
   dllimport tells the linker to expect the symbol from a DLL's import
   library; there is no DLL, only static archives. Fixed by threading
   `-DLIBXML_STATIC -DXMLSEC_STATIC` through the C build (`build_cflags()`)
   *and* into bindgen's defines, so the generated Rust declarations agree with
   how the extension actually links.
4. `undefined reference to __imp_CryptAcquireContextW` (and
   `BCryptGenRandom`, `CertOpenStore`, event-log functions, …). Static
   libcrypto and libxml2 call these Win32 APIs directly; nothing was linking
   their import libraries. Added `advapi32`, `crypt32`, `bcrypt`, `user32`,
   `gdi32` to `emit_link_flags`'s Windows branch.

**Deferred, not blocking:** the symbol-leak check (`spec/symbols_spec.rb` and
`smoke_test.sh`'s per-platform loop) has no Windows leg yet. PE export/import
inspection needs a different tool than `nm -D`/`otool -L` (objdump against a
different table format), and no such tool is confirmed present on
`windows-latest` by default. `smoke_test.sh` logs and skips this one check on
Windows rather than failing; every other check (install, load, sign, verify)
runs. Lower urgency than it sounds: unlike ELF/Mach-O, a PE DLL does not export
static-archive members by default in the first place, so the failure mode this
check guards against is differently shaped on Windows, not simply unguarded.

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
  not cache it today, and release builds start from a clean checkout.
- To force a full rebuild from verified sources, delete
  `tmp/vendor-build/<target>/` (or just its `.stamp-complete`).
- `HANKO_XML_VENDOR_CACHE` can point anywhere, including a shared or read-only
  mirror: a wrong or tampered file fails the build instead of being used. It
  must be writable if a tarball is missing, because a failed checksum deletes
  the file.

## Files

| File | Change |
|---|---|
| `dependencies.yml` | **new** — pinned versions + SHA256 |
| `ext/hanko_xml/build/vendor.rs` | **new** — download, verify, configure, build |
| `ext/hanko_xml/build.rs` | branch vendored vs system; keep system path unchanged |
| `Rakefile` | cross-compile platforms + Ruby ABIs; `symbols:check` task |
| `spec/packaging_spec.rb` | split into source-gem and native-gem shape contexts |
| `spec/hanko_xml/native_spec.rb` | `.versions` asserts the exact pinned versions |
| `spec/symbols_spec.rb` | **new** — no leaked `xml*`/`xmlSec*` exports |
| `ext/hanko_xml/src/dsig.rs` | comment only, at the `signKey` write (`:442`) |
| `.github/workflows/release.yml` | platform build matrix |
| `.github/workflows/main.yml` | run a vendored build + symbol check |
| `RELEASING.md` | vendored release policy; CVE response for pinned libs |
| `CHANGELOG.md` | record vendored versions per release |

## Verification

1. `bundle exec rake` — system build unchanged, 164 examples green.
2. `HANKO_XML_VENDOR=1 bundle exec rake compile spec` — vendored build green.
   The decisive file is `spec/hanko_xml/native_spec.rb`: it signs *and* verifies
   every fixture shape (enveloped, enveloping, detached, c14n, exclusive c14n,
   SHA-256, SHA-512, NFe). Passing it unchanged against vendored libraries is the
   strongest single signal the vendoring is correct. `build_versions` must report
   libxml2 **2.14.6**, not the Homebrew 2.15.3.
3. `rake symbols:check` — zero exported `xml*`/`xmlSec*`.
4. **The Nokogiri co-existence test** (the one that matters): in one process,
   `require "nokogiri"` *and* the vendored `hanko_xml`, then sign and verify a
   real document via `doc.sign!`. Run with Nokogiri loaded first *and* second, on
   Linux, since load order decides interposition. Use `spec/fixtures/signed.xml`
   and `signer.crt`/`signer.key`.
5. Per-platform: install the precompiled gem into a clean container with **no**
   `libxmlsec1-dev`, require it, verify a signature.

## Risks

1. **Symbol interposition** — the big one. Mitigated by Phase 2 + verification 4.
2. **macOS cross-compile from the Linux dock** — fall back to native runners.
3. **OpenSSL 1.1 hosts** — soname differs from 3.x, so this fails loudly at load
   rather than silently. Document the source-gem fallback.
4. **CVE obligation** — vendoring makes upstream security fixes our release
   duty. Patch release, CVE named in the CHANGELOG.
5. **Gem size** — static libxml2 + xmlsec1 per ABI × 4 ABIs per platform gem.
