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
2. **Dynamically link system OpenSSL 3.x; do not vendor it.** libxml2 is a
   three-party share of *public* structs (`xmlDoc`/`xmlNode`/`xmlAttr` are
   dereferenced by field offset — that *is* its ABI). OpenSSL is two-party,
   its 3.x structs are opaque behind accessors, and its pointers never enter our
   code — the only contact is six `xmlSecOpenSSLApp*` wrappers taking PEM bytes.
   Vendoring it would also put a second libcrypto in-process beside Ruby's
   `openssl` stdlib (two provider registries, two error queues).
3. **Platforms:** `x86_64-linux`, `aarch64-linux`, `x86_64-darwin`,
   `arm64-darwin`. Windows `x64-mingw-ucrt` is deferred to its own phase — it has
   no system libcrypto, so it cannot follow decision 2.
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

**The most ABI-fragile line in the codebase is `dsig.rs:442`** —
`(*ptr).signKey = key.into_raw();`, a direct field *write* into
`xmlSecDSigCtx`, bypassing any xmlsec setter. If xmlsec ever restructures that
struct, bindgen regenerates a different-but-still-valid Rust struct and the
breakage is silent. **Vendoring actively improves this**: headers and archive
become the same pinned source by construction, so the compile-time layout and
the linked code can no longer disagree. Worth a comment at that line saying so.
The only other xmlsec field access is reading `.status` (`dsig.rs:469`).

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

### Original Phase 1 design (kept for reference)

**New: `dependencies.yml`** at the repo root — pinned version, upstream URL, and
SHA256 per library. One file, read by both the build script and CI. (Nokogiri
ships the same thing; checksums matter because we become a redistributor of
crypto code.)

**New: `ext/hanko_xml/build/vendor.rs`**, called from `build.rs`, which:
1. Resolves each tarball from a local cache dir (`ext/hanko_xml/vendor/`) or
   downloads it. **Verifies SHA256 before extracting** — hard failure on mismatch.
2. Extracts into `OUT_DIR`, runs `./configure && make && make install` into
   `OUT_DIR/vendor`.
3. Emits `cargo:rustc-link-search=native=` + `cargo:rustc-link-lib=static=` for
   `xmlsec1`, `xmlsec1-openssl`, `xml2`, and `cargo:rustc-link-lib=dylib=crypto`.

Configure flags:

- **libxml2** — `--enable-static --disable-shared --with-pic --without-python
  --without-lzma --without-http --without-html --without-icu --without-modules
  --without-readline --without-history --without-debug`, keeping
  `--with-xpath --with-xptr --with-c14n --with-schemas --with-output
  --with-regexps --with-pattern --with-valid --with-iconv --with-threads`
  (xmlsec needs xpath/xptr/c14n/schemas; iconv stays for non-UTF-8 documents).
- **xmlsec1** — `--enable-static --disable-shared --with-pic --disable-apps
  --disable-docs --disable-crypto-dl --disable-apps-crypto-dl
  --with-default-crypto=openssl --with-openssl=<sysroot> --with-libxml=<our prefix>
  --without-nss --without-nspr --without-gnutls --without-gcrypt --without-libxslt`.
  `--disable-crypto-dl` is essential: otherwise xmlsec `dlopen`s its crypto
  backend at runtime, defeating static linking.
- **Both** — `CFLAGS=-fvisibility=hidden -fPIC`, and on Linux
  `-Wl,--exclude-libs,ALL` on the final cdylib link.

**Modify `ext/hanko_xml/build.rs`** — branch at the top of `main()`:
`HANKO_XML_VENDOR=1` uses the vendored prefix; otherwise the existing
pkg-config/Homebrew path runs completely unchanged. bindgen's `-I` flags and the
allowlist are shared; only the include/link paths differ. The elaborate
`link_homebrew_libxml2_by_absolute_path` workaround applies to the system path
only — vendoring makes it moot, since there is exactly one libxml2.

**Verify:** `HANKO_XML_VENDOR=1 bundle exec rake compile && bundle exec rake spec`
on arm64-darwin; confirm `HankoXml::NativeVersion.build_versions` reports
libxml2 **2.14.6** (not the Homebrew 2.15.3), proving the vendored headers won.

## Phase 2 — Symbol-leak enforcement — **DONE**

`spec/symbols_spec.rb` asserts the built artifact exports no `xml*`/`xmlSec*`
symbols and nothing but `Init_hanko_xml`/`ruby_abi_version`. It runs in
`rake default`, uses `nm -gU` on macOS and `nm -D --defined-only` on Linux, and
skips cleanly where `nm` is unavailable. On a system build it passes trivially
(nothing is statically linked in to leak); it has teeth exactly when it matters.

The rake task from the original design was folded into the spec so a plain
`bundle exec rake` catches a leak with no extra step.

### Original Phase 2 design (kept for reference)

This is the guard against the failure that would otherwise appear only on
production Linux: two statically-linked libxml2 copies in one process, where ELF
global symbol interposition binds our `xmlReadMemory` to Nokogiri's libxml2.

**New rake task `symbols:check`** — runs `nm -D --defined-only` (Linux) /
`nm -gU` (macOS) over the built artifact and asserts **zero** exported `xml*` or
`xmlSec*` symbols, allowing only `Init_hanko_xml`. Wire into `rake default` and CI.

**New spec** in `spec/` asserting the task passes for the current build, so a
local `rake` catches it too.

## Open question surfaced by Phase 1: macOS has no system libcrypto

The vendored macOS build links **`/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib`
by absolute path**. That is fine locally and fatal for a distributed gem: a user
without Homebrew's `openssl@3` at that exact path cannot load it. Unlike Linux —
where `libcrypto.so.3` resolves by soname from a real system library — macOS has
shipped no usable system OpenSSL since Apple deprecated it.

So decision 2 ("link system libcrypto") holds cleanly on Linux but **not on
macOS**, which now looks more like Windows than like Linux. Options, to decide
before Phase 3 builds macOS gems:

1. **Vendor OpenSSL for macOS only.** Self-contained, at the cost of the CVE
   treadmill on that platform and a second libcrypto beside Ruby's.
2. **Link against the libcrypto Ruby itself already links**, discovered at build
   time from `RbConfig`. No second copy, but couples the gem to how the user's
   Ruby was built.
3. **Ship no precompiled macOS gem**, letting Macs fall back to the source gem.
   Developer machines are the least painful place to require Homebrew.

Not urgent — Linux is where the install-UX win is — but it must be settled
before a macOS platform gem is published.

## Status of the Linux cross-compile (measured, not predicted)

| Platform | Result |
|---|---|
| `x86_64-linux` | **builds** — 4.0 MB platform gem, vendored libxml2 2.14.6 + xmlsec1 1.3.12, four Ruby ABIs |
| `aarch64-linux` | **blocked** on target OpenSSL — see below |

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

### The decision this forces

Decision 2 ("link the system libcrypto, do not vendor OpenSSL") holds cleanly
**only where the build is native**. It has now broken on two targets for the
same underlying reason — the build environment has no OpenSSL for the target:

- **macOS**: no system libcrypto at all; a vendored build bakes in an absolute
  Homebrew path.
- **aarch64-linux**: cross-compiling, and the container carries only x86_64
  OpenSSL.

Three ways forward, to choose before aarch64 ships:

1. **Provision the target's OpenSSL in the build container** (`dpkg
   --add-architecture arm64` + `libssl-dev:arm64`). Keeps decision 2 intact.
   Requires running commands inside the container, so the workflow has to call
   `rb-sys-dock` directly instead of via the action — no released action tag
   supports `pre-script`. Also assumes the image's apt sources carry arm64.
2. **Vendor OpenSSL for cross-compiled targets only.** Self-contained, and
   consistent with what macOS will likely need anyway; costs the OpenSSL CVE
   treadmill on those platforms and puts a second libcrypto in-process beside
   Ruby's.
3. **Ship `x86_64-linux` only.** It works today and covers most Docker images,
   CI and cloud hosts. aarch64 users fall back to the source gem.

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

## Phase 4 — Release fan-out

- Extend `.github/workflows/release.yml` with a build matrix emitting the four
  platform gems plus the source gem.
- Reuse the existing clean-`GEM_HOME` install smoke test per platform, run
  natively where a runner exists (`ubuntu-latest`, `macos-latest`) — for a
  precompiled gem it must install **without** any `apt install libxmlsec1-dev`,
  which is the whole point and the real acceptance test.
- Push all gems in one job after every platform passes.

**Specs that will conflict and must be branched, not deleted:**

- `spec/packaging_spec.rb:57-59` — `expect(files.grep(/\.(bundle|so|dylib|o|a)\z/)).to be_empty`. Correct for the source gem, false for every native gem.
- `spec/packaging_spec.rb:41-43` — `gemspec.extensions == ["ext/hanko_xml/Cargo.toml"]`. rb_sys clears `extensions` for native gems.
- `spec/hanko_xml/native_spec.rb:23-31` — `.versions` asserts a `\A\d+\.\d+\.\d+` regex. Under vendoring this should assert the *exact* pinned versions (xmlsec 1.3.12 / libxml2 2.14.6), which turns it into a real check that the vendored headers won over any system copy.

Restructure as two contexts — source-gem shape and native-gem shape — driven off
the same gemspec, so both are asserted rather than one being loosened away.

## Phase 5 — Windows (separate decision, deferred)

`x64-mingw-ucrt` has no system libcrypto; Ruby's OpenSSL comes from
RubyInstaller's own `libcrypto-3-x64.dll`. Either link that DLL's import library
(fragile: depends on RubyInstaller's naming) or vendor OpenSSL for Windows only.
Decide when Phases 1–4 are green.

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
