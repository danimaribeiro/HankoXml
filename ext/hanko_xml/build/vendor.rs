//! Builds libxml2 and xmlsec1 from pinned upstream source and links them
//! statically into this extension.
//!
//! Only runs when `HANKO_XML_VENDOR=1`. The default build still probes the
//! system libraries via pkg-config (see the parent `build.rs`), so this path
//! never executes on an ordinary user's machine -- CI sets the variable when
//! producing precompiled platform gems.
//!
//! Why vendor libxml2 but not OpenSSL: `xmlDoc`/`xmlNode`/`xmlAttr` are public
//! structs this crate dereferences by field offset, and the same `xmlDocPtr` is
//! shared with xmlsec, so all three parties must agree on one layout. OpenSSL
//! 3.x structs are opaque behind accessors and its pointers never enter this
//! crate at all. See dependencies.yml.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

/// One pinned upstream library, as declared in dependencies.yml.
struct Dependency {
    version: String,
    url: String,
    /// An alternate host serving the identical tarball. Upstream sites go down,
    /// rate-limit, or (in xmlsec's case) sit behind a CDN that blocks CI
    /// runners; a failed download should not fail the build when the same bytes
    /// are one hop away. Trust does not depend on which host answers -- the
    /// SHA256 is verified either way.
    mirror: Option<String>,
    sha256: String,
}

pub fn build() -> crate::Headers {
    let deps = read_dependencies();
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let prefix = shared_prefix(&deps);
    let cache = cache_dir();
    fs::create_dir_all(&cache).expect("could not create the vendor tarball cache");

    let dep = |name: &str| {
        deps.get(name)
            .unwrap_or_else(|| panic!("dependencies.yml has no {name} entry"))
    };

    // The stamp is written only after all three installs succeed, so an
    // interrupted build is never mistaken for a complete one.
    let stamp = prefix.join(".stamp-complete");
    if stamp.exists() {
        eprintln!("hanko_xml: reusing vendored build at {}", prefix.display());
    } else {
        // OpenSSL first: xmlsec1 configures against it.
        let openssl_src = fetch_and_extract(dep("openssl"), "openssl", &cache, &out_dir);
        build_openssl(&openssl_src, &prefix);

        let libxml2_src = fetch_and_extract(dep("libxml2"), "libxml2", &cache, &out_dir);
        build_libxml2(&libxml2_src, &prefix);

        let xmlsec1_src = fetch_and_extract(dep("xmlsec1"), "xmlsec1", &cache, &out_dir);
        build_xmlsec1(&xmlsec1_src, &prefix);

        fs::write(&stamp, "").expect("could not write the vendored build stamp");
    }

    emit_link_flags(&prefix);
    probe_vendored_headers(&prefix)
}

/// Where the three C libraries get installed.
///
/// Deliberately outside `OUT_DIR`. A platform gem is compiled once per Ruby
/// ABI, and `OUT_DIR` differs for each, so keeping the prefix there rebuilt
/// OpenSSL, libxml2 and xmlsec1 four times per platform. None of them depend
/// on the Ruby ABI in any way, so the build is keyed by target triple and the
/// pinned versions instead and shared across ABIs. Bumping any version in
/// dependencies.yml changes the key and forces a clean rebuild.
fn shared_prefix(deps: &BTreeMap<String, Dependency>) -> PathBuf {
    let key = deps
        .iter()
        .map(|(name, dep)| format!("{name}-{}", dep.version))
        .collect::<Vec<_>>()
        .join("_");
    manifest_root()
        .join("tmp/vendor-build")
        .join(target_triple())
        .join(key)
}

/// Harvests the include paths and `-D` defines from the `.pc` files the two
/// builds just installed into our own prefix.
///
/// Deliberately pkg-config rather than a hardcoded list: the define set records
/// which algorithms the library was actually compiled with (`XMLSEC_NO_MD5`,
/// `XMLSEC_NO_GOST`, and so on) plus the crypto backend selector that xmlsec's
/// headers refuse to compile without. Hardcoding it would silently drift the
/// moment a configure flag above changes. This is the same mechanism the system
/// path uses, pointed at our prefix instead of the OS's.
fn probe_vendored_headers(prefix: &Path) -> crate::Headers {
    let pkgconfig_dir = prefix.join("lib/pkgconfig");
    env::set_var("PKG_CONFIG_PATH", &pkgconfig_dir);
    // We already emitted our own link flags, and these are the archives we just
    // built for the target, so pkg-config must not second-guess a cross build.
    env::set_var("PKG_CONFIG_ALLOW_CROSS", "1");

    let mut cfg = pkg_config::Config::new();
    cfg.cargo_metadata(false).statik(true);
    let xmlsec = cfg.probe("xmlsec1-openssl").unwrap_or_else(|e| {
        panic!(
            "the vendored xmlsec1 did not install a usable xmlsec1-openssl.pc in {}: {e}",
            pkgconfig_dir.display()
        )
    });

    let mut include_paths = vec![prefix.join("include"), prefix.join("include/libxml2")];
    include_paths.extend(xmlsec.include_paths.iter().cloned());
    if let Some(multiarch) = multiarch_include_dir() {
        eprintln!("hanko_xml: multiarch include dir {}", multiarch.display());
        include_paths.push(multiarch);
    }

    crate::Headers {
        include_paths,
        defines: xmlsec
            .defines
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect(),
    }
}

// --- dependencies.yml ---------------------------------------------------

/// A deliberately small parser for the exact shape dependencies.yml has:
/// top-level keys, two-space-indented `key: "value"` pairs, `#` comments.
/// A real YAML crate would be a build dependency (and the maintained ones are
/// large) for a file we own and that spec/packaging_spec.rb already validates.
fn read_dependencies() -> BTreeMap<String, Dependency> {
    let path = manifest_root().join("dependencies.yml");
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("could not read {}: {e}", path.display()));

    let mut deps: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let mut current: Option<String> = None;

    for line in text.lines() {
        let trimmed = line.trim_end();
        if trimmed.trim_start().starts_with('#') || trimmed.trim().is_empty() {
            continue;
        }
        if !trimmed.starts_with(' ') {
            let name = trimmed.trim_end_matches(':').trim().to_string();
            deps.entry(name.clone()).or_default();
            current = Some(name);
        } else if let Some(name) = &current {
            let Some((key, value)) = trimmed.split_once(':') else {
                continue;
            };
            let value = value.trim().trim_matches('"').to_string();
            deps.get_mut(name)
                .expect("current section is present")
                .insert(key.trim().to_string(), value);
        }
    }

    deps.into_iter()
        .filter_map(|(name, fields)| {
            let version = fields.get("version")?.clone();
            let url = fields.get("url")?.clone();
            let sha256 = fields.get("sha256")?.clone();
            let mirror = fields.get("mirror").cloned();
            Some((
                name,
                Dependency {
                    version,
                    url,
                    mirror,
                    sha256,
                },
            ))
        })
        .collect()
}

fn manifest_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is ext/hanko_xml; dependencies.yml lives at the repo
    // root, which is also what ships in the gem.
    PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set")).join("../..")
}

fn cache_dir() -> PathBuf {
    match env::var_os("HANKO_XML_VENDOR_CACHE") {
        Some(dir) => PathBuf::from(dir),
        None => manifest_root().join("tmp/vendor-cache"),
    }
}

// --- fetch + verify -----------------------------------------------------

fn fetch_and_extract(dep: &Dependency, name: &str, cache: &Path, out_dir: &Path) -> PathBuf {
    let filename = dep
        .url
        .rsplit('/')
        .next()
        .unwrap_or_else(|| panic!("{name}: could not derive a filename from {}", dep.url));
    let tarball = cache.join(filename);

    if !tarball.exists() {
        download_with_fallback(dep, &tarball, name);
    }

    // Verified before extraction, every time -- including for a cached file,
    // which may have been truncated by an interrupted earlier run. We are
    // redistributing cryptographic code; a mismatch is fatal, never a warning.
    let actual = sha256_file(&tarball);
    if actual != dep.sha256 {
        let _ = fs::remove_file(&tarball);
        panic!(
            "{name} {} checksum mismatch\n  expected {}\n  actual   {}\n\
             The cached file has been removed. If this was not a corrupt download, \
             do not update the checksum in dependencies.yml without verifying the \
             release upstream.",
            dep.version, dep.sha256, actual
        );
    }

    let src = out_dir.join(format!("{name}-{}", dep.version));
    if src.exists() {
        fs::remove_dir_all(&src).ok();
    }
    run(
        Command::new("tar")
            .arg("-xf")
            .arg(&tarball)
            .arg("-C")
            .arg(out_dir),
        &format!("extracting {filename}"),
    );

    if !src.exists() {
        panic!(
            "{name}: expected {} after extracting {filename}",
            src.display()
        );
    }
    src
}

fn download_with_fallback(dep: &Dependency, dest: &Path, name: &str) {
    let mut sources = vec![dep.url.as_str()];
    sources.extend(dep.mirror.as_deref());

    let mut failures = Vec::new();
    for url in &sources {
        match download(url, dest) {
            Ok(()) => return,
            Err(err) => {
                eprintln!("hanko_xml: {name}: {url} failed ({err})");
                failures.push(format!("  {url}: {err}"));
            }
        }
    }
    panic!(
        "could not download {name} {} from any known source:\n{}",
        dep.version,
        failures.join("\n")
    );
}

fn download(url: &str, dest: &Path) -> Result<(), String> {
    let partial = dest.with_extension("partial");
    let _ = fs::remove_file(&partial);

    // An explicit User-Agent because some upstream hosts sit behind a CDN that
    // rejects curl's default one outright.
    let status = Command::new("curl")
        .args([
            "-sSfL",
            "--retry",
            "3",
            "--max-time",
            "300",
            "-A",
            "hanko_xml-build/1.0",
            "-o",
        ])
        .arg(&partial)
        .arg(url)
        .status()
        .map_err(|e| format!("could not start curl: {e}"))?;

    if !status.success() {
        let _ = fs::remove_file(&partial);
        return Err(format!("curl exited with {status}"));
    }
    fs::rename(&partial, dest).map_err(|e| format!("could not move into the cache: {e}"))
}

fn sha256_file(path: &Path) -> String {
    let bytes = fs::read(path).unwrap_or_else(|e| panic!("could not read {}: {e}", path.display()));
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    // Formatted byte-by-byte rather than with `{:x}`: sha2 0.11 returns
    // hybrid-array's `Array` instead of `GenericArray`, and that type does not
    // implement LowerHex. Doing it here keeps the build working across both.
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

// --- the builds ---------------------------------------------------------

/// Hidden visibility is not an optimisation here -- it is what keeps our
/// statically-linked libxml2 from being interposed by Nokogiri's copy (or vice
/// versa) when both are loaded into one Ruby process. On Linux the dynamic
/// linker resolves a duplicated symbol to whichever definition was loaded
/// first, process-wide, so an exported `xmlReadMemory` from this extension
/// could silently bind to a different libxml2's implementation. Upstream's
/// XMLPUBFUN/XMLSEC_EXPORT macros expand to nothing on non-Windows, so this
/// flag is not overridden.
const HIDDEN_VISIBILITY_CFLAGS: &str = "-fvisibility=hidden -fPIC -O2";

/// OpenSSL's Configure wants its target as a positional argument and cannot
/// auto-detect one when cross-compiling. Map the Rust triple onto OpenSSL's
/// own naming; returning None falls back to `./config`, which auto-detects and
/// is correct for a native build.
fn openssl_target() -> Option<&'static str> {
    match target_triple().as_str() {
        "x86_64-unknown-linux-gnu" => Some("linux-x86_64"),
        "aarch64-unknown-linux-gnu" => Some("linux-aarch64"),
        "aarch64-apple-darwin" => Some("darwin64-arm64-cc"),
        "x86_64-apple-darwin" => Some("darwin64-x86_64-cc"),
        _ => None,
    }
}

fn build_openssl(src: &Path, prefix: &Path) {
    let (cross_args, cross_env) = cross_config();
    let target = openssl_target();

    // `./Configure` takes an explicit target; `./config` guesses. Use the
    // explicit one wherever we know the mapping.
    let script = if target.is_some() {
        "./Configure"
    } else {
        "./config"
    };

    let mut args: Vec<String> = Vec::new();
    if let Some(t) = target {
        args.push(t.to_string());
    }
    args.push(format!("--prefix={}", prefix.display()));
    args.push(format!("--openssldir={}", prefix.join("ssl").display()));
    // Some platforms default to lib64/, which our single link-search path
    // would then miss entirely.
    args.push("--libdir=lib".into());
    args.push("no-shared".into());
    args.push("no-tests".into());
    args.push("no-docs".into());
    // Deliberately not no-legacy: xmlsec selects algorithms at runtime, and
    // trimming providers here would fail as a signature error much later
    // rather than as a build error now.

    let mut configure = Command::new(script);
    configure.current_dir(src).args(&args);
    // OpenSSL's own build system handles --host-style flags itself, so only
    // the toolchain environment carries over from cross_config().
    let _ = &cross_args;
    configure.env("CFLAGS", HIDDEN_VISIBILITY_CFLAGS);
    for (key, value) in &cross_env {
        configure.env(key, value);
    }
    run(
        &mut configure,
        &format!("configuring openssl for {}", target_triple()),
    );

    let jobs = env::var("NUM_JOBS").unwrap_or_else(|_| "4".into());
    let mut build = Command::new("make");
    build.current_dir(src).arg(format!("-j{jobs}"));
    for (key, value) in &cross_env {
        build.env(key, value);
    }
    run(&mut build, "building openssl");

    // install_sw is the libraries and headers only; plain `install` also
    // builds and installs man pages we do not ship.
    let mut install = Command::new("make");
    install.current_dir(src).arg("install_sw");
    for (key, value) in &cross_env {
        install.env(key, value);
    }
    run(&mut install, "installing openssl");
}

fn build_libxml2(src: &Path, prefix: &Path) {
    // Feature flags are load-bearing beyond linking: build.rs allowlists
    // `LIBXML_.*` for bindgen, which sweeps in the LIBXML_*_ENABLED macros, and
    // those gate declarations in headers bindgen parses. Disabling a feature
    // can therefore change which items exist in the generated bindings -- so
    // this list stays conservative, and any change to it needs a full rebuild
    // plus the whole spec suite.
    let args = vec![
        format!("--prefix={}", prefix.display()),
        "--enable-static".into(),
        "--disable-shared".into(),
        "--with-pic".into(),
        // Required: xmlsec needs xpath/xptr/c14n/schemas to build DSig at all,
        // and this crate needs tree + output for xmlReadMemory/xmlDocDumpMemory.
        "--with-xpath".into(),
        "--with-xptr".into(),
        "--with-c14n".into(),
        "--with-schemas".into(),
        "--with-output".into(),
        "--with-regexps".into(),
        "--with-pattern".into(),
        "--with-valid".into(),
        "--with-tree".into(),
        "--with-iconv".into(),
        "--with-threads".into(),
        // Not used by this crate, and dropping http/ftp also closes off
        // network fetches from within XML processing.
        "--without-python".into(),
        "--without-lzma".into(),
        "--without-zlib".into(),
        "--without-http".into(),
        "--without-html".into(),
        "--without-icu".into(),
        "--without-modules".into(),
        "--without-readline".into(),
        "--without-history".into(),
        "--without-debug".into(),
    ];
    configure_make_install(src, &args, "libxml2", &[]);
}

fn build_xmlsec1(src: &Path, prefix: &Path) {
    // OpenSSL is vendored into the same prefix, so xmlsec configures against
    // the exact build we just made rather than whatever the machine happens to
    // have. That is what stops the gem recording a NEEDED entry for a
    // libcrypto soname the user does not have.
    eprintln!(
        "hanko_xml: target={} cross={} openssl=vendored at {}",
        target_triple(),
        is_cross_compiling(),
        prefix.display()
    );

    let mut args = vec![
        format!("--prefix={}", prefix.display()),
        format!("--with-libxml={}", prefix.display()),
        "--enable-static".into(),
        "--disable-shared".into(),
        "--with-pic".into(),
        "--disable-apps".into(),
        "--disable-docs".into(),
        // Essential: without this xmlsec dlopen()s its crypto backend at
        // runtime, which defeats static linking entirely.
        "--disable-crypto-dl".into(),
        "--disable-apps-crypto-dl".into(),
        "--with-default-crypto=openssl".into(),
        "--without-nss".into(),
        "--without-nspr".into(),
        "--without-gnutls".into(),
        "--without-gcrypt".into(),
        "--without-libxslt".into(),
    ];
    args.push(format!("--with-openssl={}", prefix.display()));

    // OpenSSL and libxml2 are both already installed into this prefix, so
    // xmlsec's configure test-compiles resolve against exactly what we built.
    let extra_env = vec![
        (
            "PKG_CONFIG_PATH".to_string(),
            prefix.join("lib/pkgconfig").display().to_string(),
        ),
        (
            "LDFLAGS".to_string(),
            format!("-L{}", prefix.join("lib").display()),
        ),
        (
            "CPPFLAGS".to_string(),
            format!("-I{}", prefix.join("include").display()),
        ),
    ];

    configure_make_install(src, &args, "xmlsec1", &extra_env);
}

/// The Rust target triple this extension is being built for, e.g.
/// `aarch64-unknown-linux-gnu`. Cargo always sets it, including for host builds.
fn target_triple() -> String {
    env::var("TARGET").expect("TARGET not set")
}

/// True when cargo is cross-compiling. `x86_64-linux` platform gems are built
/// natively inside the x86_64 dock container and take the cheap path; only
/// `aarch64-linux` actually cross-compiles.
fn is_cross_compiling() -> bool {
    match env::var("HOST") {
        Ok(host) => host != target_triple(),
        Err(_) => false,
    }
}

/// Whether the *target* is macOS. `cfg!(target_os = ...)` is wrong here: a
/// build script is compiled for the host, so it would describe the build
/// machine rather than what we are producing.
fn target_is_macos() -> bool {
    env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos")
}

/// The cross toolchain to hand autotools, resolved from the environment the
/// way the `cc` crate does: `CC_<triple>` (underscored), then `TARGET_CC`, then
/// the conventional `<triple>-gcc` prefix that rake-compiler-dock provides.
fn cross_tool(var: &str, suffix: &str) -> Option<String> {
    let triple = target_triple();
    let underscored = triple.replace('-', "_");
    if let Ok(tool) = env::var(format!("{var}_{underscored}")).or_else(|_| env::var(format!("TARGET_{var}"))) {
        return Some(tool);
    }

    // Two prefixes to try, because Rust and the GNU toolchains disagree on
    // triple spelling. rake-compiler-dock installs the Debian-style name --
    // rb-sys passes `-C linker=aarch64-linux-gnu-gcc` -- while cargo's TARGET
    // carries the vendor field, `aarch64-unknown-linux-gnu`. Probing only the
    // Rust spelling finds nothing, which would leave CC unset and build the C
    // libraries with the *host* compiler while configured for the target.
    let gnu_triple = triple.replacen("-unknown-", "-", 1);
    [triple.as_str(), gnu_triple.as_str()]
        .iter()
        .map(|prefix| format!("{prefix}-{suffix}"))
        .find(|candidate| {
            Command::new(candidate)
                .arg("--version")
                .output()
                .is_ok_and(|out| out.status.success())
        })
}

/// Extra configure arguments and environment needed when cross-compiling.
/// Empty for a native build, so the host path is unchanged.
fn cross_config() -> (Vec<String>, Vec<(String, String)>) {
    if !is_cross_compiling() {
        return (Vec::new(), Vec::new());
    }

    let triple = target_triple();
    // autotools' config.sub understands Rust's cpu-vendor-os triples directly.
    let mut args = vec![format!("--host={triple}")];
    // libxml2 and xmlsec both run link-and-execute feature probes that cannot
    // work when the binary is for another architecture; --host already puts
    // autotools in cross mode, this just makes the intent explicit.
    args.push("--disable-dependency-tracking".into());

    let mut env_vars = Vec::new();
    for (var, suffix) in [("CC", "gcc"), ("AR", "ar"), ("RANLIB", "ranlib")] {
        if let Some(tool) = cross_tool(var, suffix) {
            env_vars.push((var.to_string(), tool));
        }
    }

    (args, env_vars)
}

fn configure_make_install(src: &Path, args: &[String], name: &str, extra_env: &[(String, String)]) {
    let (cross_args, cross_env) = cross_config();

    let mut configure = Command::new("./configure");
    configure.current_dir(src).args(args).args(&cross_args);
    configure.env("CFLAGS", HIDDEN_VISIBILITY_CFLAGS);
    for (key, value) in cross_env.iter().chain(extra_env) {
        configure.env(key, value);
    }
    run(&mut configure, &format!("configuring {name} for {}", target_triple()));

    let jobs = env::var("NUM_JOBS").unwrap_or_else(|_| "4".into());
    let mut build = Command::new("make");
    build.current_dir(src).arg(format!("-j{jobs}"));
    for (key, value) in cross_env.iter().chain(extra_env) {
        build.env(key, value);
    }
    run(&mut build, &format!("building {name}"));

    let mut install = Command::new("make");
    install.current_dir(src).arg("install");
    for (key, value) in cross_env.iter().chain(extra_env) {
        install.env(key, value);
    }
    run(&mut install, &format!("installing {name}"));
}

/// Debian and Ubuntu put architecture-specific headers under
/// `/usr/include/<multiarch triple>`, and OpenSSL's `opensslconf.h` is one of
/// them: `e_os2.h` does `#include <openssl/opensslconf.h>` and relies on that
/// directory being on the include path.
///
/// GCC adds it automatically, which is why libxml2 and xmlsec1 compile fine.
/// The clang instance bindgen runs does not, so without this the C libraries
/// build and then binding generation fails on a header GCC found without
/// being asked. Returns nothing on systems that do not use multiarch.
fn multiarch_include_dir() -> Option<PathBuf> {
    fn ask(cc: &str) -> Option<String> {
        Command::new(cc)
            .arg("-print-multiarch")
            .output()
            .ok()
            .filter(|out| out.status.success())
            .and_then(|out| String::from_utf8(out.stdout).ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    // Only ask a compiler that speaks for the *target*. Falling back to the
    // host `cc` while cross-compiling would confidently return the build
    // machine's triple — x86_64-linux-gnu while building for aarch64 — and
    // point bindgen at headers for the wrong architecture. When there is no
    // target compiler to ask, derive it instead.
    let probed = match (cross_tool("CC", "gcc"), is_cross_compiling()) {
        (Some(target_cc), _) => ask(&target_cc),
        (None, true) => None,
        (None, false) => ask("cc"),
    };

    // Fall back to deriving it from the Rust target, whose triples map onto
    // Debian's by dropping the vendor field: x86_64-unknown-linux-gnu becomes
    // x86_64-linux-gnu.
    let triple = probed.unwrap_or_else(|| target_triple().replacen("-unknown-", "-", 1));

    let dir = PathBuf::from("/usr/include").join(triple);
    dir.is_dir().then_some(dir)
}

// --- linking ------------------------------------------------------------

fn emit_link_flags(prefix: &Path) {
    println!(
        "cargo:rustc-link-search=native={}",
        prefix.join("lib").display()
    );
    // Order matters for static archives: xmlsec's OpenSSL backend depends on
    // xmlsec core, which depends on libxml2.
    println!("cargo:rustc-link-lib=static=xmlsec1-openssl");
    println!("cargo:rustc-link-lib=static=xmlsec1");
    println!("cargo:rustc-link-lib=static=xml2");
    // Static, not dylib: linking the system libcrypto is what recorded a
    // NEEDED entry for the build container's soname (libcrypto.so.1.1) and
    // made the gem unloadable on any current distro.
    println!("cargo:rustc-link-lib=static=crypto");

    if target_is_macos() {
        println!("cargo:rustc-link-lib=dylib=iconv");
    } else {
        // Keep the vendored archives' symbols out of this cdylib's dynamic
        // symbol table so they cannot interpose with Nokogiri's libxml2 -- or,
        // now, with the libcrypto Ruby's own openssl extension already loaded.
        println!("cargo:rustc-link-arg=-Wl,--exclude-libs,ALL");
        // A static libcrypto still needs these from the platform.
        println!("cargo:rustc-link-lib=dylib=dl");
        println!("cargo:rustc-link-lib=dylib=pthread");
    }
    println!("cargo:rustc-link-lib=dylib=m");
}

fn run(command: &mut Command, what: &str) {
    let status = command
        .status()
        .unwrap_or_else(|e| panic!("failed to start `{what}`: {e}"));
    if !status.success() {
        panic!("`{what}` failed with {status}");
    }
}
