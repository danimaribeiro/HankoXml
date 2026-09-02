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
    sha256: String,
}

pub fn build() -> crate::Headers {
    let deps = read_dependencies();
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let prefix = out_dir.join("vendor");
    let cache = cache_dir();
    fs::create_dir_all(&cache).expect("could not create the vendor tarball cache");

    let libxml2 = deps
        .get("libxml2")
        .expect("dependencies.yml has no libxml2 entry");
    let xmlsec1 = deps
        .get("xmlsec1")
        .expect("dependencies.yml has no xmlsec1 entry");

    let libxml2_src = fetch_and_extract(libxml2, "libxml2", &cache, &out_dir);
    build_libxml2(&libxml2_src, &prefix);

    let xmlsec1_src = fetch_and_extract(xmlsec1, "xmlsec1", &cache, &out_dir);
    build_xmlsec1(&xmlsec1_src, &prefix);

    emit_link_flags(&prefix);
    probe_vendored_headers(&prefix)
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
    if let Some(openssl) = openssl_prefix() {
        include_paths.push(openssl.join("include"));
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
            Some((
                name,
                Dependency {
                    version,
                    url,
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
        download(&dep.url, &tarball);
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

fn download(url: &str, dest: &Path) {
    let partial = dest.with_extension("partial");
    run(
        Command::new("curl")
            .args(["-sSfL", "--retry", "3", "--max-time", "300", "-o"])
            .arg(&partial)
            .arg(url),
        &format!("downloading {url}"),
    );
    fs::rename(&partial, dest).expect("could not move the downloaded tarball into the cache");
}

fn sha256_file(path: &Path) -> String {
    let bytes = fs::read(path).unwrap_or_else(|e| panic!("could not read {}: {e}", path.display()));
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    format!("{:x}", hasher.finalize())
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
    let openssl_prefix = openssl_prefix();

    // We link libcrypto rather than vendoring OpenSSL, so xmlsec's configure
    // needs OpenSSL headers for the *target*. That is trivially true for a
    // native build and an open question when cross-compiling, so say out loud
    // what was found -- cargo surfaces build-script stderr when the build
    // fails, which is exactly when this matters.
    eprintln!(
        "hanko_xml: target={} cross={} openssl_prefix={}",
        target_triple(),
        is_cross_compiling(),
        openssl_prefix
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "<default search path>".into())
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
    if let Some(prefix) = &openssl_prefix {
        args.push(format!("--with-openssl={}", prefix.display()));
    }

    // xmlsec's configure runs test compiles against libxml2 and OpenSSL, so it
    // needs to find the libxml2 we just installed into the same prefix.
    let mut extra_env = vec![(
        "PKG_CONFIG_PATH".to_string(),
        prefix.join("lib/pkgconfig").display().to_string(),
    )];
    if let Some(openssl) = &openssl_prefix {
        extra_env.push((
            "LDFLAGS".to_string(),
            format!("-L{}", openssl.join("lib").display()),
        ));
        extra_env.push((
            "CPPFLAGS".to_string(),
            format!("-I{}", openssl.join("include").display()),
        ));
    }

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
    env::var(format!("{var}_{underscored}"))
        .or_else(|_| env::var(format!("TARGET_{var}")))
        .ok()
        .or_else(|| {
            let candidate = format!("{triple}-{suffix}");
            Command::new(&candidate)
                .arg("--version")
                .output()
                .ok()
                .filter(|out| out.status.success())
                .map(|_| candidate)
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

/// Where to find the OpenSSL we link *dynamically*. Deliberately not vendored
/// -- see the module docs and dependencies.yml.
fn openssl_prefix() -> Option<PathBuf> {
    if let Some(dir) = env::var_os("HANKO_XML_OPENSSL_PREFIX") {
        return Some(PathBuf::from(dir));
    }
    if target_is_macos() && !is_cross_compiling() {
        // Homebrew keeps openssl@3 keg-only, so it is not on the default
        // search path the way it is on Linux.
        let output = Command::new("brew")
            .args(["--prefix", "openssl@3"])
            .output()
            .ok()?;
        if output.status.success() {
            let prefix = PathBuf::from(String::from_utf8(output.stdout).ok()?.trim());
            if prefix.is_dir() {
                return Some(prefix);
            }
        }
    }
    None
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

    if let Some(openssl) = openssl_prefix() {
        println!(
            "cargo:rustc-link-search=native={}",
            openssl.join("lib").display()
        );
    }
    println!("cargo:rustc-link-lib=dylib=crypto");

    if target_is_macos() {
        println!("cargo:rustc-link-lib=dylib=iconv");
    } else {
        // Keep the vendored archives' symbols out of this cdylib's dynamic
        // symbol table so they cannot interpose with Nokogiri's libxml2.
        println!("cargo:rustc-link-arg=-Wl,--exclude-libs,ALL");
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
