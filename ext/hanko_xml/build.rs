use std::env;
use std::path::PathBuf;
use std::process::Command;

#[path = "build/vendor.rs"]
mod vendor;

/// Everything bindgen needs to parse the xmlsec/libxml2 headers, produced by
/// whichever of the two paths below ran. The defines matter as much as the
/// include paths: xmlsec's headers refuse to compile without a crypto backend
/// selected (`XMLSEC_CRYPTO_OPENSSL`), and the rest of the `-D` set records
/// which algorithms the library was actually built with.
pub struct Headers {
    pub include_paths: Vec<PathBuf>,
    pub defines: Vec<(String, Option<String>)>,
}

/// Homebrew installs several of our dependencies keg-only (not symlinked
/// into the default prefix), so their .pc files aren't on the default
/// pkg-config search path. Add every keg-only formula we depend on
/// ourselves, rather than requiring every contributor to export
/// PKG_CONFIG_PATH by hand.
///
/// This matters for more than convenience: `xmlsec1-openssl.pc`'s own
/// `Libs:`/`Cflags:` lines reference libxml2 with a bare `-lxml2` and no
/// `-I`/`-L`, because pkg-config couldn't resolve libxml2's keg-only .pc
/// file either. Left alone, that makes our linker and bindgen fall back to
/// macOS's own ancient system libxml2 (`/usr/lib/libxml2.2.dylib`) instead
/// of the Homebrew libxml2 that `libxmlsec1-openssl.dylib` itself actually
/// links against — two different libxml2 builds in the same process,
/// silently handing structs allocated by one ABI to code compiled against
/// the other. So every formula below is probed explicitly, not left to
/// `Requires:` chasing.
fn add_homebrew_pkgconfig_paths(formulas: &[&str]) {
    let mut paths = match env::var_os("PKG_CONFIG_PATH") {
        Some(existing) => env::split_paths(&existing).collect::<Vec<_>>(),
        None => Vec::new(),
    };

    for formula in formulas {
        let Ok(output) = Command::new("brew").args(["--prefix", formula]).output() else {
            continue;
        };
        if !output.status.success() {
            continue;
        }
        let Ok(prefix) = String::from_utf8(output.stdout) else {
            continue;
        };
        let pkgconfig_dir = PathBuf::from(prefix.trim()).join("lib/pkgconfig");
        if pkgconfig_dir.is_dir() {
            paths.push(pkgconfig_dir);
        }
    }

    if let Ok(joined) = env::join_paths(paths) {
        env::set_var("PKG_CONFIG_PATH", joined);
    }
}

/// Links libxml2 by its exact, absolute dylib path instead of the ordinary
/// `-lxml2` + `-L<dir>` name search.
///
/// Why: rustc always emits every `-l<name>` flag *before* any `-L<dir>`
/// search path in the linker invocation it generates (verified empirically
/// with a linker-trace wrapper: `-lxml2` lands at argument position ~11,
/// our own `-L` flags land at ~40+, no matter what order we print
/// `cargo:rustc-link-lib`/`cargo:rustc-link-search` from build.rs). ld64
/// resolves `-lxml2` using only the search paths it has seen *so far* at
/// that position — none of ours — so it silently falls back to its default
/// search path and picks up macOS's own ancient system libxml2
/// (`/usr/lib/libxml2.2.dylib`) instead of the Homebrew build that
/// `libxmlsec1-openssl.dylib` itself is linked against. That leaves our
/// direct calls to `xmlReadMemory`/`xmlFreeDoc`/`xmlDocGetRootElement`
/// bound to a *different* libxml2 ABI than the one xmlsec's own internal
/// calls (`xmlSecFindNode`, ID-attribute lookups, etc.) use on the exact
/// same `xmlDocPtr` — two different struct layouts for the same pointer.
/// A direct path reference isn't resolved by name search at all, so the
/// ordering problem above doesn't apply to it.
fn link_homebrew_libxml2_by_absolute_path(libxml2: &pkg_config::Library) {
    let dylib_path = libxml2
        .link_paths
        .first()
        .map(|dir| dir.join("libxml2.dylib"))
        .filter(|path| path.exists())
        .expect("could not locate libxml2.dylib in the Homebrew libxml2 keg");
    println!("cargo:rustc-link-arg={}", dylib_path.display());
}

fn main() {
    println!("cargo:rerun-if-env-changed=HANKO_XML_VENDOR");
    println!("cargo:rerun-if-env-changed=HANKO_XML_OPENSSL_PREFIX");
    println!("cargo:rerun-if-changed=../../dependencies.yml");

    // Two mutually exclusive ways to find libxmlsec1 and libxml2:
    //
    //   vendored (HANKO_XML_VENDOR=1) -- build both from the pinned source in
    //     dependencies.yml and link them statically. Used by CI to produce the
    //     precompiled platform gems. Headers and archives then come from one
    //     source and cannot disagree.
    //
    //   system (default) -- probe pkg-config, as below. This is what an
    //     ordinary `gem install` does, so the vendored path never runs on a
    //     user's machine unless they opt in.
    //
    // Everything downstream (the bindgen allowlist, the generated bindings) is
    // shared; only the include and link paths differ.
    let headers = if env::var_os("HANKO_XML_VENDOR").is_some_and(|v| v != "0" && !v.is_empty()) {
        vendor::build()
    } else {
        system_libraries()
    };

    generate_bindings(&headers);
}

/// Probes the system libxmlsec1/libxml2 and emits their link metadata.
fn system_libraries() -> Headers {
    add_homebrew_pkgconfig_paths(&["libxmlsec1", "libxml2"]);

    // We emit link metadata ourselves below instead of letting pkg-config
    // auto-emit it, so that we can single out libxml2 for absolute-path
    // linking (macOS only — see link_homebrew_libxml2_by_absolute_path).
    let mut xmlsec_cfg = pkg_config::Config::new();
    xmlsec_cfg.cargo_metadata(cfg!(not(target_os = "macos")));
    let xmlsec = xmlsec_cfg.probe("xmlsec1-openssl").expect(
        "xmlsec1-openssl not found via pkg-config. Install the xmlsec1 \
         development package first (macOS: `brew install xmlsec1`, \
         Debian/Ubuntu: `apt install libxmlsec1-dev`).",
    );
    // Probed for its own sake: makes sure our libxml2 linkage and headers
    // resolve to the exact same build that xmlsec1-openssl.dylib links
    // against, instead of silently falling back to the OS's libxml2. See
    // the comment on add_homebrew_pkgconfig_paths above.
    let mut libxml2_cfg = pkg_config::Config::new();
    libxml2_cfg.cargo_metadata(cfg!(not(target_os = "macos")));
    let libxml2 = libxml2_cfg.probe("libxml-2.0").expect(
        "libxml2 not found via pkg-config. Install its development package \
         first (macOS: `brew install libxml2`, Debian/Ubuntu: `apt install libxml2-dev`).",
    );

    if cfg!(target_os = "macos") {
        for path in &xmlsec.link_paths {
            println!("cargo:rustc-link-search=native={}", path.display());
        }
        for lib in &xmlsec.libs {
            if lib != "xml2" {
                println!("cargo:rustc-link-lib=dylib={lib}");
            }
        }
        link_homebrew_libxml2_by_absolute_path(&libxml2);
    }

    // libxml2's include path goes first so its headers win over whatever
    // libxml2 copy the system's default clang search path would otherwise
    // find, keeping bindgen's struct layout in lockstep with the dylib we
    // actually link.
    Headers {
        include_paths: libxml2
            .include_paths
            .iter()
            .chain(&xmlsec.include_paths)
            .cloned()
            .collect(),
        defines: libxml2
            .defines
            .iter()
            .chain(&xmlsec.defines)
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect(),
    }
}

/// Runs bindgen over the xmlsec/libxml2 headers found at `include_paths` and
/// writes the result to OUT_DIR. Shared by both the vendored and system paths:
/// the allowlist and the generated surface must not depend on which one ran.
fn generate_bindings(headers: &Headers) {
    let mut builder = bindgen::Builder::default()
        .header_contents(
            "hanko_xml_wrapper.h",
            "#include <xmlsec/xmlsec.h>\n\
             #include <xmlsec/crypto.h>\n\
             #include <xmlsec/xmldsig.h>\n\
             #include <xmlsec/xmltree.h>\n\
             #include <xmlsec/errors.h>\n\
             #include <xmlsec/keys.h>\n\
             #include <xmlsec/keyinfo.h>\n\
             #include <xmlsec/app.h>\n\
             #include <xmlsec/openssl/app.h>\n\
             #include <xmlsec/openssl/crypto.h>\n\
             #include <libxml/tree.h>\n\
             #include <libxml/xmlmemory.h>\n\
             #include <libxml/xmlversion.h>\n",
        )
        .allowlist_function("xmlSec.*")
        .allowlist_type("xmlSec.*")
        .allowlist_var("xmlSec.*")
        .allowlist_var("XMLSEC_.*")
        .allowlist_var("LIBXML_.*")
        // libxml2 parsing and document management
        .allowlist_function("xmlReadMemory")
        .allowlist_function("xmlFreeDoc")
        .allowlist_function("xmlDocGetRootElement")
        // libxml2 serialization (for sign → return signed bytes)
        .allowlist_function("xmlDocDumpMemory")
        .allowlist_function("xmlDocDumpFormatMemory")
        // libxml2 node content and attribute extraction (for inspect)
        .allowlist_function("xmlNodeGetContent")
        .allowlist_function("xmlGetProp")
        .allowlist_function("__xmlFree")
        .allowlist_function("xmlMemFree")
        // libxml2 node/child traversal
        .allowlist_function("xmlNodeListGetString")
        .allowlist_type("xmlNode")
        .allowlist_type("xmlDoc")
        .allowlist_type("xmlAttr")
        .allowlist_type("xmlNs")
        .derive_default(true)
        .generate_comments(false)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()));

    for include_path in &headers.include_paths {
        builder = builder.clang_arg(format!("-I{}", include_path.display()));
    }
    for (name, value) in &headers.defines {
        builder = builder.clang_arg(match value {
            Some(v) => format!("-D{name}={v}"),
            None => format!("-D{name}"),
        });
    }

    let bindings = builder
        .generate()
        .expect("failed to generate xmlsec bindgen bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("failed to write xmlsec bindgen bindings");
}
