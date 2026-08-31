use std::env;
use std::path::PathBuf;
use std::process::Command;

/// xmlsec1 is often installed keg-only by Homebrew (not symlinked into the
/// default prefix), so its .pc file isn't on the default pkg-config search
/// path. Add it ourselves rather than requiring every contributor to export
/// PKG_CONFIG_PATH by hand.
fn add_homebrew_pkgconfig_path() {
    let Ok(output) = Command::new("brew").args(["--prefix", "libxmlsec1"]).output() else {
        return;
    };
    if !output.status.success() {
        return;
    }
    let Ok(prefix) = String::from_utf8(output.stdout) else {
        return;
    };
    let pkgconfig_dir = PathBuf::from(prefix.trim()).join("lib/pkgconfig");
    if !pkgconfig_dir.is_dir() {
        return;
    }

    let mut paths = match env::var_os("PKG_CONFIG_PATH") {
        Some(existing) => env::split_paths(&existing).collect::<Vec<_>>(),
        None => Vec::new(),
    };
    paths.push(pkgconfig_dir);
    if let Ok(joined) = env::join_paths(paths) {
        env::set_var("PKG_CONFIG_PATH", joined);
    }
}

fn main() {
    add_homebrew_pkgconfig_path();

    let library = pkg_config::Config::new()
        .probe("xmlsec1-openssl")
        .expect(
            "xmlsec1-openssl not found via pkg-config. Install the xmlsec1 \
             development package first (macOS: `brew install xmlsec1`, \
             Debian/Ubuntu: `apt install libxmlsec1-dev`).",
        );

    let mut builder = bindgen::Builder::default()
        .header_contents(
            "xmlsec_rb_wrapper.h",
            "#include <xmlsec/xmlsec.h>\n#include <xmlsec/crypto.h>\n",
        )
        .allowlist_function("xmlSec.*")
        .allowlist_type("xmlSec.*")
        .allowlist_var("xmlSec.*")
        .allowlist_var("XMLSEC_.*")
        .derive_default(true)
        .generate_comments(false)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()));

    for include_path in &library.include_paths {
        builder = builder.clang_arg(format!("-I{}", include_path.display()));
    }
    for (name, value) in &library.defines {
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
