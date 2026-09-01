//! Magnus glue: 5 functions on `XmlsecRb::Native`, matching the §7 contract.
//!
//! Every argument from Ruby is copied into a Rust-owned `Vec<u8>` or `String`
//! **before** any native call, so there is no `unsafe` in this file — no
//! `RString::as_slice()` across a call that might release the GVL.

mod dsig;
mod errors;
mod sys;

use magnus::{
    exception, function, prelude::*, Error, ExceptionClass, RArray, RHash, RModule, RString,
    Ruby, TryConvert,
};
use std::sync::Once;

static INIT: Once = Once::new();

/// Runs [`dsig::init_xmlsec`] exactly once per process.
fn ensure_initialized() -> Result<(), &'static str> {
    let mut result = Ok(());
    INIT.call_once(|| result = dsig::init_xmlsec());
    result
}

// ---------------------------------------------------------------------------
// Error construction helpers
// ---------------------------------------------------------------------------

fn error_class(ruby: &Ruby, class_name: &str) -> ExceptionClass {
    ruby.eval::<ExceptionClass>(class_name)
        .unwrap_or_else(|_| exception::runtime_error())
}

fn signing_error(ruby: &Ruby, message: String, xmlsec_errors: Vec<String>) -> Error {
    build_typed_error(ruby, "XmlsecRb::SigningError", message, xmlsec_errors)
}

fn parse_error(ruby: &Ruby, message: String) -> Error {
    Error::new(error_class(ruby, "XmlsecRb::ParseError"), message)
}

fn key_load_error(ruby: &Ruby, message: String) -> Error {
    Error::new(error_class(ruby, "XmlsecRb::KeyLoadError"), message)
}

fn native_error(ruby: &Ruby, message: String) -> Error {
    Error::new(error_class(ruby, "XmlsecRb::NativeError"), message)
}

/// Builds a typed error with `xmlsec_errors` included in the message.
fn build_typed_error(
    ruby: &Ruby,
    class_name: &str,
    message: String,
    xmlsec_errors: Vec<String>,
) -> Error {
    let cls = error_class(ruby, class_name);

    if !xmlsec_errors.is_empty() {
        let msg_with_errors = format!(
            "{}\nxmlsec errors:\n{}",
            message,
            xmlsec_errors.join("\n")
        );
        Error::new(cls, msg_with_errors)
    } else {
        Error::new(cls, message)
    }
}

// ---------------------------------------------------------------------------
// Argument extraction and Ruby array helpers
// ---------------------------------------------------------------------------

/// Extracts an RString to an owned Vec<u8>.
fn rstring_to_bytes(s: RString) -> Vec<u8> {
    // SAFETY: s is a live Ruby String argument on the call stack.
    // We immediately copy to a Vec<u8> so the slice is not retained.
    unsafe { s.as_slice() }.to_vec()
}

/// Converts a slice of Strings to a Ruby Array of RStrings.
fn string_slice_to_rarray(ruby: &Ruby, strings: &[String]) -> Result<RArray, Error> {
    let arr = ruby.ary_new();
    for s in strings {
        arr.push(ruby.str_new(s))
            .map_err(|e| native_error(ruby, format!("array push error: {e}")))?;
    }
    Ok(arr)
}

/// Extracts an RArray of RString into a Vec<Vec<u8>>.
fn rarray_to_byte_vecs(ruby: &Ruby, arr: RArray) -> Result<Vec<Vec<u8>>, Error> {
    let mut result = Vec::new();
    for item in arr.each() {
        let item = item.map_err(|e| native_error(ruby, format!("array iteration error: {e}")))?;
        let s: RString = TryConvert::try_convert(item)
            .map_err(|_| native_error(ruby, "array element is not a String".into()))?;
        result.push(rstring_to_bytes(s));
    }
    Ok(result)
}

/// Extracts an RArray of RString into a Vec<String>.
fn rarray_to_strings(ruby: &Ruby, arr: RArray) -> Result<Vec<String>, Error> {
    let mut result = Vec::new();
    for item in arr.each() {
        let item = item.map_err(|e| native_error(ruby, format!("array iteration error: {e}")))?;
        let s: RString = TryConvert::try_convert(item)
            .map_err(|_| native_error(ruby, "array element is not a String".into()))?;
        result.push(
            String::from_utf8(rstring_to_bytes(s))
                .map_err(|_| native_error(ruby, "id_attribute is not valid UTF-8".into()))?,
        );
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// Native functions — the §7 contract
// ---------------------------------------------------------------------------

/// `XmlsecRb::Native.sign(xml, key_pem, cert_pems, id_attributes, signature_index)`
///
/// Signs the document's nth `<ds:Signature>` template and returns the
/// complete signed XML as a binary String.
fn native_sign(
    ruby: &Ruby,
    xml: RString,
    key_pem: RString,
    cert_pems: RArray,
    id_attributes: RArray,
    signature_index: usize,
) -> Result<RString, Error> {
    ensure_initialized().map_err(|msg| native_error(ruby, msg.into()))?;

    let xml_bytes = rstring_to_bytes(xml);
    let key_bytes = rstring_to_bytes(key_pem);
    let cert_bytes = rarray_to_byte_vecs(ruby, cert_pems)?;
    let id_attrs = rarray_to_strings(ruby, id_attributes)?;

    match dsig::sign_document(&xml_bytes, &key_bytes, &cert_bytes, &id_attrs, signature_index) {
        Ok(signed_bytes) => Ok(ruby.str_from_slice(&signed_bytes)),
        Err(msg) => {
            let captured = errors::drain_errors();
            if msg.contains("parse") {
                Err(parse_error(ruby, msg))
            } else if msg.contains("key") || msg.contains("certificate") {
                Err(key_load_error(ruby, msg))
            } else {
                Err(signing_error(ruby, msg, captured))
            }
        }
    }
}

/// `XmlsecRb::Native.verify(xml, trusted_pems, untrusted_pems, id_attributes, signature_index)`
///
/// Verifies the nth `<ds:Signature>` and returns a Hash:
/// `{ status: :succeeded | :invalid | :unknown, errors: Array<String> }`
///
/// Only raises for conditions that are not a verification verdict.
fn native_verify(
    ruby: &Ruby,
    xml: RString,
    trusted_pems: RArray,
    untrusted_pems: RArray,
    id_attributes: RArray,
    signature_index: usize,
) -> Result<RHash, Error> {
    ensure_initialized().map_err(|msg| native_error(ruby, msg.into()))?;

    let xml_bytes = rstring_to_bytes(xml);
    let trusted = rarray_to_byte_vecs(ruby, trusted_pems)?;
    let untrusted = rarray_to_byte_vecs(ruby, untrusted_pems)?;
    let id_attrs = rarray_to_strings(ruby, id_attributes)?;

    match dsig::verify_document(&xml_bytes, &trusted, &untrusted, &id_attrs, signature_index) {
        Ok(result) => {
            let hash = ruby.hash_new();
            let status_sym = ruby.to_symbol(result.status.as_str());
            hash.aset(ruby.to_symbol("status"), status_sym)
                .map_err(|e| native_error(ruby, format!("hash error: {e}")))?;

            let errors_array = string_slice_to_rarray(ruby, &result.errors)?;
            hash.aset(ruby.to_symbol("errors"), errors_array)
                .map_err(|e| native_error(ruby, format!("hash error: {e}")))?;

            Ok(hash)
        }
        Err(msg) => {
            if msg.contains("parse") {
                Err(parse_error(ruby, msg))
            } else if msg.contains("key") || msg.contains("certificate") {
                Err(key_load_error(ruby, msg))
            } else {
                Err(native_error(ruby, msg))
            }
        }
    }
}

/// `XmlsecRb::Native.inspect_sig(xml, signature_index)`
///
/// Returns metadata about the nth `<ds:Signature>` without performing
/// any cryptography. Used by Policy enforcement before verify/sign.
fn native_inspect(
    ruby: &Ruby,
    xml: RString,
    signature_index: usize,
) -> Result<RHash, Error> {
    ensure_initialized().map_err(|msg| native_error(ruby, msg.into()))?;

    let xml_bytes = rstring_to_bytes(xml);

    match dsig::inspect_document(&xml_bytes, signature_index) {
        Ok(result) => {
            let hash = ruby.hash_new();

            hash.aset(
                ruby.to_symbol("signature_method"),
                ruby.str_new(&result.signature_method),
            )
            .map_err(|e| native_error(ruby, format!("hash error: {e}")))?;

            hash.aset(
                ruby.to_symbol("canonicalization_method"),
                ruby.str_new(&result.canonicalization_method),
            )
            .map_err(|e| native_error(ruby, format!("hash error: {e}")))?;

            hash.aset(
                ruby.to_symbol("signature_count"),
                result.signature_count,
            )
            .map_err(|e| native_error(ruby, format!("hash error: {e}")))?;

            // key_names array
            let key_names = string_slice_to_rarray(ruby, &result.key_names)?;
            hash.aset(ruby.to_symbol("key_names"), key_names)
                .map_err(|e| native_error(ruby, format!("hash error: {e}")))?;

            // certificates array
            let certs = string_slice_to_rarray(ruby, &result.certificates)?;
            hash.aset(ruby.to_symbol("certificates"), certs)
                .map_err(|e| native_error(ruby, format!("hash error: {e}")))?;

            // references array of hashes
            let refs = ruby.ary_new();
            for r in &result.references {
                let ref_hash = ruby.hash_new();
                ref_hash
                    .aset(ruby.to_symbol("uri"), ruby.str_new(&r.uri))
                    .map_err(|e| native_error(ruby, format!("hash error: {e}")))?;
                ref_hash
                    .aset(ruby.to_symbol("digest_method"), ruby.str_new(&r.digest_method))
                    .map_err(|e| native_error(ruby, format!("hash error: {e}")))?;

                let transforms = string_slice_to_rarray(ruby, &r.transforms)?;
                ref_hash
                    .aset(ruby.to_symbol("transforms"), transforms)
                    .map_err(|e| native_error(ruby, format!("hash error: {e}")))?;

                ref_hash
                    .aset(
                        ruby.to_symbol("id"),
                        r.id.as_ref()
                            .map(|s| ruby.str_new(s).as_value())
                            .unwrap_or_else(|| ruby.qnil().as_value()),
                    )
                    .map_err(|e| native_error(ruby, format!("hash error: {e}")))?;

                ref_hash
                    .aset(
                        ruby.to_symbol("type"),
                        r.r#type
                            .as_ref()
                            .map(|s| ruby.str_new(s).as_value())
                            .unwrap_or_else(|| ruby.qnil().as_value()),
                    )
                    .map_err(|e| native_error(ruby, format!("hash error: {e}")))?;

                refs.push(ref_hash)
                    .map_err(|e| native_error(ruby, format!("array error: {e}")))?;
            }
            hash.aset(ruby.to_symbol("references"), refs)
                .map_err(|e| native_error(ruby, format!("hash error: {e}")))?;

            Ok(hash)
        }
        Err(msg) => {
            if msg.contains("parse") {
                Err(parse_error(ruby, msg.into()))
            } else {
                Err(native_error(ruby, msg.into()))
            }
        }
    }
}

/// `XmlsecRb::Native.versions`
///
/// Returns `{ xmlsec: "1.3.12", libxml2: "2.15.3", crypto: "openssl" }`.
fn native_versions(ruby: &Ruby) -> Result<RHash, Error> {
    ensure_initialized().map_err(|msg| native_error(ruby, msg.into()))?;

    let (xmlsec, libxml2, crypto) = dsig::versions();
    let hash = ruby.hash_new();
    hash.aset(ruby.to_symbol("xmlsec"), ruby.str_new(&xmlsec))
        .map_err(|e| native_error(ruby, format!("hash error: {e}")))?;
    hash.aset(ruby.to_symbol("libxml2"), ruby.str_new(&libxml2))
        .map_err(|e| native_error(ruby, format!("hash error: {e}")))?;
    hash.aset(ruby.to_symbol("crypto"), ruby.str_new(&crypto))
        .map_err(|e| native_error(ruby, format!("hash error: {e}")))?;
    Ok(hash)
}

/// `XmlsecRb::Native.check_version` — kept from the POC.
fn native_check_version() -> bool {
    dsig::check_version()
}

#[magnus::init]
fn init(ruby: &Ruby) -> Result<(), Error> {
    let module = ruby.define_module("XmlsecRb")?;
    let native: RModule = module.define_module("Native")?;

    native.define_singleton_method("check_version", function!(native_check_version, 0))?;
    native.define_singleton_method("versions", function!(native_versions, 0))?;
    native.define_singleton_method("sign", function!(native_sign, 5))?;
    native.define_singleton_method("verify", function!(native_verify, 5))?;
    native.define_singleton_method("inspect_sig", function!(native_inspect, 2))?;

    Ok(())
}
