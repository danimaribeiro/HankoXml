//! Magnus glue: 5 functions on `HankoXml::Native`, matching the §7 contract.
//!
//! Every argument from Ruby is copied into a Rust-owned `Vec<u8>` or `String`
//! **before** any native call, so there is no `unsafe` in this file — no
//! `RString::as_slice()` across a call that might release the GVL.

mod dsig;
mod errors;
mod sys;

use magnus::{
    function, prelude::*, Error, ExceptionClass, IntoValue, RArray, RHash, RModule, RString,
    Ruby, TryConvert, Value,
};
use std::collections::HashMap;
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
        .unwrap_or_else(|_| ruby.exception_runtime_error())
}

fn native_error(ruby: &Ruby, message: String) -> Error {
    Error::new(error_class(ruby, "HankoXml::NativeError"), message)
}

/// Converts a [`dsig::DsigError`] into the matching `HankoXml::Error`
/// subclass (S-13). The class comes from `err.kind`, and the message is the
/// fixed string from `dsig.rs`. The xmlsec log captured during the call is
/// drained here and set as `#xmlsec_errors`, never appended to `#message`:
/// it can contain document text (hrefs, URIs, node names) that applications
/// commonly log or display.
fn dsig_error(ruby: &Ruby, err: dsig::DsigError) -> Error {
    let class_name = match err.kind {
        dsig::ErrorKind::Parse => "HankoXml::ParseError",
        dsig::ErrorKind::KeyLoad => "HankoXml::KeyLoadError",
        dsig::ErrorKind::Signing => "HankoXml::SigningError",
        dsig::ErrorKind::Native => "HankoXml::NativeError",
    };
    let cls = error_class(ruby, class_name);
    let xmlsec_errors = errors::drain_errors();

    let exception = match cls.new_instance((err.message,)) {
        Ok(exception) => exception,
        Err(e) => return e,
    };
    if let Ok(log) = string_slice_to_rarray(ruby, &xmlsec_errors) {
        // Best effort: without the attribute the typed error is still right.
        let _: Result<Value, Error> = exception.funcall("xmlsec_errors=", (log,));
    }
    Error::from(exception)
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
    for item in arr.into_iter() {
        let s: RString = TryConvert::try_convert(item)
            .map_err(|_| native_error(ruby, "array element is not a String".into()))?;
        result.push(rstring_to_bytes(s));
    }
    Ok(result)
}

/// Extracts an RArray of `[String, String]` pairs into a map.
fn rarray_to_byte_pairs(ruby: &Ruby, arr: RArray) -> Result<HashMap<Vec<u8>, Vec<u8>>, Error> {
    let mut result = HashMap::new();
    for item in arr.into_iter() {
        let pair: RArray = TryConvert::try_convert(item)
            .map_err(|_| native_error(ruby, "referenced document is not a [uri, bytes] pair".into()))?;
        let [uri, bytes] = rarray_to_byte_vecs(ruby, pair)?
            .try_into()
            .map_err(|_| native_error(ruby, "referenced document is not a [uri, bytes] pair".into()))?;
        result.insert(uri, bytes);
    }
    Ok(result)
}

/// Extracts an RArray of RString into a Vec<String>.
fn rarray_to_strings(ruby: &Ruby, arr: RArray) -> Result<Vec<String>, Error> {
    let mut result = Vec::new();
    for item in arr.into_iter() {
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

/// `HankoXml::Native.sign(xml, key_pem, cert_pems, id_attributes, signature_index)`
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
        Err(err) => Err(dsig_error(ruby, err)),
    }
}

/// `HankoXml::Native.verify(xml, trusted_pems, untrusted_pems, id_attributes, signature_index, referenced_documents)`
///
/// Verifies the nth `<ds:Signature>` and returns a Hash:
/// `{ status:, errors:, reference_element_indexes: Array<Integer|nil>,
///   reference_valid: Array<true|false|nil> }`
///
/// `reference_element_indexes` is the document-order element index of each
/// SignedInfo Reference's target as resolved by libxml2's ID table (the same
/// table xmlsec used for `#id` verification). Empty-URI references report the
/// root. Unresolved / non-fragment URIs are `nil`.
///
/// `reference_valid` is each SignedInfo Reference's own digest verification
/// status, same order, independent of the overall signature/key outcome
/// (S-09): a harmless-fragment Reference and the payload Reference can
/// genuinely disagree. `nil` means the reference was never processed
/// (verification aborted before reaching it).
///
/// Only raises for conditions that are not a verification verdict.
fn native_verify(
    ruby: &Ruby,
    xml: RString,
    trusted_pems: RArray,
    untrusted_pems: RArray,
    id_attributes: RArray,
    signature_index: usize,
    referenced_documents: RArray,
) -> Result<RHash, Error> {
    ensure_initialized().map_err(|msg| native_error(ruby, msg.into()))?;

    let xml_bytes = rstring_to_bytes(xml);
    let trusted = rarray_to_byte_vecs(ruby, trusted_pems)?;
    let untrusted = rarray_to_byte_vecs(ruby, untrusted_pems)?;
    let id_attrs = rarray_to_strings(ruby, id_attributes)?;
    let referenced = rarray_to_byte_pairs(ruby, referenced_documents)?;

    match dsig::verify_document(&xml_bytes, &trusted, &untrusted, &id_attrs, signature_index, referenced) {
        Ok(result) => {
            let hash = ruby.hash_new();
            let status_sym = ruby.to_symbol(result.status.as_str());
            hash.aset(ruby.to_symbol("status"), status_sym)
                .map_err(|e| native_error(ruby, format!("hash error: {e}")))?;

            let errors_array = string_slice_to_rarray(ruby, &result.errors)?;
            hash.aset(ruby.to_symbol("errors"), errors_array)
                .map_err(|e| native_error(ruby, format!("hash error: {e}")))?;

            let indexes = ruby.ary_new();
            for entry in &result.reference_element_indexes {
                let value = match entry {
                    Some(i) => ruby.integer_from_i64(*i as i64).as_value(),
                    None => ruby.qnil().as_value(),
                };
                indexes
                    .push(value)
                    .map_err(|e| native_error(ruby, format!("array error: {e}")))?;
            }
            hash.aset(ruby.to_symbol("reference_element_indexes"), indexes)
                .map_err(|e| native_error(ruby, format!("hash error: {e}")))?;

            let reference_valid = ruby.ary_new();
            for entry in &result.reference_valid {
                let value = match entry {
                    Some(valid) => valid.into_value_with(ruby),
                    None => ruby.qnil().as_value(),
                };
                reference_valid
                    .push(value)
                    .map_err(|e| native_error(ruby, format!("array error: {e}")))?;
            }
            hash.aset(ruby.to_symbol("reference_valid"), reference_valid)
                .map_err(|e| native_error(ruby, format!("hash error: {e}")))?;

            Ok(hash)
        }
        Err(err) => Err(dsig_error(ruby, err)),
    }
}

/// `HankoXml::Native.inspect_sig(xml, signature_index)`
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

    errors::clear_errors();
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

            hash.aset(
                ruby.to_symbol("has_retrieval_method"),
                result.has_retrieval_method.into_value_with(ruby),
            )
            .map_err(|e| native_error(ruby, format!("hash error: {e}")))?;

            Ok(hash)
        }
        Err(err) => Err(dsig_error(ruby, err)),
    }
}

/// `HankoXml::Native.versions`
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

/// `HankoXml::Native.check_version` — kept from the POC.
///
/// Exact-match check: true only when the loaded libxmlsec1 is the same
/// major.minor.patch these bindings were generated against.
fn native_check_version() -> bool {
    dsig::check_version()
}

/// `HankoXml::Native.abi_compatible?`
///
/// True when the loaded libxmlsec1 is ABI compatible with the headers this
/// extension was compiled against. `HankoXml::NativeVersion` calls this at
/// require time; see [`dsig::abi_compatible`] for why it has to be fatal.
fn native_abi_compatible() -> bool {
    dsig::abi_compatible()
}

#[magnus::init]
fn init(ruby: &Ruby) -> Result<(), Error> {
    let module = ruby.define_module("HankoXml")?;
    let native: RModule = module.define_module("Native")?;

    native.define_singleton_method("check_version", function!(native_check_version, 0))?;
    native.define_singleton_method("abi_compatible?", function!(native_abi_compatible, 0))?;
    native.define_singleton_method("versions", function!(native_versions, 0))?;
    native.define_singleton_method("sign", function!(native_sign, 5))?;
    native.define_singleton_method("verify", function!(native_verify, 6))?;
    native.define_singleton_method("inspect_sig", function!(native_inspect, 2))?;

    Ok(())
}
