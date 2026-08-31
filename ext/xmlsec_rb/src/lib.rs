mod dsig;
mod sys;

use dsig::{OwnedXmlDoc, XmlDoc};
use magnus::{exception, function, prelude::*, Error, ExceptionClass, RModule, RString, Ruby};
use std::sync::Once;

static INIT: Once = Once::new();

/// Runs [`dsig::init_xmlsec`] exactly once per process, the first time it's
/// actually needed. Ruby callers never have to think about init ordering.
fn ensure_initialized() -> Result<(), &'static str> {
    let mut result = Ok(());
    INIT.call_once(|| result = dsig::init_xmlsec());
    result
}

fn xmlsec_error_class(ruby: &Ruby) -> ExceptionClass {
    ruby.eval::<ExceptionClass>("XmlsecRb::Error")
        .unwrap_or_else(|_| exception::runtime_error())
}

fn xmlsec_error(ruby: &Ruby, message: impl Into<String>) -> Error {
    Error::new(xmlsec_error_class(ruby), message.into())
}

/// Entry point for `XmlsecRb.validate` given an XML String or the contents
/// read from a path. We own the parse, so `OwnedXmlDoc`'s `Drop` owns the
/// free — see `dsig::OwnedXmlDoc`.
fn validate_bytes(ruby: &Ruby, xml: RString, cert_pem: RString) -> Result<bool, Error> {
    ensure_initialized().map_err(|message| xmlsec_error(ruby, message))?;

    // SAFETY: xml/cert_pem are live Ruby String arguments for this entire
    // call — they're still on the Ruby call stack, so the GC can't touch
    // them — and we don't retain either slice past this function returning.
    let (xml_bytes, cert_bytes) = unsafe { (xml.as_slice(), cert_pem.as_slice()) };

    let doc = OwnedXmlDoc::parse(xml_bytes)
        .ok_or_else(|| xmlsec_error(ruby, "failed to parse XML document"))?;

    dsig::verify_signature(doc.as_doc(), cert_bytes).map_err(|message| xmlsec_error(ruby, message))
}

/// Entry point for `XmlsecRb.validate` given a `Nokogiri::XML::Document`.
/// `doc_pointer` is that document's `#pointer_id` — the address of the
/// libxml2 `xmlDoc` Nokogiri already parsed and holds via Ruby's GC. We
/// never free it: `dsig::XmlDoc` (unlike `OwnedXmlDoc`) has no `Drop` impl,
/// matching that Ruby, not us, owns this document. This also avoids a
/// to_xml-and-reparse round trip for a document the caller just built in
/// memory (e.g. about to be signed).
fn validate_doc_pointer(ruby: &Ruby, doc_pointer: usize, cert_pem: RString) -> Result<bool, Error> {
    ensure_initialized().map_err(|message| xmlsec_error(ruby, message))?;

    // SAFETY: doc_pointer is a Nokogiri::XML::Document's #pointer_id — the
    // address of an xmlDoc kept alive by Ruby's GC for at least the
    // lifetime of the `xml` argument on the caller's Ruby stack frame,
    // which spans this entire call.
    let doc = unsafe { XmlDoc::from_raw(doc_pointer as sys::xmlDocPtr) }
        .ok_or_else(|| xmlsec_error(ruby, "invalid (null) document pointer"))?;

    // SAFETY: same as validate_bytes above.
    let cert_bytes = unsafe { cert_pem.as_slice() };

    dsig::verify_signature(doc, cert_bytes).map_err(|message| xmlsec_error(ruby, message))
}

#[magnus::init]
fn init(ruby: &Ruby) -> Result<(), Error> {
    let module = ruby.define_module("XmlsecRb")?;
    let native: RModule = module.define_module("Native")?;
    native.define_singleton_method("check_version", function!(dsig::check_version, 0))?;
    native.define_singleton_method("validate_bytes", function!(validate_bytes, 2))?;
    native.define_singleton_method("validate_doc_pointer", function!(validate_doc_pointer, 2))?;
    Ok(())
}
