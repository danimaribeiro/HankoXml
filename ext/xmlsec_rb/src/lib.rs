use magnus::{exception, function, prelude::*, Error, Ruby};

#[allow(non_upper_case_globals, non_camel_case_types, non_snake_case, dead_code)]
mod sys {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

fn runtime_error(message: impl Into<String>) -> Error {
    Error::new(exception::runtime_error(), message.into())
}

/// True when the linked libxmlsec1 matches the version these bindings were
/// generated against. A real call into libxmlsec1 (xmlSecCheckVersionExt),
/// not a compile-time constant.
fn check_version() -> bool {
    unsafe {
        sys::xmlSecCheckVersionExt(
            sys::XMLSEC_VERSION_MAJOR as i32,
            sys::XMLSEC_VERSION_MINOR as i32,
            sys::XMLSEC_VERSION_SUBMINOR as i32,
            sys::xmlSecCheckVersionMode_xmlSecCheckVersionExactMatch,
        ) == 1
    }
}

/// Initializes xmlsec and its OpenSSL crypto backend. Must be called once
/// before signing/verifying; pair with `xmlsec_shutdown`.
fn xmlsec_init() -> Result<(), Error> {
    unsafe {
        if sys::xmlSecInit() < 0 {
            return Err(runtime_error("xmlSecInit failed"));
        }
        if sys::xmlSecOpenSSLAppInit(std::ptr::null()) < 0 {
            return Err(runtime_error("xmlSecOpenSSLAppInit failed"));
        }
        if sys::xmlSecOpenSSLInit() < 0 {
            return Err(runtime_error("xmlSecOpenSSLInit failed"));
        }
    }
    Ok(())
}

/// Tears down the OpenSSL crypto backend and xmlsec, in reverse init order.
fn xmlsec_shutdown() -> Result<(), Error> {
    unsafe {
        if sys::xmlSecOpenSSLShutdown() < 0 {
            return Err(runtime_error("xmlSecOpenSSLShutdown failed"));
        }
        if sys::xmlSecOpenSSLAppShutdown() < 0 {
            return Err(runtime_error("xmlSecOpenSSLAppShutdown failed"));
        }
        if sys::xmlSecShutdown() < 0 {
            return Err(runtime_error("xmlSecShutdown failed"));
        }
    }
    Ok(())
}

#[magnus::init]
fn init(ruby: &Ruby) -> Result<(), Error> {
    let module = ruby.define_module("XmlsecRb")?;
    module.define_singleton_method("check_version", function!(check_version, 0))?;
    module.define_singleton_method("init!", function!(xmlsec_init, 0))?;
    module.define_singleton_method("shutdown!", function!(xmlsec_shutdown, 0))?;
    Ok(())
}
