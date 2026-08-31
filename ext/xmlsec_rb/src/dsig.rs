//! Safe wrappers around the raw [`crate::sys`] bindings, plus
//! [`verify_signature`] — the one function that actually coordinates an
//! XML-DSig verification.
//!
//! Every FFI call in this module lives in its own minimal `unsafe` block
//! with a `// SAFETY:` comment justifying it. `verify_signature` itself,
//! and everything above this module (`lib.rs`), contains no `unsafe` at
//! all — the RAII types below (`OwnedXmlDoc`, `KeysMngr`, `DsigCtx`) each
//! own exactly one libxmlsec1/libxml2 resource and free it on `Drop`, so
//! composing them safely composes the underlying C calls correctly too.

use crate::sys;
use std::marker::PhantomData;
use std::ptr;

/// A borrowed view over a libxml2 document. Exposes only safe accessors
/// and never frees anything — see [`OwnedXmlDoc`] for a document we parsed
/// and own ourselves.
#[derive(Clone, Copy)]
pub struct XmlDoc<'a> {
    ptr: sys::xmlDocPtr,
    _marker: PhantomData<&'a ()>,
}

impl<'a> XmlDoc<'a> {
    /// # Safety
    /// `ptr` must be non-null and point to a valid `xmlDoc` that stays
    /// valid for at least `'a`.
    pub unsafe fn from_raw(ptr: sys::xmlDocPtr) -> Option<Self> {
        (!ptr.is_null()).then_some(Self {
            ptr,
            _marker: PhantomData,
        })
    }

    fn root_element(&self) -> Option<XmlNode<'a>> {
        // SAFETY: self.ptr is valid for 'a by construction (see from_raw).
        let root = unsafe { sys::xmlDocGetRootElement(self.ptr) };
        // SAFETY: a non-null root is a valid node for at least as long as
        // the document (`'a`) is.
        (!root.is_null()).then_some(XmlNode {
            ptr: root,
            _marker: PhantomData,
        })
    }

    /// Registers common ID-attribute names across the whole document, so a
    /// `Reference URI="#foo"` can resolve to whichever element has
    /// `Id`/`ID`/`id="foo"`.
    ///
    /// xmlsec doesn't treat any attribute as type ID by default — without
    /// this, `URI="#foo"` only resolves when the target is a descendant of
    /// the `<Signature>` itself (xmlsec falls back to a plain subtree
    /// search there); a *detached* signature, where the referenced element
    /// is a sibling or elsewhere in the document, fails outright. This is
    /// the same thing `xmlsec1`'s CLI `--add-id-attr` flag does.
    ///
    /// This is a broad, unconfigured default covering the common
    /// conventions (SAML's `ID`, XML-DSig examples' and Brazilian NFe's
    /// `Id`, XHTML's `id`); a document using some other attribute as its
    /// ID isn't served by it.
    fn register_common_id_attributes(&self, root: XmlNode<'a>) {
        const NAMES: [&[u8]; 3] = [b"ID\0", b"Id\0", b"id\0"];
        let mut ids: [*const sys::xmlChar; 4] = [
            NAMES[0].as_ptr().cast(),
            NAMES[1].as_ptr().cast(),
            NAMES[2].as_ptr().cast(),
            ptr::null(),
        ];
        // SAFETY: self.ptr and root.ptr are valid for 'a; `ids` is a
        // NUL-terminated array of NUL-terminated static byte strings,
        // matching what xmlSecAddIDs expects.
        unsafe { sys::xmlSecAddIDs(self.ptr, root.ptr, ids.as_mut_ptr()) }
    }
}

/// A borrowed view over a libxml2 node. Never frees anything — nodes are
/// owned by their document.
#[derive(Clone, Copy)]
struct XmlNode<'a> {
    ptr: sys::xmlNodePtr,
    _marker: PhantomData<&'a ()>,
}

impl<'a> XmlNode<'a> {
    /// Finds the first `<dsig:Signature>` descendant-or-self, the same
    /// starting point xmlsec's own `verify2.c` example uses.
    fn find_signature_node(&self) -> Option<XmlNode<'a>> {
        // SAFETY: self.ptr is valid for 'a; xmlSecNodeSignature and
        // xmlSecDSigNs are statics owned by libxmlsec1 for the whole
        // program's lifetime, so pointers into them are always valid here.
        let node = unsafe {
            sys::xmlSecFindNode(
                self.ptr,
                sys::xmlSecNodeSignature.as_ptr(),
                sys::xmlSecDSigNs.as_ptr(),
            )
        };
        (!node.is_null()).then_some(XmlNode {
            ptr: node,
            _marker: PhantomData,
        })
    }
}

/// An owned libxml2 document parsed from an in-memory buffer. Frees itself
/// on drop.
pub struct OwnedXmlDoc(sys::xmlDocPtr);

impl OwnedXmlDoc {
    pub fn parse(xml: &[u8]) -> Option<Self> {
        // SAFETY: xmlReadMemory reads exactly xml.len() bytes starting at
        // xml.as_ptr() and copies them into buffers it manages itself, so
        // xml doesn't need to outlive this call.
        let ptr = unsafe {
            sys::xmlReadMemory(
                xml.as_ptr().cast(),
                xml.len() as i32,
                ptr::null(),
                ptr::null(),
                0,
            )
        };
        (!ptr.is_null()).then_some(Self(ptr))
    }

    pub fn as_doc(&self) -> XmlDoc<'_> {
        // SAFETY: self.0 is non-null (parse() only ever wraps a non-null
        // pointer) and stays valid for at least as long as `self` is
        // borrowed here, since Drop can't run until that borrow ends.
        unsafe { XmlDoc::from_raw(self.0) }.expect("OwnedXmlDoc always wraps a non-null pointer")
    }
}

impl Drop for OwnedXmlDoc {
    fn drop(&mut self) {
        // SAFETY: we're the exclusive owner of this doc, and no XmlDoc/
        // XmlNode borrow can outlive us — as_doc() ties their lifetime to
        // &self.
        unsafe { sys::xmlFreeDoc(self.0) }
    }
}

/// An xmlsec keys manager trusting exactly one PEM certificate. Frees
/// itself on drop.
struct KeysMngr(sys::xmlSecKeysMngrPtr);

impl KeysMngr {
    fn trusting(cert_pem: &[u8]) -> Result<Self, &'static str> {
        // SAFETY: takes no arguments; returns either null or a freshly
        // allocated manager we exclusively own from here on.
        let ptr = unsafe { sys::xmlSecKeysMngrCreate() };
        if ptr.is_null() {
            return Err("failed to create xmlsec keys manager");
        }
        let mngr = Self(ptr);

        // SAFETY: mngr.0 is non-null and exclusively ours.
        if unsafe { sys::xmlSecOpenSSLAppDefaultKeysMngrInit(mngr.0) } < 0 {
            return Err("failed to initialize xmlsec keys manager");
        }

        // SAFETY: mngr.0 is valid and initialized; cert_pem is a valid
        // slice for the duration of this call, which is all this function
        // needs — it doesn't retain the pointer after returning.
        let loaded = unsafe {
            sys::xmlSecOpenSSLAppKeysMngrCertLoadMemory(
                mngr.0,
                cert_pem.as_ptr(),
                cert_pem.len(),
                sys::xmlSecKeyDataFormat_xmlSecKeyDataFormatPem,
                sys::xmlSecKeyDataTypeTrusted,
            )
        };
        if loaded < 0 {
            return Err("failed to load trusted certificate");
        }

        Ok(mngr)
    }
}

impl Drop for KeysMngr {
    fn drop(&mut self) {
        // SAFETY: we're the exclusive owner; any DsigCtx borrowing us has
        // already been dropped first — enforced by its lifetime parameter,
        // which the borrow checker uses to order these two Drops for us.
        unsafe { sys::xmlSecKeysMngrDestroy(self.0) }
    }
}

/// An xmlsec signature context bound to a [`KeysMngr`]. Frees itself on
/// drop.
struct DsigCtx<'mngr> {
    ptr: sys::xmlSecDSigCtxPtr,
    _mngr: PhantomData<&'mngr KeysMngr>,
}

impl<'mngr> DsigCtx<'mngr> {
    fn new(mngr: &'mngr KeysMngr) -> Result<Self, &'static str> {
        // SAFETY: mngr.0 is valid; tying this context's lifetime to
        // `'mngr` via PhantomData makes the borrow checker keep `mngr`
        // alive at least as long as we are (and drop it only after us).
        let ptr = unsafe { sys::xmlSecDSigCtxCreate(mngr.0) };
        if ptr.is_null() {
            return Err("failed to create xmlsec signature context");
        }
        Ok(Self {
            ptr,
            _mngr: PhantomData,
        })
    }

    /// Verifies `node`. `false` covers both a well-formed-but-invalid
    /// signature and "no key in KeyInfo matches the trusted certificate" —
    /// xmlsec reports the latter as a negative return from
    /// `xmlSecDSigCtxVerify` rather than via `status`, and both read as
    /// the ordinary "not verified" outcome from this API's point of view.
    fn verify(&mut self, node: XmlNode<'_>) -> bool {
        // SAFETY: self.ptr is valid and exclusively ours; node.ptr is
        // valid for the duration of this call (its lifetime parameter
        // ties it to the doc it was found in, which the caller keeps
        // alive across this call).
        if unsafe { sys::xmlSecDSigCtxVerify(self.ptr, node.ptr) } < 0 {
            return false;
        }
        // SAFETY: self.ptr is valid; `status` is a plain enum field, and
        // holding &mut self here rules out any aliasing concern.
        let status = unsafe { (*self.ptr).status };
        status == sys::xmlSecDSigStatus_xmlSecDSigStatusSucceeded
    }
}

impl Drop for DsigCtx<'_> {
    fn drop(&mut self) {
        // SAFETY: we're the exclusive owner of this context.
        unsafe { sys::xmlSecDSigCtxDestroy(self.ptr) }
    }
}

/// Verifies the XML-DSig `<Signature>` found under `doc`'s root element
/// against the trusted certificate `cert_pem` (PEM-encoded). Mirrors
/// xmlsec's own `verify2.c` example: find `<Signature>`, build a keys
/// manager trusting one certificate, verify, check status.
///
/// No `unsafe` here — every FFI call is behind one of the RAII wrappers
/// above, each individually reviewed at its own call site.
pub fn verify_signature(doc: XmlDoc<'_>, cert_pem: &[u8]) -> Result<bool, &'static str> {
    let root = doc.root_element().ok_or("XML document has no root element")?;
    doc.register_common_id_attributes(root);
    let sig_node = root
        .find_signature_node()
        .ok_or("no <Signature> element found in document")?;

    let mngr = KeysMngr::trusting(cert_pem)?;
    let mut ctx = DsigCtx::new(&mngr)?;

    Ok(ctx.verify(sig_node))
}

/// Initializes xmlsec + its OpenSSL crypto backend. `crate` wraps this in
/// a `std::sync::Once` so it runs exactly once per process, lazily, the
/// first time it's actually needed.
pub fn init_xmlsec() -> Result<(), &'static str> {
    // SAFETY: each of these takes either no arguments or a null config
    // pointer (meaning "use defaults"). They must run in this exact order,
    // before any other xmlsec call — guaranteed by the caller's Once.
    unsafe {
        if sys::xmlSecInit() < 0 {
            return Err("xmlSecInit failed");
        }
        if sys::xmlSecOpenSSLAppInit(ptr::null()) < 0 {
            return Err("xmlSecOpenSSLAppInit failed");
        }
        if sys::xmlSecOpenSSLInit() < 0 {
            return Err("xmlSecOpenSSLInit failed");
        }
    }
    Ok(())
}

/// True when the linked libxmlsec1 matches the version these bindings were
/// generated against. A real call into libxmlsec1 (`xmlSecCheckVersionExt`),
/// not a compile-time constant.
pub fn check_version() -> bool {
    // SAFETY: takes only plain integers — no pointers, no preconditions
    // beyond the xmlsec headers/library being loaded, which they always
    // are once this crate is linked.
    unsafe {
        sys::xmlSecCheckVersionExt(
            sys::XMLSEC_VERSION_MAJOR as i32,
            sys::XMLSEC_VERSION_MINOR as i32,
            sys::XMLSEC_VERSION_SUBMINOR as i32,
            sys::xmlSecCheckVersionMode_xmlSecCheckVersionExactMatch,
        ) == 1
    }
}
