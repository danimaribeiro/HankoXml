//! Safe wrappers around the raw [`crate::sys`] bindings, implementing
//! the §7 native contract: `sign_document`, `verify_document`,
//! `inspect_document`, `versions`, and `check_version`.
//!
//! Every FFI call in this module lives in its own minimal `unsafe` block
//! with a `// SAFETY:` comment justifying it. The public functions
//! (`sign_document`, `verify_document`, `inspect_document`) contain no
//! `unsafe` — the RAII types below each own exactly one C resource and
//! free it on `Drop`.
//!
//! Phase 2 changes from the POC:
//! - `XmlDoc<'a>` and `XmlNode<'a>` are deleted — bytes-only I/O means
//!   every document is `OwnedXmlDoc`, never borrowed.
//! - `XmlSecKey` added (with `into_raw()`) for signing.
//! - `errors` module captures xmlsec diagnostics (no more stderr).
//! - All functions take `id_attributes` + `signature_index`.

use crate::errors;
use crate::sys;
use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_void};
use std::ptr;

// ---------------------------------------------------------------------------
// OwnedXmlDoc — owned libxml2 document
// ---------------------------------------------------------------------------

/// An owned libxml2 document parsed from an in-memory buffer. Frees itself
/// on drop.
pub struct OwnedXmlDoc(sys::xmlDocPtr);

/// Safely frees memory allocated by libxml2 functions (xmlGetProp, xmlNodeGetContent, xmlDocDumpMemory).
unsafe fn xml_free(ptr: *mut std::os::raw::c_void) {
    if !ptr.is_null() {
        extern "C" {
            static xmlFree: Option<unsafe extern "C" fn(*mut std::os::raw::c_void)>;
        }
        if let Some(free_fn) = xmlFree {
            free_fn(ptr);
        } else {
            extern "C" {
                fn free(ptr: *mut std::os::raw::c_void);
            }
            free(ptr);
        }
    }
}

/// Which Ruby exception a native failure maps to (S-13).
///
/// Decided at the call site that failed, never by looking at the message:
/// the xmlsec log can contain document text (algorithm hrefs, URIs, node
/// names), so matching words in it let a document pick its own exception
/// class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    Parse,
    KeyLoad,
    Signing,
    Native,
}

/// A failure from one of the public entry points below. `message` is always
/// a fixed string from this file, so it never carries document content; the
/// xmlsec log for the call is drained separately by the caller.
#[derive(Debug)]
pub struct DsigError {
    pub kind: ErrorKind,
    pub message: &'static str,
}

impl DsigError {
    fn parse(message: &'static str) -> Self {
        Self { kind: ErrorKind::Parse, message }
    }

    fn key_load(message: &'static str) -> Self {
        Self { kind: ErrorKind::KeyLoad, message }
    }

    fn signing(message: &'static str) -> Self {
        Self { kind: ErrorKind::Signing, message }
    }

    fn native(message: &'static str) -> Self {
        Self { kind: ErrorKind::Native, message }
    }
}

/// Converts a buffer length to the integer type an FFI function takes (S-12).
///
/// A plain `as` cast wraps silently: past `i32::MAX` an `int` length goes
/// negative, and past `u32::MAX` an unsigned one keeps only the low 32 bits,
/// so libxml2/xmlsec would read a different number of bytes than the caller
/// passed. The width of `xmlSecSize` also differs between xmlsec 1.2 and 1.3,
/// hence the generic target.
fn ffi_len<T: TryFrom<usize>>(len: usize) -> Option<T> {
    T::try_from(len).ok()
}

impl OwnedXmlDoc {
    /// Parses `xml` bytes into a libxml2 document.
    ///
    /// Documents longer than `c_int::MAX` bytes (about 2 GiB) are rejected
    /// rather than truncated (S-12).
    ///
    /// libxml2's diagnostics go to the error buffer, never stderr. A
    /// recoverable error (an undefined namespace prefix, an invalid
    /// `xml:id`) still yields a document; see [`Self::parse_strict`].
    pub fn parse(xml: &[u8]) -> Result<Self, &'static str> {
        let len: std::os::raw::c_int = ffi_len(xml.len())
            .ok_or("failed to parse XML document: larger than the 2 GiB libxml2 limit")?;
        let _capture = Libxml2Capture::start();
        // Never NOENT, DTDLOAD or HUGE; NONET so nothing is fetched (§6.3).
        let options = sys::xmlParserOption_XML_PARSE_NONET as std::os::raw::c_int;
        // SAFETY: xmlReadMemory reads exactly len (== xml.len()) bytes
        // starting at xml.as_ptr() and copies them into buffers it manages
        // itself, so xml doesn't need to outlive this call.
        let ptr = unsafe {
            sys::xmlReadMemory(xml.as_ptr().cast(), len, ptr::null(), ptr::null(), options)
        };
        if ptr.is_null() {
            return Err("failed to parse XML document");
        }
        Ok(Self(ptr))
    }

    /// Like [`Self::parse`], but any error-level libxml2 diagnostic fails
    /// the parse: the rule `HankoXml.parse` applies with Nokogiri (strict,
    /// `doc.errors` empty), so input given as bytes is held to the same
    /// standard without a DOM (#102).
    pub fn parse_strict(xml: &[u8]) -> Result<Self, &'static str> {
        let before = errors::libxml2_error_count();
        let doc = Self::parse(xml)?;
        if errors::libxml2_error_count() != before {
            return Err("the document is not well-formed XML");
        }
        Ok(doc)
    }

    /// Returns the root element, or None if the document is empty.
    pub fn root_element(&self) -> Option<sys::xmlNodePtr> {
        // SAFETY: self.0 is valid (parse only wraps non-null).
        let root = unsafe { sys::xmlDocGetRootElement(self.0) };
        (!root.is_null()).then_some(root)
    }

    /// Registers ID-attribute names so `URI="#foo"` can resolve.
    ///
    /// `id_attrs` is a list of unqualified attribute name strings
    /// (e.g. `["Id", "ID", "id"]`).
    pub fn register_id_attributes(&self, root: sys::xmlNodePtr, id_attrs: &[String]) {
        if id_attrs.is_empty() {
            return;
        }
        // Build a NUL-terminated array of NUL-terminated C strings.
        let c_strings: Vec<Vec<u8>> = id_attrs
            .iter()
            .map(|s| {
                let mut v = s.as_bytes().to_vec();
                v.push(0);
                v
            })
            .collect();
        let mut ptrs: Vec<*const sys::xmlChar> = c_strings
            .iter()
            .map(|v| v.as_ptr().cast())
            .collect();
        ptrs.push(ptr::null()); // NUL-terminated sentinel

        // SAFETY: self.0 and root are valid; ptrs is a NUL-terminated
        // array of NUL-terminated byte strings.
        unsafe { sys::xmlSecAddIDs(self.0, root, ptrs.as_mut_ptr()) }
    }

    /// Finds the nth `<ds:Signature>` element in document order (0-based).
    /// Returns the node pointer, or None if there are fewer than
    /// `index + 1` signatures.
    pub fn find_nth_signature(&self, root: sys::xmlNodePtr, index: usize) -> Option<sys::xmlNodePtr> {
        let mut signatures = Vec::new();
        collect_signature_nodes(root, &mut signatures);
        signatures.get(index).copied()
    }

    /// Counts the total number of `<ds:Signature>` elements.
    pub fn count_signatures(&self, root: sys::xmlNodePtr) -> usize {
        let mut signatures = Vec::new();
        collect_signature_nodes(root, &mut signatures);
        signatures.len()
    }

    /// Serializes the document to an XML byte string.
    pub fn serialize(&self) -> Result<Vec<u8>, &'static str> {
        let mut buf: *mut sys::xmlChar = ptr::null_mut();
        let mut size: i32 = 0;

        // SAFETY: self.0 is valid; xmlDocDumpMemory writes into its own
        // allocated buffer and returns the pointer + length.
        unsafe { sys::xmlDocDumpMemory(self.0, &mut buf, &mut size) };

        if buf.is_null() || size <= 0 {
            return Err("failed to serialize XML document");
        }

        // SAFETY: buf is non-null, allocated by libxml2, and size is its
        // length. We copy the bytes out, then free the libxml2 buffer.
        let bytes = unsafe { std::slice::from_raw_parts(buf as *const u8, size as usize) }.to_vec();
        unsafe { xml_free(buf as *mut _) };

        Ok(bytes)
    }
}

impl Drop for OwnedXmlDoc {
    fn drop(&mut self) {
        // SAFETY: we're the exclusive owner of this doc.
        unsafe { sys::xmlFreeDoc(self.0) }
    }
}

// ---------------------------------------------------------------------------
// Libxml2Capture — libxml2 diagnostics into the error buffer
// ---------------------------------------------------------------------------

/// Routes libxml2's structured errors on this thread to
/// [`errors::libxml2_error_handler`] until dropped, then removes the handler.
/// Nokogiri installs its own handler around each of its calls the same way,
/// so the two never see each other's errors even on one libxml2 (§3.1).
struct Libxml2Capture;

impl Libxml2Capture {
    fn start() -> Self {
        // SAFETY: sets a thread-local libxml2 global to a valid handler
        // with a null context; the handler never dereferences the context.
        unsafe { sys::xmlSetStructuredErrorFunc(ptr::null_mut(), errors::libxml2_error_handler()) };
        Self
    }
}

impl Drop for Libxml2Capture {
    fn drop(&mut self) {
        // SAFETY: restores libxml2's default (no structured handler).
        unsafe { sys::xmlSetStructuredErrorFunc(ptr::null_mut(), None) };
    }
}

// ---------------------------------------------------------------------------
// Signature node collection
// ---------------------------------------------------------------------------

/// Recursively collects all `<ds:Signature>` nodes in document order.
fn collect_signature_nodes(node: sys::xmlNodePtr, result: &mut Vec<sys::xmlNodePtr>) {
    if node.is_null() {
        return;
    }

    // SAFETY: node is non-null and valid within the document's lifetime.
    let node_ref = unsafe { &*node };

    // Check if this is a <Signature> in the dsig namespace
    if node_ref.type_ == sys::xmlElementType_XML_ELEMENT_NODE {
        let name = unsafe { node_name(node) };
        let ns_href = unsafe { node_ns_href(node) };

        if name == "Signature" && ns_href == "http://www.w3.org/2000/09/xmldsig#" {
            result.push(node);
        }
    }

    // Recurse into children
    let mut child = node_ref.children;
    while !child.is_null() {
        collect_signature_nodes(child, result);
        child = unsafe { (*child).next };
    }
}

/// Returns the local name of a node as a Rust string.
///
/// # Safety
/// `node` must be non-null and point to a valid xmlNode.
unsafe fn node_name(node: sys::xmlNodePtr) -> String {
    let name_ptr = (*node).name;
    if name_ptr.is_null() {
        return String::new();
    }
    let cstr = std::ffi::CStr::from_ptr(name_ptr as *const _);
    cstr.to_str().unwrap_or("").to_string()
}

/// Returns the namespace href of a node, or "" if none.
///
/// # Safety
/// `node` must be non-null and point to a valid xmlNode.
unsafe fn node_ns_href(node: sys::xmlNodePtr) -> String {
    let ns = (*node).ns;
    if ns.is_null() {
        return String::new();
    }
    let href = (*ns).href;
    if href.is_null() {
        return String::new();
    }
    let cstr = std::ffi::CStr::from_ptr(href as *const _);
    cstr.to_str().unwrap_or("").to_string()
}

/// Returns the text content of a node attribute, or None.
///
/// # Safety
/// `node` must be non-null and valid. `attr_name` is a NUL-terminated C string.
unsafe fn get_attribute(node: sys::xmlNodePtr, attr_name: &[u8]) -> Option<String> {
    let val = sys::xmlGetProp(node, attr_name.as_ptr().cast());
    if val.is_null() {
        return None;
    }
    let cstr = std::ffi::CStr::from_ptr(val as *const _);
    let result = cstr.to_str().unwrap_or("").to_string();
    unsafe { xml_free(val as *mut _) };
    Some(result)
}

/// Returns the text content of a node (all child text concatenated).
///
/// # Safety
/// `node` must be non-null and valid.
unsafe fn get_text_content(node: sys::xmlNodePtr) -> String {
    let content = sys::xmlNodeGetContent(node);
    if content.is_null() {
        return String::new();
    }
    let cstr = std::ffi::CStr::from_ptr(content as *const _);
    let result = cstr.to_str().unwrap_or("").to_string();
    unsafe { xml_free(content as *mut _) };
    result
}

/// Finds a direct child element with the given local name and namespace href.
///
/// # Safety
/// `parent` must be non-null and valid.
unsafe fn find_child(parent: sys::xmlNodePtr, name: &str, ns_href: &str) -> Option<sys::xmlNodePtr> {
    let mut child = (*parent).children;
    while !child.is_null() {
        let child_ref = &*child;
        if child_ref.type_ == sys::xmlElementType_XML_ELEMENT_NODE
            && node_name(child) == name
            && node_ns_href(child) == ns_href
        {
            return Some(child);
        }
        child = child_ref.next;
    }
    None
}

/// Collects all direct child elements with the given local name and namespace href.
///
/// # Safety
/// `parent` must be non-null and valid.
unsafe fn find_children(parent: sys::xmlNodePtr, name: &str, ns_href: &str) -> Vec<sys::xmlNodePtr> {
    let mut result = Vec::new();
    let mut child = (*parent).children;
    while !child.is_null() {
        let child_ref = &*child;
        if child_ref.type_ == sys::xmlElementType_XML_ELEMENT_NODE
            && node_name(child) == name
            && node_ns_href(child) == ns_href
        {
            result.push(child);
        }
        child = child_ref.next;
    }
    result
}

// ---------------------------------------------------------------------------
// XmlSecKey — RAII wrapper for xmlsec key
// ---------------------------------------------------------------------------

/// An xmlsec key loaded from PEM. Frees itself on drop unless ownership
/// is transferred via `into_raw()`.
pub struct XmlSecKey(sys::xmlSecKeyPtr);

impl XmlSecKey {
    /// Loads a private or public key from PEM bytes.
    pub fn from_pem(pem: &[u8]) -> Result<Self, &'static str> {
        let len = ffi_len(pem.len()).ok_or("failed to load PEM key: too large")?;
        // SAFETY: pem is a valid slice; xmlSecOpenSSLAppKeyLoadMemory
        // copies what it needs. xmlsec tries a private key first, then a
        // SubjectPublicKeyInfo / RSA public key — the `key:` verify path
        // depends on that fallback.
        let ptr = unsafe {
            sys::xmlSecOpenSSLAppKeyLoadMemory(
                pem.as_ptr(),
                len,
                sys::KEY_FORMAT_PEM,
                ptr::null(),  // no password (already decrypted in Ruby)
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if ptr.is_null() {
            return Err("failed to load PEM key");
        }
        Ok(Self(ptr))
    }

    /// Loads a public key from a PEM certificate.
    ///
    /// `xmlSecKeyDataFormatCertPem` makes xmlsec read the X.509 cert and
    /// extract its SPKI, so the cert can be pinned as `signKey` the same
    /// way a bare public-key PEM is. Without this, a cert PEM is only a
    /// KeysMngr trust anchor and xmlsec still takes `<KeyValue>` from the
    /// document (S-01).
    pub fn from_cert_pem(pem: &[u8]) -> Result<Self, &'static str> {
        let len = ffi_len(pem.len()).ok_or("failed to load PEM certificate: too large")?;
        // SAFETY: pem is a valid slice; xmlSecOpenSSLAppKeyLoadMemory
        // copies what it needs. KEY_FORMAT_CERT_PEM dispatches to
        // xmlSecOpenSSLAppKeyFromCertLoadBIO rather than treating the
        // bytes as a PKCS#1/SPKI key.
        let ptr = unsafe {
            sys::xmlSecOpenSSLAppKeyLoadMemory(
                pem.as_ptr(),
                len,
                sys::KEY_FORMAT_CERT_PEM,
                ptr::null(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if ptr.is_null() {
            return Err("failed to load PEM certificate");
        }
        Ok(Self(ptr))
    }

    /// Attaches a PEM certificate to this key (for KeyInfo population).
    pub fn add_cert_pem(&self, cert_pem: &[u8]) -> Result<(), &'static str> {
        let len = ffi_len(cert_pem.len()).ok_or("failed to attach certificate to key: too large")?;
        // SAFETY: self.0 is valid; cert_pem is a valid slice.
        let rc = unsafe {
            sys::xmlSecOpenSSLAppKeyCertLoadMemory(
                self.0,
                cert_pem.as_ptr(),
                len,
                sys::KEY_FORMAT_PEM,
            )
        };
        if rc < 0 {
            return Err("failed to attach certificate to key");
        }
        Ok(())
    }

    /// Transfers ownership of the raw pointer. The caller is responsible
    /// for freeing it (typically by adopting it into a KeysMngr or DsigCtx).
    /// This `XmlSecKey` must not be used or dropped after this call.
    pub fn into_raw(self) -> sys::xmlSecKeyPtr {
        let ptr = self.0;
        std::mem::forget(self);
        ptr
    }
}

impl Drop for XmlSecKey {
    fn drop(&mut self) {
        // SAFETY: we're the exclusive owner.
        unsafe { sys::xmlSecKeyDestroy(self.0) }
    }
}

// ---------------------------------------------------------------------------
// KeysMngr — xmlsec keys manager
// ---------------------------------------------------------------------------

/// An xmlsec keys manager. Frees itself on drop.
struct KeysMngr(sys::xmlSecKeysMngrPtr);

impl KeysMngr {
    /// Creates a new keys manager with trusted and untrusted certificates.
    fn new(
        trusted_pems: &[Vec<u8>],
        untrusted_pems: &[Vec<u8>],
    ) -> Result<Self, &'static str> {
        // SAFETY: no arguments; returns either null or a freshly
        // allocated manager we exclusively own.
        let ptr = unsafe { sys::xmlSecKeysMngrCreate() };
        if ptr.is_null() {
            return Err("failed to create xmlsec keys manager");
        }
        let mngr = Self(ptr);

        // SAFETY: mngr.0 is non-null and exclusively ours.
        if unsafe { sys::xmlSecOpenSSLAppDefaultKeysMngrInit(mngr.0) } < 0 {
            return Err("failed to initialize xmlsec keys manager");
        }

        for cert_pem in trusted_pems {
            let len = ffi_len(cert_pem.len()).ok_or("failed to load trusted certificate: too large")?;
            // SAFETY: mngr.0 is valid and initialized; cert_pem is a valid slice.
            let loaded = unsafe {
                sys::xmlSecOpenSSLAppKeysMngrCertLoadMemory(
                    mngr.0,
                    cert_pem.as_ptr(),
                    len,
                    sys::xmlSecKeyDataFormat_xmlSecKeyDataFormatPem,
                    sys::xmlSecKeyDataTypeTrusted,
                )
            };
            if loaded < 0 {
                return Err("failed to load trusted certificate");
            }
        }

        for cert_pem in untrusted_pems {
            let len =
                ffi_len(cert_pem.len()).ok_or("failed to load untrusted/intermediate certificate: too large")?;
            // SAFETY: same as above, but with type 0 (not trusted — intermediate).
            let loaded = unsafe {
                sys::xmlSecOpenSSLAppKeysMngrCertLoadMemory(
                    mngr.0,
                    cert_pem.as_ptr(),
                    len,
                    sys::xmlSecKeyDataFormat_xmlSecKeyDataFormatPem,
                    0, // not trusted — intermediate for chain building
                )
            };
            if loaded < 0 {
                return Err("failed to load untrusted/intermediate certificate");
            }
        }

        Ok(mngr)
    }
}

impl Drop for KeysMngr {
    fn drop(&mut self) {
        // SAFETY: we're the exclusive owner; any DsigCtx borrowing us has
        // already been dropped first — enforced by its lifetime parameter.
        unsafe { sys::xmlSecKeysMngrDestroy(self.0) }
    }
}

// ---------------------------------------------------------------------------
// DsigCtx — xmlsec signature context
// ---------------------------------------------------------------------------

/// An xmlsec signature context bound to a [`KeysMngr`]. Frees itself on
/// drop.
struct DsigCtx<'mngr> {
    ptr: sys::xmlSecDSigCtxPtr,
    _mngr: std::marker::PhantomData<&'mngr KeysMngr>,
}

impl<'mngr> DsigCtx<'mngr> {
    fn new(mngr: &'mngr KeysMngr) -> Result<Self, &'static str> {
        // SAFETY: mngr.0 is valid; tying this context's lifetime to
        // `'mngr` makes the borrow checker keep `mngr` alive at least
        // as long as we are.
        let ptr = unsafe { sys::xmlSecDSigCtxCreate(mngr.0) };
        if ptr.is_null() {
            return Err("failed to create xmlsec signature context");
        }
        Ok(Self {
            ptr,
            _mngr: std::marker::PhantomData,
        })
    }

    /// Creates a signature context with `signKey` already set.
    ///
    /// Used for both signing and verification. On verify, a pre-set
    /// `signKey` makes xmlsec skip KeyInfo — the document cannot pick
    /// the verification key (S-01).
    fn for_signing(mngr: &'mngr KeysMngr, key: XmlSecKey) -> Result<Self, &'static str> {
        let mut ctx = Self::new(mngr)?;
        // SAFETY: setting signKey transfers ownership of the key to the context.
        // xmlSecDSigCtxDestroy will call xmlSecKeyDestroy on it.
        //
        // This is the most ABI-fragile line in the crate: a direct field write
        // into xmlSecDSigCtx, at an offset bindgen computed from whichever
        // xmlsec headers were present at build time. If xmlsec ever moves
        // signKey, bindgen regenerates a different-but-still-valid Rust struct
        // and nothing fails to compile — the write simply lands somewhere else.
        // That is why the vendored builds pin xmlsec (dependencies.yml) rather
        // than binding against whatever the OS ships: headers and archive then
        // come from one source and cannot disagree. For system builds,
        // HankoXml::NativeVersion is the runtime backstop.
        unsafe {
            (*ctx.ptr).signKey = key.into_raw();
        }
        ctx.restrict_reference_uris_to_same_document();
        ctx.resolve_bare_fragments_by_id();
        ctx.ignore_manifests();
        ctx.restrict_transforms()?;
        Ok(ctx)
    }

    /// By default xmlsec turns `URI="#foo"` into the XPointer
    /// `xpointer(id('foo'))` by string formatting, so an Id containing an
    /// apostrophe produced an invalid expression and could not be signed or
    /// verified (#71). The flag (named for the Visa3D protocol that needed
    /// it first) makes xmlsec look the bare name up with `xmlGetID` instead:
    /// the same ID table and the same node set without comments, minus the
    /// quoting. It is also stricter -- `id('a b')` selects two elements,
    /// the lookup finds none. `#xpointer(...)` URIs are unaffected.
    fn resolve_bare_fragments_by_id(&mut self) {
        // SAFETY: self.ptr is a live xmlSecDSigCtx we exclusively own; flags
        // is application-settable and read when each Reference context is
        // initialized. Same ABI caveat as the signKey write.
        unsafe {
            (*self.ptr).flags |= sys::XMLSEC_DSIG_FLAGS_USE_VISA3D_HACK;
        }
    }

    /// By default xmlsec also resolves and digests the references inside
    /// every `<Object><Manifest>`, whose URIs, transforms and digest methods
    /// never reach Ruby Policy, which reads only `<SignedInfo>` (#75). XML-DSig
    /// core validation leaves Manifest references to the application, and
    /// this library never treats their targets as signed: a `<Reference>` to
    /// the `<Manifest>` still digests the Manifest element itself, and nothing
    /// it points to.
    fn ignore_manifests(&mut self) {
        // SAFETY: self.ptr is a live xmlSecDSigCtx we exclusively own; flags
        // is application-settable and read while processing the Signature.
        // Same ABI caveat as the signKey write.
        unsafe {
            (*self.ptr).flags |= sys::XMLSEC_DSIG_FLAGS_IGNORE_MANIFESTS;
        }
    }

    /// xmlSecDSigCtxCreate leaves `enabledReferenceUris` /
    /// `transformCtx.enabledUris` as `xmlSecTransformUriTypeAny`, so a
    /// `<Reference URI="file://…">` or `http://…` is fetched before Ruby
    /// Policy can reject it (S-04). Limit both to empty + same-document;
    /// `referenced_documents:` is the only supported non-fragment path
    /// and it never hits libxml2 I/O.
    fn restrict_reference_uris_to_same_document(&mut self) {
        let allowed = sys::URI_TYPE_EMPTY | sys::URI_TYPE_SAME_DOCUMENT;
        // SAFETY: self.ptr is a live xmlSecDSigCtx we exclusively own.
        // enabledReferenceUris and transformCtx.enabledUris are
        // application-settable; xmlsec reads them when resolving
        // Reference hrefs. Same ABI caveat as the signKey write.
        unsafe {
            (*self.ptr).enabledReferenceUris = allowed;
            (*self.ptr).transformCtx.enabledUris = allowed;
        }
    }

    /// Lets References name URIs outside the document, for a verification
    /// whose caller passed `referenced_documents:` (#74). Only the IO
    /// callbacks installed by [`init_xmlsec`] can open such a URI, and they
    /// serve nothing but that map: no filesystem, no network.
    fn allow_referenced_documents(&mut self) {
        let allowed = sys::URI_TYPE_EMPTY
            | sys::URI_TYPE_SAME_DOCUMENT
            | sys::xmlSecTransformUriTypeLocal
            | sys::xmlSecTransformUriTypeRemote;
        // SAFETY: same fields and caveat as
        // restrict_reference_uris_to_same_document.
        unsafe {
            (*self.ptr).enabledReferenceUris = allowed;
            (*self.ptr).transformCtx.enabledUris = allowed;
        }
    }

    /// Restricts `enabledReferenceTransforms` to core DSig transforms only.
    ///
    /// xmlSecDSigCtxCreate leaves `enabledReferenceTransforms` as NULL, so
    /// all registered transforms are allowed, including XSLT when the host
    /// xmlsec was built with libxslt (S-10). Initialize the list and add
    /// only safe core DSig transforms — excluding XSLT, XPath, and XPointer.
    /// SHA-3 digest klasses exist only in xmlsec 1.3+; they are looked up
    /// by href so a 1.2 host still compiles (#60).
    fn restrict_transforms(&mut self) -> Result<(), &'static str> {
        // List of safe transform IDs to allow. These cover the standard
        // DSig operations: canonicalization, base64, enveloped signature.
        // Notably absent: XSLT, XPath, XPointer, and other potentially
        // dangerous transforms.
        let safe_transforms: &[unsafe extern "C" fn() -> sys::xmlSecTransformId] = &[
            sys::xmlSecTransformEnvelopedGetKlass,
            sys::xmlSecTransformBase64GetKlass,
            sys::xmlSecTransformInclC14NGetKlass,
            sys::xmlSecTransformInclC14NWithCommentsGetKlass,
            sys::xmlSecTransformInclC14N11GetKlass,
            sys::xmlSecTransformInclC14N11WithCommentsGetKlass,
            sys::xmlSecTransformExclC14NGetKlass,
            sys::xmlSecTransformExclC14NWithCommentsGetKlass,
            // Digest methods
            sys::xmlSecOpenSSLTransformSha1GetKlass,
            sys::xmlSecOpenSSLTransformSha224GetKlass,
            sys::xmlSecOpenSSLTransformSha256GetKlass,
            sys::xmlSecOpenSSLTransformSha384GetKlass,
            sys::xmlSecOpenSSLTransformSha512GetKlass,
        ];

        // SAFETY: self.ptr is a live xmlSecDSigCtx we exclusively own.
        // xmlSecDSigCtxEnableReferenceTransform initializes the
        // enabledReferenceTransforms list on first call and adds the
        // transform ID. After this, only transforms in the list are allowed.
        for get_klass in safe_transforms {
            let transform_id = unsafe { get_klass() };
            let rc = unsafe {
                sys::xmlSecDSigCtxEnableReferenceTransform(self.ptr, transform_id)
            };
            if rc < 0 {
                return Err("failed to enable safe transform");
            }
        }
        self.enable_sha3_digest_transforms()
    }

    /// Enables SHA-3 `DigestMethod` klasses when the linked xmlsec registered
    /// them. Looked up by href rather than `xmlSecOpenSSLTransformSha3_*GetKlass`
    /// so Ubuntu's xmlsec 1.2 (no SHA-3 symbols) still compiles (S-10, #60).
    fn enable_sha3_digest_transforms(&mut self) -> Result<(), &'static str> {
        const SHA3_DIGEST_HREFS: &[&[u8]] = &[
            b"http://www.w3.org/2007/05/xmldsig-more#sha3-224",
            b"http://www.w3.org/2007/05/xmldsig-more#sha3-256",
            b"http://www.w3.org/2007/05/xmldsig-more#sha3-384",
            b"http://www.w3.org/2007/05/xmldsig-more#sha3-512",
        ];

        // SAFETY: xmlSecTransformIdsGet returns the process-global registry
        // list, populated once by init_xmlsec and never mutated afterwards.
        let registry = unsafe { sys::xmlSecTransformIdsGet() };
        if registry.is_null() {
            return Err("xmlsec transform registry is unavailable");
        }
        // SAFETY: registry is a valid list (checked above).
        let size = unsafe { sys::xmlSecPtrListGetSize(registry) };
        for pos in 0..size {
            // SAFETY: pos < size; every item is a static xmlSecTransformKlass.
            let id = unsafe { sys::xmlSecPtrListGetItem(registry, pos) } as sys::xmlSecTransformId;
            if id.is_null() {
                continue;
            }
            // SAFETY: id is a non-null static klass; href is a static
            // NUL-terminated string or null.
            let href = unsafe { (*id).href };
            if href.is_null() {
                continue;
            }
            // SAFETY: href is non-null and NUL-terminated (see above).
            let href = unsafe { CStr::from_ptr(href.cast()) }.to_bytes();
            if !SHA3_DIGEST_HREFS.contains(&href) {
                continue;
            }
            // SAFETY: self.ptr is a live xmlSecDSigCtx we exclusively own;
            // enabledReferenceTransforms was initialized by the SHA-2 loop
            // above, and id is static for the life of the process.
            let rc = unsafe { sys::xmlSecDSigCtxEnableReferenceTransform(self.ptr, id) };
            if rc < 0 {
                return Err("failed to enable SHA-3 digest transform");
            }
        }
        Ok(())
    }

    /// Lets the signing KeyInfo writer fill `<KeyName>`, `<KeyValue>` and
    /// `<X509Data>`.
    ///
    /// xmlsec 1.3 registers the KeyValue key data *disabled* globally (it
    /// is unsafe to *read*), so with the default empty
    /// `keyInfoWriteCtx.enabledKeyData` a `<KeyValue/>` template stayed
    /// empty. A non-empty local list replaces the global one for this
    /// context only, so it must name every KeyInfo child we write and the
    /// key value classes KeyValue may serialize. Reading is untouched:
    /// verification pins `signKey` and never consults KeyInfo (S-01).
    ///
    /// Classes are picked from xmlsec's registry by name rather than by
    /// `xmlSec*GetKlass` symbol because the EC class is `ec` in 1.3 but
    /// `ecdsa` (a different symbol) in the 1.2 that Linux distros ship.
    fn enable_key_info_writing(&mut self) -> Result<(), &'static str> {
        const WRITABLE: &[&[u8]] = &[b"key-name", b"key-value", b"x509", b"rsa", b"ec", b"ecdsa", b"dsa"];

        // SAFETY: xmlSecKeyDataIdsGet returns the process-global registry
        // list, populated once by init_xmlsec and never mutated afterwards.
        let registry = unsafe { sys::xmlSecKeyDataIdsGet() };
        if registry.is_null() {
            return Err("xmlsec key data registry is unavailable");
        }
        // SAFETY: registry is a valid list (checked above).
        let size = unsafe { sys::xmlSecPtrListGetSize(registry) };
        for pos in 0..size {
            // SAFETY: pos < size; every item is a static xmlSecKeyDataKlass.
            let id = unsafe { sys::xmlSecPtrListGetItem(registry, pos) } as sys::xmlSecKeyDataId;
            if id.is_null() {
                continue;
            }
            // SAFETY: id is a non-null static klass; name is a static
            // NUL-terminated string or null.
            let name = unsafe { (*id).name };
            if name.is_null() {
                continue;
            }
            // SAFETY: name is non-null and NUL-terminated (see above).
            let name = unsafe { std::ffi::CStr::from_ptr(name.cast()) }.to_bytes();
            if !WRITABLE.contains(&name) {
                continue;
            }
            // SAFETY: self.ptr is a live xmlSecDSigCtx we exclusively own;
            // enabledKeyData was initialized as an xmlSecKeyDataIdListId
            // list by xmlSecDSigCtxCreate, and id is static for the life of
            // the process. Same ABI caveat as the signKey write.
            let rc = unsafe {
                sys::xmlSecPtrListAdd(&mut (*self.ptr).keyInfoWriteCtx.enabledKeyData, id as sys::xmlSecPtr)
            };
            if rc < 0 {
                return Err("failed to enable KeyInfo key data for writing");
            }
        }
        Ok(())
    }

    /// Signs the document at the given signature node.
    fn sign(&mut self, sig_node: sys::xmlNodePtr) -> Result<(), &'static str> {
        // SAFETY: self.ptr is valid and exclusively ours; sig_node is
        // valid within the document's lifetime.
        let rc = unsafe { sys::xmlSecDSigCtxSign(self.ptr, sig_node) };
        if rc < 0 {
            return Err("xmlSecDSigCtxSign failed");
        }
        Ok(())
    }

    /// Verifies the signature at the given node. Returns the status.
    fn verify(&mut self, sig_node: sys::xmlNodePtr) -> VerifyStatus {
        // SAFETY: self.ptr is valid; sig_node is valid within the
        // document's lifetime.
        if unsafe { sys::xmlSecDSigCtxVerify(self.ptr, sig_node) } < 0 {
            return VerifyStatus::Unknown;
        }
        // SAFETY: self.ptr is valid; status is a plain enum field.
        let status = unsafe { (*self.ptr).status };
        match status {
            s if s == sys::DSIG_STATUS_SUCCEEDED => VerifyStatus::Succeeded,
            s if s == sys::DSIG_STATUS_INVALID => VerifyStatus::Invalid,
            _ => VerifyStatus::Unknown,
        }
    }

    /// Per-`<SignedInfo><Reference>` digest verification status, in document
    /// order, after `verify()` has run (S-09). `xmlSecDSigCtxVerify`
    /// processes and digest-checks every SignedInfo Reference before it ever
    /// looks at the overall `SignatureValue` (see xmldsig.c), so this is
    /// independent of the overall `signKey`/`SignatureValue` outcome: a
    /// harmless-fragment Reference and the payload Reference in a
    /// multi-Reference signature can genuinely disagree.
    ///
    /// `Some(true)`/`Some(false)` is a completed status; `None` means the
    /// reference was never processed (verification aborted earlier, e.g. a
    /// malformed `SignedInfo`) and the caller has no real answer to give.
    /// `<Manifest>` references are not read here -- this library does not
    /// otherwise resolve or expose Manifest semantics.
    fn reference_statuses(&self) -> Vec<Option<bool>> {
        // SAFETY: self.ptr is a live xmlSecDSigCtx; signedInfoReferences is
        // an embedded xmlSecPtrList (not a pointer) that verify() populated.
        let list = unsafe { ptr::addr_of!((*self.ptr).signedInfoReferences) as sys::xmlSecPtrListPtr };
        // SAFETY: list points at a valid, initialized xmlSecPtrList for the
        // lifetime of self.
        let size = unsafe { sys::xmlSecPtrListGetSize(list) };
        (0..size)
            .map(|pos| {
                // SAFETY: pos is in [0, size), so GetItem returns one of the
                // list's own xmlSecDSigReferenceCtxPtr entries.
                let item = unsafe { sys::xmlSecPtrListGetItem(list, pos) };
                if item.is_null() {
                    return None;
                }
                let reference_ctx = item as sys::xmlSecDSigReferenceCtxPtr;
                // SAFETY: reference_ctx is a live xmlSecDSigReferenceCtx
                // owned by the list; status is a plain enum field.
                let status = unsafe { (*reference_ctx).status };
                match status {
                    s if s == sys::DSIG_STATUS_SUCCEEDED => Some(true),
                    s if s == sys::DSIG_STATUS_INVALID => Some(false),
                    _ => None,
                }
            })
            .collect()
    }
}

impl Drop for DsigCtx<'_> {
    fn drop(&mut self) {
        // SAFETY: we're the exclusive owner of this context.
        unsafe { sys::xmlSecDSigCtxDestroy(self.ptr) }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyStatus {
    Succeeded,
    Invalid,
    Unknown,
}

impl VerifyStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Invalid => "invalid",
            Self::Unknown => "unknown",
        }
    }
}

// ---------------------------------------------------------------------------
// Public API — the §7 contract
// ---------------------------------------------------------------------------

/// Result of `inspect_document`.
#[derive(Debug)]
pub struct InspectResult {
    pub signature_method: String,
    pub canonicalization_method: String,
    pub signature_count: usize,
    pub key_names: Vec<String>,
    pub certificates: Vec<String>,
    pub references: Vec<InspectReference>,
    /// Whether `<KeyInfo>` contains a `<RetrievalMethod>` (S-06,
    /// `allow_retrieval_method`) -- checked structurally, before any
    /// dereferencing, the same way S-04 checks Reference URIs.
    pub has_retrieval_method: bool,
}

#[derive(Debug)]
pub struct InspectReference {
    pub uri: String,
    pub digest_method: String,
    pub transforms: Vec<String>,
    pub id: Option<String>,
    pub r#type: Option<String>,
}

/// Result of `verify_document`.
#[derive(Debug)]
pub struct VerifyResult {
    pub status: VerifyStatus,
    pub errors: Vec<String>,
    /// Per SignedInfo `<Reference>`, the document-order element index of the
    /// node xmlsec's ID table resolved (same table `#id` verification used).
    /// Empty URI → root element's index. Unresolved / non-fragment → `None`.
    pub reference_element_indexes: Vec<Option<usize>>,
    /// Per SignedInfo `<Reference>`, its own digest verification status --
    /// independent of the overall signature/key outcome (S-09). Same
    /// indexing/order as `reference_element_indexes`. `None` when the
    /// reference was never processed (verification aborted before reaching
    /// it), not when we simply do not know.
    pub reference_valid: Vec<Option<bool>>,
    /// Index into `trusted_pems` of the PEM whose key verified the signature,
    /// or `None` when none did. Lets Ruby name the certificate that verified
    /// (`Verification#certificate`), which `certificates:` otherwise leaves
    /// ambiguous.
    pub trusted_index: Option<usize>,
}

const DSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";

/// Inspects the nth `<ds:Signature>` without performing any cryptography.
/// Returns metadata about the signature for policy enforcement.
///
/// No `unsafe` in this function body — every FFI call is behind a helper.
pub fn inspect_document(
    xml: &[u8],
    signature_index: usize,
) -> Result<InspectResult, DsigError> {
    let doc = OwnedXmlDoc::parse(xml).map_err(DsigError::parse)?;
    let root = doc
        .root_element()
        .ok_or(DsigError::parse("XML document has no root element"))?;

    let sig_count = doc.count_signatures(root);
    let sig_node = doc
        .find_nth_signature(root, signature_index)
        .ok_or(DsigError::native("signature index out of range"))?;

    // Extract <SignedInfo>
    let signed_info = unsafe { find_child(sig_node, "SignedInfo", DSIG_NS) }
        .ok_or(DsigError::native("no <SignedInfo> element in <Signature>"))?;

    // CanonicalizationMethod/@Algorithm
    let c14n_method = unsafe { find_child(signed_info, "CanonicalizationMethod", DSIG_NS) }
        .and_then(|n| unsafe { get_attribute(n, b"Algorithm\0") })
        .unwrap_or_default();

    // SignatureMethod/@Algorithm
    let sig_method = unsafe { find_child(signed_info, "SignatureMethod", DSIG_NS) }
        .and_then(|n| unsafe { get_attribute(n, b"Algorithm\0") })
        .unwrap_or_default();

    // References
    let ref_nodes = unsafe { find_children(signed_info, "Reference", DSIG_NS) };
    let mut references = Vec::new();
    for ref_node in ref_nodes {
        let uri = unsafe { get_attribute(ref_node, b"URI\0") }.unwrap_or_default();
        let id = unsafe { get_attribute(ref_node, b"Id\0") };
        let type_attr = unsafe { get_attribute(ref_node, b"Type\0") };

        // DigestMethod/@Algorithm
        let digest_method = unsafe { find_child(ref_node, "DigestMethod", DSIG_NS) }
            .and_then(|n| unsafe { get_attribute(n, b"Algorithm\0") })
            .unwrap_or_default();

        // Transforms
        let mut transforms = Vec::new();
        if let Some(transforms_node) = unsafe { find_child(ref_node, "Transforms", DSIG_NS) } {
            let transform_nodes = unsafe { find_children(transforms_node, "Transform", DSIG_NS) };
            for t_node in transform_nodes {
                if let Some(alg) = unsafe { get_attribute(t_node, b"Algorithm\0") } {
                    transforms.push(alg);
                }
            }
        }

        references.push(InspectReference {
            uri,
            digest_method,
            transforms,
            id,
            r#type: type_attr,
        });
    }

    // KeyInfo — KeyName, X509Certificate, and RetrievalMethod presence
    let mut key_names = Vec::new();
    let mut certificates = Vec::new();
    let mut has_retrieval_method = false;
    if let Some(key_info) = unsafe { find_child(sig_node, "KeyInfo", DSIG_NS) } {
        // KeyName elements
        let key_name_nodes = unsafe { find_children(key_info, "KeyName", DSIG_NS) };
        for kn in key_name_nodes {
            let text = unsafe { get_text_content(kn) };
            if !text.is_empty() {
                key_names.push(text);
            }
        }

        // X509Data/X509Certificate elements
        let x509_data_nodes = unsafe { find_children(key_info, "X509Data", DSIG_NS) };
        for x509_data in x509_data_nodes {
            let cert_nodes = unsafe { find_children(x509_data, "X509Certificate", DSIG_NS) };
            for cert_node in cert_nodes {
                let text = unsafe { get_text_content(cert_node) }.trim().to_string();
                if !text.is_empty() {
                    // Wrap in PEM markers for consistency
                    let pem = format!("-----BEGIN CERTIFICATE-----\n{text}\n-----END CERTIFICATE-----");
                    certificates.push(pem);
                }
            }
        }

        has_retrieval_method =
            unsafe { find_child(key_info, "RetrievalMethod", DSIG_NS) }.is_some();
    }

    Ok(InspectResult {
        signature_method: sig_method,
        canonicalization_method: c14n_method,
        signature_count: sig_count,
        key_names,
        certificates,
        references,
        has_retrieval_method,
    })
}

/// Result of `scan_document`: the structural facts the Ruby layer used to
/// read from a Nokogiri DOM, taken from the same parse xmlsec works on.
#[derive(Debug)]
pub struct ScanResult {
    pub signature_count: usize,
    /// Per `<ds:Signature>` in document order, whether its
    /// `<SignatureValue>` has non-whitespace content.
    pub signature_values: Vec<bool>,
    /// Per `<ds:Signature>`, its document-order element index (root = 0),
    /// the numbering `Native.verify`'s `reference_element_indexes` use.
    pub signature_element_indexes: Vec<Option<usize>>,
    /// Whether two ID attributes (any of `id_attrs`, matched by local name
    /// the way `xmlSecAddIDs` matches them) carry the same value (S-06).
    pub duplicate_ids: bool,
    /// Values `#value` resolves to the root element through the ID table
    /// xmlsec uses, for `require_signed_root` (S-06).
    pub root_ids: Vec<String>,
}

/// Scans the document's structure without cryptography: signature count
/// and presence, duplicate IDs, and the root's IDs. `strict` rejects any
/// libxml2 error, the way a strict Nokogiri parse does; it is set for input
/// that arrived as bytes, and unset for a DOM the caller already holds.
pub fn scan_document(xml: &[u8], id_attrs: &[String], strict: bool) -> Result<ScanResult, DsigError> {
    errors::clear_errors();

    let doc = if strict { OwnedXmlDoc::parse_strict(xml) } else { OwnedXmlDoc::parse(xml) }
        .map_err(DsigError::parse)?;
    let root = doc
        .root_element()
        .ok_or(DsigError::parse("XML document has no root element"))?;

    let mut signatures = Vec::new();
    collect_signature_nodes(root, &mut signatures);
    let signature_values = signatures
        .iter()
        .map(|&sig| {
            unsafe { find_child(sig, "SignatureValue", DSIG_NS) }
                .map(|value| !ruby_strip(&unsafe { get_text_content(value) }).is_empty())
                .unwrap_or(false)
        })
        .collect();
    let signature_element_indexes = signatures
        .iter()
        .map(|&sig| element_document_index(root, sig))
        .collect();

    let mut id_values: Vec<(sys::xmlAttrPtr, String)> = Vec::new();
    collect_id_attributes(root, id_attrs, &mut id_values);
    let mut seen = std::collections::HashSet::new();
    let duplicate_ids = id_values.iter().any(|(_, value)| !seen.insert(value.as_str()));

    doc.register_id_attributes(root, id_attrs);
    let root_ids = id_values
        .iter()
        .filter(|(attr, _)| unsafe { (**attr).parent } == root)
        .filter(|(_, value)| element_for_id(&doc, value) == Some(root))
        .map(|(_, value)| value.clone())
        .collect();

    errors::clear_errors();
    Ok(ScanResult {
        signature_count: signatures.len(),
        signature_values,
        signature_element_indexes,
        duplicate_ids,
        root_ids,
    })
}

/// Ruby's `String#strip`: ASCII whitespace and NUL, nothing else, so a
/// `<SignatureValue>` holding only U+00A0 counts as present in both layers.
fn ruby_strip(text: &str) -> &str {
    text.trim_matches(|c: char| c.is_ascii_whitespace() || c == '\x0b' || c == '\0')
}

/// Every attribute, in document order, whose local name is one of
/// `id_attrs`, whatever its namespace: the attributes `xmlSecAddIDs`
/// registers.
fn collect_id_attributes(node: sys::xmlNodePtr, id_attrs: &[String], out: &mut Vec<(sys::xmlAttrPtr, String)>) {
    if node.is_null() || id_attrs.is_empty() {
        return;
    }
    // SAFETY: node is non-null and valid within the document's lifetime.
    let node_ref = unsafe { &*node };
    if node_ref.type_ == sys::xmlElementType_XML_ELEMENT_NODE {
        let mut attr = node_ref.properties;
        while !attr.is_null() {
            // SAFETY: attr is a valid attribute of this element.
            let attr_ref = unsafe { &*attr };
            let name = if attr_ref.name.is_null() {
                ""
            } else {
                // SAFETY: attribute names are NUL-terminated.
                unsafe { CStr::from_ptr(attr_ref.name.cast()) }.to_str().unwrap_or("")
            };
            if id_attrs.iter().any(|id| id == name) {
                // SAFETY: attr's children are its value's text nodes.
                let value = unsafe { sys::xmlNodeListGetString(node_ref.doc, attr_ref.children, 1) };
                let text = if value.is_null() {
                    String::new()
                } else {
                    // SAFETY: non-null, NUL-terminated, freed right after.
                    let text = unsafe { CStr::from_ptr(value.cast()) }.to_str().unwrap_or("").to_string();
                    unsafe { xml_free(value.cast()) };
                    text
                };
                out.push((attr, text));
            }
            attr = attr_ref.next;
        }
    }
    let mut child = node_ref.children;
    while !child.is_null() {
        collect_id_attributes(child, id_attrs, out);
        // SAFETY: child is a valid sibling in this document.
        child = unsafe { (*child).next };
    }
}

/// Validates a copy of the nth `<ds:Signature>`, as the root of a fresh
/// document, against the XSD at `xsd_path` (relative imports resolve
/// against it). Returns libxml2's validation errors; empty means valid.
/// Nokogiri's `schema: :default` path validated the same copy (#102).
pub fn validate_signature_schema(
    xml: &[u8],
    signature_index: usize,
    xsd_path: &str,
) -> Result<Vec<String>, DsigError> {
    errors::clear_errors();

    let doc = OwnedXmlDoc::parse(xml).map_err(DsigError::parse)?;
    let root = doc
        .root_element()
        .ok_or(DsigError::parse("XML document has no root element"))?;
    let sig_node = doc
        .find_nth_signature(root, signature_index)
        .ok_or(DsigError::native("signature index out of range"))?;

    let mut path = xsd_path.as_bytes().to_vec();
    path.push(0);
    errors::clear_errors();
    let _capture = Libxml2Capture::start();

    // SAFETY: path is NUL-terminated for the call; the parser context is
    // freed below on every path.
    let parser = unsafe { sys::xmlSchemaNewParserCtxt(path.as_ptr().cast()) };
    if parser.is_null() {
        return Err(DsigError::native("failed to load the XML-DSig schema"));
    }
    // SAFETY: parser is valid; the handler takes a null context.
    unsafe { sys::xmlSchemaSetParserStructuredErrors(parser, errors::libxml2_error_handler(), ptr::null_mut()) };
    // SAFETY: parser is valid. The parsed schema outlives its parser.
    let schema = unsafe { sys::xmlSchemaParse(parser) };
    // SAFETY: freed exactly once, after xmlSchemaParse.
    unsafe { sys::xmlSchemaFreeParserCtxt(parser) };
    if schema.is_null() {
        return Err(DsigError::native("failed to load the XML-DSig schema"));
    }

    // SAFETY: "1.0" is NUL-terminated; the new document is owned below.
    let copy = unsafe { sys::xmlNewDoc(c"1.0".as_ptr().cast()) };
    if copy.is_null() {
        // SAFETY: schema is valid and freed once.
        unsafe { sys::xmlSchemaFree(schema) };
        return Err(DsigError::native("failed to copy <Signature> for schema validation"));
    }
    let copy = OwnedXmlDoc(copy);
    // SAFETY: sig_node is valid in doc; the recursive copy belongs to copy.0
    // once set as its root, and is freed with it.
    let copied = unsafe { sys::xmlDocCopyNode(sig_node, copy.0, 1) };
    if !copied.is_null() {
        // SAFETY: copy.0 has no root yet, so nothing is unlinked or leaked.
        unsafe { sys::xmlDocSetRootElement(copy.0, copied) };
    }

    errors::clear_errors();
    // SAFETY: schema is valid; the context is freed below.
    let valid_ctxt = unsafe { sys::xmlSchemaNewValidCtxt(schema) };
    let result = if valid_ctxt.is_null() || copied.is_null() {
        Err(DsigError::native("failed to set up schema validation"))
    } else {
        // SAFETY: valid_ctxt and copy.0 are valid for the call.
        let status = unsafe {
            sys::xmlSchemaSetValidStructuredErrors(valid_ctxt, errors::libxml2_error_handler(), ptr::null_mut());
            sys::xmlSchemaValidateDoc(valid_ctxt, copy.0)
        };
        let mut messages = errors::drain_errors();
        if status != 0 && messages.is_empty() {
            messages.push("<Signature> does not validate against the XML-DSig schema".into());
        }
        Ok(messages)
    };
    // SAFETY: each freed once; a null context is skipped.
    unsafe {
        if !valid_ctxt.is_null() {
            sys::xmlSchemaFreeValidCtxt(valid_ctxt);
        }
        sys::xmlSchemaFree(schema);
    }
    result
}

/// Signs the document's nth `<ds:Signature>` template.
///
/// The XML must already contain a `<ds:Signature>` skeleton with empty
/// `<DigestValue>`, `<SignatureValue>` etc. — built by Ruby's Template
/// layer.
pub fn sign_document(
    xml: &[u8],
    key_pem: &[u8],
    cert_pems: &[Vec<u8>],
    id_attrs: &[String],
    signature_index: usize,
) -> Result<Vec<u8>, DsigError> {
    errors::clear_errors();

    let doc = OwnedXmlDoc::parse(xml).map_err(DsigError::parse)?;
    let root = doc
        .root_element()
        .ok_or(DsigError::parse("XML document has no root element"))?;

    doc.register_id_attributes(root, id_attrs);

    let sig_node = doc
        .find_nth_signature(root, signature_index)
        .ok_or(DsigError::native("signature index out of range or no <Signature> found"))?;

    let key = XmlSecKey::from_pem(key_pem).map_err(DsigError::key_load)?;

    for cert_pem in cert_pems {
        key.add_cert_pem(cert_pem).map_err(DsigError::key_load)?;
    }

    let mngr = KeysMngr::new(&[], &[]).map_err(DsigError::native)?;

    let mut ctx = DsigCtx::for_signing(&mngr, key).map_err(DsigError::native)?;
    ctx.enable_key_info_writing().map_err(DsigError::native)?;

    ctx.sign(sig_node).map_err(DsigError::signing)?;

    doc.serialize().map_err(DsigError::native)
}

/// Verifies the nth `<ds:Signature>` against trusted/untrusted certs.
///
/// `trusted_pems` may contain certificate PEMs, key PEMs, or both.
/// Every trusted PEM is converted to a public key and pinned on the
/// dsig context as `signKey`, which makes xmlsec skip KeyInfo lookup.
/// That is the `key:` / `certificate:` contract: the document cannot
/// supply the verification key via `<KeyValue>`, `<DEREncodedKeyValue>`,
/// or `<RetrievalMethod>` (S-01). Multiple certificate PEMs are tried
/// in order until one verifies (`certificates:` — any one of these).
/// An empty trust list fails closed (`:invalid`), never by reading
/// KeyInfo.
///
/// Returns a `VerifyResult` with status and captured error messages.
/// Only raises (returns `Err`) for conditions that are not a verification
/// verdict (unparseable input, out-of-range index, unreadable key).
pub fn verify_document(
    xml: &[u8],
    trusted_pems: &[Vec<u8>],
    untrusted_pems: &[Vec<u8>],
    id_attrs: &[String],
    signature_index: usize,
    referenced_documents: HashMap<Vec<u8>, Vec<u8>>,
) -> Result<VerifyResult, DsigError> {
    errors::clear_errors();
    let serves_external = !referenced_documents.is_empty();
    let _referenced = ReferencedDocuments::activate(referenced_documents);

    let doc = OwnedXmlDoc::parse(xml).map_err(DsigError::parse)?;
    let root = doc
        .root_element()
        .ok_or(DsigError::parse("XML document has no root element"))?;

    doc.register_id_attributes(root, id_attrs);

    let sig_node = doc
        .find_nth_signature(root, signature_index)
        .ok_or(DsigError::native("no <Signature> element found in document"))?;

    let mut pinned_key_pems: Vec<&[u8]> = Vec::new();
    let mut cert_pems: Vec<&[u8]> = Vec::new();
    let mut key_indexes = Vec::new();
    let mut cert_indexes = Vec::new();
    for (index, pem) in trusted_pems.iter().enumerate() {
        if pem_is_certificate(pem) {
            cert_pems.push(pem);
            cert_indexes.push(index);
        } else {
            pinned_key_pems.push(pem);
            key_indexes.push(index);
        }
    }

    if pinned_key_pems.len() > 1 {
        return Err(DsigError::native("at most one trusted key PEM is supported"));
    }

    // Chain building stays a Ruby `store:` concern. Native only ever pins
    // a verification key; untrusted PEMs are still accepted so the FFI
    // shape is unchanged, but they are not consulted once signKey is set.
    // Loads the untrusted PEMs, so a failure is about certificate input.
    let mngr = KeysMngr::new(&[], untrusted_pems).map_err(DsigError::key_load)?;

    let keys_to_try = load_pinned_keys(&pinned_key_pems, &cert_pems)?;
    // load_pinned_keys tries the one key PEM alone, or else every certificate.
    let tried_indexes = if pinned_key_pems.is_empty() { cert_indexes } else { key_indexes };
    let reference_element_indexes =
        collect_reference_element_indexes(&doc, root, sig_node);

    if keys_to_try.is_empty() {
        return Ok(VerifyResult {
            status: VerifyStatus::Invalid,
            errors: vec!["no trusted key or certificate provided".into()],
            reference_valid: vec![None; reference_element_indexes.len()],
            reference_element_indexes,
            trusted_index: None,
        });
    }

    let mut status = VerifyStatus::Invalid;
    let mut captured_errors = Vec::new();
    let mut reference_valid = Vec::new();
    let mut trusted_index = None;
    for (key, index) in keys_to_try.into_iter().zip(tried_indexes) {
        errors::clear_errors();
        let mut ctx = DsigCtx::for_signing(&mngr, key).map_err(DsigError::native)?;
        if serves_external {
            ctx.allow_referenced_documents();
        }
        status = ctx.verify(sig_node);
        captured_errors = errors::drain_errors();
        reference_valid = ctx.reference_statuses();
        if status == VerifyStatus::Succeeded {
            trusted_index = Some(index);
            break;
        }
    }

    Ok(VerifyResult {
        status,
        errors: captured_errors,
        reference_element_indexes,
        reference_valid,
        trusted_index,
    })
}

/// One key PEM pins immediately. Otherwise each certificate PEM is loaded
/// as a public key so `certificates:` can try them until one matches.
fn load_pinned_keys(
    key_pems: &[&[u8]],
    cert_pems: &[&[u8]],
) -> Result<Vec<XmlSecKey>, DsigError> {
    if let Some(pem) = key_pems.first() {
        return Ok(vec![XmlSecKey::from_pem(pem).map_err(DsigError::key_load)?]);
    }

    cert_pems
        .iter()
        .map(|pem| XmlSecKey::from_cert_pem(pem).map_err(DsigError::key_load))
        .collect()
}

/// For each SignedInfo `<Reference>`, report the document-order element index
/// of the node the libxml2 ID table resolves — the same table xmlsec used for
/// `#id` fragment verification. Empty URI → root index. Non-fragment / missing
/// ID → `None`.
fn collect_reference_element_indexes(
    doc: &OwnedXmlDoc,
    root: sys::xmlNodePtr,
    sig_node: sys::xmlNodePtr,
) -> Vec<Option<usize>> {
    let signed_info = unsafe { find_child(sig_node, "SignedInfo", DSIG_NS) };
    let Some(signed_info) = signed_info else {
        return Vec::new();
    };

    let ref_nodes = unsafe { find_children(signed_info, "Reference", DSIG_NS) };
    ref_nodes
        .into_iter()
        .map(|ref_node| {
            let uri = unsafe { get_attribute(ref_node, b"URI\0") }.unwrap_or_default();
            resolve_reference_element(doc, root, &uri)
                .and_then(|node| element_document_index(root, node))
        })
        .collect()
}

fn resolve_reference_element(
    doc: &OwnedXmlDoc,
    root: sys::xmlNodePtr,
    uri: &str,
) -> Option<sys::xmlNodePtr> {
    if uri.is_empty() {
        return Some(root);
    }
    if let Some(id) = uri.strip_prefix('#') {
        // Bare fragment only — xpointer(...) / other same-document forms are
        // left unresolved here (Ruby already treats them as node: nil).
        if id.is_empty() || id.contains('(') {
            return None;
        }
        return element_for_id(doc, id);
    }
    None
}

fn element_for_id(doc: &OwnedXmlDoc, id: &str) -> Option<sys::xmlNodePtr> {
    let mut id_bytes = id.as_bytes().to_vec();
    id_bytes.push(0);

    // SAFETY: doc.0 is a live OwnedXmlDoc; id_bytes is NUL-terminated for the
    // duration of the call. xmlGetID returns a pointer into the document's ID
    // table (not newly allocated).
    let attr = unsafe { sys::xmlGetID(doc.0, id_bytes.as_ptr().cast()) };
    if attr.is_null() {
        return None;
    }

    // SAFETY: attr is a valid xmlAttr from this document; its parent is the
    // element that owns the ID attribute.
    let parent = unsafe { (*attr).parent };
    if parent.is_null() {
        return None;
    }
    let parent_ref = unsafe { &*parent };
    if parent_ref.type_ != sys::xmlElementType_XML_ELEMENT_NODE {
        return None;
    }
    Some(parent)
}

/// Document-order index among element nodes only (root = 0), matching
/// Nokogiri/`//*` order for the same serialized tree.
fn element_document_index(root: sys::xmlNodePtr, target: sys::xmlNodePtr) -> Option<usize> {
    let mut index = 0usize;
    find_element_index(root, target, &mut index)
}

fn find_element_index(
    node: sys::xmlNodePtr,
    target: sys::xmlNodePtr,
    index: &mut usize,
) -> Option<usize> {
    if node.is_null() {
        return None;
    }

    // SAFETY: node is non-null within the document lifetime.
    let node_ref = unsafe { &*node };
    if node_ref.type_ == sys::xmlElementType_XML_ELEMENT_NODE {
        if std::ptr::eq(node, target) {
            return Some(*index);
        }
        *index += 1;

        let mut child = node_ref.children;
        while !child.is_null() {
            if let Some(found) = find_element_index(child, target, index) {
                return Some(found);
            }
            child = unsafe { (*child).next };
        }
    }
    None
}

fn pem_is_certificate(pem: &[u8]) -> bool {
    const MARKER: &[u8] = b"BEGIN CERTIFICATE";
    pem.windows(MARKER.len()).any(|window| window == MARKER)
}

/// Returns version information for the linked libraries.
pub fn versions() -> (String, String, String) {
    let xmlsec_version = std::str::from_utf8(sys::XMLSEC_VERSION)
        .unwrap_or("unknown\0")
        .trim_matches('\0')
        .to_string();

    let libxml2_version = std::str::from_utf8(sys::LIBXML_DOTTED_VERSION)
        .unwrap_or("unknown\0")
        .trim_matches('\0')
        .to_string();

    // The crypto backend is always openssl in our build
    let crypto = "openssl".to_string();

    (xmlsec_version, libxml2_version, crypto)
}

/// Initializes xmlsec + its OpenSSL crypto backend + our error callback.
/// `crate` wraps this in a `std::sync::Once` so it runs exactly once per
/// process.
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
        errors::install_error_callback();

        // xmlSecInit registers file, HTTP and FTP readers for Reference
        // URIs. Replace them with one that reads only the caller's
        // referenced_documents: map (#74), so no URI can ever reach the
        // filesystem or network, whatever enabledReferenceUris allows. This
        // is xmlsec's own input list; libxml2's parser I/O (Nokogiri's) is
        // untouched.
        sys::xmlSecIOCleanupCallbacks();
        if sys::xmlSecIORegisterCallbacks(
            Some(referenced_match),
            Some(referenced_open),
            Some(referenced_read),
            Some(referenced_close),
        ) < 0
        {
            return Err("xmlSecIORegisterCallbacks failed");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ReferencedDocuments — the only source xmlsec may read a URI from
// ---------------------------------------------------------------------------

thread_local! {
    /// The `referenced_documents:` of the verification running on this
    /// thread, keyed by URI (the Reference URI up to any `#`). The GVL is held
    /// for the whole native call, and xmlsec calls the IO callbacks on the
    /// calling thread, so a thread-local is enough (§7.1).
    static REFERENCED: RefCell<HashMap<Vec<u8>, Vec<u8>>> = RefCell::new(HashMap::new());
}

/// Makes a map visible to the IO callbacks until dropped, so an early
/// return cannot leave one verification's documents readable by the next.
struct ReferencedDocuments;

impl ReferencedDocuments {
    fn activate(documents: HashMap<Vec<u8>, Vec<u8>>) -> Self {
        REFERENCED.with(|map| *map.borrow_mut() = documents);
        Self
    }
}

impl Drop for ReferencedDocuments {
    fn drop(&mut self) {
        REFERENCED.with(|map| map.borrow_mut().clear());
    }
}

/// An open referenced document: its bytes and the read position.
struct ReferencedReader {
    data: Vec<u8>,
    pos: usize,
}

/// # Safety
///
/// `uri` is null or a NUL-terminated string, per `xmlInputMatchCallback`.
unsafe extern "C" fn referenced_match(uri: *const c_char) -> c_int {
    if uri.is_null() {
        return 0;
    }
    // SAFETY: non-null and NUL-terminated (see above).
    let uri = unsafe { CStr::from_ptr(uri) }.to_bytes();
    REFERENCED.with(|map| map.try_borrow().map(|m| m.contains_key(uri)).unwrap_or(false)) as c_int
}

/// # Safety
///
/// `uri` is null or a NUL-terminated string, per `xmlInputOpenCallback`.
unsafe extern "C" fn referenced_open(uri: *const c_char) -> *mut c_void {
    if uri.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: non-null and NUL-terminated (see above).
    let uri = unsafe { CStr::from_ptr(uri) }.to_bytes();
    let data = REFERENCED.with(|map| map.try_borrow().ok().and_then(|m| m.get(uri).cloned()));
    match data {
        Some(data) => Box::into_raw(Box::new(ReferencedReader { data, pos: 0 })).cast(),
        None => ptr::null_mut(),
    }
}

/// # Safety
///
/// `context` came from [`referenced_open`] and has not been closed;
/// `buffer` has room for `len` bytes.
unsafe extern "C" fn referenced_read(context: *mut c_void, buffer: *mut c_char, len: c_int) -> c_int {
    if context.is_null() || buffer.is_null() || len < 0 {
        return -1;
    }
    // SAFETY: context is a live ReferencedReader (see above).
    let reader = unsafe { &mut *context.cast::<ReferencedReader>() };
    let count = (reader.data.len() - reader.pos).min(len as usize);
    // SAFETY: count <= len bytes fit in buffer, and count bytes remain in data.
    unsafe { ptr::copy_nonoverlapping(reader.data.as_ptr().add(reader.pos), buffer.cast::<u8>(), count) };
    reader.pos += count;
    count as c_int
}

/// # Safety
///
/// `context` came from [`referenced_open`] and is closed exactly once.
unsafe extern "C" fn referenced_close(context: *mut c_void) -> c_int {
    if !context.is_null() {
        // SAFETY: context is the Box leaked by referenced_open.
        drop(unsafe { Box::from_raw(context.cast::<ReferencedReader>()) });
    }
    0
}

/// True when the linked libxmlsec1 matches the version these bindings were
/// generated against, down to the patch level.
///
/// Stricter than [`abi_compatible`] and used only for reporting: an exact
/// mismatch is worth telling the user about, but on its own it is not a
/// reason to refuse to load.
pub fn check_version() -> bool {
    check_version_mode(sys::xmlSecCheckVersionMode_xmlSecCheckVersionExactMatch)
}

/// True when the linked libxmlsec1 is ABI compatible with the headers these
/// bindings were generated from — same major version, and a minor version no
/// older than ours.
///
/// This is the check that actually matters. bindgen bakes xmlsec's and
/// libxml2's struct layouts into this extension at build time, and nothing
/// about a layout change is visible to the dynamic linker: every symbol still
/// resolves, the library still loads, and then a field gets read at the offset
/// our headers claimed rather than the one the loaded library used. Refusing
/// to load is the only safe response in a library whose job is deciding
/// whether a signature can be trusted.
pub fn abi_compatible() -> bool {
    check_version_mode(sys::xmlSecCheckVersionMode_xmlSecCheckVersionABICompatible)
}

fn check_version_mode(mode: sys::xmlSecCheckVersionMode) -> bool {
    // SAFETY: takes only plain integers — no pointers, no preconditions
    // beyond the xmlsec headers/library being loaded.
    unsafe {
        sys::xmlSecCheckVersionExt(
            sys::XMLSEC_VERSION_MAJOR as i32,
            sys::XMLSEC_VERSION_MINOR as i32,
            sys::XMLSEC_VERSION_SUBMINOR as i32,
            mode,
        ) == 1
    }
}


#[cfg(test)]
mod tests {
    use super::ffi_len;
    use std::os::raw::c_int;

    #[test]
    fn ffi_len_rejects_lengths_that_would_wrap() {
        assert_eq!(ffi_len::<c_int>(0), Some(0));
        assert_eq!(ffi_len::<c_int>(c_int::MAX as usize), Some(c_int::MAX));
        assert_eq!(ffi_len::<c_int>(c_int::MAX as usize + 1), None);
        assert_eq!(ffi_len::<u32>(u32::MAX as usize + 1), None);
        assert_eq!(ffi_len::<c_int>(usize::MAX), None);
    }
}
