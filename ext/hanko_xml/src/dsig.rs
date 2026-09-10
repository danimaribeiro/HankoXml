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

impl OwnedXmlDoc {
    /// Parses `xml` bytes into a libxml2 document.
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
        if child_ref.type_ == sys::xmlElementType_XML_ELEMENT_NODE {
            if node_name(child) == name && node_ns_href(child) == ns_href {
                return Some(child);
            }
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
        if child_ref.type_ == sys::xmlElementType_XML_ELEMENT_NODE {
            if node_name(child) == name && node_ns_href(child) == ns_href {
                result.push(child);
            }
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
        // SAFETY: pem is a valid slice; xmlSecOpenSSLAppKeyLoadMemory
        // copies what it needs. xmlsec tries a private key first, then a
        // SubjectPublicKeyInfo / RSA public key — the `key:` verify path
        // depends on that fallback.
        let ptr = unsafe {
            sys::xmlSecOpenSSLAppKeyLoadMemory(
                pem.as_ptr(),
                pem.len() as _,
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

    /// Attaches a PEM certificate to this key (for KeyInfo population).
    pub fn add_cert_pem(&self, cert_pem: &[u8]) -> Result<(), &'static str> {
        // SAFETY: self.0 is valid; cert_pem is a valid slice.
        let rc = unsafe {
            sys::xmlSecOpenSSLAppKeyCertLoadMemory(
                self.0,
                cert_pem.as_ptr(),
                cert_pem.len() as _,
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
            // SAFETY: mngr.0 is valid and initialized; cert_pem is a valid slice.
            let loaded = unsafe {
                sys::xmlSecOpenSSLAppKeysMngrCertLoadMemory(
                    mngr.0,
                    cert_pem.as_ptr(),
                    cert_pem.len() as _,
                    sys::xmlSecKeyDataFormat_xmlSecKeyDataFormatPem,
                    sys::xmlSecKeyDataTypeTrusted,
                )
            };
            if loaded < 0 {
                return Err("failed to load trusted certificate");
            }
        }

        for cert_pem in untrusted_pems {
            // SAFETY: same as above, but with type 0 (not trusted — intermediate).
            let loaded = unsafe {
                sys::xmlSecOpenSSLAppKeysMngrCertLoadMemory(
                    mngr.0,
                    cert_pem.as_ptr(),
                    cert_pem.len() as _,
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

    /// Creates a signature context for signing with a specific key.
    fn for_signing(mngr: &'mngr KeysMngr, key: XmlSecKey) -> Result<Self, &'static str> {
        // SAFETY: mngr.0 is a valid initialized keys manager.
        let ptr = unsafe { sys::xmlSecDSigCtxCreate(mngr.0) };
        if ptr.is_null() {
            return Err("failed to create xmlsec signature context");
        }
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
            (*ptr).signKey = key.into_raw();
        }
        Ok(Self {
            ptr,
            _mngr: std::marker::PhantomData,
        })
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
    /// node xmlsec's ID table resolved (same table `#id` verification used),
    /// or `None` when the URI is empty (root), unresolved, or non-fragment.
    /// Empty URI references always report the root element's index.
    pub reference_element_indexes: Vec<Option<usize>>,
}

const DSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";

/// Inspects the nth `<ds:Signature>` without performing any cryptography.
/// Returns metadata about the signature for policy enforcement.
///
/// No `unsafe` in this function body — every FFI call is behind a helper.
pub fn inspect_document(
    xml: &[u8],
    signature_index: usize,
) -> Result<InspectResult, &'static str> {
    let doc = OwnedXmlDoc::parse(xml).ok_or("failed to parse XML document")?;
    let root = doc.root_element().ok_or("XML document has no root element")?;

    let sig_count = doc.count_signatures(root);
    let sig_node = doc
        .find_nth_signature(root, signature_index)
        .ok_or("signature index out of range")?;

    // Extract <SignedInfo>
    let signed_info = unsafe { find_child(sig_node, "SignedInfo", DSIG_NS) }
        .ok_or("no <SignedInfo> element in <Signature>")?;

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

    // KeyInfo — KeyName and X509Certificate
    let mut key_names = Vec::new();
    let mut certificates = Vec::new();
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
    }

    Ok(InspectResult {
        signature_method: sig_method,
        canonicalization_method: c14n_method,
        signature_count: sig_count,
        key_names,
        certificates,
        references,
    })
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
) -> Result<Vec<u8>, String> {
    errors::clear_errors();

    let doc = OwnedXmlDoc::parse(xml)
        .ok_or_else(|| format_error("failed to parse XML document"))?;
    let root = doc
        .root_element()
        .ok_or_else(|| format_error("XML document has no root element"))?;

    doc.register_id_attributes(root, id_attrs);

    let sig_node = doc
        .find_nth_signature(root, signature_index)
        .ok_or_else(|| format_error("signature index out of range or no <Signature> found"))?;

    let key = XmlSecKey::from_pem(key_pem)
        .map_err(|msg| format_error(msg))?;

    for cert_pem in cert_pems {
        key.add_cert_pem(cert_pem)
            .map_err(|msg| format_error(msg))?;
    }

    let mngr = KeysMngr::new(&[], &[])
        .map_err(|msg| format_error(msg))?;

    let mut ctx = DsigCtx::for_signing(&mngr, key)
        .map_err(|msg| format_error(msg))?;

    ctx.sign(sig_node)
        .map_err(|msg| format_error(msg))?;

    doc.serialize()
        .map_err(|msg| format_error(msg))
}

/// Verifies the nth `<ds:Signature>` against trusted/untrusted certs.
///
/// `trusted_pems` may contain certificate PEMs, key PEMs, or both.
/// Certificates are loaded as trust anchors. A key PEM is pinned on the
/// dsig context as `signKey`, which makes xmlsec skip KeyInfo lookup —
/// the `key:` contract (bare public key, KeyInfo ignored).
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
) -> Result<VerifyResult, String> {
    errors::clear_errors();

    let doc = OwnedXmlDoc::parse(xml)
        .ok_or_else(|| format_error("failed to parse XML document"))?;
    let root = doc
        .root_element()
        .ok_or_else(|| format_error("XML document has no root element"))?;

    doc.register_id_attributes(root, id_attrs);

    let sig_node = doc
        .find_nth_signature(root, signature_index)
        .ok_or_else(|| format_error("no <Signature> element found in document"))?;

    let trusted_certs: Vec<Vec<u8>> = trusted_pems
        .iter()
        .filter(|pem| pem_is_certificate(pem))
        .cloned()
        .collect();

    let mut pinned_key = None;
    for pem in trusted_pems {
        if pem_is_certificate(pem) {
            continue;
        }
        if pinned_key.is_some() {
            return Err("at most one trusted key PEM is supported".into());
        }
        pinned_key = Some(XmlSecKey::from_pem(pem).map_err(|msg| format_error(msg))?);
    }

    let mngr = KeysMngr::new(&trusted_certs, untrusted_pems)
        .map_err(|msg| format_error(msg))?;

    // Pinning signKey is the same field write used for signing. For verify,
    // xmlsec uses a pre-set signKey instead of reading KeyInfo — that is
    // what lets `key:` ignore the document's certificates entirely.
    let mut ctx = if let Some(key) = pinned_key {
        DsigCtx::for_signing(&mngr, key).map_err(|msg| format_error(msg))?
    } else {
        DsigCtx::new(&mngr).map_err(|msg| format_error(msg))?
    };

    let status = ctx.verify(sig_node);
    let captured_errors = errors::drain_errors();
    let reference_element_indexes =
        collect_reference_element_indexes(&doc, root, sig_node);

    Ok(VerifyResult {
        status,
        errors: captured_errors,
        reference_element_indexes,
    })
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
    }
    Ok(())
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

/// Formats an error message including any captured xmlsec errors.
fn format_error(base_msg: &str) -> String {
    let captured = errors::drain_errors();
    if captured.is_empty() {
        base_msg.to_string()
    } else {
        format!("{base_msg}\nxmlsec errors:\n{}", captured.join("\n"))
    }
}
