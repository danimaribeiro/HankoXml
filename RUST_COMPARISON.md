# Rust Implementation Comparison

Original: `nokogiri-xmlsec-danimar/ext/xmlsec_danimar_rust/src/lib.rs` (single file, ~440 lines)
New: `hanko_xml/ext/hanko_xml/src/{sys.rs, dsig.rs, lib.rs}` + `build.rs` (~460 lines total)

---

## 1. File Structure

| Original | New |
|----------|-----|
| Single `lib.rs` with everything: FFI decls, RAII types, Ruby glue | Three files: `sys.rs` (bindgen include), `dsig.rs` (safe wrappers + RAII), `lib.rs` (Ruby entry points) |

The original is easier to navigate — you see the whole picture in one file. The new version separates concerns more formally but forces you to jump between files for context. For a lib this size (~400 lines), the single-file approach is arguably better.

---

## 2. FFI Bindings: Hand-written vs Bindgen

**Original** — hand-written `extern "C"` block with explicit type signatures:
```rust
extern "C" {
    fn xmlReadMemory(buf: *const c_char, size: c_int, ...) -> *mut c_void;
    fn xmlSecFindNode(parent: *const XmlNode, ...) -> *mut XmlNode;
    fn xmlSecOpenSSLAppKeyLoadMemory(data: *const c_uchar, ...) -> *mut c_void;
    // ~20 declarations total
}
```

**New** — auto-generated via bindgen:
```rust
// sys.rs
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
```

### Trade-offs

| | Hand-written | Bindgen |
|---|---|---|
| **Build time** | Fast (no bindgen step) | Slower (runs clang parser at build time) |
| **Build deps** | None beyond magnus | Needs `bindgen` + `pkg-config` crates + clang headers |
| **Portability** | Must manually match each platform's types | Auto-adapts to the installed library version |
| **Correctness** | You pick the types — easy to get `usize` vs `c_uint` wrong for `xmlSecSize` | Bindgen gets them right from the actual headers |
| **Readability** | You see exactly what you're calling | Generated file is thousands of lines of noise; real API hidden behind verbose enum names like `sys::xmlSecKeyDataFormat_xmlSecKeyDataFormatPem` |
| **ABI safety** | You declare what you need, the rest is `*mut c_void` | Full struct layouts generated — but you're also exposing internals you might not want |

The original uses `*mut c_void` for opaque types (doc, ctx, key), which is correct — those are opaque to us. Bindgen generates full struct definitions for them, which gives field access (good for `DsigCtx.status`) but also couples you to exact struct layouts across library versions.

The original's `XmlNode` struct is hand-written with just the fields it needs (`children`, `next`, `name`, `_type`). This is sufficient and clear.

**The original's `dsig_offset.rs` approach** (generated at build time by a small C program) to get `DsigCtx.signKey` and `DsigCtx.status` field offsets was a pragmatic middle ground: you generate only the two offsets you need, not the entire binding surface.

---

## 3. RAII Types

### XmlDoc / OwnedXmlDoc

**Original** — an enum that handles both cases:
```rust
enum XmlDoc {
    Owned(*mut c_void),    // we parsed it, we free it
    Borrowed(*mut c_void), // Nokogiri owns it
}

impl Drop for XmlDoc {
    fn drop(&mut self) {
        if let XmlDoc::Owned(ptr) = self { xmlFreeDoc(*ptr) }
    }
}
```

**New** — two separate types with lifetime tracking:
```rust
struct XmlDoc<'a> {
    ptr: sys::xmlDocPtr,
    _marker: PhantomData<&'a ()>,
}

struct OwnedXmlDoc(sys::xmlDocPtr);
impl Drop for OwnedXmlDoc { ... }
```

The original's enum is simpler and self-documenting: you see `Owned` vs `Borrowed` right in the code. The new version's lifetime-parameterized `XmlDoc<'a>` is more "Rust-correct" (the borrow checker can enforce that borrows don't outlive the doc), but adds complexity with `PhantomData` and a separate `as_doc()` method. For this use case where docs are always short-lived within a single function call, the enum approach works fine.

### XmlSecKey

**Original** — `Option` wrapper with ownership transfer:
```rust
struct XmlSecKey(Option<*mut c_void>);

impl XmlSecKey {
    fn into_raw(mut self) -> *mut c_void {
        self.0.take().unwrap()  // takes ownership, Drop becomes a no-op
    }
}
```

**New** — no equivalent. Key management is hidden inside `KeysMngr`:
```rust
struct KeysMngr(sys::xmlSecKeysMngrPtr);
```

The original's `into_raw()` pattern is elegant — it transfers key ownership to the DsigCtx without double-free, by nulling the Option before Drop runs. The new version doesn't need this because it uses a `KeysMngr` (keys manager) that owns the key internally via `xmlSecOpenSSLAppDefaultKeysMngrInit` + `xmlSecOpenSSLAppKeysMngrCertLoadMemory`.

### DsigCtx

**Original** — raw pointer with byte-offset field access:
```rust
struct DsigCtx(*mut c_void);

fn set_key(&mut self, key: XmlSecKey) {
    let raw = key.into_raw();
    let slot = (self.0 as *mut u8).add(DSIG_CTX_SIGN_KEY_OFFSET) as *mut *mut c_void;
    *slot = raw;
}

fn verify(&self, sig_node: *mut XmlNode) -> bool {
    let status = *((self.0 as *const u8).add(DSIG_CTX_STATUS_OFFSET) as *const c_int);
    ret == 0 && status == DSIG_STATUS_SUCCEEDED
}
```

**New** — lifetime-parameterized to the keys manager, uses bindgen struct for field access:
```rust
struct DsigCtx<'mngr> {
    ptr: sys::xmlSecDSigCtxPtr,
    _mngr: PhantomData<&'mngr KeysMngr>,
}

fn verify(&mut self, node: XmlNode<'_>) -> bool {
    let status = unsafe { (*self.ptr).status };
    status == sys::xmlSecDSigStatus_xmlSecDSigStatusSucceeded
}
```

The new version's `DsigCtx<'mngr>` with `PhantomData<&'mngr KeysMngr>` ensures the borrow checker drops the context before the manager — correct and compile-time enforced. However, the original's approach works too because in practice the ctx is always destroyed before the key in the same function scope.

The byte-offset approach in the original (`DSIG_CTX_SIGN_KEY_OFFSET`) is less pretty but avoids coupling to the full struct layout. The new version accesses `(*self.ptr).status` directly through the bindgen-generated struct, which is cleaner to read but only works because bindgen generated the full `xmlSecDSigCtx` struct.

---

## 4. XmlNode

**Original** — hand-written, used for tree walking:
```rust
#[repr(C)]
struct XmlNode {
    _private: *mut c_void,
    _type: c_int,
    name: *const c_char,
    children: *mut XmlNode,
    _last: *mut XmlNode,
    _parent: *mut XmlNode,
    next: *mut XmlNode,
}
```

**New** — lifetime-parameterized borrowing view:
```rust
struct XmlNode<'a> {
    ptr: sys::xmlNodePtr,
    _marker: PhantomData<&'a ()>,
}
```

The original needs the struct fields because it does a manual recursive tree walk for ID registration (`walk_register_ids`). The new version doesn't need them because it uses `xmlSecAddIDs()` instead (see point 5).

---

## 5. ID Registration

**Original** — manual recursive tree walk:
```rust
unsafe fn walk_register_ids(doc: *mut c_void, node: *mut XmlNode, attr_name: &[u8]) {
    let attr = xmlHasProp(node, attr_name.as_ptr());
    if !attr.is_null() {
        let value = xmlNodeListGetString(doc, children, 1);
        if xmlGetID(doc, value).is_null() {
            xmlAddID(std::ptr::null_mut(), doc, value, attr);
        }
        free(value as *mut c_void);
    }
    // recurse into children...
}
```

**New** — delegates to libxmlsec1's own function:
```rust
fn register_common_id_attributes(&self, root: XmlNode<'a>) {
    const NAMES: [&[u8]; 3] = [b"ID\0", b"Id\0", b"id\0"];
    let mut ids = [NAMES[0].as_ptr().cast(), NAMES[1].as_ptr().cast(), ...];
    unsafe { sys::xmlSecAddIDs(self.ptr, root.ptr, ids.as_mut_ptr()) }
}
```

The new version is better here. `xmlSecAddIDs` does the same recursive walk internally but:
- Handles all three common ID names (`ID`, `Id`, `id`) in one call
- Less code to maintain
- Less surface area for bugs

The original's `walk_register_ids` duplicates what `xmlSecAddIDs` already does, and only handles one attr name per call (though it gets called with `b"ID\0"` which covers the main case).

---

## 6. Verification Architecture

**Original** — direct key loading, no keys manager:
```rust
fn validate_inner(doc: &XmlDoc, cert_bytes: &[u8], id_attr: Option<&str>) -> bool {
    let key = XmlSecKey::from_cert_der(cert_bytes)?;
    let mut ctx = DsigCtx::new()?;
    ctx.set_key(key);    // transfers key ownership via into_raw()
    ctx.verify(sig)
}
```

**New** — uses a KeysMngr (keys manager) like xmlsec's own verify2.c:
```rust
pub fn verify_signature(doc: XmlDoc<'_>, cert_pem: &[u8]) -> Result<bool, &'static str> {
    let mngr = KeysMngr::trusting(cert_pem)?;
    let mut ctx = DsigCtx::new(&mngr)?;
    Ok(ctx.verify(sig_node))
}
```

Both work. The keys manager approach is what xmlsec's official examples use and is more correct for complex scenarios (multiple trusted certs, CRL checking). The original's direct key assignment is simpler and sufficient for the single-cert-verification use case.

However, **the new version takes PEM cert bytes** while the **original takes DER cert bytes** (`cert.to_der` in Ruby, `KEY_DATA_FORMAT_CERT_DER` in Rust). The Ruby wrapper in the new version calls `certificate.to_pem.b`, while the original calls `cert.to_der`. Both formats work with `xmlSecOpenSSLAppKeyLoadMemory`/`xmlSecOpenSSLAppKeysMngrCertLoadMemory` as long as the format constant matches.

---

## 7. Error Handling

**Original** — returns `bool` or `Option`, uses generic `RuntimeError`:
```rust
fn validate_inner(...) -> bool { ... }

// Ruby entry point:
Err(Error::new(ruby.exception_runtime_error(), "failed to parse XML"))
```

**New** — returns `Result<bool, &'static str>`, uses custom exception class:
```rust
pub fn verify_signature(...) -> Result<bool, &'static str> { ... }

// Ruby entry point:
fn xmlsec_error(ruby: &Ruby, message: impl Into<String>) -> Error {
    Error::new(xmlsec_error_class(ruby), message.into())
}
// where xmlsec_error_class resolves to HankoXml::Error
```

The new version is better here. A custom `HankoXml::Error < StandardError` lets callers rescue specifically. And using `Result<bool, &str>` instead of bare `bool` distinguishes "signature is invalid" (Ok(false)) from "couldn't even attempt verification" (Err("no Signature element")).

The original conflates both cases into `false`, which means "failed to parse XML" and "signature didn't verify" look the same to the caller.

---

## 8. Initialization

**Original** — `static mut` boolean (unsound):
```rust
static mut INITIALIZED: bool = false;

fn ensure_init() -> Result<(), &'static str> {
    unsafe {
        if INITIALIZED { return Ok(()); }
        // ... init calls ...
        INITIALIZED = true;
    }
    Ok(())
}
```

**New** — `std::sync::Once` (sound, thread-safe):
```rust
static INIT: Once = Once::new();

fn ensure_initialized() -> Result<(), &'static str> {
    let mut result = Ok(());
    INIT.call_once(|| result = dsig::init_xmlsec());
    result
}
```

The new version is strictly better. `static mut` is unsound under concurrent access and is being deprecated in future Rust editions. `Once` is the idiomatic, thread-safe solution.

---

## 9. Build System (`build.rs`)

**Original** — uses `rb_sys` + `rake-compiler`, no special build.rs for the Rust crate (relies on the offset-generating C program and the workspace Cargo.toml).

**New** — sophisticated `build.rs` with:
- `add_homebrew_pkgconfig_paths()`: auto-discovers keg-only Homebrew formulas
- `link_homebrew_libxml2_by_absolute_path()`: links libxml2 by absolute dylib path to avoid the rustc `-l`-before-`-L` ordering bug that silently picks up macOS's system libxml2 instead of Homebrew's
- Bindgen header generation with explicit `-I` paths prioritizing Homebrew's libxml2

The new build.rs is significantly more robust. The original doesn't handle the libxml2 ABI mismatch problem at the Rust build level (we discovered and fixed this issue manually during the original project).

---

## 10. Ruby Wrapper

**Original** (`lib/xmlsec_danimar_rust.rb`):
```ruby
def self.validate(xml_source, cert, id_attr: nil)
  case xml_source
  when Nokogiri::XML::Document
    validate_doc(xml_source, cert, id_attr)
  when ->(s) { s.respond_to?(:read) }
    validate_raw(xml_source.read, cert, id_attr)
  when String
    validate_raw(xml_source, cert, id_attr)
  end
end
```

**New** (`lib/hanko_xml.rb`):
```ruby
def self.validate(xml, certificate)
  cert = cert_pem_bytes(certificate)
  if nokogiri_document?(xml)
    Native.validate_doc_pointer(xml.pointer_id, cert)
  else
    Native.validate_bytes(xml_bytes(xml), cert)
  end
end
```

The new version's Ruby wrapper is more polished:
- Accepts `Pathname`/`to_path` objects (reads from disk) instead of only IO/String
- Has `cert_pem_bytes()` that handles cert coercion (OpenSSL object, PEM string, or path)
- Uses `xml.b` for binary encoding
- Better error messages in `ArgumentError`
- Uses `private` helper methods instead of inline logic

But the original supports `IO`/`StringIO` via `respond_to?(:read)`, which is useful for streaming. The new version dropped this in favor of `to_path`, which only works for file-backed objects.

---

## 11. Sign Support

**Original** — fully implemented:
```rust
fn sign_inner(doc: &XmlDoc, pem_bytes: &[u8]) -> Option<String> {
    doc.register_id_attrs(b"ID\0");
    let sig = doc.find_signature()?;
    let key = XmlSecKey::from_pem(pem_bytes)?;
    let mut ctx = DsigCtx::new()?;
    ctx.set_key(key);
    if !ctx.sign(sig) { return None; }
    doc.dump_to_string()
}
```

**New** — not implemented yet. Only has `validate`.

---

## 12. Safety Comments

**Original** — no `// SAFETY:` comments on `unsafe` blocks.

**New** — every `unsafe` block has a `// SAFETY:` comment explaining the invariant:
```rust
// SAFETY: self.ptr is valid for 'a by construction (see from_raw).
let root = unsafe { sys::xmlDocGetRootElement(self.ptr) };
```

The new version follows Rust's recommended practice for documenting unsafe code. This is genuinely useful for reviewers and future maintainers.

---

## 13. Nokogiri Pointer Access

**Original** — calls `pointer_id` from Rust via `funcall`:
```rust
let doc_addr: u64 = noko_doc.funcall("pointer_id", ())?;
let doc = XmlDoc::from_ptr(doc_addr).ok_or(...)?;
```

**New** — receives the pointer as a `usize` parameter, Ruby wrapper calls `pointer_id`:
```rust
fn validate_doc_pointer(ruby: &Ruby, doc_pointer: usize, cert_pem: RString) -> Result<bool, Error> {
    let doc = unsafe { XmlDoc::from_raw(doc_pointer as sys::xmlDocPtr) }
```

The new version is better — it keeps the `funcall` in Ruby land (where it's a normal method call) rather than calling Ruby methods from Rust. The Rust function receives a plain `usize`, which is simpler and doesn't require `Value` conversion.

---

## Summary: What the New Version Does Better

1. **`std::sync::Once`** instead of `static mut` for initialization
2. **`xmlSecAddIDs`** instead of manual tree walk for ID registration
3. **`Result<bool, &str>`** instead of bare `bool` — distinguishes "invalid" from "error"
4. **Custom exception class** (`HankoXml::Error`) instead of `RuntimeError`
5. **`// SAFETY:` comments** on every unsafe block
6. **`build.rs`** handles libxml2 ABI mismatch and Homebrew keg-only discovery automatically
7. **Lifetime-parameterized** `DsigCtx<'mngr>` enforces drop ordering at compile time
8. **Nokogiri pointer** passed as `usize` from Ruby instead of `funcall` from Rust
9. **Ruby wrapper** accepts `Pathname`/`to_path` and handles cert coercion cleanly

## What the Original Does Better

1. **Single file** — everything in one place, easy to follow top-to-bottom
2. **Hand-written FFI** — minimal, readable, fast builds, no bindgen dependency
3. **`XmlDoc` enum** (`Owned`/`Borrowed`) — self-documenting, simpler than two separate types
4. **`XmlSecKey` with `into_raw()`** — elegant ownership transfer pattern
5. **Sign is implemented** — complete `sign_inner` + `sign_raw` + `dump_to_string`
6. **IO/StringIO support** in Ruby wrapper via `respond_to?(:read)`
7. **`xmlsec_info` diagnostic** method on `Nokogiri::XML::Document`
8. **Less ceremony** — no PhantomData, no lifetime parameters, just works
