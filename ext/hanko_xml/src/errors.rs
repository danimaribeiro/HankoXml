//! Error callback capture for libxmlsec1.
//!
//! libxmlsec1's default error handler prints to stderr, which is
//! unacceptable in a library. This module installs a custom callback
//! via `xmlSecErrorsSetCallback` that captures error messages into a
//! thread-local buffer. Each native call should bracket with
//! [`clear_errors`] / [`drain_errors`] to collect diagnostics.
//!
//! Thread-safety: the GVL is held for the entire duration of every
//! native call (§7.1), so a thread-local `RefCell<Vec<String>>` is
//! sufficient — no `Mutex` needed.

use std::cell::{Cell, RefCell};
use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_void};

thread_local! {
    static ERROR_BUF: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    /// How many error-level libxml2 diagnostics the structured handler has
    /// seen on this thread. Callers compare it before and after a parse.
    static LIBXML2_ERRORS: Cell<usize> = const { Cell::new(0) };
}

/// Clears the thread-local error buffer. Call at the start of each
/// native entry point.
pub fn clear_errors() {
    ERROR_BUF.with(|buf| buf.borrow_mut().clear());
}

/// Drains and returns all captured error messages since the last
/// [`clear_errors`]. Call at the end of each native entry point.
pub fn drain_errors() -> Vec<String> {
    ERROR_BUF.with(|buf| {
        let mut b = buf.borrow_mut();
        let drained = b.clone();
        b.clear();
        drained
    })
}

/// The `extern "C"` callback installed via `xmlSecErrorsSetCallback`.
///
/// Signature matches `xmlSecErrorsCallback`:
/// ```c
/// typedef void (*xmlSecErrorsCallback)(
///     const char* file, int line, const char* func,
///     const char* errorObject, const char* errorSubject,
///     int reason, const char* msg);
/// ```
///
/// # Safety
///
/// Called by libxmlsec1 internally. All pointer arguments are either
/// valid C strings or null. We treat null as empty and never retain
/// any pointer past this function's return.
unsafe extern "C" fn error_callback(
    file: *const c_char,
    line: c_int,
    func: *const c_char,
    error_object: *const c_char,
    error_subject: *const c_char,
    reason: c_int,
    msg: *const c_char,
) {
    let safe_str = |ptr: *const c_char| -> &str {
        if ptr.is_null() {
            ""
        } else {
            // SAFETY: libxmlsec1 passes NUL-terminated C strings or null.
            unsafe { CStr::from_ptr(ptr) }.to_str().unwrap_or("")
        }
    };

    let file_s = safe_str(file);
    let func_s = safe_str(func);
    let obj_s = safe_str(error_object);
    let subj_s = safe_str(error_subject);
    let msg_s = safe_str(msg).trim_end();

    let entry = format!(
        "func={func_s}:file={file_s}:line={line}:obj={obj_s}:subj={subj_s}:error={reason}:{msg_s}"
    );

    ERROR_BUF.with(|buf| {
        buf.borrow_mut().push(entry);
    });
}

/// Installs our error callback. Must be called once during
/// `init_xmlsec()`, after `xmlSecInit()`.
///
/// # Safety
///
/// `xmlSecErrorsSetCallback` is safe to call after `xmlSecInit()`.
pub unsafe fn install_error_callback() {
    unsafe {
        crate::sys::xmlSecErrorsSetCallback(Some(error_callback));
    }
}

/// libxml2's structured error handler, installed around each native parse
/// and schema validation by `dsig::Libxml2Capture`. Keeps libxml2's
/// diagnostics off stderr and in the same buffer as xmlsec's, so they reach
/// `#xmlsec_errors` and never `#message`: they can quote the document.
///
/// Only error and fatal levels are kept. Warnings are dropped, matching
/// what a strict Nokogiri parse rejects (§6.3).
///
/// # Safety
///
/// Called by libxml2 with a valid `xmlError` or null, and never retained.
/// Declared with `*const` (libxml2 2.12+); 2.9 passes the same pointer as
/// `*mut`, which has the same ABI.
unsafe extern "C" fn libxml2_error_callback(_ctx: *mut c_void, error: *const crate::sys::xmlError) {
    if error.is_null() {
        return;
    }
    // SAFETY: libxml2 passes a valid xmlError for the duration of the call.
    let err = unsafe { &*error };
    if (err.level as i64) < (crate::sys::xmlErrorLevel_XML_ERR_ERROR as i64) {
        return;
    }
    let message = if err.message.is_null() {
        ""
    } else {
        // SAFETY: a non-null message is a NUL-terminated C string.
        unsafe { CStr::from_ptr(err.message) }.to_str().unwrap_or("")
    };
    let entry = format!("{}:{}: ERROR: {}", err.line, err.int2, message.trim_end());

    LIBXML2_ERRORS.with(|count| count.set(count.get() + 1));
    ERROR_BUF.with(|buf| buf.borrow_mut().push(entry));
}

/// The handler above, typed as libxml2's `xmlStructuredErrorFunc`, whose
/// pointer argument is `*mut` before libxml2 2.12 and `*const` after.
pub fn libxml2_error_handler() -> crate::sys::xmlStructuredErrorFunc {
    let handler: unsafe extern "C" fn(*mut c_void, *const crate::sys::xmlError) = libxml2_error_callback;
    // SAFETY: both spellings of the callback type have the same ABI; only
    // the constness of the xmlError pointer differs between libxml2 versions.
    unsafe { std::mem::transmute(Some(handler)) }
}

/// Error-level libxml2 diagnostics seen on this thread so far.
pub fn libxml2_error_count() -> usize {
    LIBXML2_ERRORS.with(Cell::get)
}
