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

use std::cell::RefCell;
use std::ffi::CStr;
use std::os::raw::{c_char, c_int};

thread_local! {
    static ERROR_BUF: RefCell<Vec<String>> = RefCell::new(Vec::new());
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
