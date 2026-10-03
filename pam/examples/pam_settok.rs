//! A PAM module for the tests only: sets the items pam_unix would set
//! (applications may not), from its options `authtok=`, `old=` and `new=`.

use std::ffi::{CStr, CString, c_char, c_int, c_void};

#[repr(C)]
pub struct PamHandle {
    _private: [u8; 0],
}

const PAM_SUCCESS: c_int = 0;
const PAM_AUTHTOK: c_int = 6;
const PAM_OLDAUTHTOK: c_int = 7;

unsafe extern "C" {
    fn pam_set_item(pamh: *mut PamHandle, item_type: c_int, item: *const c_void) -> c_int;
}

fn option(argc: c_int, argv: *const *const c_char, name: &str) -> Option<CString> {
    (0..argc as usize).find_map(|i| {
        // SAFETY: PAM passes `argc` valid strings.
        let arg = unsafe { CStr::from_ptr(*argv.add(i)) }.to_str().ok()?;
        CString::new(arg.strip_prefix(name)?.strip_prefix('=')?).ok()
    })
}

fn set(pamh: *mut PamHandle, which: c_int, value: Option<CString>) {
    if let Some(v) = value {
        // SAFETY: PAM copies the string.
        unsafe { pam_set_item(pamh, which, v.as_ptr().cast()) };
    }
}

/// # Safety
///
/// Called by libpam.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut PamHandle,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    set(pamh, PAM_AUTHTOK, option(argc, argv, "authtok"));
    PAM_SUCCESS
}

/// # Safety
///
/// Called by libpam.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_setcred(_: *mut PamHandle, _: c_int, _: c_int, _: *const *const c_char) -> c_int {
    PAM_SUCCESS
}

/// # Safety
///
/// Called by libpam.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_chauthtok(
    pamh: *mut PamHandle,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    set(pamh, PAM_OLDAUTHTOK, option(argc, argv, "old"));
    set(pamh, PAM_AUTHTOK, option(argc, argv, "new"));
    PAM_SUCCESS
}
