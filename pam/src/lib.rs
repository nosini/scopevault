//! `pam_scopevault.so`: hands the login password to scopevault
//! (docs/LOGIN-UNLOCK.md).
//!
//! This code runs as root inside GDM's session worker and `passwd`, so it
//! does as little as possible. It never compares or stores the password and
//! never connects to a socket. It passes the password to
//! `scopevault-pam-helper`, started as the user, which delivers it to the
//! daemon:
//!
//! | Phase | What happens |
//! | --- | --- |
//! | `auth` | The password is stashed for `open_session`, and the helper runs with `--if-running` (a screen unlock: the daemon is up) |
//! | `open_session` | The stashed password goes to the helper with `--wait` (a login: the daemon starts after PAM) |
//! | `chauthtok` | In the update phase, the old and the new password go to the helper with `--change` |
//!
//! Every entry point returns `PAM_IGNORE`, whatever happens: the module
//! must never decide or break a login. Panics are caught.
//!
//! Option: `helper=/absolute/path`. The default is
//! `/usr/local/libexec/scopevault-pam-helper`, or the path in
//! `SCOPEVAULT_PAM_HELPER` when the module was built (packages set it). The
//! helper must be a file the user cannot replace: it starts as root's
//! child.

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};

use zeroize::Zeroizing;

pub mod ffi {
    //! The parts of the Linux-PAM module interface this module uses.
    use std::ffi::{c_char, c_int, c_void};

    #[repr(C)]
    pub struct PamHandle {
        _private: [u8; 0],
    }

    pub const PAM_SUCCESS: c_int = 0;
    pub const PAM_NO_MODULE_DATA: c_int = 18;
    pub const PAM_IGNORE: c_int = 25;
    pub const PAM_USER: c_int = 2;
    pub const PAM_AUTHTOK: c_int = 6;
    pub const PAM_OLDAUTHTOK: c_int = 7;
    pub const PAM_UPDATE_AUTHTOK: c_int = 0x2000;

    pub type Cleanup = unsafe extern "C" fn(*mut PamHandle, *mut c_void, c_int);

    unsafe extern "C" {
        pub fn pam_get_item(pamh: *const PamHandle, item_type: c_int, item: *mut *const c_void) -> c_int;
        pub fn pam_set_item(pamh: *mut PamHandle, item_type: c_int, item: *const c_void) -> c_int;
        pub fn pam_set_data(
            pamh: *mut PamHandle,
            name: *const c_char,
            data: *mut c_void,
            cleanup: Option<Cleanup>,
        ) -> c_int;
        pub fn pam_get_data(pamh: *const PamHandle, name: *const c_char, data: *mut *const c_void) -> c_int;
        pub fn pam_getenv(pamh: *mut PamHandle, name: *const c_char) -> *const c_char;
        pub fn pam_syslog(pamh: *const PamHandle, priority: c_int, fmt: *const c_char, ...);
    }
}

use ffi::PamHandle;

const DEFAULT_HELPER: &str = match option_env!("SCOPEVAULT_PAM_HELPER") {
    Some(path) => path,
    None => "/usr/local/libexec/scopevault-pam-helper",
};
const _: () =
    assert!(!DEFAULT_HELPER.is_empty() && DEFAULT_HELPER.as_bytes()[0] == b'/', "the helper path must be absolute");
const STASH: &CStr = c"scopevault_authtok";

fn log(pamh: *mut PamHandle, priority: c_int, msg: &str) {
    let Ok(msg) = CString::new(msg) else { return };
    // SAFETY: `pamh` is the handle PAM passed in; the format takes exactly
    // one string argument.
    unsafe { ffi::pam_syslog(pamh, priority, c"%s".as_ptr(), msg.as_ptr()) };
}

/// Runs `f`, catching panics; always `PAM_IGNORE`.
fn guarded(pamh: *mut PamHandle, f: impl FnOnce()) -> c_int {
    if catch_unwind(AssertUnwindSafe(f)).is_err() {
        log(pamh, libc::LOG_ERR, "internal error; ignored");
    }
    ffi::PAM_IGNORE
}

/// The `helper=` option, or the default. `None` for a relative path.
fn helper_path(argc: c_int, argv: *const *const c_char) -> Option<CString> {
    let mut path = DEFAULT_HELPER.to_owned();
    for i in 0..usize::try_from(argc).unwrap_or(0) {
        // SAFETY: PAM passes `argc` valid NUL-terminated strings.
        let arg = unsafe { CStr::from_ptr(*argv.add(i)) };
        if let Some(p) = arg.to_str().ok().and_then(|a| a.strip_prefix("helper=")) {
            path = p.to_owned();
        }
    }
    if !path.starts_with('/') {
        return None;
    }
    CString::new(path).ok()
}

/// A PAM item that is a string (the user, a password), as bytes.
fn item(pamh: *mut PamHandle, which: c_int) -> Option<Zeroizing<Vec<u8>>> {
    let mut ptr: *const c_void = std::ptr::null();
    // SAFETY: `ptr` is a valid out-pointer; PAM keeps the item alive for the
    // duration of this call, and it is copied at once.
    let rc = unsafe { ffi::pam_get_item(pamh, which, &mut ptr) };
    if rc != ffi::PAM_SUCCESS || ptr.is_null() {
        return None;
    }
    // SAFETY: string items are NUL-terminated C strings.
    let bytes = unsafe { CStr::from_ptr(ptr.cast()) }.to_bytes();
    (!bytes.is_empty()).then(|| Zeroizing::new(bytes.to_vec()))
}

/// The target account, looked up before anything forks.
struct Account {
    uid: libc::uid_t,
    gid: libc::gid_t,
    home: CString,
    groups: Vec<libc::gid_t>,
}

fn account(pamh: *mut PamHandle) -> Option<Account> {
    let name = CString::new(item(pamh, ffi::PAM_USER)?.to_vec()).ok()?;
    let mut buf = vec![0u8; 16 * 1024];
    let mut pwd = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: all pointers refer to live memory of the given sizes.
    let rc =
        unsafe { libc::getpwnam_r(name.as_ptr(), pwd.as_mut_ptr(), buf.as_mut_ptr().cast(), buf.len(), &mut result) };
    if rc != 0 || result.is_null() {
        return None;
    }
    // SAFETY: filled in by a successful getpwnam_r; strings point into `buf`.
    let pwd = unsafe { pwd.assume_init() };
    let home = unsafe { CStr::from_ptr(pwd.pw_dir) }.to_owned();
    let mut groups = vec![0 as libc::gid_t; 256];
    let mut n: c_int = groups.len() as c_int;
    // SAFETY: `groups` holds `n` entries.
    let rc = unsafe { libc::getgrouplist(name.as_ptr(), pwd.pw_gid, groups.as_mut_ptr(), &mut n) };
    if rc < 0 {
        // More than 256 groups: retry with the size it reported.
        groups.resize(usize::try_from(n).ok()?, 0);
        // SAFETY: as above, with the larger buffer.
        if unsafe { libc::getgrouplist(name.as_ptr(), pwd.pw_gid, groups.as_mut_ptr(), &mut n) } < 0 {
            return None;
        }
    }
    groups.truncate(usize::try_from(n).ok()?);
    Some(Account { uid: pwd.pw_uid, gid: pwd.pw_gid, home, groups })
}

/// [`account`], logging when there is none.
fn known_account(pamh: *mut PamHandle) -> Option<Account> {
    let acct = account(pamh);
    if acct.is_none() {
        log(pamh, libc::LOG_NOTICE, "unknown user; password not passed on");
    }
    acct
}

/// Starts the helper as the user with `passwords` (each NUL-terminated) on
/// its stdin, and waits briefly for it: it reads its input and forks into
/// the background.
fn run_helper(pamh: *mut PamHandle, acct: &Account, helper: &CStr, mode: &CStr, passwords: &[&[u8]]) {
    if acct.uid == 0 {
        return;
    }
    // SAFETY: plain queries.
    let (ruid, euid) = unsafe { (libc::getuid(), libc::geteuid()) };
    // As root (GDM, passwd), drop to the user. Already running as the user
    // (a screen locker using PAM itself), no change is needed. Anything
    // else is not ours to handle.
    let drop_privileges = euid == 0;
    if !drop_privileges && (ruid != acct.uid || euid != acct.uid) {
        return;
    }

    // Everything the child needs is prepared here: after fork it may only
    // call async-signal-safe functions.
    let runtime = {
        // SAFETY: pam_getenv returns NULL or a string PAM owns.
        let v = unsafe { ffi::pam_getenv(pamh, c"XDG_RUNTIME_DIR".as_ptr()) };
        let from_pam = (!v.is_null()).then(|| unsafe { CStr::from_ptr(v) }.to_bytes().to_vec());
        from_pam.filter(|v| v.starts_with(b"/")).unwrap_or_else(|| format!("/run/user/{}", acct.uid).into_bytes())
    };
    let mut env_runtime = b"XDG_RUNTIME_DIR=".to_vec();
    env_runtime.extend_from_slice(&runtime);
    let mut env_home = b"HOME=".to_vec();
    env_home.extend_from_slice(acct.home.to_bytes());
    let (Ok(env_runtime), Ok(env_home)) = (CString::new(env_runtime), CString::new(env_home)) else { return };
    let argv = [helper.as_ptr(), mode.as_ptr(), std::ptr::null()];
    let envp = [env_runtime.as_ptr(), env_home.as_ptr(), std::ptr::null()];
    let input = helper_input(passwords);

    // A socket pair rather than a pipe: `send` with MSG_NOSIGNAL cannot
    // raise SIGPIPE in the host process if the helper exits early.
    let mut fds = [-1 as c_int; 2];
    // SAFETY: `fds` has room for two descriptors.
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0, fds.as_mut_ptr()) } != 0 {
        log(pamh, libc::LOG_ERR, "socketpair failed; password not passed on");
        return;
    }
    let [ours, theirs] = fds;
    let devnull = c"/dev/null";

    // SAFETY: the child branch only calls async-signal-safe functions on
    // memory prepared above, and ends in execve or _exit.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe { child(theirs, devnull.as_ptr(), drop_privileges, acct, helper.as_ptr(), argv.as_ptr(), envp.as_ptr()) }
    }
    // SAFETY: closing our copy of the child's end.
    unsafe { libc::close(theirs) };
    if pid < 0 {
        log(pamh, libc::LOG_ERR, "fork failed; password not passed on");
        unsafe { libc::close(ours) };
        return;
    }
    let mut sent = 0;
    while sent < input.len() {
        // SAFETY: sending from a live buffer.
        let n = unsafe { libc::send(ours, input[sent..].as_ptr().cast(), input.len() - sent, libc::MSG_NOSIGNAL) };
        if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        if n <= 0 {
            break;
        }
        sent += n as usize;
    }
    // SAFETY: our descriptor; closing it is the helper's end of input.
    unsafe { libc::close(ours) };
    if sent < input.len() {
        log(pamh, libc::LOG_NOTICE, "the helper did not take the password");
    }
    reap(pamh, pid);
}

/// The helper's input: each password followed by a NUL. Allocated in full
/// first: a buffer that grew would leave copies of the passwords behind in
/// the allocations it moved out of.
fn helper_input(passwords: &[&[u8]]) -> Zeroizing<Vec<u8>> {
    let mut input = Zeroizing::new(Vec::with_capacity(passwords.iter().map(|p| p.len() + 1).sum()));
    for p in passwords {
        input.extend_from_slice(p);
        input.push(0);
    }
    input
}

/// Waits up to 5 s for the helper's first process, which exits as soon as
/// it has read its input; one that takes longer is killed and reaped, so
/// no child is left behind in the host process. If the host process
/// ignores SIGCHLD, the kernel reaps it and `waitpid` reports ECHILD, which
/// is fine.
fn reap(pamh: *mut PamHandle, pid: libc::pid_t) {
    for _ in 0..500 {
        let mut status = 0;
        // SAFETY: waiting for our own child.
        let r = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if r == pid {
            if !(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0) {
                log(pamh, libc::LOG_NOTICE, "the helper failed (see its own log)");
            }
            return;
        }
        if r < 0 {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    log(pamh, libc::LOG_NOTICE, "the helper did not return within 5 s; stopped");
    // SAFETY: our own child, not yet reaped, so the PID is still its.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
        let mut status = 0;
        while libc::waitpid(pid, &mut status, 0) < 0
            && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
        {}
    }
}

/// The forked child. Async-signal-safe calls only; never returns.
///
/// # Safety
///
/// Must be called in a freshly forked child, with pointers prepared by the
/// parent before forking.
unsafe fn child(
    stdin: c_int,
    devnull: *const c_char,
    drop_privileges: bool,
    acct: &Account,
    path: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> ! {
    unsafe {
        let mut empty: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut empty);
        libc::sigprocmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut());
        if libc::dup2(stdin, 0) < 0 {
            libc::_exit(126);
        }
        let null = libc::open(devnull, libc::O_RDWR);
        if null < 0 || libc::dup2(null, 1) < 0 || libc::dup2(null, 2) < 0 {
            libc::_exit(126);
        }
        // Nothing else of the host process reaches the helper. Without
        // close_range (Linux 5.9, or refused by a syscall filter) there is
        // no async-signal-safe way to find every open descriptor, so the
        // helper is not started.
        if libc::syscall(libc::SYS_close_range, 3 as libc::c_uint, libc::c_uint::MAX, 0 as libc::c_uint) != 0 {
            libc::_exit(126);
        }
        if drop_privileges {
            if libc::setgroups(acct.groups.len(), acct.groups.as_ptr()) != 0
                || libc::setresgid(acct.gid, acct.gid, acct.gid) != 0
                || libc::setresuid(acct.uid, acct.uid, acct.uid) != 0
            {
                libc::_exit(126);
            }
            // The drop must be permanent.
            if libc::setuid(0) == 0 || libc::getuid() != acct.uid || libc::geteuid() != acct.uid {
                libc::_exit(126);
            }
        }
        libc::execve(path, argv, envp);
        libc::_exit(127);
    }
}

/// The password from `auth`, kept for `open_session`, with the account it
/// was given for: the application may change `PAM_USER` in between (sudo
/// does, to the target user), and the password must only ever reach the
/// account it belongs to.
struct Stash {
    uid: libc::uid_t,
    password: Zeroizing<Vec<u8>>,
}

impl Stash {
    /// The password, if `acct` is the account it was stashed for.
    fn password_for(&self, acct: &Account) -> Option<&[u8]> {
        (self.uid == acct.uid).then_some(&self.password[..])
    }
}

unsafe extern "C" fn drop_stash(_pamh: *mut PamHandle, data: *mut c_void, _status: c_int) {
    if !data.is_null() {
        // SAFETY: `data` came from Box::into_raw in `stash`; PAM calls this
        // once per stored value. Dropping zeroizes the password.
        drop(unsafe { Box::from_raw(data.cast::<Stash>()) });
    }
}

fn stash(pamh: *mut PamHandle, uid: libc::uid_t, password: &[u8]) {
    let data = Box::into_raw(Box::new(Stash { uid, password: Zeroizing::new(password.to_vec()) }));
    // SAFETY: PAM owns `data` from here and frees it through `drop_stash`.
    let rc = unsafe { ffi::pam_set_data(pamh, STASH.as_ptr(), data.cast(), Some(drop_stash)) };
    if rc != ffi::PAM_SUCCESS {
        // SAFETY: PAM did not take it.
        drop(unsafe { Box::from_raw(data) });
    }
}

fn take_stash(pamh: *mut PamHandle) -> Option<Stash> {
    let mut ptr: *const c_void = std::ptr::null();
    // SAFETY: a valid out-pointer.
    let rc = unsafe { ffi::pam_get_data(pamh, STASH.as_ptr(), &mut ptr) };
    if rc != ffi::PAM_SUCCESS || ptr.is_null() {
        return None;
    }
    // SAFETY: stored by `stash` as a boxed Stash.
    let stored = unsafe { &*ptr.cast::<Stash>() };
    let copy = Stash { uid: stored.uid, password: Zeroizing::new(stored.password.to_vec()) };
    // Replacing the value runs `drop_stash` on the old one.
    // SAFETY: storing a null pointer without cleanup.
    unsafe { ffi::pam_set_data(pamh, STASH.as_ptr(), std::ptr::null_mut(), None) };
    Some(copy)
}

/// # Safety
///
/// Called by libpam with a valid handle and `argc` option strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut PamHandle,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    guarded(pamh, || {
        let Some(helper) = helper_path(argc, argv) else { return };
        let Some(password) = item(pamh, ffi::PAM_AUTHTOK) else { return };
        let Some(acct) = known_account(pamh) else { return };
        stash(pamh, acct.uid, &password);
        run_helper(pamh, &acct, &helper, c"--if-running", &[&password]);
    })
}

/// # Safety
///
/// Called by libpam.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_setcred(
    pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    guarded(pamh, || {})
}

/// # Safety
///
/// Called by libpam with a valid handle and `argc` option strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_open_session(
    pamh: *mut PamHandle,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    guarded(pamh, || {
        let Some(stash) = take_stash(pamh) else { return };
        let Some(helper) = helper_path(argc, argv) else { return };
        let Some(acct) = known_account(pamh) else { return };
        let Some(password) = stash.password_for(&acct) else {
            log(pamh, libc::LOG_NOTICE, "the account changed since authentication; password not passed on");
            return;
        };
        run_helper(pamh, &acct, &helper, c"--wait", &[password]);
    })
}

/// # Safety
///
/// Called by libpam.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_close_session(
    pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    guarded(pamh, || {})
}

/// # Safety
///
/// Called by libpam with a valid handle and `argc` option strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_chauthtok(
    pamh: *mut PamHandle,
    flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    guarded(pamh, || {
        if flags & ffi::PAM_UPDATE_AUTHTOK == 0 {
            return;
        }
        let Some(helper) = helper_path(argc, argv) else { return };
        let (Some(old), Some(new)) = (item(pamh, ffi::PAM_OLDAUTHTOK), item(pamh, ffi::PAM_AUTHTOK)) else { return };
        let Some(acct) = known_account(pamh) else { return };
        run_helper(pamh, &acct, &helper, c"--change", &[&old, &new]);
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&CStr]) -> Vec<*const c_char> {
        list.iter().map(|a| a.as_ptr()).collect()
    }

    #[test]
    fn the_stash_is_only_for_its_own_account() {
        let acct = |uid| Account { uid, gid: uid, home: c"/home/x".to_owned(), groups: Vec::new() };
        let stash = Stash { uid: 1000, password: Zeroizing::new(b"secret".to_vec()) };
        assert_eq!(stash.password_for(&acct(1000)), Some(&b"secret"[..]));
        assert_eq!(stash.password_for(&acct(1001)), None);
    }

    #[test]
    fn helper_input_is_allocated_once() {
        let input = helper_input(&[b"old password", &[b'n'; 300]]);
        assert_eq!(input.len(), 13 + 301);
        assert_eq!(input.capacity(), input.len());
    }

    #[test]
    fn helper_option() {
        let none = args(&[]);
        assert_eq!(helper_path(0, none.as_ptr()).unwrap().to_str().unwrap(), DEFAULT_HELPER);
        let a = args(&[c"debug", c"helper=/opt/h"]);
        assert_eq!(helper_path(2, a.as_ptr()).unwrap().to_str().unwrap(), "/opt/h");
        let rel = args(&[c"helper=h"]);
        assert!(helper_path(1, rel.as_ptr()).is_none());
    }
}
