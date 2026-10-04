//! Checking the login password with pam_unix's `unix_chkpwd` helper.
//!
//! `unix_chkpwd USER nonull` reads a password (terminated by NUL) on stdin
//! and exits with 0 if it is USER's password in `/etc/shadow`. It is setuid
//! or setgid so that it can read the shadow file, and refuses to check any
//! account but the caller's own. It is an internal interface of pam_unix
//! (`run_helper_binary` in its `support.c`); it knows local accounts only,
//! not SSSD, LDAP or systemd-homed ones.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::PasswordCheck;

/// Where openSUSE (and most distributions) install it.
pub const DEFAULT_PROGRAM: &str = "/usr/sbin/unix_chkpwd";
/// pam_unix's limit (`MAXPASS`); longer passwords cannot be checked.
const MAX_PASSWORD: usize = 512;
/// What `unix_chkpwd` exits with for a wrong password (`PAM_AUTH_ERR`).
const PAM_AUTH_ERR: i32 = 7;
/// How long a check may take before the checker is stopped. Login requests
/// wait for it one at a time, holding the password.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

pub struct UnixChkpwd {
    program: PathBuf,
    user: String,
    timeout: Duration,
}

impl UnixChkpwd {
    /// For the account the daemon runs as.
    pub fn new(program: PathBuf) -> Result<Self, String> {
        Ok(UnixChkpwd { program, user: current_user()?, timeout: DEFAULT_TIMEOUT })
    }

    /// Another limit than [`DEFAULT_TIMEOUT`].
    pub fn with_timeout(self, timeout: Duration) -> Self {
        UnixChkpwd { timeout, ..self }
    }
}

impl PasswordCheck for UnixChkpwd {
    fn check(&self, password: &[u8]) -> Result<bool, String> {
        if password.contains(&0) {
            return Ok(false);
        }
        if password.len() > MAX_PASSWORD {
            return Err(format!("passwords longer than {MAX_PASSWORD} bytes cannot be checked"));
        }
        let mut child = Command::new(&self.program)
            .args([self.user.as_str(), "nonull"])
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("cannot run {}: {e}", self.program.display()))?;
        let mut input = zeroize::Zeroizing::new(Vec::with_capacity(password.len() + 1));
        input.extend_from_slice(password);
        input.push(0);
        let mut stdin = child.stdin.take().expect("piped");
        // A helper that exits early (refusing the call) closes the pipe; its
        // exit status says why.
        let _ = stdin.write_all(&input);
        drop(stdin);
        // It runs setuid as the caller's real user, so it can be stopped.
        let deadline = Instant::now() + self.timeout;
        let status = loop {
            match child.try_wait().map_err(|e| format!("{}: {e}", self.program.display()))? {
                Some(status) => break status,
                None if Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("{} did not finish within {:?}", self.program.display(), self.timeout));
                }
                None => std::thread::sleep(Duration::from_millis(10)),
            }
        };
        match status.code() {
            Some(0) => Ok(true),
            Some(PAM_AUTH_ERR) => Ok(false),
            Some(code) => Err(format!("{} failed with exit status {code}", self.program.display())),
            None => Err(format!("{} was killed", self.program.display())),
        }
    }
}

/// The name of the account this process runs as.
fn current_user() -> Result<String, String> {
    let uid = rustix::process::getuid().as_raw();
    let mut buf = vec![0u8; 4096];
    let mut pwd = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: every pointer refers to memory owned by this frame, `buf` is
    // as long as the length passed, and `result` is only read after the
    // call returned.
    let rc = unsafe { libc::getpwuid_r(uid, pwd.as_mut_ptr(), buf.as_mut_ptr().cast(), buf.len(), &mut result) };
    if rc != 0 || result.is_null() {
        return Err(format!("no account entry for UID {uid}"));
    }
    // SAFETY: on success `pwd` was filled in and `pw_name` points to a
    // NUL-terminated string inside `buf`, which is still alive.
    let name = unsafe { std::ffi::CStr::from_ptr((*result).pw_name) };
    name.to_str().map(str::to_owned).map_err(|_| format!("the name of UID {uid} is not UTF-8"))
}
