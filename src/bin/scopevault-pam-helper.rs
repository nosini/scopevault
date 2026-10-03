//! Hands the login password from the PAM module to the daemon.
//!
//! `pam_scopevault.so` starts this program as the user (never as root),
//! with the password on stdin, NUL-terminated, and one of:
//!
//! - `--if-running`: deliver it if the daemon's login socket answers now
//!   (a screen unlock), otherwise give up;
//! - `--wait`: deliver it once the daemon is up, for up to 120 s (a login:
//!   the daemon starts with the graphical session, after PAM);
//! - `--change`: stdin holds the old and the new password; deliver both if
//!   the daemon is running.
//!
//! It reads stdin, then forks into the background and exits at once, so the
//! login does not wait for it. The password is sent only to a socket whose
//! peer has the user's UID (as gnome-keyring's PAM module checks). The
//! outcome goes to syslog (the journal), never the password.

use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use scopevault::login::protocol::{MAX_PASSWORD, Request};
use zeroize::Zeroizing;

const WAIT: Duration = Duration::from_secs(120);
const RETRY: Duration = Duration::from_millis(500);
/// The daemon derives a key (about 1 s) and may rewrap the slot.
const REPLY_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    IfRunning,
    Wait,
    Change,
}

fn log(level: libc::c_int, msg: &str) {
    let msg = std::ffi::CString::new(msg.replace('\0', " ")).expect("no NUL left");
    // SAFETY: both strings are valid and NUL-terminated; the format takes
    // exactly one string argument.
    unsafe { libc::syslog(level, c"%s".as_ptr(), msg.as_ptr()) };
}

fn main() -> ExitCode {
    // SAFETY: a static identifier string; called once before any logging.
    unsafe { libc::openlog(c"scopevault-pam-helper".as_ptr(), libc::LOG_PID, libc::LOG_AUTHPRIV) };
    let mode = match std::env::args().nth(1).as_deref() {
        Some("--if-running") => Mode::IfRunning,
        Some("--wait") => Mode::Wait,
        Some("--change") => Mode::Change,
        _ => {
            eprintln!("usage: scopevault-pam-helper --if-running | --wait | --change  (password on stdin)");
            return ExitCode::from(2);
        }
    };
    if rustix::process::getuid().is_root() || rustix::process::geteuid().is_root() {
        log(libc::LOG_ERR, "refusing to run as root");
        return ExitCode::FAILURE;
    }
    let _ = rustix::process::setrlimit(
        rustix::process::Resource::Core,
        rustix::process::Rlimit { current: Some(0), maximum: Some(0) },
    );
    let request = match read_request(mode) {
        Ok(r) => r,
        Err(e) => {
            log(libc::LOG_ERR, &format!("bad input: {e}"));
            return ExitCode::FAILURE;
        }
    };
    // Not made non-dumpable on purpose: the daemon identifies its peers
    // through /proc, which that would make unreadable.

    // SAFETY: the process is single-threaded here, so the child may go on
    // running ordinary code.
    match unsafe { libc::fork() } {
        -1 => {
            log(libc::LOG_ERR, "cannot fork");
            return ExitCode::FAILURE;
        }
        0 => {}
        _ => return ExitCode::SUCCESS,
    }
    let _ = rustix::process::setsid();
    detach_stdio();
    match deliver(mode, &request) {
        Ok(reply) => log(libc::LOG_INFO, &format!("{}: {reply}", what(mode))),
        Err(e) => log(libc::LOG_NOTICE, &format!("{}: {e}", what(mode))),
    }
    ExitCode::SUCCESS
}

fn what(mode: Mode) -> &'static str {
    match mode {
        Mode::IfRunning | Mode::Wait => "login password delivered",
        Mode::Change => "password change delivered",
    }
}

/// stdin holds one password (two for a change), each followed by a NUL;
/// the last NUL may be missing.
fn read_request(mode: Mode) -> Result<Request, String> {
    let count = if mode == Mode::Change { 2 } else { 1 };
    let limit = count * (MAX_PASSWORD + 1);
    let mut input = Zeroizing::new(Vec::with_capacity(limit + 1));
    std::io::stdin()
        .take(limit as u64 + 1)
        .read_to_end(&mut input)
        .map_err(|e| format!("cannot read the password: {e}"))?;
    if input.len() > limit {
        return Err("password too long".into());
    }
    let body = input.strip_suffix(&[0]).unwrap_or(&input);
    let parts: Vec<&[u8]> = body.split(|&b| b == 0).collect();
    if parts.len() != count || parts.iter().any(|p| p.is_empty() || p.len() > MAX_PASSWORD) {
        return Err(format!("expected {count} non-empty password(s)"));
    }
    let owned = |p: &[u8]| Zeroizing::new(p.to_vec());
    Ok(match parts.as_slice() {
        [p] => Request::Deliver(owned(p)),
        [old, new] => Request::Change { old: owned(old), new: owned(new) },
        _ => unreachable!("count checked"),
    })
}

fn detach_stdio() {
    if let Ok(null) = std::fs::OpenOptions::new().read(true).write(true).open("/dev/null") {
        for fd in 0..=2 {
            // SAFETY: dup2 onto the standard descriptors, which this process
            // owns; `null` stays open until after the calls.
            unsafe { libc::dup2(std::os::fd::AsRawFd::as_raw_fd(&null), fd) };
        }
    }
}

fn socket_path() -> PathBuf {
    let uid = rustix::process::getuid().as_raw();
    let dir = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| PathBuf::from(format!("/run/user/{uid}")));
    dir.join("scopevault").join("login")
}

fn connect(mode: Mode) -> Result<UnixStream, String> {
    let path = socket_path();
    let deadline = Instant::now() + if mode == Mode::Wait { WAIT } else { Duration::ZERO };
    loop {
        match UnixStream::connect(&path) {
            Ok(s) => return Ok(s),
            Err(e)
                if matches!(e.kind(), std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused)
                    && Instant::now() < deadline =>
            {
                std::thread::sleep(RETRY);
            }
            Err(e) => return Err(format!("the daemon is not running ({}: {e})", path.display())),
        }
    }
}

fn deliver(mode: Mode, request: &Request) -> Result<String, String> {
    let mut stream = connect(mode)?;
    let peer = rustix::net::sockopt::socket_peercred(stream.as_fd()).map_err(|e| format!("peer credentials: {e}"))?;
    if peer.uid != rustix::process::getuid() {
        return Err(format!("the socket belongs to UID {}; not sending the password", peer.uid.as_raw()));
    }
    let bytes = request.encode().map_err(str::to_owned)?;
    stream.write_all(&bytes).map_err(|e| format!("cannot send: {e}"))?;
    stream.set_read_timeout(Some(REPLY_TIMEOUT)).map_err(|e| e.to_string())?;
    let mut reply = String::new();
    stream.take(64).read_to_string(&mut reply).map_err(|e| format!("no reply: {e}"))?;
    Ok(reply.trim().to_owned())
}
