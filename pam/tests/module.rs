//! The module loaded by the real libpam (`pam_start_confdir` with a private
//! configuration directory), with a stand-in helper script that records
//! how it was started. `examples/pam_settok.rs` sets the password items as
//! pam_unix would.
//!
//! Runs as an ordinary user, so the module takes its "already running as
//! the user" path; dropping privileges as root is left to the desktop test.

use std::ffi::{CString, c_char, c_int, c_void};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[repr(C)]
struct PamHandle {
    _private: [u8; 0],
}

type ConvFn = unsafe extern "C" fn(c_int, *mut *const c_void, *mut *mut c_void, *mut c_void) -> c_int;

#[repr(C)]
struct PamConv {
    conv: Option<ConvFn>,
    appdata: *mut c_void,
}

const PAM_SUCCESS: c_int = 0;
const PAM_CONV_ERR: c_int = 19;

unsafe extern "C" {
    fn pam_start_confdir(
        service: *const c_char,
        user: *const c_char,
        conv: *const PamConv,
        confdir: *const c_char,
        pamh: *mut *mut PamHandle,
    ) -> c_int;
    fn pam_authenticate(pamh: *mut PamHandle, flags: c_int) -> c_int;
    fn pam_open_session(pamh: *mut PamHandle, flags: c_int) -> c_int;
    fn pam_chauthtok(pamh: *mut PamHandle, flags: c_int) -> c_int;
    fn pam_putenv(pamh: *mut PamHandle, name_value: *const c_char) -> c_int;
    fn pam_end(pamh: *mut PamHandle, status: c_int) -> c_int;
}

unsafe extern "C" fn no_conversation(_: c_int, _: *mut *const c_void, _: *mut *mut c_void, _: *mut c_void) -> c_int {
    PAM_CONV_ERR
}

static CONV: PamConv = PamConv { conv: Some(no_conversation), appdata: std::ptr::null_mut() };
// SAFETY: never written; libpam only reads it.
unsafe impl Sync for PamConv {}

fn target_dir() -> PathBuf {
    // target/debug/deps/module-HASH
    std::env::current_exe().unwrap().parent().unwrap().parent().unwrap().to_owned()
}

/// `cargo test` builds the library as an rlib for the tests, not the
/// module itself: build the module and the stand-in, so the tests never
/// load a stale one.
fn build_modules() {
    static BUILT: std::sync::Once = std::sync::Once::new();
    BUILT.call_once(|| {
        let status = std::process::Command::new(env!("CARGO"))
            .args(["build", "--lib", "--examples", "--manifest-path"])
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
            .status()
            .unwrap();
        assert!(status.success(), "cannot build the module");
    });
}

struct Fixture {
    dir: PathBuf,
    log: PathBuf,
}

impl Fixture {
    /// A configuration directory with service `test`, whose module lines
    /// use `helper` (a path, or a whole `helper=` option to override).
    fn new(name: &str, helper_body: &str, helper_option: Option<&str>) -> Self {
        let dir = std::env::temp_dir().join(format!("pam-scopevault-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("log");
        let helper = dir.join("helper");
        std::fs::write(&helper, format!("#!/bin/sh\nLOG='{}'\n{helper_body}", log.display())).unwrap();
        std::fs::set_permissions(&helper, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
        build_modules();
        let module = target_dir().join("libpam_scopevault.so");
        let settok = target_dir().join("examples/libpam_settok.so");
        assert!(module.exists() && settok.exists(), "build the module and the example first");
        let opt = helper_option.map_or_else(|| format!("helper={}", helper.display()), str::to_owned);
        let (m, s) = (module.display(), settok.display());
        std::fs::write(
            dir.join("test"),
            format!(
                "auth     required {s} authtok=first\n\
                 auth     optional {m} {opt}\n\
                 session  optional {m} {opt}\n\
                 session  required pam_permit.so\n\
                 password required {s} old=first new=second\n\
                 password optional {m} {opt}\n"
            ),
        )
        .unwrap();
        Fixture { dir, log }
    }

    fn start(&self, user: &str) -> *mut PamHandle {
        let service = CString::new("test").unwrap();
        let user = CString::new(user).unwrap();
        let confdir = CString::new(self.dir.to_str().unwrap()).unwrap();
        let mut pamh = std::ptr::null_mut();
        // SAFETY: valid strings and out-pointer; CONV lives forever.
        let rc = unsafe { pam_start_confdir(service.as_ptr(), user.as_ptr(), &CONV, confdir.as_ptr(), &mut pamh) };
        assert_eq!(rc, PAM_SUCCESS);
        pamh
    }

    fn entries(&self) -> Vec<String> {
        let text = std::fs::read_to_string(&self.log).unwrap_or_default();
        text.split("--\n").filter(|e| !e.trim().is_empty()).map(str::to_owned).collect()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn me() -> (String, u32, String) {
    let out = |args: &[&str]| {
        String::from_utf8(std::process::Command::new("id").args(args).output().unwrap().stdout)
            .unwrap()
            .trim()
            .to_owned()
    };
    let home = std::env::var("HOME").unwrap();
    (out(&["-un"]), out(&["-u"]).parse().unwrap(), home)
}

/// Records how it was started: arguments, UID, environment, whether the
/// descriptor `leak` reached it, and its stdin.
fn recorder(leak: c_int) -> String {
    format!(
        "{{\n\
         echo \"args: $*\"\n\
         echo \"uid: $(id -u)\"\n\
         echo \"env: $(env | grep -v -e '^PWD=' -e '^SHLVL=' -e '^_=' | sort | tr '\\n' ' ')\"\n\
         if [ -e /proc/$$/fd/{leak} ]; then echo 'fd: leaked'; else echo 'fd: closed'; fi\n\
         printf 'stdin: %s\\n' \"$(od -An -c | tr -s ' \\n' '  ')\"\n\
         echo --\n\
         }} >> \"$LOG\"\n"
    )
}

fn field<'a>(entry: &'a str, name: &str) -> &'a str {
    entry.lines().find_map(|l| l.strip_prefix(name)?.strip_prefix(": ")).unwrap_or("").trim()
}

#[test]
fn passwords_reach_the_helper_in_each_phase() {
    // A descriptor the host process leaves open (not close-on-exec): the
    // helper must not get it.
    // SAFETY: opening a file; the descriptor is closed at the end.
    let leak = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
    assert!(leak > 2);
    let fx = Fixture::new("phases", &recorder(leak), None);
    let (user, uid, home) = me();
    let pamh = fx.start(&user);

    // SAFETY: `pamh` is live until pam_end.
    unsafe {
        assert_eq!(pam_authenticate(pamh, 0), PAM_SUCCESS, "the module must not change the result");
        let e = fx.entries();
        assert_eq!(e.len(), 1, "{e:?}");
        assert_eq!(field(&e[0], "args"), "--if-running");
        assert_eq!(field(&e[0], "uid"), uid.to_string());
        assert_eq!(field(&e[0], "env"), format!("HOME={home} XDG_RUNTIME_DIR=/run/user/{uid}"), "{}", e[0]);
        assert_eq!(field(&e[0], "fd"), "closed");
        assert_eq!(field(&e[0], "stdin"), "f i r s t \\0");

        // The session's XDG_RUNTIME_DIR (pam_systemd sets it) is passed on.
        let env = CString::new("XDG_RUNTIME_DIR=/run/elsewhere").unwrap();
        assert_eq!(pam_putenv(pamh, env.as_ptr()), PAM_SUCCESS);
        assert_eq!(pam_open_session(pamh, 0), PAM_SUCCESS);
        let e = fx.entries();
        assert_eq!(e.len(), 2, "{e:?}");
        assert_eq!(field(&e[1], "args"), "--wait");
        assert_eq!(field(&e[1], "env"), format!("HOME={home} XDG_RUNTIME_DIR=/run/elsewhere"));
        assert_eq!(field(&e[1], "stdin"), "f i r s t \\0");

        // The stash is used once.
        assert_eq!(pam_open_session(pamh, 0), PAM_SUCCESS);
        assert_eq!(fx.entries().len(), 2);

        // A password change: only the update phase, with both passwords.
        assert_eq!(pam_chauthtok(pamh, 0), PAM_SUCCESS);
        let e = fx.entries();
        assert_eq!(e.len(), 3, "{e:?}");
        assert_eq!(field(&e[2], "args"), "--change");
        assert_eq!(field(&e[2], "stdin"), "f i r s t \\0 s e c o n d \\0");

        pam_end(pamh, PAM_SUCCESS);
        libc::close(leak);
    }
}

#[test]
fn other_users_and_missing_helpers_change_nothing() {
    let fx = Fixture::new("others", &recorder(999), None);
    // Not root and not the target user: the module stays out of it.
    for user in ["root", "nobody", "no-such-user-here"] {
        let pamh = fx.start(user);
        // SAFETY: `pamh` is live until pam_end.
        unsafe {
            assert_eq!(pam_authenticate(pamh, 0), PAM_SUCCESS, "{user}");
            assert_eq!(pam_open_session(pamh, 0), PAM_SUCCESS, "{user}");
            pam_end(pamh, PAM_SUCCESS);
        }
    }
    assert!(fx.entries().is_empty(), "{:?}", fx.entries());

    let (user, ..) = me();
    for option in ["helper=/nonexistent/helper", "helper=relative/helper"] {
        let fx = Fixture::new("missing", "", Some(option));
        let pamh = fx.start(&user);
        // SAFETY: as above.
        unsafe {
            assert_eq!(pam_authenticate(pamh, 0), PAM_SUCCESS);
            assert_eq!(pam_open_session(pamh, 0), PAM_SUCCESS);
            assert_eq!(pam_chauthtok(pamh, 0), PAM_SUCCESS);
            pam_end(pamh, PAM_SUCCESS);
        }
    }
}

#[test]
fn a_hanging_helper_does_not_hold_up_the_login_for_long() {
    let fx = Fixture::new("hang", "cat > /dev/null\nexec sleep 30\n", None);
    let (user, ..) = me();
    let pamh = fx.start(&user);
    let started = Instant::now();
    // SAFETY: as above.
    unsafe {
        assert_eq!(pam_authenticate(pamh, 0), PAM_SUCCESS);
        pam_end(pamh, PAM_SUCCESS);
    }
    let took = started.elapsed();
    assert!(took >= Duration::from_secs(4) && took < Duration::from_secs(8), "{took:?}");
}
