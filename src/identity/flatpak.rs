//! Flatpak caller identification.
//!
//! The approach follows xdg-desktop-portal (`shared/xdp-app-info-flatpak.c`,
//! LGPL-2.1-or-later): read `/.flatpak-info` from the caller's root
//! directory. Flatpak writes that file outside the sandbox and the app cannot
//! replace it; confined apps also cannot create user namespaces (Flatpak's
//! seccomp filter blocks it), so they cannot build a root with a forged copy.
//!
//! Differences from the portal, which this module adds on top:
//! - procfs is reached only through a pidfd-bound directory fd
//!   ([`super::process`]), not by PID number;
//! - `.flatpak-info` is opened with `O_NOFOLLOW | O_NONBLOCK` and must be a
//!   regular file;
//! - runtime sandboxes (`[Runtime]` instead of `[Application]`) are rejected;
//! - the metadata must match a live instance recorded by Flatpak under
//!   `$XDG_RUNTIME_DIR/.flatpak/<instance-id>/` ([`InstanceRecords`]).

use std::fs::File;
use std::io::Read;
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};

use rustix::fs::{Mode, OFlags};
use serde::Serialize;

use super::IdentityError;
use super::keyfile::{KeyFile, MAX_KEYFILE_SIZE};
use super::process::{self, Namespaces, ProcessHandle};

/// A validated Flatpak application ID.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct AppId(String);

impl AppId {
    /// Applies Flatpak's documented application-name rules
    /// (`flatpak_is_valid_name`): three or more non-empty elements separated
    /// by `.`, ASCII `[A-Za-z0-9_-]` only, no element starting with a digit,
    /// `-` only in the last element, at most 255 bytes.
    pub fn parse(s: &str) -> Result<Self, IdentityError> {
        let invalid = || IdentityError::InvalidAppId;
        if s.is_empty() || s.len() > 255 {
            return Err(invalid());
        }
        let elements: Vec<&str> = s.split('.').collect();
        if elements.len() < 3 {
            return Err(invalid());
        }
        let last = elements.len() - 1;
        for (i, el) in elements.iter().enumerate() {
            let allow_dash = i == last;
            let mut chars = el.chars();
            let first = chars.next().ok_or_else(invalid)?;
            let initial_ok = first.is_ascii_alphabetic() || first == '_' || (allow_dash && first == '-');
            if !initial_ok {
                return Err(invalid());
            }
            if !chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || (allow_dash && c == '-')) {
                return Err(invalid());
            }
        }
        Ok(AppId(s.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for AppId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Sandbox permissions that weaken or bypass the isolation this service
/// provides. They do not change the app's scope; they are shown to the user
/// and recorded so nobody mistakes namespace isolation for protection
/// against apps that hold them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct FlatpakRisks {
    /// `--socket=session-bus`: talks to the bus without the filtering proxy.
    pub unrestricted_session_bus: bool,
    /// Can talk to `org.freedesktop.Flatpak`, which runs commands on the host.
    pub host_command: bool,
    /// Filesystem grants that allow writing host files that later run as
    /// host code (for example `home` gives access to `~/.bashrc`).
    pub broad_filesystems: Vec<String>,
    /// `--allow=devel` (ptrace and similar).
    pub devel: bool,
}

impl FlatpakRisks {
    pub fn any(&self) -> bool {
        self.unrestricted_session_bus || self.host_command || self.devel || !self.broad_filesystems.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlatpakInfo {
    pub app_id: AppId,
    pub instance_id: String,
    pub session_bus_proxy: bool,
    pub risks: FlatpakRisks,
    /// The exact bytes, for comparison against Flatpak's instance record.
    pub raw: Vec<u8>,
}

/// Informational, not exhaustive: grants covering the home directory, the
/// host filesystem or whole XDG base directories.
const BROAD_FILESYSTEMS: &[&str] =
    &["host", "host-os", "host-etc", "home", "~", "/", "xdg-config", "xdg-data", "xdg-run", "xdg-config/autostart"];

pub fn parse_flatpak_info(raw: Vec<u8>) -> Result<FlatpakInfo, IdentityError> {
    let kf = KeyFile::parse(&raw).map_err(IdentityError::FlatpakInfo)?;
    if kf.has_group("Runtime") {
        return Err(IdentityError::RuntimeSandbox);
    }
    if !kf.has_group("Application") {
        return Err(IdentityError::Malformed(".flatpak-info has no [Application] group"));
    }
    let name =
        kf.get("Application", "name").ok_or(IdentityError::Malformed(".flatpak-info has no application name"))?;
    let app_id = AppId::parse(name)?;

    let instance_id =
        kf.get("Instance", "instance-id").ok_or(IdentityError::Malformed(".flatpak-info has no instance-id"))?;
    if !is_valid_instance_id(instance_id) {
        return Err(IdentityError::Malformed("invalid instance-id"));
    }

    let sockets = kf.get_list("Context", "sockets");
    let mut risks = FlatpakRisks {
        unrestricted_session_bus: sockets.iter().any(|s| s == "session-bus"),
        devel: kf.get_list("Context", "features").iter().any(|f| f == "devel"),
        ..Default::default()
    };
    for (name, policy) in kf.keys("Session Bus Policy") {
        let flatpak_service = name == "org.freedesktop.Flatpak" || name == "org.freedesktop.Flatpak.*";
        if flatpak_service && matches!(policy, "talk" | "own") {
            risks.host_command = true;
        }
    }
    for fs in kf.get_list("Context", "filesystems") {
        if fs.starts_with('!') {
            continue;
        }
        let base = fs.split(':').next().unwrap_or("");
        let base = if base.len() > 1 { base.trim_end_matches('/') } else { base };
        if BROAD_FILESYSTEMS.contains(&base) {
            risks.broad_filesystems.push(fs);
        }
    }

    Ok(FlatpakInfo {
        app_id,
        instance_id: instance_id.to_owned(),
        session_bus_proxy: kf.get("Instance", "session-bus-proxy") == Some("true"),
        risks,
        raw,
    })
}

/// Flatpak allocates instance IDs as `printf("%u", g_random_int())`.
fn is_valid_instance_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 10 && s.bytes().all(|b| b.is_ascii_digit()) && s.parse::<u32>().is_ok()
}

/// Reads `/.flatpak-info` from a caller's root. `Ok(None)` means the file
/// does not exist; any other failure is an error.
pub fn read_flatpak_info(root: &OwnedFd) -> Result<Option<Vec<u8>>, IdentityError> {
    let fd = match rustix::fs::openat(
        root,
        ".flatpak-info",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(e) => return Err(IdentityError::Inspect("open .flatpak-info", e.into())),
    };
    read_regular_file(fd, None).map(Some)
}

fn read_regular_file(fd: OwnedFd, owner: Option<u32>) -> Result<Vec<u8>, IdentityError> {
    let st = rustix::fs::fstat(&fd).map_err(|e| IdentityError::Inspect("stat metadata file", e.into()))?;
    if rustix::fs::FileType::from_raw_mode(st.st_mode) != rustix::fs::FileType::RegularFile {
        return Err(IdentityError::Malformed("metadata file is not a regular file"));
    }
    if let Some(uid) = owner
        && st.st_uid != uid
    {
        return Err(IdentityError::Malformed("metadata file has unexpected owner"));
    }
    let mut buf = Vec::new();
    File::from(fd)
        .take(MAX_KEYFILE_SIZE as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|e| IdentityError::Inspect("read metadata file", e))?;
    if buf.len() > MAX_KEYFILE_SIZE {
        return Err(IdentityError::Malformed("metadata file too large"));
    }
    Ok(buf)
}

/// How the caller relates to the live Flatpak instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum InstanceRelation {
    /// The caller shares the sandbox's mount namespace (no bus proxy).
    InSandbox,
    /// The caller is a separate process (normally Flatpak's xdg-dbus-proxy).
    Proxy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InstanceCheck {
    pub sandbox_pid: i32,
    pub relation: InstanceRelation,
}

/// Flatpak's per-instance records in `$XDG_RUNTIME_DIR/.flatpak`.
#[derive(Debug, Clone)]
pub struct InstanceRecords {
    runtime_dir: PathBuf,
    uid: u32,
}

#[derive(serde::Deserialize)]
struct BwrapInfo {
    #[serde(rename = "child-pid")]
    child_pid: i32,
    #[serde(rename = "mnt-namespace")]
    mnt_namespace: Option<u64>,
}

impl InstanceRecords {
    pub fn new(runtime_dir: impl Into<PathBuf>, uid: u32) -> Self {
        InstanceRecords { runtime_dir: runtime_dir.into(), uid }
    }

    pub fn runtime_dir(&self) -> &Path {
        &self.runtime_dir
    }

    fn open_dir(&self, parent: impl AsFd, name: &str) -> Result<OwnedFd, IdentityError> {
        let fd = rustix::fs::openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| IdentityError::Instance("cannot open instance directory", e.into()))?;
        let st = rustix::fs::fstat(&fd).map_err(|e| IdentityError::Instance("stat instance directory", e.into()))?;
        if st.st_uid != self.uid {
            return Err(IdentityError::InstanceMismatch("instance directory has unexpected owner"));
        }
        Ok(fd)
    }

    fn read_file(&self, dir: &OwnedFd, name: &str) -> Result<Vec<u8>, IdentityError> {
        let fd = rustix::fs::openat(
            dir,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| IdentityError::Instance("cannot open instance record", e.into()))?;
        read_regular_file(fd, Some(self.uid))
    }

    /// Confirms that `info` describes a live instance Flatpak launched:
    /// the recorded `info` file has the same bytes, the recorded sandbox
    /// process is alive in the recorded mount namespace, and that sandbox's
    /// own `/.flatpak-info` also has the same bytes.
    pub fn verify(&self, info: &FlatpakInfo, caller_ns: &Namespaces) -> Result<InstanceCheck, IdentityError> {
        let runtime = rustix::fs::openat(
            rustix::fs::CWD,
            &self.runtime_dir,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| IdentityError::Instance("cannot open runtime directory", e.into()))?;
        let base = self.open_dir(&runtime, ".flatpak")?;
        let inst = self.open_dir(&base, &info.instance_id)?;

        if self.read_file(&inst, "info")? != info.raw {
            return Err(IdentityError::InstanceMismatch("metadata differs from instance record"));
        }

        let bwrap: BwrapInfo = serde_json::from_slice(&self.read_file(&inst, "bwrapinfo.json")?)
            .map_err(|_| IdentityError::InstanceMismatch("unparsable bwrapinfo.json"))?;
        let sandbox = process::handle_for_pid(bwrap.child_pid)
            .map_err(|_| IdentityError::InstanceMismatch("recorded sandbox process is not running"))?;
        let sandbox_ns = sandbox.namespaces()?;
        let recorded_mnt =
            bwrap.mnt_namespace.ok_or(IdentityError::InstanceMismatch("bwrapinfo.json lacks mnt-namespace"))?;
        if sandbox_ns.mnt.ino != recorded_mnt {
            return Err(IdentityError::InstanceMismatch("recorded sandbox PID belongs to another process"));
        }
        match read_flatpak_info(&sandbox.open_root()?)? {
            Some(bytes) if bytes == info.raw => {}
            _ => return Err(IdentityError::InstanceMismatch("live sandbox metadata differs")),
        }
        sandbox.ensure_alive()?;

        let relation =
            if caller_ns.mnt == sandbox_ns.mnt { InstanceRelation::InSandbox } else { InstanceRelation::Proxy };
        Ok(InstanceCheck { sandbox_pid: sandbox.pid(), relation })
    }
}

/// Convenience for diagnostics: identify a process by PID (never use for callers).
pub fn describe_pid(pid: i32) -> Result<(ProcessHandle, Option<FlatpakInfo>), IdentityError> {
    let h = process::handle_for_pid(pid)?;
    let info = read_flatpak_info(&h.open_root()?)?.map(parse_flatpak_info).transpose()?;
    Ok((h, info))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_id_rules() {
        for ok in ["org.gnome.Calculator", "com.example.My-App", "_a.b.c", "org.mozilla.firefox", "io.github.x_y.Z9"] {
            assert!(AppId::parse(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "org.example",
            "org..example.App",
            ".org.example.App",
            "org.example.App.",
            "org.my-example.App",
            "org.example.9App",
            "org.exämple.App",
            "org/example/App",
            "org.example.App\n",
            &"a.b.".repeat(100),
        ] {
            assert!(AppId::parse(bad).is_err(), "{bad:?}");
        }
    }

    fn info(body: &str) -> Result<FlatpakInfo, IdentityError> {
        parse_flatpak_info(body.as_bytes().to_vec())
    }

    #[test]
    fn parses_application_metadata() {
        let i = info(
            "[Application]\nname=org.example.App\n[Instance]\ninstance-id=42\nsession-bus-proxy=true\n\
             [Context]\nsockets=wayland;\nfilesystems=xdg-download;home;!host;\n\
             [Session Bus Policy]\norg.freedesktop.secrets=talk\n",
        )
        .unwrap();
        assert_eq!(i.app_id.as_str(), "org.example.App");
        assert_eq!(i.instance_id, "42");
        assert!(i.session_bus_proxy);
        assert_eq!(i.risks.broad_filesystems, vec!["home"]);
        assert!(!i.risks.unrestricted_session_bus && !i.risks.host_command);
    }

    #[test]
    fn flags_risky_permissions() {
        let i = info(
            "[Application]\nname=org.example.App\n[Instance]\ninstance-id=1\n\
             [Context]\nsockets=session-bus;\nfilesystems=host:ro;~/Documents;\n\
             [Session Bus Policy]\norg.freedesktop.Flatpak=talk\n",
        )
        .unwrap();
        assert!(i.risks.unrestricted_session_bus && i.risks.host_command);
        assert_eq!(i.risks.broad_filesystems, vec!["host:ro"]);
    }

    #[test]
    fn rejects_bad_metadata() {
        let cases = [
            "[Runtime]\nname=org.freedesktop.Platform\n[Instance]\ninstance-id=1\n",
            "[Application]\nname=org.example\n[Instance]\ninstance-id=1\n",
            "[Application]\nname=org.example.App\n",
            "[Application]\nname=org.example.App\n[Instance]\ninstance-id=../1\n",
            "[Application]\nname=org.example.App\n[Instance]\ninstance-id=99999999999\n",
            "[Application]\nname=org.example.App\n[Application]\nname=org.other.App\n[Instance]\ninstance-id=1\n",
        ];
        for c in cases {
            assert!(info(c).is_err(), "{c}");
        }
    }
}
