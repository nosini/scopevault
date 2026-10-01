//! Resolving D-Bus callers into authenticated principals.
//!
//! The only inputs are what the bus daemon reports for a unique connection
//! name (`GetConnectionCredentials`: UID, PID, pidfd, LSM label) and what the
//! kernel shows for that pidfd. Nothing the caller sends (PIDs, app IDs,
//! attributes, environment) is ever used as identity.
//!
//! Classification is deliberately conservative:
//! - Flatpak: `/.flatpak-info` in the caller's root, matching a live
//!   instance recorded by Flatpak ([`flatpak`]).
//! - Host: positively established. The caller must share every namespace,
//!   the root directory and the LSM label with the daemon ([`HostBaseline`]).
//!   Merely lacking Flatpak metadata is not enough.
//! - Everything else (other sandboxes, exited processes, missing pidfd,
//!   unreadable or malformed metadata) is denied.

pub mod flatpak;
pub mod keyfile;
pub mod process;
pub mod resolver;

use std::sync::Arc;

use serde::Serialize;

pub use flatpak::{AppId, FlatpakRisks, InstanceCheck, InstanceRecords};
pub use process::{FileId, Namespaces, ProcessHandle};
pub use resolver::{BusIdentityResolver, CallerResolver};

/// Why a caller could not be identified. Messages never include secrets;
/// they may include paths and PIDs, which are not sensitive here.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("bus did not report a process fd (ProcessFD); refusing PID-only identification")]
    NoProcessFd,
    #[error("bus did not report a UID")]
    NoUid,
    #[error("caller UID {0} differs from the service UID")]
    UidMismatch(u32),
    #[error("caller process has exited")]
    ProcessExited,
    #[error("caller process is not visible in our PID namespace")]
    ForeignPidNamespace,
    #[error("inconsistent credentials: {0}")]
    InconsistentCredentials(&'static str),
    #[error("cannot inspect caller ({0}): {1}")]
    Inspect(&'static str, std::io::Error),
    #[error("malformed identity data: {0}")]
    Malformed(&'static str),
    #[error("malformed .flatpak-info: {0}")]
    FlatpakInfo(keyfile::KeyFileError),
    #[error("Flatpak runtime sandboxes (no application) are not supported")]
    RuntimeSandbox,
    #[error("invalid Flatpak application ID")]
    InvalidAppId,
    #[error("Flatpak instance record unavailable ({0}): {1}")]
    Instance(&'static str, std::io::Error),
    #[error("Flatpak instance check failed: {0}")]
    InstanceMismatch(&'static str),
    #[error("Flatpak metadata found in the host mount namespace")]
    FlatpakInfoOnHost,
    #[error("unsupported sandbox or container: differs from host in {0}")]
    NotHost(String),
    #[error("bus error: {0}")]
    Bus(String),
}

/// An authenticated caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Principal {
    Host,
    Flatpak { app_id: AppId, instance_id: String, risks: FlatpakRisks },
}

/// The storage namespace a principal acts in. Instance IDs and risk flags
/// do not affect the scope: every instance of an app shares its scope.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(tag = "kind", content = "app_id", rename_all = "kebab-case")]
pub enum Scope {
    Host,
    Flatpak(AppId),
}

impl Principal {
    pub fn scope(&self) -> Scope {
        match self {
            Principal::Host => Scope::Host,
            Principal::Flatpak { app_id, .. } => Scope::Flatpak(app_id.clone()),
        }
    }
}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Scope::Host => f.write_str("host"),
            Scope::Flatpak(id) => write!(f, "flatpak/{id}"),
        }
    }
}

/// Credentials as reported by the bus daemon for one unique name.
#[derive(Debug, Default)]
pub struct BusCredentials {
    pub uid: Option<u32>,
    pub pid: Option<u32>,
    pub pidfd: Option<std::os::fd::OwnedFd>,
    pub security_label: Option<Vec<u8>>,
}

/// Everything observed while classifying, for the probe and for logs.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Evidence {
    pub pid: Option<i32>,
    pub uid: Option<u32>,
    pub had_process_fd: bool,
    pub bus_label: Option<String>,
    pub proc_label: Option<String>,
    pub namespace_differences: Vec<&'static str>,
    pub same_root: Option<bool>,
    pub flatpak_info_present: Option<bool>,
    pub flatpak_app_id: Option<String>,
    pub instance: Option<InstanceCheck>,
    pub exe: Option<String>,
    pub ppid: Option<i32>,
    pub no_new_privs: Option<bool>,
    pub seccomp_mode: Option<u8>,
}

pub struct Classification {
    pub result: Result<Principal, IdentityError>,
    pub evidence: Evidence,
}

/// The daemon's own process view, which host callers must share.
#[derive(Debug, Clone)]
pub struct HostBaseline {
    pub uid: u32,
    pub namespaces: Namespaces,
    pub root: FileId,
    pub security_label: Option<Vec<u8>>,
}

impl HostBaseline {
    pub fn capture() -> Result<Self, IdentityError> {
        let me = process::self_handle()?;
        Ok(HostBaseline {
            uid: rustix::process::getuid().as_raw(),
            namespaces: me.namespaces()?,
            root: me.root_id()?,
            security_label: me.security_label()?,
        })
    }
}

/// Tunable checks. Defaults are the strict settings; relaxing them is a
/// deliberate configuration choice, never a fallback.
#[derive(Debug, Clone)]
pub struct IdentityPolicy {
    /// Require a host caller's LSM label to equal the daemon's.
    pub require_host_label_match: bool,
    /// Require Flatpak metadata to match a live Flatpak instance record.
    pub require_flatpak_instance: bool,
}

impl Default for IdentityPolicy {
    fn default() -> Self {
        IdentityPolicy { require_host_label_match: true, require_flatpak_instance: true }
    }
}

pub struct Classifier {
    pub baseline: HostBaseline,
    pub instances: InstanceRecords,
    pub policy: IdentityPolicy,
}

fn lossy(label: &[u8]) -> String {
    String::from_utf8_lossy(label).into_owned()
}

impl Classifier {
    /// Builds a classifier for the current process and `$XDG_RUNTIME_DIR`.
    pub fn for_current_process(policy: IdentityPolicy) -> Result<Self, IdentityError> {
        let baseline = HostBaseline::capture()?;
        let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| format!("/run/user/{}", baseline.uid).into());
        Ok(Classifier { instances: InstanceRecords::new(runtime_dir, baseline.uid), baseline, policy })
    }

    /// Classifies one connection. Blocking (procfs and file I/O).
    pub fn classify(&self, creds: BusCredentials) -> Classification {
        let mut ev = Evidence {
            uid: creds.uid,
            had_process_fd: creds.pidfd.is_some(),
            bus_label: creds.security_label.as_deref().map(lossy),
            ..Default::default()
        };
        let result = self.classify_inner(creds, &mut ev);
        Classification { result, evidence: ev }
    }

    fn classify_inner(&self, creds: BusCredentials, ev: &mut Evidence) -> Result<Principal, IdentityError> {
        let uid = creds.uid.ok_or(IdentityError::NoUid)?;
        if uid != self.baseline.uid {
            return Err(IdentityError::UidMismatch(uid));
        }
        let pidfd = creds.pidfd.ok_or(IdentityError::NoProcessFd)?;
        let proc = ProcessHandle::from_pidfd(pidfd, creds.pid)?;
        ev.pid = Some(proc.pid());

        let status = proc.status()?;
        ev.ppid = status.ppid;
        ev.no_new_privs = status.no_new_privs;
        ev.seccomp_mode = status.seccomp_mode;
        if status.uids.len() != 4 || status.uids.iter().any(|&u| u != self.baseline.uid) {
            return Err(IdentityError::InconsistentCredentials("process UIDs differ from the service UID"));
        }
        let proc_label = proc.security_label()?;
        ev.proc_label = proc_label.as_deref().map(lossy);
        ev.exe = proc.exe_path().ok();

        let ns = proc.namespaces()?;
        ev.namespace_differences = ns.differences(&self.baseline.namespaces);
        let root = proc.open_root()?;
        let root_id = {
            let st = rustix::fs::fstat(&root).map_err(|e| IdentityError::Inspect("stat process root", e.into()))?;
            FileId { dev: st.st_dev as u64, ino: st.st_ino as u64 }
        };
        ev.same_root = Some(root_id == self.baseline.root);

        let info = flatpak::read_flatpak_info(&root)?;
        ev.flatpak_info_present = Some(info.is_some());
        let principal = match info {
            Some(raw) => {
                if ns.mnt == self.baseline.namespaces.mnt {
                    return Err(IdentityError::FlatpakInfoOnHost);
                }
                let info = flatpak::parse_flatpak_info(raw)?;
                ev.flatpak_app_id = Some(info.app_id.to_string());
                if self.policy.require_flatpak_instance {
                    ev.instance = Some(self.instances.verify(&info, &ns)?);
                }
                Principal::Flatpak { app_id: info.app_id, instance_id: info.instance_id, risks: info.risks }
            }
            None => {
                let mut diffs: Vec<&str> = ev.namespace_differences.clone();
                if root_id != self.baseline.root {
                    diffs.push("root directory");
                }
                if self.policy.require_host_label_match {
                    // The bus label is captured at connect time; the procfs
                    // label is current. Both must match.
                    let base = self.baseline.security_label.as_deref();
                    let bus = creds.security_label.as_deref().map(|l| l.strip_suffix(b"\0").unwrap_or(l));
                    if proc_label.as_deref() != base || (bus.is_some() && bus != base) {
                        diffs.push("security label");
                    }
                }
                if !diffs.is_empty() {
                    return Err(IdentityError::NotHost(diffs.join(", ")));
                }
                Principal::Host
            }
        };
        proc.ensure_alive()?;
        Ok(principal)
    }
}

/// Shared, cheaply clonable result of resolving one connection.
pub type Resolved = Arc<Result<Principal, IdentityError>>;
