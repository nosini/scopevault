//! Lifetime-safe inspection of a peer process through its pidfd.
//!
//! The bus gives us a pidfd for the process that opened the connection.
//! A PID number alone is not safe to use: the process may exit and the
//! number may be reused before we look at `/proc/<pid>`. We therefore
//!
//! 1. read the PID the pidfd currently refers to (from `fdinfo`),
//! 2. open `/proc/<pid>` as a directory fd,
//! 3. confirm through the pidfd that the process is still alive.
//!
//! While the process has not been reaped its PID cannot be reused, so after
//! step 3 the directory fd is bound to the same process. A procfs directory
//! fd never rebinds to a later process with the same number: once the
//! original exits, lookups through it fail. Every later read goes through
//! that directory fd and is followed by another liveness check.

use std::fs::File;
use std::io::Read;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};

use rustix::fs::{AtFlags, CWD, Mode, OFlags};

use super::IdentityError;

/// Identifies a namespace (the nsfs inode).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NsId {
    pub dev: u64,
    pub ino: u64,
}

impl std::fmt::Display for NsId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.ino)
    }
}

/// Inode identity of a file, used to compare roots and executables.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileId {
    pub dev: u64,
    pub ino: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Namespaces {
    pub mnt: NsId,
    pub user: NsId,
    pub pid: NsId,
    pub net: NsId,
    pub ipc: NsId,
    pub uts: NsId,
    pub cgroup: NsId,
}

impl Namespaces {
    /// Names of the namespaces that differ from `other`.
    pub fn differences(&self, other: &Namespaces) -> Vec<&'static str> {
        let mut d = Vec::new();
        let pairs = [
            ("mnt", self.mnt, other.mnt),
            ("user", self.user, other.user),
            ("pid", self.pid, other.pid),
            ("net", self.net, other.net),
            ("ipc", self.ipc, other.ipc),
            ("uts", self.uts, other.uts),
            ("cgroup", self.cgroup, other.cgroup),
        ];
        for (name, a, b) in pairs {
            if a != b {
                d.push(name);
            }
        }
        d
    }
}

/// Fields of `/proc/<pid>/status` that identification uses or reports.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcStatus {
    pub ppid: Option<i32>,
    /// Real, effective, saved and filesystem UIDs, as seen from our user namespace.
    pub uids: Vec<u32>,
    pub no_new_privs: Option<bool>,
    pub seccomp_mode: Option<u8>,
}

const MAX_PROC_READ: u64 = 64 * 1024;

pub struct ProcessHandle {
    pidfd: OwnedFd,
    pid: i32,
    proc_dir: OwnedFd,
}

impl ProcessHandle {
    /// Binds to the process behind `pidfd`. `reported_pid` is the PID the
    /// bus reported alongside it; a mismatch is treated as inconsistent
    /// credentials.
    pub fn from_pidfd(pidfd: OwnedFd, reported_pid: Option<u32>) -> Result<Self, IdentityError> {
        let pid = pidfd_pid(pidfd.as_fd())?;
        if let Some(reported) = reported_pid
            && i64::from(reported) != i64::from(pid)
        {
            return Err(IdentityError::InconsistentCredentials("bus ProcessID does not match ProcessFD"));
        }
        let proc_dir = rustix::fs::openat(
            CWD,
            format!("/proc/{pid}"),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| IdentityError::Inspect("open /proc/<pid>", e.into()))?;
        let handle = ProcessHandle { pidfd, pid, proc_dir };
        handle.ensure_alive()?;
        Ok(handle)
    }

    pub fn pid(&self) -> i32 {
        self.pid
    }

    pub fn pidfd(&self) -> BorrowedFd<'_> {
        self.pidfd.as_fd()
    }

    /// Fails if the process has exited since we bound to it.
    pub fn ensure_alive(&self) -> Result<(), IdentityError> {
        if pidfd_has_exited(self.pidfd.as_fd())? {
            return Err(IdentityError::ProcessExited);
        }
        match pidfd_pid(self.pidfd.as_fd()) {
            Ok(p) if p == self.pid => Ok(()),
            Ok(_) => Err(IdentityError::InconsistentCredentials("pidfd changed PID")),
            Err(e) => Err(e),
        }
    }

    pub fn namespaces(&self) -> Result<Namespaces, IdentityError> {
        let ns = |name: &'static str| -> Result<NsId, IdentityError> {
            let st = rustix::fs::statat(&self.proc_dir, name, AtFlags::empty())
                .map_err(|e| IdentityError::Inspect(name, e.into()))?;
            Ok(NsId { dev: st.st_dev as u64, ino: st.st_ino as u64 })
        };
        let result = Namespaces {
            mnt: ns("ns/mnt")?,
            user: ns("ns/user")?,
            pid: ns("ns/pid")?,
            net: ns("ns/net")?,
            ipc: ns("ns/ipc")?,
            uts: ns("ns/uts")?,
            cgroup: ns("ns/cgroup")?,
        };
        self.ensure_alive()?;
        Ok(result)
    }

    /// Opens the process's root directory (following the `root` magic link,
    /// which is what makes the process's mount view reachable).
    pub fn open_root(&self) -> Result<OwnedFd, IdentityError> {
        let fd = rustix::fs::openat(
            &self.proc_dir,
            "root",
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| IdentityError::Inspect("open /proc/<pid>/root", e.into()))?;
        self.ensure_alive()?;
        Ok(fd)
    }

    pub fn root_id(&self) -> Result<FileId, IdentityError> {
        let root = self.open_root()?;
        let st = rustix::fs::fstat(&root).map_err(|e| IdentityError::Inspect("stat process root", e.into()))?;
        Ok(FileId { dev: st.st_dev as u64, ino: st.st_ino as u64 })
    }

    pub fn exe_id(&self) -> Result<FileId, IdentityError> {
        let st = rustix::fs::statat(&self.proc_dir, "exe", AtFlags::empty())
            .map_err(|e| IdentityError::Inspect("stat /proc/<pid>/exe", e.into()))?;
        self.ensure_alive()?;
        Ok(FileId { dev: st.st_dev as u64, ino: st.st_ino as u64 })
    }

    /// The executable's path as the kernel reports it. For display only:
    /// the path is interpreted in the process's own mount namespace.
    pub fn exe_path(&self) -> Result<String, IdentityError> {
        let target = rustix::fs::readlinkat(&self.proc_dir, "exe", Vec::new())
            .map_err(|e| IdentityError::Inspect("readlink /proc/<pid>/exe", e.into()))?;
        self.ensure_alive()?;
        Ok(target.to_string_lossy().into_owned())
    }

    pub fn status(&self) -> Result<ProcStatus, IdentityError> {
        let text = self.read_text("status")?;
        Ok(parse_status(&text))
    }

    /// The LSM label from `attr/current`, without the trailing NUL/newline.
    /// `None` if no LSM exposes one.
    pub fn security_label(&self) -> Result<Option<Vec<u8>>, IdentityError> {
        match read_at(&self.proc_dir, "attr/current", MAX_PROC_READ) {
            Ok(mut v) => {
                self.ensure_alive()?;
                while matches!(v.last(), Some(0 | b'\n')) {
                    v.pop();
                }
                Ok(Some(v))
            }
            Err(e) if is_absent(&e) => Ok(None),
            Err(e) => Err(IdentityError::Inspect("read attr/current", e)),
        }
    }

    fn read_text(&self, name: &'static str) -> Result<String, IdentityError> {
        let bytes = read_at(&self.proc_dir, name, MAX_PROC_READ).map_err(|e| IdentityError::Inspect(name, e))?;
        self.ensure_alive()?;
        String::from_utf8(bytes).map_err(|_| IdentityError::Malformed("non-UTF-8 procfs data"))
    }
}

fn is_absent(e: &std::io::Error) -> bool {
    matches!(e.raw_os_error(), Some(libc_errno::ENOENT | libc_errno::EINVAL | libc_errno::EOPNOTSUPP))
}

mod libc_errno {
    pub const ENOENT: i32 = rustix::io::Errno::NOENT.raw_os_error();
    pub const EINVAL: i32 = rustix::io::Errno::INVAL.raw_os_error();
    pub const EOPNOTSUPP: i32 = rustix::io::Errno::OPNOTSUPP.raw_os_error();
}

fn read_at(dir: impl AsFd, name: &str, limit: u64) -> std::io::Result<Vec<u8>> {
    let fd = rustix::fs::openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOCTTY | OFlags::NONBLOCK,
        Mode::empty(),
    )?;
    let mut buf = Vec::new();
    File::from(fd).take(limit).read_to_end(&mut buf)?;
    Ok(buf)
}

fn parse_status(text: &str) -> ProcStatus {
    let mut st = ProcStatus::default();
    for line in text.lines() {
        let Some((k, v)) = line.split_once(':') else { continue };
        let v = v.trim();
        match k {
            "PPid" => st.ppid = v.parse().ok(),
            "Uid" => st.uids = v.split_whitespace().filter_map(|x| x.parse().ok()).collect(),
            "NoNewPrivs" => st.no_new_privs = v.parse::<u8>().ok().map(|x| x != 0),
            "Seccomp" => st.seccomp_mode = v.parse().ok(),
            _ => {}
        }
    }
    st
}

/// The PID a pidfd refers to, in our PID namespace.
fn pidfd_pid(pidfd: BorrowedFd<'_>) -> Result<i32, IdentityError> {
    let path = format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd());
    let bytes = read_at(CWD, &path, MAX_PROC_READ).map_err(|e| IdentityError::Inspect("read pidfd fdinfo", e))?;
    let text = String::from_utf8(bytes).map_err(|_| IdentityError::Malformed("non-UTF-8 fdinfo"))?;
    let pid = text
        .lines()
        .find_map(|l| l.strip_prefix("Pid:"))
        .ok_or(IdentityError::Malformed("fd is not a pidfd"))?
        .trim()
        .parse::<i32>()
        .map_err(|_| IdentityError::Malformed("unparsable pidfd Pid"))?;
    match pid {
        -1 => Err(IdentityError::ProcessExited),
        0 => Err(IdentityError::ForeignPidNamespace),
        p if p > 0 => Ok(p),
        _ => Err(IdentityError::Malformed("negative pidfd Pid")),
    }
}

/// A pidfd becomes readable when the process exits.
fn pidfd_has_exited(pidfd: BorrowedFd<'_>) -> Result<bool, IdentityError> {
    use rustix::event::{PollFd, PollFlags, Timespec, poll};
    let mut fds = [PollFd::new(&pidfd, PollFlags::IN)];
    let zero = Timespec { tv_sec: 0, tv_nsec: 0 };
    poll(&mut fds, Some(&zero)).map_err(|e| IdentityError::Inspect("poll pidfd", e.into()))?;
    Ok(fds[0].revents().intersects(PollFlags::IN | PollFlags::HUP | PollFlags::ERR))
}

/// Our own process, used as the host reference. Opened through a pidfd so
/// the same code path applies.
pub fn self_handle() -> Result<ProcessHandle, IdentityError> {
    let pid = rustix::process::getpid();
    let pidfd = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty())
        .map_err(|e| IdentityError::Inspect("pidfd_open self", e.into()))?;
    ProcessHandle::from_pidfd(pidfd, Some(pid.as_raw_nonzero().get() as u32))
}

/// Opens a pidfd for an arbitrary PID. Only for diagnostics and for
/// checking Flatpak's recorded sandbox PID; never for identifying a caller.
pub fn handle_for_pid(pid: i32) -> Result<ProcessHandle, IdentityError> {
    let p = rustix::process::Pid::from_raw(pid).ok_or(IdentityError::Malformed("PID <= 0"))?;
    let pidfd = rustix::process::pidfd_open(p, rustix::process::PidfdFlags::empty())
        .map_err(|e| IdentityError::Inspect("pidfd_open", e.into()))?;
    ProcessHandle::from_pidfd(pidfd, Some(pid as u32))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_handle_works() {
        let h = self_handle().unwrap();
        let ns = h.namespaces().unwrap();
        assert!(ns.differences(&ns).is_empty());
        let st = h.status().unwrap();
        assert_eq!(st.uids.first().copied(), Some(rustix::process::getuid().as_raw()));
    }

    #[test]
    fn exited_child_is_rejected() {
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id() as i32;
        let p = rustix::process::Pid::from_raw(pid).unwrap();
        let pidfd = rustix::process::pidfd_open(p, rustix::process::PidfdFlags::empty()).unwrap();
        child.wait().unwrap();
        let err = ProcessHandle::from_pidfd(pidfd, Some(pid as u32)).err().unwrap();
        assert!(matches!(err, IdentityError::ProcessExited), "{err:?}");
    }

    #[test]
    fn handle_detects_later_exit() {
        let mut child = std::process::Command::new("sleep").arg("10").spawn().unwrap();
        let h = handle_for_pid(child.id() as i32).unwrap();
        h.ensure_alive().unwrap();
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(matches!(h.ensure_alive(), Err(IdentityError::ProcessExited)));
        assert!(h.namespaces().is_err());
    }

    #[test]
    fn pid_mismatch_is_inconsistent() {
        let pid = rustix::process::getpid();
        let pidfd = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()).unwrap();
        let err = ProcessHandle::from_pidfd(pidfd, Some(1)).err().unwrap();
        assert!(matches!(err, IdentityError::InconsistentCredentials(_)), "{err:?}");
    }
}
