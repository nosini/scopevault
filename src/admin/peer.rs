//! Credentials of the process at the other end of a Unix socket, as the
//! kernel reports them: the same inputs the bus daemon reports for a D-Bus
//! connection, so the same [`crate::identity::Classifier`] applies.

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

use crate::identity::BusCredentials;

/// Labels are short; anything longer is refused rather than truncated.
const MAX_LABEL: usize = 4096;

/// UID and PID (`SO_PEERCRED`), a pidfd (`SO_PEERPIDFD`, Linux 6.5+) and
/// the LSM label (`SO_PEERSEC`) of the socket's peer, all captured by the
/// kernel when the peer connected. A missing pidfd or label is reported as
/// `None`; the classifier refuses a peer without a pidfd.
pub fn peer_credentials(sock: BorrowedFd<'_>) -> std::io::Result<BusCredentials> {
    let cred = rustix::net::sockopt::socket_peercred(sock)?;
    let pidfd = {
        let mut fd: libc::c_int = -1;
        match getsockopt(sock, libc::SO_PEERPIDFD, std::ptr::from_mut(&mut fd).cast(), size_of::<libc::c_int>()) {
            Ok(n) if n == size_of::<libc::c_int>() && fd >= 0 => {
                // SAFETY: on success the kernel installed a new descriptor
                // that nothing else owns.
                let fd = unsafe { OwnedFd::from_raw_fd(fd) };
                rustix::io::fcntl_setfd(&fd, rustix::io::FdFlags::CLOEXEC)?;
                Some(fd)
            }
            Ok(_) => None,
            Err(e) if e.raw_os_error() == Some(libc::ENOPROTOOPT) => None,
            Err(e) => return Err(e),
        }
    };
    let security_label = {
        let mut buf = vec![0u8; MAX_LABEL];
        match getsockopt(sock, libc::SO_PEERSEC, buf.as_mut_ptr().cast(), buf.len()) {
            Ok(n) => {
                buf.truncate(n);
                Some(buf)
            }
            // No LSM providing labels.
            Err(e) if e.raw_os_error() == Some(libc::ENOPROTOOPT) => None,
            Err(e) => return Err(e),
        }
    };
    Ok(BusCredentials {
        uid: Some(cred.uid.as_raw()),
        pid: u32::try_from(cred.pid.as_raw_nonzero().get()).ok(),
        pidfd,
        security_label,
    })
}

/// `getsockopt(SOL_SOCKET, option)` into `len` bytes at `value`; returns the
/// length the kernel wrote.
fn getsockopt(
    sock: BorrowedFd<'_>,
    option: libc::c_int,
    value: *mut libc::c_void,
    len: usize,
) -> std::io::Result<usize> {
    let mut len = libc::socklen_t::try_from(len).map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
    // SAFETY: `sock` is a valid descriptor for the duration of the call, and
    // `value` points to `len` writable bytes owned by the caller.
    let r = unsafe { libc::getsockopt(sock.as_fd().as_raw_fd(), libc::SOL_SOCKET, option, value, &mut len) };
    if r != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(len as usize)
}
