//! The login socket, served by the daemon: `$XDG_RUNTIME_DIR/scopevault/login`.
//!
//! `scopevault-pam-helper` delivers the login password here (see
//! [`super::protocol`]). The helper is started by the PAM module inside
//! GDM's session worker or `passwd`, dropped to the user, so its SELinux
//! label is theirs (`xdm_t`, `passwd_t`), not the session's. Peers are
//! therefore classified with the host check minus the label comparison:
//! same UID, not a Flatpak, and the same namespaces and root as the daemon.
//! That is enough here because the socket can only unlock the vault with a
//! correct password and only rewrap the login slot under the current login
//! password; it is not the admin socket, which stays strict.

use std::os::fd::AsFd;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;
use zeroize::Zeroize;

use super::protocol::Request;
use super::{LoginUnlock, Outcome};
use crate::admin::peer::peer_credentials;
use crate::admin::server::PeerClassifier;
use crate::identity::{Classifier, IdentityPolicy, Principal};

const MAX_CLIENTS: usize = 4;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// The default socket path, beside the admin socket.
pub fn default_socket_path() -> Option<std::path::PathBuf> {
    crate::admin::server::default_socket_path().map(|p| p.with_file_name("login"))
}

/// `base` without the LSM label comparison, for this socket only.
pub fn relaxed_classifier(base: &Classifier) -> Classifier {
    Classifier {
        baseline: base.baseline.clone(),
        instances: base.instances.clone(),
        policy: IdentityPolicy { require_host_label_match: false, ..base.policy.clone() },
    }
}

pub struct LoginServer {
    classify: PeerClassifier,
    login: Arc<LoginUnlock>,
    slots: Arc<Semaphore>,
}

impl LoginServer {
    pub fn new(classify: PeerClassifier, login: Arc<LoginUnlock>) -> Arc<Self> {
        Arc::new(LoginServer { classify, login, slots: Arc::new(Semaphore::new(MAX_CLIENTS)) })
    }

    pub async fn serve(self: Arc<Self>, listener: &UnixListener) {
        loop {
            let stream = match listener.accept().await {
                Ok((s, _)) => s,
                Err(e) => {
                    tracing::warn!(error = %e, "login socket: accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let Ok(permit) = self.slots.clone().try_acquire_owned() else {
                tracing::warn!("login socket: too many clients; connection closed");
                continue;
            };
            let this = self.clone();
            tokio::spawn(async move {
                let _permit = permit;
                this.handle(stream).await;
            });
        }
    }

    async fn allowed(&self, stream: &UnixStream) -> bool {
        let creds = match peer_credentials(stream.as_fd()) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "login socket: cannot read peer credentials");
                return false;
            }
        };
        let classify = self.classify.clone();
        match tokio::task::spawn_blocking(move || classify(creds)).await {
            Ok(Ok(Principal::Host)) => true,
            Ok(Ok(other)) => {
                tracing::warn!(scope = %other.scope(), "login socket: refused a sandboxed caller");
                false
            }
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "login socket: refused an unidentified caller");
                false
            }
            Err(e) => {
                tracing::warn!(error = %e, "login socket: classification failed");
                false
            }
        }
    }

    async fn handle(&self, mut stream: UnixStream) {
        let outcome = if !self.allowed(&stream).await {
            Outcome::Refused("access denied")
        } else {
            match tokio::time::timeout(REQUEST_TIMEOUT, Request::read(&mut stream)).await {
                Ok(Ok(Request::Deliver(password))) => {
                    let o = self.login.deliver(password).await;
                    log("login password delivered", &o);
                    o
                }
                Ok(Ok(Request::Change { old, new })) => {
                    let o = self.login.change(old, new).await;
                    log("login password change", &o);
                    o
                }
                Ok(Err(e)) => {
                    tracing::info!(error = %e, "login socket: bad request");
                    Outcome::Refused("bad request")
                }
                Err(_) => return,
            }
        };
        let _ = stream.write_all(format!("{}\n", outcome.word()).as_bytes()).await;
        let _ = stream.shutdown().await;
        // A refused request may not have been read (or not to its end).
        // Closing with unread input would reset the connection and the
        // client might lose the answer, so read a little of it first.
        let mut sink = [0u8; 512];
        let mut left: usize = 4 * 1024;
        let drain = async {
            while left > 0 {
                match stream.read(&mut sink).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => left = left.saturating_sub(n),
                }
            }
        };
        let _ = tokio::time::timeout(Duration::from_secs(1), drain).await;
        sink.zeroize();
    }
}

fn log(what: &str, o: &Outcome) {
    match o {
        Outcome::Refused(why) => tracing::info!(outcome = o.word(), reason = why, "{what}"),
        Outcome::Failed(e) => tracing::warn!(outcome = o.word(), error = %e, "{what}"),
        _ => tracing::info!(outcome = o.word(), "{what}"),
    }
}
