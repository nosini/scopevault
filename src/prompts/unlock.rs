//! Coordinating vault unlocks.
//!
//! Every request that needs the vault unlocked calls
//! [`Unlocker::ensure_unlocked`]. At most one unlock dialog exists at a time:
//! concurrent requests wait for the same one. The dialog runs in its own
//! task; when every waiting request has gone away (for example because the
//! clients disconnected and their requests were dropped), the task is
//! aborted, which kills pinentry.
//!
//! If no vault exists yet, the same flow asks for a new password (entered
//! twice) and creates one.
//!
//! The slow key derivation runs on a blocking thread and does not hold the
//! vault lock, so other requests are not stalled by it.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::watch;
use tokio::task::AbortHandle;

use super::pinentry::{self, PinOutcome, PinRequest, PinentryConfig};
use crate::crypto::{KdfParams, VaultKey};
use crate::identity::Scope;
use crate::store::{StoreError, Vault};

pub const MAX_ATTEMPTS: usize = 3;
/// After a cancelled or failed dialog, automatic unlock attempts (requests
/// that need the vault but did not ask for a prompt) fail at once for this
/// long, so an app retrying in a loop cannot reopen the dialog over and over.
pub const IMPLICIT_COOLDOWN: Duration = Duration::from_secs(30);

/// The vault, or the place where it will be created.
pub struct VaultSlot {
    pub dir: PathBuf,
    pub vault: Option<Vault>,
}

impl VaultSlot {
    /// Opens the vault in `dir` if there is one (locked).
    pub fn open(dir: PathBuf) -> Result<Self, StoreError> {
        let vault = if Vault::exists(&dir) { Some(Vault::open(&dir)?) } else { None };
        Ok(VaultSlot { dir, vault })
    }

    pub fn is_unlocked(&self) -> bool {
        self.vault.as_ref().is_some_and(Vault::is_unlocked)
    }
}

pub type SharedVault = Arc<Mutex<VaultSlot>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnlockOutcome {
    Unlocked,
    /// The user dismissed the dialog, or ran out of attempts.
    Cancelled,
    /// Something is wrong that retrying will not fix. The message is safe
    /// to log and contains no secret.
    Failed(String),
}

struct Flight {
    id: u64,
    result: watch::Receiver<Option<UnlockOutcome>>,
    waiters: Arc<AtomicUsize>,
    abort: AbortHandle,
}

pub struct Unlocker {
    vault: SharedVault,
    pinentry: PinentryConfig,
    new_vault_kdf: KdfParams,
    flight: Mutex<Option<Flight>>,
    next_id: AtomicU64,
    /// Held while any dialog is shown, so dialogs never overlap.
    dialog_gate: tokio::sync::Mutex<()>,
    cooldown_until: Mutex<Option<Instant>>,
    unlocked_tx: tokio::sync::broadcast::Sender<()>,
}

/// Drops one waiter; the last one out cancels the dialog.
struct WaiterGuard {
    unlocker: Arc<Unlocker>,
    id: u64,
    waiters: Arc<AtomicUsize>,
}

impl Drop for WaiterGuard {
    fn drop(&mut self) {
        if self.waiters.fetch_sub(1, Ordering::AcqRel) == 1 {
            let mut f = self.unlocker.flight.lock().unwrap();
            if f.as_ref().is_some_and(|f| f.id == self.id)
                && let Some(f) = f.take()
            {
                f.abort.abort();
            }
        }
    }
}

fn display(scope: &Scope) -> String {
    match scope {
        Scope::Host => "An application on your computer".into(),
        Scope::Flatpak(id) => format!("The application {id}"),
    }
}

impl Unlocker {
    pub fn new(vault: SharedVault, pinentry: PinentryConfig, new_vault_kdf: KdfParams) -> Arc<Self> {
        Arc::new(Unlocker {
            vault,
            pinentry,
            new_vault_kdf,
            flight: Mutex::new(None),
            next_id: AtomicU64::new(1),
            dialog_gate: tokio::sync::Mutex::new(()),
            cooldown_until: Mutex::new(None),
            unlocked_tx: tokio::sync::broadcast::channel(4).0,
        })
    }

    pub fn vault(&self) -> &SharedVault {
        &self.vault
    }

    /// Notified each time a dialog unlocks (or creates) the vault.
    pub fn subscribe_unlocked(&self) -> tokio::sync::broadcast::Receiver<()> {
        self.unlocked_tx.subscribe()
    }

    /// Returns once the vault is unlocked, the user cancelled, or unlocking
    /// failed. `requester` is only used for the dialog text.
    pub async fn ensure_unlocked(self: &Arc<Self>, requester: &Scope) -> UnlockOutcome {
        if self.vault.lock().unwrap().is_unlocked() {
            return UnlockOutcome::Unlocked;
        }
        let (mut rx, guard) = {
            let mut slot = self.flight.lock().unwrap();
            let reuse = slot.as_ref().filter(|f| f.result.borrow().is_none());
            let flight = match reuse {
                Some(f) => f,
                None => {
                    let id = self.next_id.fetch_add(1, Ordering::Relaxed);
                    let (tx, rx) = watch::channel(None);
                    let this = self.clone();
                    let who = display(requester);
                    let task = tokio::spawn(async move {
                        let outcome = this.dialog(&who).await;
                        let _ = tx.send(Some(outcome));
                    });
                    *slot = Some(Flight {
                        id,
                        result: rx,
                        waiters: Arc::new(AtomicUsize::new(0)),
                        abort: task.abort_handle(),
                    });
                    slot.as_ref().unwrap()
                }
            };
            flight.waiters.fetch_add(1, Ordering::AcqRel);
            let guard = WaiterGuard { unlocker: self.clone(), id: flight.id, waiters: flight.waiters.clone() };
            (flight.result.clone(), guard)
        };
        let outcome = match rx.wait_for(Option::is_some).await {
            Ok(v) => v.clone().expect("waited for Some"),
            Err(_) => UnlockOutcome::Cancelled,
        };
        drop(guard);
        // A failing dialog (pinentry missing or unable to show) pauses
        // automatic unlocks too; otherwise every request would start
        // another pinentry at once.
        if outcome != UnlockOutcome::Unlocked {
            *self.cooldown_until.lock().unwrap() = Some(Instant::now() + IMPLICIT_COOLDOWN);
        }
        outcome
    }

    /// Like [`Unlocker::ensure_unlocked`], for requests that need the vault
    /// without having asked for a prompt. Shortly after a cancelled or failed
    /// dialog it returns `Cancelled` without showing another one.
    pub async fn ensure_unlocked_implicit(self: &Arc<Self>, requester: &Scope) -> UnlockOutcome {
        if self.vault.lock().unwrap().is_unlocked() {
            return UnlockOutcome::Unlocked;
        }
        if self.cooldown_until.lock().unwrap().is_some_and(|t| Instant::now() < t) {
            return UnlockOutcome::Cancelled;
        }
        self.ensure_unlocked(requester).await
    }

    /// Asks for the master password and checks it, without changing the
    /// vault. Used to reopen a collection its owner locked while the vault
    /// stays unlocked. Dropping the future closes the dialog.
    pub async fn confirm_password(self: &Arc<Self>, requester: &Scope) -> UnlockOutcome {
        let _gate = self.dialog_gate.lock().await;
        let who = display(requester);
        let mut error = None;
        for _ in 0..MAX_ATTEMPTS {
            let req = PinRequest {
                title: "Unlock collection".into(),
                description: format!(
                    "{who} wants to unlock one of its locked collections. Enter your keyring password to allow it."
                ),
                prompt: "Password:".into(),
                error: error.take(),
                repeat: None,
            };
            let password = match pinentry::ask(&self.pinentry, &req).await {
                Ok(PinOutcome::Entered(p)) => p,
                Ok(PinOutcome::Cancelled) => return UnlockOutcome::Cancelled,
                Err(e) => return UnlockOutcome::Failed(e.to_string()),
            };
            let wrap = match self.vault.lock().unwrap().vault.as_ref().map(Vault::key_wrap) {
                Some(Ok(w)) => w,
                Some(Err(e)) => return UnlockOutcome::Failed(e.to_string()),
                None => return UnlockOutcome::Failed("no vault".into()),
            };
            match tokio::task::spawn_blocking(move || VaultKey::unwrap(&wrap, password.as_bytes()).map(drop)).await {
                Ok(Ok(())) => return UnlockOutcome::Unlocked,
                Ok(Err(crate::crypto::CryptoError::Unwrap)) => error = Some("Wrong password. Try again.".into()),
                Ok(Err(e)) => return UnlockOutcome::Failed(e.to_string()),
                Err(e) => return UnlockOutcome::Failed(e.to_string()),
            }
        }
        UnlockOutcome::Cancelled
    }

    async fn dialog(&self, who: &str) -> UnlockOutcome {
        let _gate = self.dialog_gate.lock().await;
        if self.vault.lock().unwrap().is_unlocked() {
            return UnlockOutcome::Unlocked;
        }
        let exists = self.vault.lock().unwrap().vault.is_some();
        let outcome = if exists { self.unlock_dialog(who).await } else { self.create_dialog(who).await };
        if outcome == UnlockOutcome::Unlocked {
            let _ = self.unlocked_tx.send(());
        }
        outcome
    }

    async fn unlock_dialog(&self, who: &str) -> UnlockOutcome {
        let mut error = None;
        for _ in 0..MAX_ATTEMPTS {
            let req = PinRequest {
                title: "Unlock keyring".into(),
                description: format!(
                    "{who} wants to use its stored passwords. Enter your keyring password to unlock the keyring."
                ),
                prompt: "Password:".into(),
                error: error.take(),
                repeat: None,
            };
            let password = match pinentry::ask(&self.pinentry, &req).await {
                Ok(PinOutcome::Entered(p)) => p,
                Ok(PinOutcome::Cancelled) => return UnlockOutcome::Cancelled,
                Err(e) => return UnlockOutcome::Failed(e.to_string()),
            };
            let wrap = {
                let slot = self.vault.lock().unwrap();
                if slot.is_unlocked() {
                    return UnlockOutcome::Unlocked;
                }
                match slot.vault.as_ref().map(Vault::key_wrap) {
                    Some(Ok(w)) => w,
                    Some(Err(e)) => return UnlockOutcome::Failed(e.to_string()),
                    None => return UnlockOutcome::Failed("vault disappeared".into()),
                }
            };
            let key = tokio::task::spawn_blocking(move || VaultKey::unwrap(&wrap, password.as_bytes())).await;
            match key {
                Ok(Ok(key)) => {
                    let vault = self.vault.clone();
                    let r = tokio::task::spawn_blocking(move || {
                        let mut slot = vault.lock().unwrap();
                        slot.vault.as_mut().expect("checked above").unlock_with_key(key)
                    })
                    .await;
                    return match r {
                        Ok(Ok(())) => UnlockOutcome::Unlocked,
                        Ok(Err(e)) => UnlockOutcome::Failed(e.to_string()),
                        Err(e) => UnlockOutcome::Failed(e.to_string()),
                    };
                }
                Ok(Err(crate::crypto::CryptoError::Unwrap)) => error = Some("Wrong password. Try again.".into()),
                Ok(Err(e)) => return UnlockOutcome::Failed(e.to_string()),
                Err(e) => return UnlockOutcome::Failed(e.to_string()),
            }
        }
        UnlockOutcome::Cancelled
    }

    async fn create_dialog(&self, who: &str) -> UnlockOutcome {
        let req = PinRequest {
            title: "Create keyring password".into(),
            description: format!(
                "{who} wants to store a password. Choose a password to protect the passwords your applications store. \
                 You will need it to unlock them after logging in."
            ),
            prompt: "New password:".into(),
            error: None,
            repeat: Some("Repeat:".into()),
        };
        let password = match pinentry::ask(&self.pinentry, &req).await {
            Ok(PinOutcome::Entered(p)) if p.is_empty() => return UnlockOutcome::Cancelled,
            Ok(PinOutcome::Entered(p)) => p,
            Ok(PinOutcome::Cancelled) => return UnlockOutcome::Cancelled,
            Err(e) => return UnlockOutcome::Failed(e.to_string()),
        };
        let vault = self.vault.clone();
        let kdf = self.new_vault_kdf;
        let r = tokio::task::spawn_blocking(move || {
            let mut slot = vault.lock().unwrap();
            if slot.vault.is_some() {
                return Err(StoreError::Exists);
            }
            let v = Vault::create(&slot.dir, password.as_bytes(), kdf)?;
            slot.vault = Some(v);
            Ok(())
        })
        .await;
        match r {
            Ok(Ok(())) => UnlockOutcome::Unlocked,
            Ok(Err(e)) => UnlockOutcome::Failed(e.to_string()),
            Err(e) => UnlockOutcome::Failed(e.to_string()),
        }
    }
}
