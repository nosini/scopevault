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

use std::collections::{HashMap, VecDeque};
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
/// Explicit prompts (an app's `Unlock` or `CreateCollection`) always show a
/// dialog, but once a scope's dialogs were cancelled or failed this many
/// times within [`EXPLICIT_REFUSAL_WINDOW`], its further prompts are
/// dismissed without one until the oldest of those refusals is that old.
/// An app cannot reopen the dialog after every cancel; other apps are not
/// affected.
pub const EXPLICIT_REFUSAL_LIMIT: usize = 3;
pub const EXPLICIT_REFUSAL_WINDOW: Duration = Duration::from_secs(120);

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
    explicit_refusals: Mutex<HashMap<Scope, VecDeque<Instant>>>,
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

/// How dialogs name the administrative tool.
const ADMIN: &str = "The keyring administration tool (scopevault-admin)";

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
            explicit_refusals: Mutex::default(),
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
        self.ensure_unlocked_as(display(requester)).await
    }

    /// [`Unlocker::ensure_unlocked`] for the administrative interface.
    pub async fn ensure_unlocked_admin(self: &Arc<Self>) -> UnlockOutcome {
        self.ensure_unlocked_as(ADMIN.into()).await
    }

    /// `who` names the requester in the dialog, if one is started.
    async fn ensure_unlocked_as(self: &Arc<Self>, who: String) -> UnlockOutcome {
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

    /// Whether an explicit prompt of `scope` may show a dialog now (see
    /// [`EXPLICIT_REFUSAL_LIMIT`]).
    pub fn explicit_dialog_allowed(&self, scope: &Scope) -> bool {
        let mut all = self.explicit_refusals.lock().unwrap();
        let Some(times) = all.get_mut(scope) else { return true };
        while times.front().is_some_and(|t| t.elapsed() >= EXPLICIT_REFUSAL_WINDOW) {
            times.pop_front();
        }
        if times.is_empty() {
            all.remove(scope);
            return true;
        }
        times.len() < EXPLICIT_REFUSAL_LIMIT
    }

    /// Records that an explicit prompt's dialog was cancelled or failed.
    pub fn record_explicit_refusal(&self, scope: &Scope) {
        let mut all = self.explicit_refusals.lock().unwrap();
        let times = all.entry(scope.clone()).or_default();
        times.push_back(Instant::now());
        while times.len() > EXPLICIT_REFUSAL_LIMIT {
            times.pop_front();
        }
    }

    /// Asks for the master password and checks it, without changing the
    /// vault. Used to reopen a collection its owner locked while the vault
    /// stays unlocked. Dropping the future closes the dialog.
    pub async fn confirm_password(self: &Arc<Self>, requester: &Scope) -> UnlockOutcome {
        let who = display(requester);
        let description =
            format!("{who} wants to unlock one of its locked collections. Enter your keyring password to allow it.");
        self.confirm("Unlock collection", &description).await
    }

    /// Asks for the master password to allow an administrative action,
    /// described by `action` ("move 2 items from ... to ...").
    pub async fn confirm_admin(self: &Arc<Self>, action: &str) -> UnlockOutcome {
        let description = format!("{ADMIN} wants to {action}. Enter your keyring password to allow it.");
        self.confirm("Allow keyring administration", &description).await
    }

    async fn confirm(self: &Arc<Self>, title: &str, description: &str) -> UnlockOutcome {
        let _gate = self.dialog_gate.lock().await;
        let mut error = None;
        for _ in 0..MAX_ATTEMPTS {
            let req = PinRequest {
                title: title.into(),
                description: description.into(),
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

    /// Asks for the current password, then a new one (twice), and rewraps
    /// the vault key. The passwords go only to this process. The slow key
    /// derivations run without holding the vault.
    pub async fn change_password(self: &Arc<Self>) -> UnlockOutcome {
        let (key, old_wrap) = match self.current_key("Change keyring password").await {
            Ok(k) => k,
            Err(outcome) => return outcome,
        };
        let _gate = self.dialog_gate.lock().await;
        let req = PinRequest {
            title: "Change keyring password".into(),
            description: "Choose a new keyring password.".into(),
            prompt: "New password:".into(),
            error: None,
            repeat: Some("Repeat:".into()),
        };
        let new = match pinentry::ask(&self.pinentry, &req).await {
            Ok(PinOutcome::Entered(p)) if p.is_empty() => return UnlockOutcome::Cancelled,
            Ok(PinOutcome::Entered(p)) => p,
            Ok(PinOutcome::Cancelled) => return UnlockOutcome::Cancelled,
            Err(e) => return UnlockOutcome::Failed(e.to_string()),
        };
        let kdf = self.new_vault_kdf;
        let new_wrap = match tokio::task::spawn_blocking(move || key.wrap(new.as_bytes(), kdf)).await {
            Ok(Ok(w)) => w,
            Ok(Err(e)) => return UnlockOutcome::Failed(e.to_string()),
            Err(e) => return UnlockOutcome::Failed(e.to_string()),
        };
        let mut slot = self.vault.lock().unwrap();
        match slot.vault.as_mut().map(|v| v.replace_key_wrap(&old_wrap, &new_wrap)) {
            Some(Ok(())) => UnlockOutcome::Unlocked,
            Some(Err(e)) => UnlockOutcome::Failed(e.to_string()),
            None => UnlockOutcome::Failed("no vault exists yet".into()),
        }
    }

    /// Asks for the current master password until it is right; returns the
    /// vault key and the wrap it came from.
    async fn current_key(&self, title: &str) -> Result<(VaultKey, crate::crypto::KeyWrap), UnlockOutcome> {
        let _gate = self.dialog_gate.lock().await;
        let mut error = None;
        for _ in 0..MAX_ATTEMPTS {
            let req = PinRequest {
                title: title.into(),
                description: format!("{ADMIN} wants to change the keyring password. Enter the current password."),
                prompt: "Current password:".into(),
                error: error.take(),
                repeat: None,
            };
            let password = match pinentry::ask(&self.pinentry, &req).await {
                Ok(PinOutcome::Entered(p)) => p,
                Ok(PinOutcome::Cancelled) => return Err(UnlockOutcome::Cancelled),
                Err(e) => return Err(UnlockOutcome::Failed(e.to_string())),
            };
            let wrap = match self.vault.lock().unwrap().vault.as_ref().map(Vault::key_wrap) {
                Some(Ok(w)) => w,
                Some(Err(e)) => return Err(UnlockOutcome::Failed(e.to_string())),
                None => return Err(UnlockOutcome::Failed("no vault exists yet".into())),
            };
            let w = wrap.clone();
            match tokio::task::spawn_blocking(move || VaultKey::unwrap(&w, password.as_bytes())).await {
                Ok(Ok(key)) => return Ok((key, wrap)),
                Ok(Err(crate::crypto::CryptoError::Unwrap)) => error = Some("Wrong password. Try again.".into()),
                Ok(Err(e)) => return Err(UnlockOutcome::Failed(e.to_string())),
                Err(e) => return Err(UnlockOutcome::Failed(e.to_string())),
            }
        }
        Err(UnlockOutcome::Cancelled)
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
