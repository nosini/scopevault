//! Coordinating vault unlocks.
//!
//! Every request that needs the vault unlocked calls
//! [`Unlocker::ensure_unlocked`]. At most one unlock dialog exists at a time:
//! concurrent requests wait for the same one. The dialog runs in its own
//! task; when every waiting request has gone away (for example because the
//! clients disconnected and their requests were dropped), the task is
//! aborted, which kills pinentry.
//!
//! Requests that did not ask for a prompt (and the Secret portal's) do not
//! fail while a dialog was cancelled or failed: they wait for an unlock by
//! anything else — another dialog, an explicit prompt, `scopevault-admin
//! unlock` — up to their deadline ([`UnlockTimings::implicit_wait`]), so an
//! unlock at login serves the applications that started with it.
//!
//! If no vault exists yet, the same flow asks for a new password (entered
//! twice) and creates one.
//!
//! The slow key derivation runs on a blocking thread and does not hold the
//! vault lock, so other requests are not stalled by it.
//!
//! The vault can also be unlocked without a dialog, through a key slot
//! ([`Unlocker::unlock_with_slot`], the login password). That serves every
//! waiting request and closes an unlock dialog that is open.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::watch;
use tokio::task::AbortHandle;

use super::pinentry::{self, PinOutcome, PinRequest, PinentryConfig, PinentryError};
use zeroize::Zeroizing;

use crate::crypto::{KdfParams, Slot, VaultKey};
use crate::identity::Scope;
use crate::store::{StoreError, Vault};

pub const MAX_ATTEMPTS: usize = 3;
/// After a cancelled or failed dialog, implicit and portal requests wait
/// without opening another dialog for this long (an app retrying in a loop
/// must not reopen the dialog over and over). Requests that ask for a
/// prompt explicitly are not subject to it.
pub const IMPLICIT_COOLDOWN: Duration = Duration::from_secs(30);
/// How long an implicit or portal request waits for an unlock — its own or
/// another request's dialog — before it gives up.
pub const IMPLICIT_WAIT: Duration = Duration::from_secs(300);
/// A pinentry that cannot show its window yet (the session prompter is not
/// up, so it falls back to curses and fails without a terminal) is retried
/// after this long.
pub const NOT_READY_DELAY: Duration = Duration::from_secs(2);
/// Retries for a prompter that is not ready stop once this long has passed
/// since the dialog's first attempt.
pub const NOT_READY_WINDOW: Duration = Duration::from_secs(30);
/// Explicit prompts (an app's `Unlock` or `CreateCollection`) always show a
/// dialog, but once a scope's dialogs were cancelled or failed this many
/// times within [`EXPLICIT_REFUSAL_WINDOW`], its further prompts are
/// dismissed without one until the oldest of those refusals is that old.
/// An app cannot reopen the dialog after every cancel; other apps are not
/// affected.
pub const EXPLICIT_REFUSAL_LIMIT: usize = 3;
/// Why an unlock did not complete: a global lock came while its key was
/// derived.
const LOCKED_MEANWHILE: &str = "the vault was locked while the key was derived";
pub const EXPLICIT_REFUSAL_WINDOW: Duration = Duration::from_secs(120);

/// The waits around unlocking, configurable so tests do not need the
/// defaults' patience.
#[derive(Debug, Clone, Copy)]
pub struct UnlockTimings {
    pub implicit_wait: Duration,
    pub not_ready_delay: Duration,
    pub not_ready_window: Duration,
}

impl Default for UnlockTimings {
    fn default() -> Self {
        UnlockTimings {
            implicit_wait: IMPLICIT_WAIT,
            not_ready_delay: NOT_READY_DELAY,
            not_ready_window: NOT_READY_WINDOW,
        }
    }
}

/// The vault, or the place where it will be created.
pub struct VaultSlot {
    pub dir: PathBuf,
    pub vault: Option<Vault>,
    /// Counts global locks; see [`VaultSlot::lock`].
    lock_epoch: u64,
}

impl VaultSlot {
    pub fn new(dir: PathBuf, vault: Option<Vault>) -> Self {
        VaultSlot { dir, vault, lock_epoch: 0 }
    }

    /// Opens the vault in `dir` if there is one (locked).
    pub fn open(dir: PathBuf) -> Result<Self, StoreError> {
        let vault = if Vault::exists(&dir) { Some(Vault::open(&dir)?) } else { None };
        Ok(Self::new(dir, vault))
    }

    pub fn is_unlocked(&self) -> bool {
        self.vault.as_ref().is_some_and(Vault::is_unlocked)
    }

    /// Global lock. Every call counts, also on a vault that is locked
    /// already: an unlock whose key derivation started before it does not
    /// complete (see [`VaultSlot::lock_epoch`]). Returns whether the vault
    /// was unlocked. [`Unlocker::lock`] also tells those who wait for it.
    fn lock(&mut self) -> bool {
        self.lock_epoch += 1;
        let was_unlocked = self.is_unlocked();
        if let Some(v) = self.vault.as_mut() {
            v.lock();
        }
        was_unlocked
    }

    /// Changes with every global lock. An unlock notes it before deriving
    /// the key and installs the key only if it is unchanged.
    pub fn lock_epoch(&self) -> u64 {
        self.lock_epoch
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
    /// Shared with the dialog task; an unlock through a key slot settles the
    /// flight from outside.
    settle: Arc<watch::Sender<Option<UnlockOutcome>>>,
    result: watch::Receiver<Option<UnlockOutcome>>,
    waiters: Arc<AtomicUsize>,
    abort: AbortHandle,
}

pub struct Unlocker {
    vault: SharedVault,
    pinentry: PinentryConfig,
    new_vault_kdf: KdfParams,
    timings: UnlockTimings,
    flight: Mutex<Option<Flight>>,
    next_id: AtomicU64,
    /// Held while any dialog is shown, so dialogs never overlap.
    dialog_gate: tokio::sync::Mutex<()>,
    cooldown_until: Mutex<Option<Instant>>,
    explicit_refusals: Mutex<HashMap<Scope, VecDeque<Instant>>>,
    unlocked_tx: tokio::sync::broadcast::Sender<()>,
    locked_tx: tokio::sync::broadcast::Sender<()>,
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
        Scope::Portal => "The Secret portal".into(),
    }
}

impl Unlocker {
    pub fn new(vault: SharedVault, pinentry: PinentryConfig, new_vault_kdf: KdfParams) -> Arc<Self> {
        Self::with_timings(vault, pinentry, new_vault_kdf, UnlockTimings::default())
    }

    /// [`Unlocker::new`] with other waits (tests use short ones).
    pub fn with_timings(
        vault: SharedVault,
        pinentry: PinentryConfig,
        new_vault_kdf: KdfParams,
        timings: UnlockTimings,
    ) -> Arc<Self> {
        Arc::new(Unlocker {
            vault,
            pinentry,
            new_vault_kdf,
            timings,
            flight: Mutex::new(None),
            next_id: AtomicU64::new(1),
            dialog_gate: tokio::sync::Mutex::new(()),
            cooldown_until: Mutex::new(None),
            explicit_refusals: Mutex::default(),
            unlocked_tx: tokio::sync::broadcast::channel(4).0,
            locked_tx: tokio::sync::broadcast::channel(4).0,
        })
    }

    pub fn vault(&self) -> &SharedVault {
        &self.vault
    }

    /// Global lock of `slot`, which is this unlocker's vault, locked by the
    /// caller (who may look at it first). See [`VaultSlot::lock`]; returns
    /// whether the vault was unlocked.
    pub fn lock(&self, slot: &mut VaultSlot) -> bool {
        let was_unlocked = slot.lock();
        let _ = self.locked_tx.send(());
        was_unlocked
    }

    /// Notified at each global lock, whether or not the vault was unlocked.
    pub fn subscribe_locked(&self) -> tokio::sync::broadcast::Receiver<()> {
        self.locked_tx.subscribe()
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
                    let settle = Arc::new(tx);
                    let tx = settle.clone();
                    let this = self.clone();
                    let task = tokio::spawn(async move {
                        let outcome = this.dialog(&who).await;
                        settle_once(&tx, outcome);
                    });
                    *slot = Some(Flight {
                        id,
                        settle,
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
    /// without having asked for a prompt: instead of failing while the
    /// cooldown is active they wait for an unlock by anything else, up to
    /// [`UnlockTimings::implicit_wait`] after `since` (when the request
    /// arrived), so a request made while the user is still answering one
    /// dialog is served by it.
    pub async fn ensure_unlocked_implicit(self: &Arc<Self>, requester: &Scope, since: Instant) -> UnlockOutcome {
        self.wait_for_unlock(display(requester), since).await
    }

    /// [`Unlocker::ensure_unlocked_implicit`] for the Secret portal backend:
    /// the dialog names the application whose key is wanted. `app_id` is
    /// validated before this is called. Without a vault it fails without a
    /// dialog: the portal never creates one.
    pub async fn ensure_unlocked_portal(self: &Arc<Self>, app_id: &str) -> UnlockOutcome {
        if self.vault.lock().unwrap().vault.is_none() {
            return UnlockOutcome::Failed("no vault".into());
        }
        self.wait_for_unlock(format!("The application {app_id}"), Instant::now()).await
    }

    /// The waiting loop behind [`Unlocker::ensure_unlocked_implicit`] and
    /// [`Unlocker::ensure_unlocked_portal`]: until the deadline, join or
    /// start the shared dialog while no cooldown is active, and wait without
    /// opening another one while it is. A waiting request never opens a
    /// second dialog, so it does not wake up when the cooldown expires; a
    /// new request arriving after the cooldown has expired does, as usual.
    async fn wait_for_unlock(self: &Arc<Self>, who: String, started: Instant) -> UnlockOutcome {
        // Subscribed before the first check, so an unlock in between is not
        // missed.
        let mut unlocked = self.unlocked_tx.subscribe();
        let deadline = tokio::time::Instant::from_std(started + self.timings.implicit_wait);
        'wait: loop {
            if self.vault.lock().unwrap().is_unlocked() {
                return UnlockOutcome::Unlocked;
            }
            // A request that waited in its connection's queue until after
            // its deadline opens no dialog (`timeout_at` would start one).
            if tokio::time::Instant::now() >= deadline {
                break 'wait;
            }
            let cooling_down = self.cooldown_until.lock().unwrap().is_some_and(|t| Instant::now() < t);
            if cooling_down {
                match tokio::time::timeout_at(deadline, unlocked_by(&mut unlocked)).await {
                    Err(_) => break 'wait,
                    Ok(true) => continue,
                    // The unlocker itself is gone; nothing will unlock.
                    Ok(false) => return UnlockOutcome::Cancelled,
                }
            }
            match tokio::time::timeout_at(deadline, self.ensure_unlocked_as(who.clone())).await {
                Ok(UnlockOutcome::Unlocked) => return UnlockOutcome::Unlocked,
                // The dialog ended cancelled or failed, which started the
                // cooldown; keep waiting instead of failing the request.
                Ok(_) => continue,
                Err(_) => break 'wait,
            }
        }
        tracing::info!(who = %who, waited = started.elapsed().as_secs(), "request gave up waiting for the unlock");
        UnlockOutcome::Cancelled
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
    ///
    /// This is an explicit prompt of `requester`: `None` means it was over
    /// the refusal limit and no dialog was shown. The limit is checked when
    /// the dialog's turn comes, and a cancel or failure is recorded before
    /// the next dialog may start, so prompts that wait together cannot get
    /// past it.
    pub async fn confirm_password(self: &Arc<Self>, requester: &Scope) -> Option<UnlockOutcome> {
        let who = display(requester);
        let description =
            format!("{who} wants to unlock one of its locked collections. Enter your keyring password to allow it.");
        let _gate = self.dialog_gate.lock().await;
        if !self.explicit_dialog_allowed(requester) {
            return None;
        }
        let outcome = self.confirm("Unlock collection", &description).await;
        if outcome != UnlockOutcome::Unlocked {
            self.record_explicit_refusal(requester);
        }
        Some(outcome)
    }

    /// Asks for the master password to allow an administrative action,
    /// described by `action` ("move 2 items from ... to ...").
    pub async fn confirm_admin(self: &Arc<Self>, action: &str) -> UnlockOutcome {
        let description = format!("{ADMIN} wants to {action}. Enter your keyring password to allow it.");
        let _gate = self.dialog_gate.lock().await;
        self.confirm("Allow keyring administration", &description).await
    }

    /// The password dialog behind the confirmations; the caller holds
    /// `dialog_gate`.
    async fn confirm(self: &Arc<Self>, title: &str, description: &str) -> UnlockOutcome {
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

    /// The key derivation cost for new wraps of the vault key: the master
    /// wrap's, so the login slot or a new master password costs an attacker
    /// as much as the vault's password does now. Without a vault, the cost
    /// chosen for a new one.
    pub fn kdf(&self) -> KdfParams {
        let slot = self.vault.lock().unwrap();
        slot.vault.as_ref().and_then(|v| v.key_wrap().ok()).map_or(self.new_vault_kdf, |w| w.kdf)
    }

    /// Asks for a password that is not the master password (the login
    /// password, to set up the login slot) in the daemon's dialog. The
    /// caller checks it.
    pub async fn ask_password(&self, title: &str, description: &str) -> Result<Zeroizing<String>, UnlockOutcome> {
        let _gate = self.dialog_gate.lock().await;
        let req = PinRequest {
            title: title.into(),
            description: description.into(),
            prompt: "Password:".into(),
            error: None,
            repeat: None,
        };
        match pinentry::ask(&self.pinentry, &req).await {
            Ok(PinOutcome::Entered(p)) if p.is_empty() => Err(UnlockOutcome::Cancelled),
            Ok(PinOutcome::Entered(p)) => Ok(p),
            Ok(PinOutcome::Cancelled) => Err(UnlockOutcome::Cancelled),
            Err(e) => Err(UnlockOutcome::Failed(e.to_string())),
        }
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
        let kdf = old_wrap.kdf;
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
        let started = Instant::now();
        let outcome = if exists { self.unlock_dialog(who).await } else { self.create_dialog(who).await };
        let elapsed = started.elapsed().as_millis() as u64;
        match &outcome {
            UnlockOutcome::Unlocked if exists => tracing::info!(who, elapsed_ms = elapsed, "unlock dialog: unlocked"),
            UnlockOutcome::Unlocked => tracing::info!(who, elapsed_ms = elapsed, "unlock dialog: vault created"),
            UnlockOutcome::Cancelled => tracing::info!(who, elapsed_ms = elapsed, "unlock dialog: cancelled"),
            UnlockOutcome::Failed(reason) => {
                tracing::warn!(who, elapsed_ms = elapsed, reason = %reason, "unlock dialog failed")
            }
        }
        if outcome == UnlockOutcome::Unlocked {
            let _ = self.unlocked_tx.send(());
        }
        outcome
    }

    /// Runs one `pinentry::ask`, retrying while the prompter may not be up
    /// yet: a pinentry that cannot show its window fails with an I/O or
    /// protocol error and is tried again after `not_ready_delay`, as long as
    /// less than `not_ready_window` has passed since `started`. A retry is
    /// the same request (same text, same `error` line) and does not use up a
    /// password attempt. `Spawn` and `Timeout` are never retried, and a
    /// cancel ends at once.
    async fn ask_retry(&self, req: &PinRequest, started: Instant) -> Result<PinOutcome, PinentryError> {
        loop {
            match pinentry::ask(&self.pinentry, req).await {
                Ok(outcome) => return Ok(outcome),
                // A pinentry that cannot show its window fails with an I/O
                // or protocol error; everything else ends the dialog.
                Err(e) if matches!(e, PinentryError::Io(_) | PinentryError::Protocol(_)) => {
                    if started.elapsed() >= self.timings.not_ready_window {
                        return Err(e);
                    }
                    tracing::info!(
                        "pinentry failed: {e}; retrying in {} s, the prompter may not be ready yet",
                        self.timings.not_ready_delay.as_secs()
                    );
                    tokio::time::sleep(self.timings.not_ready_delay).await;
                }
                Err(e) => return Err(e),
            }
        }
    }

    async fn unlock_dialog(&self, who: &str) -> UnlockOutcome {
        let started = Instant::now();
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
            let password = match self.ask_retry(&req, started).await {
                Ok(PinOutcome::Entered(p)) => p,
                Ok(PinOutcome::Cancelled) => return UnlockOutcome::Cancelled,
                Err(e) => return UnlockOutcome::Failed(e.to_string()),
            };
            let (wrap, epoch) = {
                let slot = self.vault.lock().unwrap();
                if slot.is_unlocked() {
                    return UnlockOutcome::Unlocked;
                }
                match slot.vault.as_ref().map(Vault::key_wrap) {
                    Some(Ok(w)) => (w, slot.lock_epoch()),
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
                        if slot.lock_epoch() != epoch {
                            return Err(StoreError::Locked);
                        }
                        slot.vault.as_mut().expect("checked above").unlock_with_key(key)
                    })
                    .await;
                    return match r {
                        Ok(Ok(())) => UnlockOutcome::Unlocked,
                        Ok(Err(StoreError::Locked)) => UnlockOutcome::Failed(LOCKED_MEANWHILE.into()),
                        Ok(Err(e)) => UnlockOutcome::Failed(e.to_string()),
                        Err(e) => UnlockOutcome::Failed(e.to_string()),
                    };
                }
                Ok(Err(crate::crypto::CryptoError::Unwrap)) => error = Some("Wrong password. Try again.".into()),
                Ok(Err(e)) => return UnlockOutcome::Failed(e.to_string()),
                Err(e) => return UnlockOutcome::Failed(e.to_string()),
            }
        }
        tracing::info!(who, "unlock dialog ended after too many wrong passwords");
        UnlockOutcome::Cancelled
    }

    async fn create_dialog(&self, who: &str) -> UnlockOutcome {
        let started = Instant::now();
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
        let password = match self.ask_retry(&req, started).await {
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

/// The outcome of [`Unlocker::unlock_with_slot`]. Messages contain no
/// secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotUnlock {
    Unlocked,
    /// It was unlocked already; the password was not tried.
    AlreadyUnlocked,
    /// The password does not open the slot.
    WrongPassword,
    /// There is no vault, or it has no such slot.
    NoSlot,
    Failed(String),
}

impl Unlocker {
    /// Unlocks the vault with `password` through `slot` (the login
    /// password's), without a dialog. On success, waiting requests are
    /// served and an open unlock dialog is closed. The key derivation runs
    /// without holding the vault.
    ///
    /// A global lock while the key is derived, or a change of the slot,
    /// cancels the unlock.
    pub async fn unlock_with_slot(self: &Arc<Self>, slot: Slot, password: Zeroizing<Vec<u8>>) -> SlotUnlock {
        let (wrap, epoch) = {
            let s = self.vault.lock().unwrap();
            if s.is_unlocked() {
                return SlotUnlock::AlreadyUnlocked;
            }
            match s.vault.as_ref().map(|v| v.key_slot(slot)) {
                None | Some(Ok(None)) => return SlotUnlock::NoSlot,
                Some(Ok(Some(w))) => (w, s.lock_epoch()),
                Some(Err(e)) => return SlotUnlock::Failed(e.to_string()),
            }
        };
        let tried = wrap.clone();
        let key = match tokio::task::spawn_blocking(move || VaultKey::unwrap_for(slot, &tried, &password)).await {
            Ok(Ok(key)) => key,
            Ok(Err(crate::crypto::CryptoError::Unwrap)) => return SlotUnlock::WrongPassword,
            Ok(Err(e)) => return SlotUnlock::Failed(e.to_string()),
            Err(e) => return SlotUnlock::Failed(e.to_string()),
        };
        let vault = self.vault.clone();
        let r = tokio::task::spawn_blocking(move || {
            let mut s = vault.lock().unwrap();
            if s.lock_epoch() != epoch {
                return Ok(Err(LOCKED_MEANWHILE));
            }
            let Some(v) = s.vault.as_mut() else { return Err(StoreError::NotFound) };
            if v.key_slot(slot)?.as_ref() != Some(&wrap) {
                return Ok(Err("the slot changed while the key was derived"));
            }
            v.unlock_with_key(key).map(Ok)
        })
        .await;
        match r {
            Ok(Ok(Ok(()))) => {
                self.unlocked_elsewhere();
                SlotUnlock::Unlocked
            }
            Ok(Ok(Err(why))) => SlotUnlock::Failed(why.into()),
            Ok(Err(e)) => SlotUnlock::Failed(e.to_string()),
            Err(e) => SlotUnlock::Failed(e.to_string()),
        }
    }

    /// The vault was unlocked without the shared dialog: wakes requests
    /// waiting for an unlock, and settles a dialog that is still open as
    /// unlocked and closes it (aborting its task kills pinentry).
    fn unlocked_elsewhere(&self) {
        if let Some(f) = self.flight.lock().unwrap().as_ref()
            && settle_once(&f.settle, UnlockOutcome::Unlocked)
        {
            f.abort.abort();
            tracing::info!("unlock dialog closed: the vault was unlocked without it");
        }
        let _ = self.unlocked_tx.send(());
    }
}

/// Sets a flight's outcome unless it has one already. Returns whether it
/// did.
fn settle_once(tx: &watch::Sender<Option<UnlockOutcome>>, outcome: UnlockOutcome) -> bool {
    tx.send_if_modified(|v| {
        if v.is_some() {
            return false;
        }
        *v = Some(outcome);
        true
    })
}

/// Resolves once the vault was unlocked by anything — a dialog, an explicit
/// prompt, `scopevault-admin unlock`. `false`: the unlocker itself is gone.
async fn unlocked_by(rx: &mut tokio::sync::broadcast::Receiver<()>) -> bool {
    // Missed notifications (the channel moved on) were unlocks too: the
    // caller looks at the vault again.
    !matches!(rx.recv().await, Err(tokio::sync::broadcast::error::RecvError::Closed))
}
