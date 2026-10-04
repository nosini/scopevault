//! Unlocking with the login password (docs/LOGIN-UNLOCK.md).
//!
//! The vault key can be wrapped a second time, for the login slot. The PAM
//! module hands the login password to a helper running as the user, which
//! delivers it on the login socket ([`server`]); this module decides what
//! to do with it:
//!
//! - **Locked vault:** try the login slot. If it does not open, the
//!   password was changed (or mistyped); it is kept for a short time, and
//!   once the vault is unlocked by the master password the slot is
//!   repaired with it.
//! - **Unlocked vault:** check whether the password still opens the slot,
//!   and repair it if not.
//! - **Password change** (from `chauthtok`): rewrap the slot under the new
//!   password.
//!
//! The slot is only ever rewrapped under a password that [`PasswordCheck`]
//! confirms is the user's current login password (or, when enabling, after
//! the master password was entered in the daemon's dialog as well).
//! Otherwise a host process that can reach the socket could set the slot to
//! a password it knows and unwrap the vault key from `vault.db`.

pub mod chkpwd;
pub mod protocol;
pub mod server;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::crypto::{KeyWrap, Slot, VaultKey};
use crate::prompts::unlock::{SlotUnlock, UnlockOutcome, Unlocker};
use crate::store::now;

/// Whether a password is the user's current login password.
pub trait PasswordCheck: Send + Sync + 'static {
    /// `Ok(false)`: it is not. `Err`: it cannot be told (the checker is
    /// missing or broken); the message contains no secret. Blocking.
    fn check(&self, password: &[u8]) -> Result<bool, String>;
}

/// Limits on how often the slow key derivation runs for the login socket.
#[derive(Debug, Clone, Copy)]
pub struct LoginTimings {
    /// At most one request that derives a key per this interval; others
    /// are refused. Bounds the CPU and memory a caller can use, and makes
    /// guessing through the socket no faster than offline.
    pub min_interval: Duration,
    /// How long a password that did not open the locked vault's slot is
    /// kept for repairing the slot after a master-password unlock.
    pub keep_for_repair: Duration,
}

impl Default for LoginTimings {
    fn default() -> Self {
        LoginTimings { min_interval: Duration::from_secs(5), keep_for_repair: Duration::from_secs(300) }
    }
}

/// What a delivery or change did. [`Outcome::word`] is the reply on the
/// login socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The vault was locked and the login slot opened it.
    Unlocked,
    /// The vault was unlocked and the password opens the slot.
    AlreadyUnlocked,
    /// The password did not open the slot and the slot was not repaired
    /// (yet: a locked vault's slot is repaired after the next unlock).
    Stale,
    /// The slot was rewrapped under the delivered password.
    Repaired,
    /// The slot was rewrapped under the new password of a change.
    Changed,
    /// There is no vault, or it has no login slot.
    NoSlot,
    /// Refused without trying (too soon after the last request, another
    /// one running, or not the login password).
    Refused(&'static str),
    Failed(String),
}

impl Outcome {
    pub fn word(&self) -> &'static str {
        match self {
            Outcome::Unlocked => "unlocked",
            Outcome::AlreadyUnlocked => "already-unlocked",
            Outcome::Stale => "stale",
            Outcome::Repaired => "repaired",
            Outcome::Changed => "changed",
            Outcome::NoSlot => "no-slot",
            Outcome::Refused(_) => "refused",
            Outcome::Failed(_) => "failed",
        }
    }
}

/// What `scopevault-admin login-unlock status` reports.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LoginStatus {
    /// The vault has a login slot.
    pub enabled: bool,
    /// When the login slot last unlocked the vault (Unix time), since the
    /// daemon started.
    pub last_unlock: Option<u64>,
    /// When the login slot was last rewrapped (repair or change), since
    /// the daemon started.
    pub last_rewrap: Option<u64>,
}

struct State {
    /// A delivered password that did not open the locked vault's slot.
    pending: Option<(Zeroizing<Vec<u8>>, Instant)>,
    last_derivation: Option<Instant>,
    last_unlock: Option<u64>,
    last_rewrap: Option<u64>,
}

pub struct LoginUnlock {
    unlocker: Arc<Unlocker>,
    checker: Arc<dyn PasswordCheck>,
    timings: LoginTimings,
    /// One socket request at a time.
    busy: tokio::sync::Mutex<()>,
    state: Mutex<State>,
    /// Wakes the background task when a password is kept, so it can wipe
    /// it on time.
    kept: Arc<tokio::sync::Notify>,
}

impl LoginUnlock {
    /// Also starts the task that repairs the slot once the vault is
    /// unlocked after a delivery that did not open it, and wipes a kept
    /// password when it expires or the vault is locked.
    pub fn new(unlocker: Arc<Unlocker>, checker: Arc<dyn PasswordCheck>, timings: LoginTimings) -> Arc<Self> {
        let this = Arc::new(LoginUnlock {
            unlocker,
            checker,
            timings,
            busy: tokio::sync::Mutex::new(()),
            state: Mutex::new(State { pending: None, last_derivation: None, last_unlock: None, last_rewrap: None }),
            kept: Arc::new(tokio::sync::Notify::new()),
        });
        let weak = Arc::downgrade(&this);
        let kept = this.kept.clone();
        let mut unlocked = this.unlocker.subscribe_unlocked();
        let mut locked = this.unlocker.subscribe_locked();
        tokio::spawn(async move {
            use tokio::sync::broadcast::error::RecvError;
            loop {
                let expires = {
                    let Some(this) = weak.upgrade() else { return };
                    let st = this.state.lock().unwrap();
                    st.pending.as_ref().map(|(_, at)| *at + this.timings.keep_for_repair)
                };
                let sleep = async {
                    match expires {
                        Some(t) => tokio::time::sleep_until(t.into()).await,
                        None => std::future::pending().await,
                    }
                };
                tokio::select! {
                    r = unlocked.recv() => {
                        if matches!(r, Err(RecvError::Closed)) {
                            return;
                        }
                        let Some(this) = weak.upgrade() else { return };
                        this.repair_pending().await;
                    }
                    r = locked.recv() => {
                        if matches!(r, Err(RecvError::Closed)) {
                            return;
                        }
                        let Some(this) = weak.upgrade() else { return };
                        this.state.lock().unwrap().pending = None;
                    }
                    () = sleep => {
                        let Some(this) = weak.upgrade() else { return };
                        let mut st = this.state.lock().unwrap();
                        if st.pending.as_ref().is_some_and(|(_, at)| at.elapsed() >= this.timings.keep_for_repair) {
                            st.pending = None;
                        }
                    }
                    () = kept.notified() => {}
                }
            }
        });
        this
    }

    /// Keeps a password that did not open the locked vault's slot, for
    /// repairing the slot after the next unlock.
    fn keep(&self, password: Zeroizing<Vec<u8>>) {
        self.state.lock().unwrap().pending = Some((password, Instant::now()));
        self.kept.notify_one();
    }

    /// Whether a password is kept for repair (for tests).
    pub fn keeps_a_password(&self) -> bool {
        self.state.lock().unwrap().pending.is_some()
    }

    /// The password the PAM module delivered at login or screen unlock.
    pub async fn deliver(&self, password: Zeroizing<Vec<u8>>) -> Outcome {
        let Ok(_one) = self.busy.try_lock() else { return Outcome::Refused("another request is running") };
        if self.login_slot().is_none() {
            return Outcome::NoSlot;
        }
        if !self.may_derive() {
            return Outcome::Refused("too soon after the last request");
        }
        match self.unlocker.unlock_with_slot(Slot::Login, password.clone()).await {
            SlotUnlock::Unlocked => {
                let mut st = self.state.lock().unwrap();
                st.pending = None;
                st.last_unlock = Some(now());
                Outcome::Unlocked
            }
            SlotUnlock::WrongPassword => {
                self.keep(password);
                Outcome::Stale
            }
            SlotUnlock::AlreadyUnlocked => self.check_and_repair(password).await,
            SlotUnlock::NoSlot => Outcome::NoSlot,
            SlotUnlock::Failed(e) => Outcome::Failed(e),
        }
    }

    /// A password change seen by the PAM module (`chauthtok`).
    pub async fn change(&self, old: Zeroizing<Vec<u8>>, new: Zeroizing<Vec<u8>>) -> Outcome {
        let Ok(_one) = self.busy.try_lock() else { return Outcome::Refused("another request is running") };
        let Some(current) = self.login_slot() else { return Outcome::NoSlot };
        if !self.may_derive() {
            return Outcome::Refused("too soon after the last request");
        }
        let key = match self.unlocker.vault().lock().unwrap().vault.as_ref().map(|v| v.vault_key()) {
            Some(Ok(key)) => Some(key),
            _ => None,
        };
        let key = match key {
            Some(key) => key,
            // Locked: the old password must open the slot.
            None => match blocking(move || VaultKey::unwrap_for(Slot::Login, &current, &old)).await {
                Ok(Ok(key)) => key,
                Ok(Err(crate::crypto::CryptoError::Unwrap)) => return Outcome::Stale,
                Ok(Err(e)) => return Outcome::Failed(e.to_string()),
                Err(e) => return Outcome::Failed(e),
            },
        };
        let checker = self.checker.clone();
        let candidate = new.clone();
        match blocking(move || checker.check(&candidate)).await {
            Ok(Ok(true)) => {}
            Ok(Ok(false)) => {
                tracing::info!("login password change: the new password is not the login password");
                return Outcome::Refused("not the login password");
            }
            Ok(Err(e)) | Err(e) => {
                tracing::warn!(error = %e, "login password change: cannot check the new password");
                return Outcome::Stale;
            }
        }
        match self.rewrap(key, new).await {
            Ok(()) => Outcome::Changed,
            Err(o) => o,
        }
    }

    pub fn status(&self) -> LoginStatus {
        let st = self.state.lock().unwrap();
        LoginStatus { enabled: self.login_slot().is_some(), last_unlock: st.last_unlock, last_rewrap: st.last_rewrap }
    }

    /// `scopevault-admin login-unlock enable`: asks for the master password
    /// (to allow it) and the login password, checks the latter and wraps
    /// the vault key for it. Replaces an existing login slot.
    pub async fn enable(&self) -> Result<String, String> {
        self.confirm("let your login password unlock the keyring").await?;
        let password = self
            .unlocker
            .ask_password(
                "Login password",
                "Enter the password you log in with. From now on it unlocks the keyring when you log in.",
            )
            .await
            .map_err(outcome_error)?;
        let password = Zeroizing::new(password.as_bytes().to_vec());
        let checker = self.checker.clone();
        let candidate = password.clone();
        match blocking(move || checker.check(&candidate)).await {
            Ok(Ok(true)) => {}
            Ok(Ok(false)) => return Err("that is not your login password".into()),
            Ok(Err(e)) | Err(e) => return Err(format!("cannot check the login password: {e}")),
        }
        let key = self.vault_key()?;
        let current = self.login_slot();
        let kdf = self.unlocker.kdf();
        let wrap = blocking(move || key.wrap_for(Slot::Login, &password, kdf))
            .await
            .and_then(|r| r.map_err(|e| e.to_string()))?;
        self.store_slot(current.as_ref(), Some(&wrap)).map_err(|e| format!("cannot store the login slot: {e}"))?;
        tracing::info!("login unlock enabled");
        Ok("your login password now unlocks the keyring".into())
    }

    /// `scopevault-admin login-unlock disable`: asks for the master
    /// password, then removes the login slot.
    pub async fn disable(&self) -> Result<String, String> {
        let Some(current) = self.login_slot() else { return Ok("login unlock was not enabled".into()) };
        self.confirm("stop your login password from unlocking the keyring").await?;
        self.store_slot(Some(&current), None).map_err(|e| format!("cannot remove the login slot: {e}"))?;
        self.state.lock().unwrap().pending = None;
        tracing::info!("login unlock disabled");
        Ok("your login password no longer unlocks the keyring".into())
    }

    /// The vault must be unlocked; the master password is asked for.
    async fn confirm(&self, action: &str) -> Result<(), String> {
        if self.unlocker.vault().lock().unwrap().vault.is_none() {
            return Err("there is no vault yet".into());
        }
        match self.unlocker.ensure_unlocked_admin().await {
            UnlockOutcome::Unlocked => {}
            other => return Err(outcome_error(other)),
        }
        match self.unlocker.confirm_admin(action).await {
            UnlockOutcome::Unlocked => Ok(()),
            other => Err(outcome_error(other)),
        }
    }

    fn login_slot(&self) -> Option<KeyWrap> {
        let slot = self.unlocker.vault().lock().unwrap();
        slot.vault.as_ref().and_then(|v| v.key_slot(Slot::Login).ok().flatten())
    }

    fn vault_key(&self) -> Result<VaultKey, String> {
        let slot = self.unlocker.vault().lock().unwrap();
        slot.vault.as_ref().ok_or("there is no vault yet")?.vault_key().map_err(|e| e.to_string())
    }

    fn store_slot(&self, current: Option<&KeyWrap>, new: Option<&KeyWrap>) -> Result<(), String> {
        let mut slot = self.unlocker.vault().lock().unwrap();
        let v = slot.vault.as_mut().ok_or("there is no vault yet")?;
        v.replace_key_slot(Slot::Login, current, new).map_err(|e| e.to_string())
    }

    /// Whether a request may run the slow key derivation now; if so, the
    /// interval starts again.
    fn may_derive(&self) -> bool {
        let mut st = self.state.lock().unwrap();
        if st.last_derivation.is_some_and(|t| t.elapsed() < self.timings.min_interval) {
            return false;
        }
        st.last_derivation = Some(Instant::now());
        true
    }

    /// The vault is unlocked: if `password` no longer opens the login
    /// slot, repairs the slot with it.
    async fn check_and_repair(&self, password: Zeroizing<Vec<u8>>) -> Outcome {
        let Some(current) = self.login_slot() else { return Outcome::NoSlot };
        let candidate = password.clone();
        match blocking(move || VaultKey::unwrap_for(Slot::Login, &current, &candidate)).await {
            Ok(Ok(_)) => return Outcome::AlreadyUnlocked,
            Ok(Err(crate::crypto::CryptoError::Unwrap)) => {}
            Ok(Err(e)) => return Outcome::Failed(e.to_string()),
            Err(e) => return Outcome::Failed(e),
        }
        self.repair(password).await
    }

    /// Rewraps the slot under `password` if it is the current login
    /// password. If that cannot be checked, nothing changes: asking for the
    /// master password instead would open a dialog after every mistyped
    /// screen unlock. `scopevault-admin login-unlock enable` sets the slot
    /// again.
    async fn repair(&self, password: Zeroizing<Vec<u8>>) -> Outcome {
        let checker = self.checker.clone();
        let candidate = password.clone();
        match blocking(move || checker.check(&candidate)).await {
            Ok(Ok(true)) => {}
            Ok(Ok(false)) => {
                tracing::info!("login slot not repaired: the password is not the login password");
                return Outcome::Stale;
            }
            Ok(Err(e)) | Err(e) => {
                tracing::warn!(
                    error = %e,
                    "login slot not repaired: cannot check the login password; \
                     `scopevault-admin login-unlock enable` sets it again"
                );
                return Outcome::Stale;
            }
        }
        let key = match self.vault_key() {
            Ok(k) => k,
            Err(e) => return Outcome::Failed(e),
        };
        match self.rewrap(key, password).await {
            Ok(()) => Outcome::Repaired,
            Err(o) => o,
        }
    }

    /// Wraps `key` for the login slot under `password` and replaces the
    /// stored slot, unless the slot was removed or changed meanwhile.
    async fn rewrap(&self, key: VaultKey, password: Zeroizing<Vec<u8>>) -> Result<(), Outcome> {
        let Some(current) = self.login_slot() else { return Err(Outcome::NoSlot) };
        let kdf = self.unlocker.kdf();
        let wrap = match blocking(move || key.wrap_for(Slot::Login, &password, kdf)).await {
            Ok(Ok(w)) => w,
            Ok(Err(e)) => return Err(Outcome::Failed(e.to_string())),
            Err(e) => return Err(Outcome::Failed(e)),
        };
        self.store_slot(Some(&current), Some(&wrap)).map_err(Outcome::Failed)?;
        self.state.lock().unwrap().last_rewrap = Some(now());
        tracing::info!("login slot rewrapped under the current login password");
        Ok(())
    }

    /// After an unlock: repairs the slot with a password kept from a
    /// delivery that did not open it, if it is recent enough.
    async fn repair_pending(&self) {
        let _one = self.busy.lock().await;
        let pending = self.state.lock().unwrap().pending.take();
        let Some((password, at)) = pending else { return };
        if at.elapsed() > self.timings.keep_for_repair || !self.unlocker.vault().lock().unwrap().is_unlocked() {
            return;
        }
        let outcome = self.check_and_repair(password).await;
        tracing::info!(outcome = outcome.word(), "login slot repair after unlock");
    }
}

fn outcome_error(o: UnlockOutcome) -> String {
    match o {
        UnlockOutcome::Unlocked => "unlocked".into(),
        UnlockOutcome::Cancelled => crate::admin::protocol::CANCELLED.into(),
        UnlockOutcome::Failed(e) => format!("the password dialog failed: {e}"),
    }
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, String> {
    tokio::task::spawn_blocking(f).await.map_err(|e| e.to_string())
}
