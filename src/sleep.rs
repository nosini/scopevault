//! Locking the vault before the system sleeps.
//!
//! A suspended machine should not hold the vault key in memory: someone
//! who takes it can read RAM. The daemon takes a logind "delay" inhibitor
//! for sleep on the system bus. logind then announces
//! `PrepareForSleep(true)` and waits (up to its `InhibitDelayMaxSec`, 5 s by
//! default) until delay inhibitors are released. The daemon locks the vault
//! globally, then releases its inhibitor, and takes a new one after
//! `PrepareForSleep(false)` (resume). The screen unlock after resume opens
//! the vault again through the login password (see `crate::login`).
//!
//! Without logind (no system bus, `Inhibit` refused) the daemon still locks
//! when the signal arrives, but cannot make the sleep wait for it.

use futures_util::StreamExt;
use zbus::zvariant::OwnedFd;
use zbus::{Connection, MatchRule, MessageStream};

const LOGIN1: &str = "org.freedesktop.login1";
const PATH: &str = "/org/freedesktop/login1";
const MANAGER: &str = "org.freedesktop.login1.Manager";

/// Watches logind on `system` and calls `lock` before every sleep. Runs
/// until the connection closes. `lock` returns whether the vault was
/// unlocked.
pub async fn lock_before_sleep(system: Connection, lock: impl Fn() -> bool + Send + 'static) {
    let rule = MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .sender(LOGIN1)
        .and_then(|b| b.path(PATH))
        .and_then(|b| b.interface(MANAGER))
        .and_then(|b| b.member("PrepareForSleep"))
        .map(|b| b.build());
    let rule = match rule {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "cannot watch for sleep; the vault is not locked before suspend");
            return;
        }
    };
    // Subscribed before the inhibitor is taken, so no announcement is
    // missed while holding it.
    let mut stream = match MessageStream::for_match_rule(rule, &system, None).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "cannot watch for sleep; the vault is not locked before suspend");
            return;
        }
    };
    let mut inhibitor = inhibit(&system).await;
    if inhibitor.is_some() {
        tracing::info!("the vault is locked before the system sleeps");
    }
    while let Some(msg) = stream.next().await {
        let Ok(msg) = msg else { continue };
        let Ok(sleeping) = msg.body().deserialize::<bool>() else { continue };
        if sleeping {
            let was_unlocked = lock();
            tracing::info!(was_unlocked, "the system is going to sleep: vault locked");
            // Releasing the inhibitor lets the sleep go ahead.
            inhibitor = None;
        } else {
            tracing::info!("the system resumed");
            if inhibitor.is_none() {
                inhibitor = inhibit(&system).await;
            }
        }
    }
    drop(inhibitor);
    tracing::warn!("the system bus connection closed; the vault is no longer locked before suspend");
}

/// A delay inhibitor for sleep, held as long as the descriptor is open.
async fn inhibit(system: &Connection) -> Option<OwnedFd> {
    let args = ("sleep", "scopevault", "Lock the keyring before the system sleeps", "delay");
    let reply = system.call_method(Some(LOGIN1), PATH, Some(MANAGER), "Inhibit", &args).await;
    match reply.and_then(|m| m.body().deserialize::<OwnedFd>()) {
        Ok(fd) => Some(fd),
        Err(e) => {
            tracing::warn!(
                error = %e,
                "cannot delay sleep through logind; the vault is still locked on the sleep signal, \
                 but the system may suspend first"
            );
            None
        }
    }
}
