//! Unlocking with the login password: the login socket, as
//! `scopevault-pam-helper` uses it, and the slot repair rules
//! (docs/LOGIN-UNLOCK.md). The checker for "is this the login password" is
//! [`FakeCheck`]; `unix_chkpwd` itself is tested with a stand-in script.

mod common;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use common::tempdir::TempDir;
use common::{FakeCheck, LOGIN_PASSWORD, PASSWORD, VaultFixture, VaultState};
use scopevault::admin::server::{BoundSocket, PeerClassifier, bind};
use scopevault::crypto::{KdfParams, Slot, VaultKey};
use scopevault::identity::{Classifier, HostBaseline, IdentityPolicy, InstanceRecords};
use scopevault::login::chkpwd::UnixChkpwd;
use scopevault::login::protocol::Request;
use scopevault::login::server::{LoginServer, relaxed_classifier};
use scopevault::login::{LoginTimings, LoginUnlock, PasswordCheck};
use scopevault::prompts::unlock::UnlockOutcome;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use zeroize::Zeroizing;

struct Env {
    vault: VaultFixture,
    check: Arc<FakeCheck>,
    login: Arc<LoginUnlock>,
    tmp: TempDir,
    socket: PathBuf,
    _bound: Arc<BoundSocket>,
}

const FAST: LoginTimings = LoginTimings { min_interval: Duration::ZERO, keep_for_repair: Duration::from_secs(60) };

/// A vault in `state`; with `slot`, it has a login slot for
/// [`LOGIN_PASSWORD`] (and is left in `state`).
async fn env(state: VaultState, slot: bool, timings: LoginTimings) -> Env {
    let vault = VaultFixture::new(state);
    if slot {
        let mut s = vault.unlocker.vault().lock().unwrap();
        let v = s.vault.as_mut().unwrap();
        let was_locked = !v.is_unlocked();
        v.unlock(PASSWORD.as_bytes()).unwrap();
        let wrap = v.vault_key().unwrap().wrap_for(Slot::Login, LOGIN_PASSWORD.as_bytes(), KdfParams::MINIMUM).unwrap();
        v.replace_key_slot(Slot::Login, None, Some(&wrap)).unwrap();
        if was_locked {
            v.lock();
        }
    }
    let check = FakeCheck::new(LOGIN_PASSWORD);
    let login = LoginUnlock::new(vault.unlocker.clone(), check.clone(), timings);

    let tmp = TempDir::new("login");
    let socket = tmp.path().join("run").join("login");
    let bound = Arc::new(bind(&socket).unwrap());
    let baseline = HostBaseline::capture().unwrap();
    let uid = baseline.uid;
    let strict =
        Classifier { baseline, instances: InstanceRecords::new(tmp.path(), uid), policy: IdentityPolicy::default() };
    let relaxed = Arc::new(relaxed_classifier(&strict));
    assert!(!relaxed.policy.require_host_label_match && relaxed.policy.require_flatpak_instance);
    let classify: PeerClassifier = Arc::new(move |creds| relaxed.classify(creds).result);
    let server = LoginServer::new(classify, login.clone());
    let b = bound.clone();
    tokio::spawn(async move { server.serve(&b.listener).await });
    Env { vault, check, login, tmp, socket, _bound: bound }
}

fn pw(s: &str) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(s.as_bytes().to_vec())
}

impl Env {
    async fn send(&self, req: &Request) -> String {
        let mut s = UnixStream::connect(&self.socket).await.unwrap();
        s.write_all(&req.encode().unwrap()).await.unwrap();
        let mut reply = String::new();
        s.read_to_string(&mut reply).await.unwrap();
        reply.trim_end().to_owned()
    }

    async fn deliver(&self, p: &str) -> String {
        self.send(&Request::Deliver(pw(p))).await
    }

    async fn change(&self, old: &str, new: &str) -> String {
        self.send(&Request::Change { old: pw(old), new: pw(new) }).await
    }

    /// Whether the stored login slot opens with `p`.
    fn slot_opens(&self, p: &str) -> bool {
        let s = self.vault.unlocker.vault().lock().unwrap();
        let Some(wrap) = s.vault.as_ref().unwrap().key_slot(Slot::Login).unwrap() else { return false };
        VaultKey::unwrap_for(Slot::Login, &wrap, p.as_bytes()).is_ok()
    }

    /// Waits for the background repair after an unlock.
    async fn wait_for_slot(&self, p: &str) -> bool {
        for _ in 0..100 {
            if self.slot_opens(p) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        false
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_login_password_unlocks_the_vault() {
    let e = env(VaultState::Locked, true, FAST).await;
    assert_eq!(e.deliver(LOGIN_PASSWORD).await, "unlocked");
    assert!(e.vault.unlocked());
    assert_eq!(e.vault.dialogs(), 0);
    assert_eq!(e.check.calls(), 0, "a password that opens the slot needs no check");
    let st = e.login.status();
    assert!(st.enabled && st.last_unlock.is_some() && st.last_rewrap.is_none());

    // Unlocked: the same password still opens the slot; nothing changes.
    assert_eq!(e.deliver(LOGIN_PASSWORD).await, "already-unlocked");
    assert_eq!(e.check.calls(), 0);
    // The master password is not the login password.
    e.vault.lock_vault();
    assert_eq!(e.deliver(PASSWORD).await, "stale");
    assert!(!e.vault.unlocked());
}

#[tokio::test(flavor = "multi_thread")]
async fn without_a_slot_nothing_is_tried_or_kept() {
    let e = env(VaultState::Locked, false, FAST).await;
    assert_eq!(e.deliver(PASSWORD).await, "no-slot");
    assert!(!e.vault.unlocked(), "the master password is not tried through the login socket");
    e.vault.set_pins(&[PASSWORD]);
    assert_eq!(e.vault.unlocker.ensure_unlocked_admin().await, UnlockOutcome::Unlocked);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(e.check.calls(), 0);
    assert!(!e.slot_opens(PASSWORD));
    assert!(!e.login.status().enabled);

    let missing = env(VaultState::Missing, false, FAST).await;
    assert_eq!(missing.deliver(LOGIN_PASSWORD).await, "no-slot");
    assert!(missing.vault.unlocker.vault().lock().unwrap().vault.is_none(), "no vault is created");
}

/// After a password change PAM did not see: the next login delivers the
/// new password, the slot does not open, the user unlocks with the master
/// password, and the slot is rewrapped under the new password.
#[tokio::test(flavor = "multi_thread")]
async fn a_locked_vaults_slot_is_repaired_after_the_master_password_unlock() {
    let e = env(VaultState::Locked, true, FAST).await;
    e.check.set("new login");
    assert_eq!(e.deliver("new login").await, "stale");
    assert!(!e.vault.unlocked());
    e.vault.set_pins(&[PASSWORD]);
    assert_eq!(e.vault.unlocker.ensure_unlocked_admin().await, UnlockOutcome::Unlocked);
    assert!(e.wait_for_slot("new login").await, "slot not repaired");
    assert!(!e.slot_opens(LOGIN_PASSWORD));
    assert!(e.login.status().last_rewrap.is_some());

    e.vault.lock_vault();
    assert_eq!(e.deliver("new login").await, "unlocked");
    assert_eq!(e.vault.dialogs(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn only_the_current_login_password_repairs_the_slot() {
    // A delivered password the checker refuses (a typo, or a host process
    // trying to set its own) leaves the slot alone.
    let e = env(VaultState::Locked, true, FAST).await;
    assert_eq!(e.deliver("typo").await, "stale");
    e.vault.set_pins(&[PASSWORD]);
    assert_eq!(e.vault.unlocker.ensure_unlocked_admin().await, UnlockOutcome::Unlocked);
    for _ in 0..50 {
        if e.check.calls() > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(e.check.calls(), 1);
    assert!(e.slot_opens(LOGIN_PASSWORD) && !e.slot_opens("typo"));

    // Unlocked vault: the same rule, immediately.
    assert_eq!(e.deliver("attacker's choice").await, "stale");
    assert!(e.slot_opens(LOGIN_PASSWORD));
    // A checker that cannot check repairs nothing, and opens no dialog.
    e.check.broken.store(true, std::sync::atomic::Ordering::SeqCst);
    e.check.set("changed");
    assert_eq!(e.deliver("changed").await, "stale");
    assert!(e.slot_opens(LOGIN_PASSWORD));
    assert_eq!(e.vault.dialogs(), 1);
    // Once it works again, a screen unlock repairs the slot.
    e.check.broken.store(false, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(e.deliver("changed").await, "repaired");
    assert!(e.slot_opens("changed") && !e.slot_opens(LOGIN_PASSWORD));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_kept_password_expires() {
    let e = env(
        VaultState::Locked,
        true,
        LoginTimings { min_interval: Duration::ZERO, keep_for_repair: Duration::from_millis(200) },
    )
    .await;
    e.check.set("new login");
    assert_eq!(e.deliver("new login").await, "stale");
    tokio::time::sleep(Duration::from_millis(400)).await;
    e.vault.set_pins(&[PASSWORD]);
    assert_eq!(e.vault.unlocker.ensure_unlocked_admin().await, UnlockOutcome::Unlocked);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(e.check.calls(), 0);
    assert!(e.slot_opens(LOGIN_PASSWORD));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_password_change_rewraps_the_slot() {
    // Locked: the old password opens the slot, the new one is checked.
    let e = env(VaultState::Locked, true, FAST).await;
    e.check.set("second");
    assert_eq!(e.change("wrong old", "second").await, "stale");
    assert!(e.slot_opens(LOGIN_PASSWORD));
    assert_eq!(e.change(LOGIN_PASSWORD, "second").await, "changed");
    assert!(!e.vault.unlocked(), "a change does not unlock the vault");
    assert!(e.slot_opens("second") && !e.slot_opens(LOGIN_PASSWORD));

    // pam_unix refused the change, but our module ran anyway: the new
    // password is not the login password, so the slot stays.
    assert_eq!(e.change("second", "refused by pam_unix").await, "refused");
    assert!(e.slot_opens("second"));

    // Unlocked: the old password does not matter, the new one does.
    e.vault.set_pins(&[PASSWORD]);
    assert_eq!(e.vault.unlocker.ensure_unlocked_admin().await, UnlockOutcome::Unlocked);
    e.check.set("third");
    assert_eq!(e.change("anything", "third").await, "changed");
    assert!(e.slot_opens("third"));
    // No slot, no change.
    let none = env(VaultState::Unlocked, false, FAST).await;
    assert_eq!(none.change("a", LOGIN_PASSWORD).await, "no-slot");
    assert!(!none.login.status().enabled);
}

#[tokio::test(flavor = "multi_thread")]
async fn requests_that_derive_keys_are_rate_limited() {
    let e = env(
        VaultState::Locked,
        true,
        LoginTimings { min_interval: Duration::from_millis(800), keep_for_repair: Duration::from_secs(60) },
    )
    .await;
    assert_eq!(e.deliver("guess 1").await, "stale");
    assert_eq!(e.deliver(LOGIN_PASSWORD).await, "refused");
    assert_eq!(e.change(LOGIN_PASSWORD, "x").await, "refused");
    assert!(!e.vault.unlocked());
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert_eq!(e.deliver(LOGIN_PASSWORD).await, "unlocked");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_delivery_closes_the_unlock_dialog_of_the_login_unit() {
    let e = env(VaultState::Locked, true, FAST).await;
    e.vault.set_pins(&["HANG"]);
    let u = e.vault.unlocker.clone();
    let dialog = tokio::spawn(async move { u.ensure_unlocked_admin().await });
    for _ in 0..100 {
        if e.vault.log().contains("GETPIN") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(e.deliver(LOGIN_PASSWORD).await, "unlocked");
    let outcome = tokio::time::timeout(Duration::from_secs(5), dialog).await.expect("dialog not closed").unwrap();
    assert_eq!(outcome, UnlockOutcome::Unlocked);
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_requests_and_sandboxes_are_refused() {
    let e = env(VaultState::Locked, true, FAST).await;
    for bytes in [&b"X"[..], b"D\x00\x00", b"D\x05\x00aaaa"] {
        let mut s = UnixStream::connect(&e.socket).await.unwrap();
        s.write_all(bytes).await.unwrap();
        s.shutdown().await.unwrap();
        let mut reply = String::new();
        s.read_to_string(&mut reply).await.unwrap();
        assert_eq!(reply, "refused\n", "{bytes:?}");
    }

    // A Flatpak-like sandbox and an unknown sandbox that can reach the
    // socket are refused before the request is read.
    let send = r#"
import socket, sys
s = socket.socket(socket.AF_UNIX)
s.connect(sys.argv[1])
pw = sys.argv[2].encode()
s.sendall(b"D" + len(pw).to_bytes(2, "big") + pw)
print(s.makefile().read().strip())
"#;
    for mode in ["ok", "plain"] {
        let out = std::process::Command::new(common::support_script("fake-flatpak.sh"))
            .args([mode, "org.example.Alpha", "900", e.tmp.path().to_str().unwrap(), "--", "python3", "-c", send])
            .args([e.socket.to_str().unwrap(), LOGIN_PASSWORD])
            .output()
            .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            "refused",
            "{mode}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    assert!(!e.vault.unlocked());
    // The same request from the host works.
    assert_eq!(e.deliver(LOGIN_PASSWORD).await, "unlocked");
}

/// `unix_chkpwd` is called as pam_unix calls it: the account name and
/// `nonull` as arguments, the password and a NUL on stdin, no environment.
#[test]
fn unix_chkpwd_protocol() {
    let tmp = TempDir::new("chkpwd");
    let fake = tmp.path().join("unix_chkpwd");
    let log = tmp.path().join("log");
    std::fs::write(
        &fake,
        format!(
            "#!/bin/sh\nprintf '%s|%s|%s\\n' \"$1\" \"$2\" \"$(env | wc -l)\" > '{log}'\n\
             input=$(od -An -c | tr -s ' ')\nprintf '%s\\n' \"$input\" >> '{log}'\n\
             case \"$input\" in *'r i g h t \\0'*) exit 0 ;; *'b r o k e n'*) exit 4 ;; esac\nexit 7\n",
            log = log.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&fake, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    let check = UnixChkpwd::new(fake.clone()).unwrap();
    assert_eq!(check.check(b"right"), Ok(true));
    let logged = std::fs::read_to_string(&log).unwrap();
    let user = String::from_utf8(std::process::Command::new("id").arg("-un").output().unwrap().stdout).unwrap();
    // `env` in an empty environment still prints the variables sh sets
    // itself (PWD, maybe SHLVL); there is no HOME or PATH from us.
    let first = logged.lines().next().unwrap();
    let fields: Vec<&str> = first.split('|').collect();
    assert_eq!((fields[0], fields[1]), (user.trim(), "nonull"), "{logged}");
    assert!(fields[2].trim().parse::<u32>().unwrap() <= 3, "{logged}");
    assert!(logged.contains("r i g h t \\0"), "{logged}");

    assert_eq!(check.check(b"wrong"), Ok(false));
    assert!(check.check(b"broken").is_err());
    assert_eq!(check.check(b"a\0b"), Ok(false));
    assert!(check.check(&[b'x'; 513]).is_err());
    assert!(UnixChkpwd::new(tmp.path().join("missing")).unwrap().check(b"x").is_err());
}
