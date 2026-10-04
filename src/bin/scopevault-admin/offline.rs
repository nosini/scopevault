//! Commands that work on the vault files directly, while the daemon is
//! stopped: restore, import (migration from another provider) and export
//! (rollback to it). The vault's lock file guarantees that no daemon has it
//! open meanwhile.
//!
//! Passwords are asked with pinentry, as the daemon does; they never appear
//! on the command line or in the environment.

use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use scopevault::admin::provider::Provider;
use scopevault::crypto::KdfParams;
use scopevault::identity::Scope;
use scopevault::prompts::pinentry::{self, PinOutcome, PinRequest, PinentryConfig};
use scopevault::store::{
    AdminAuthority, DEFAULT_ALIAS, PortableCollection, PortableItem, StoreError, Vault, split_portal_keys,
};
use zeroize::Zeroizing;

use super::fail;

const ATTEMPTS: usize = 3;

pub struct Options {
    pub data_dir: PathBuf,
    pub pinentry: PinentryConfig,
    /// Bus address of the other provider; the session bus if `None`.
    pub bus: Option<String>,
    pub scope: Scope,
}

/// Parses `--data-dir`, `--pinentry`, `--bus` and `--scope`; returns the
/// options and the remaining (positional) arguments.
pub fn parse(args: &[&str]) -> Result<(Options, Vec<String>), String> {
    let mut data_dir = None;
    let mut program = PathBuf::from("pinentry");
    let mut bus = None;
    let mut scope = Scope::Host;
    let mut rest = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut value = || it.next().map(|s| s.to_string()).ok_or(format!("{a} needs a value"));
        match *a {
            "--data-dir" => data_dir = Some(PathBuf::from(value()?)),
            "--pinentry" => program = PathBuf::from(value()?),
            "--bus" => bus = Some(value()?),
            "--scope" => {
                scope = value()?.parse().map_err(|_| "--scope is host, flatpak/APP-ID or portal".to_owned())?
            }
            s if s.starts_with("--") => return Err(format!("unknown option {s}")),
            s => rest.push(s.to_owned()),
        }
    }
    let data_dir = match data_dir {
        Some(d) => d,
        None => scopevault::admin::default_data_dir().ok_or("cannot determine the data directory; use --data-dir")?,
    };
    if !data_dir.is_absolute() {
        return Err("--data-dir must be an absolute path".into());
    }
    let pinentry = PinentryConfig { program, timeout: Duration::from_secs(300) };
    Ok((Options { data_dir, pinentry, bus, scope }, rest))
}

fn open(dir: &Path) -> Result<Vault, String> {
    Vault::open(dir).map_err(|e| match e {
        StoreError::InUse => format!("the vault in {} is in use: stop scopevault-daemon first", dir.display()),
        StoreError::NotFound => format!("there is no vault in {}", dir.display()),
        e => format!("cannot open the vault in {}: {e}", dir.display()),
    })
}

async fn ask(cfg: &PinentryConfig, req: &PinRequest) -> Result<Zeroizing<String>, String> {
    match pinentry::ask(cfg, req).await {
        Ok(PinOutcome::Entered(p)) => Ok(p),
        Ok(PinOutcome::Cancelled) => Err(scopevault::admin::protocol::CANCELLED.into()),
        Err(e) => Err(format!("the password dialog failed: {e}")),
    }
}

/// Asks for the vault's password until it is right (3 attempts).
async fn unlock(v: &mut Vault, cfg: &PinentryConfig, description: &str) -> Result<(), String> {
    let mut error = None;
    for _ in 0..ATTEMPTS {
        let req = PinRequest {
            title: "Unlock keyring".into(),
            description: description.into(),
            prompt: "Password:".into(),
            error: error.take(),
            repeat: None,
        };
        let password = ask(cfg, &req).await?;
        match v.unlock(password.as_bytes()) {
            Ok(()) => return Ok(()),
            Err(StoreError::WrongPassword) => error = Some("Wrong password. Try again.".into()),
            Err(e) => return Err(format!("cannot unlock the vault: {e}")),
        }
    }
    Err("wrong password".into())
}

/// How many of `wanted`'s items have an identical item in `have`.
fn found_in(have: &[PortableCollection], wanted: &[PortableCollection]) -> (usize, usize) {
    let all: Vec<&PortableItem> = have.iter().flat_map(|c| &c.items).collect();
    let items: Vec<&PortableItem> = wanted.iter().flat_map(|c| &c.items).collect();
    let found = items.iter().filter(|w| all.iter().any(|h| h.same_as(w))).count();
    (found, items.len())
}

/// Hardens this process before it handles the master password, the vault
/// key or plaintext secrets: no core dumps, no ptrace by other processes,
/// private files. Import and export call it once their provider connection
/// is set up: a provider may identify its callers through procfs (as
/// scopevault does, and the tests' stand-in provider is scopevault), which
/// hardening makes unreadable; it does so on the first call and keeps the
/// result for the connection. The online commands are not hardened: they
/// handle no secrets, and the daemon identifies its admin client the same
/// way.
fn harden() -> Result<(), String> {
    scopevault::hardening::harden_process().map_err(|e| format!("cannot harden the process: {e}"))
}

/// A summary without secrets or attribute values.
fn summarize(cols: &[PortableCollection]) {
    for c in cols {
        let alias = if c.aliases.is_empty() { String::new() } else { format!(" [{}]", c.aliases.join(", ")) };
        println!("  {:?}{alias}: {} items", c.label, c.items.len());
    }
}

/// Migration: copies everything from the provider on the bus into a scope
/// (default `host`) of the vault, creating the vault if there is none.
/// Portal keys are split out first and go into the `portal` scope, byte for
/// byte.
pub async fn import(opts: Options) -> ExitCode {
    if opts.scope == Scope::Portal {
        return fail("the portal keys are imported into their own scope; import with a different --scope");
    }
    let dir = &opts.data_dir;
    // Fail on a running daemon before showing the provider's dialog.
    let existing = if Vault::exists(dir) {
        match open(dir) {
            Ok(v) => Some(v),
            Err(e) => return fail(e),
        }
    } else {
        None
    };
    let provider = match Provider::connect(opts.bus.as_deref()).await {
        Ok(p) => p,
        Err(e) => return fail(e),
    };
    if let Err(e) = harden() {
        return fail(e);
    }
    println!("reading from {} ...", provider.owner().await);
    let source = match provider.read_all().await {
        Ok(s) => s,
        Err(e) => return fail(e),
    };
    println!("found {} items in {} collections:", source.iter().map(|c| c.items.len()).sum::<usize>(), source.len());
    summarize(&source);
    // Split the portal keys out before anything is unlocked or created: an
    // ambiguous one stops the import (see `split_portal_keys`).
    let split = match split_portal_keys(source) {
        Ok(s) => s,
        Err(e) => return fail(format!("the import failed and changed nothing: {e}")),
    };
    for note in &split.notes {
        println!("note: {note}");
    }

    let mut vault = match existing {
        Some(mut v) => {
            let what =
                format!("scopevault-admin wants to import passwords into {}. Enter its password.", dir.display());
            if let Err(e) = unlock(&mut v, &opts.pinentry, &what).await {
                return fail(e);
            }
            v
        }
        None => match create(dir, &opts.pinentry).await {
            Ok(v) => v,
            Err(e) => return fail(e),
        },
    };
    let auth = AdminAuthority::offline();
    let (report, portal) = match vault.import_with_portal_keys(&auth, &opts.scope, &split.collections, &split.keys) {
        Ok(r) => r,
        Err(e) => return fail(format!("the import failed and changed nothing: {e}")),
    };
    // Verify by reading back.
    let stored = match vault.export(&auth, &opts.scope) {
        Ok(s) => s,
        Err(e) => return fail(format!("cannot read the vault back: {e}")),
    };
    let (found, total) = found_in(&stored, &split.collections);
    println!(
        "imported {} items into {} ({} already there, {} new collections{})",
        report.items_imported,
        opts.scope,
        report.items_skipped,
        report.collections_created,
        if report.aliases_set.is_empty() { String::new() } else { format!(", set {}", report.aliases_set.join(", ")) }
    );
    if !split.keys.is_empty() {
        let ids: Vec<&str> = split.keys.iter().map(|k| k.attributes["app_id"].as_str()).collect();
        println!("portal keys for {}: {} imported, {} skipped", ids.join(", "), portal.imported, portal.skipped);
    }
    let portal_stored = match vault.export(&auth, &Scope::Portal) {
        Ok(s) => s,
        Err(e) => return fail(format!("cannot read the vault back: {e}")),
    };
    for key in &split.keys {
        let id = key.attributes["app_id"].as_str();
        let ok = portal_stored
            .iter()
            .flat_map(|c| &c.items)
            .any(|i| i.attributes.get("app_id").map(String::as_str) == Some(id) && i.secret.value == key.secret.value);
        if !ok {
            return fail(format!("verification failed: the portal key for {id} did not read back identically"));
        }
    }
    if found != total {
        return fail(format!("verification failed: only {found} of {total} items read back identically"));
    }
    println!("verified: all {total} items read back identically. The old provider was not changed.");
    ExitCode::SUCCESS
}

async fn create(dir: &Path, cfg: &PinentryConfig) -> Result<Vault, String> {
    let req = PinRequest {
        title: "Create keyring password".into(),
        description: format!(
            "scopevault-admin is creating a new keyring in {}. Choose its master password.",
            dir.display()
        ),
        prompt: "New password:".into(),
        error: None,
        repeat: Some("Repeat:".into()),
    };
    let password = ask(cfg, &req).await?;
    if password.is_empty() {
        return Err("the password must not be empty".into());
    }
    let kdf = KdfParams::calibrate(Duration::from_secs(1)).map_err(|e| format!("cannot calibrate: {e}"))?;
    Vault::create(dir, password.as_bytes(), kdf).map_err(|e| format!("cannot create the vault: {e}"))
}

/// Rollback: copies a scope (default `host`) into the provider on the bus.
/// Items the provider already has are skipped. The portal keys (with
/// `--scope portal`) are written back into the provider's default
/// collection, where gnome-keyring looks for them.
pub async fn export(opts: Options) -> ExitCode {
    let dir = &opts.data_dir;
    let mut vault = match open(dir) {
        Ok(v) => v,
        Err(e) => return fail(e),
    };
    // Connected before anything secret is handled; see `harden`.
    let provider = match Provider::connect(opts.bus.as_deref()).await {
        Ok(p) => p,
        Err(e) => return fail(e),
    };
    if let Err(e) = harden() {
        return fail(e);
    }
    let what = format!("scopevault-admin wants to copy passwords out of {}. Enter its password.", dir.display());
    if let Err(e) = unlock(&mut vault, &opts.pinentry, &what).await {
        return fail(e);
    }
    let cols = match vault.export(&AdminAuthority::offline(), &opts.scope) {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    drop(vault);
    println!(
        "{} has {} items in {} collections:",
        opts.scope,
        cols.iter().map(|c| c.items.len()).sum::<usize>(),
        cols.len()
    );
    summarize(&cols);
    println!("writing to {} ...", provider.owner().await);
    if opts.scope == Scope::Portal {
        // A key must never land beside a different one for the same app:
        // the app's own files stay encrypted with the old key. Read
        // everything first, and refuse before writing anything.
        let there = match provider.read_all().await {
            Ok(t) => t,
            Err(e) => return fail(format!("cannot read the provider: {e}")),
        };
        let conflicts = portal_conflicts(&cols, &there);
        if !conflicts.is_empty() {
            return fail(format!(
                "the provider's default collection holds different portal keys for {}; move them away there first",
                conflicts.join(", ")
            ));
        }
    }
    let report = match provider.write(&cols).await {
        Ok(r) => r,
        Err(e) if e.partial => {
            return fail(format!("{} (items written before this remain in the provider)", e.message));
        }
        Err(e) => return fail(format!("{}. Nothing was written", e.message)),
    };
    let back = match provider.read_all().await {
        Ok(b) => b,
        Err(e) => return fail(format!("cannot read the provider back: {e}")),
    };
    let (found, total) = found_in(&back, &cols);
    println!(
        "wrote {} items, replaced {} older versions ({} already there, {} new collections)",
        report.items_written, report.items_replaced, report.items_skipped, report.collections_created
    );
    if found != total {
        return fail(format!("verification failed: only {found} of {total} items read back identically"));
    }
    println!("verified: all {total} items are in the provider. The vault was not changed.");
    ExitCode::SUCCESS
}

/// App IDs for which the provider's default collection holds an item whose
/// secret bytes differ from the key that would be written.
fn portal_conflicts(cols: &[PortableCollection], there: &[PortableCollection]) -> Vec<String> {
    let Some(default) = there.iter().find(|c| c.aliases.iter().any(|a| a == DEFAULT_ALIAS)) else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    for key in cols.iter().flat_map(|c| &c.items) {
        let Some(id) = key.attributes.get("app_id") else { continue };
        if out.contains(id) {
            continue;
        }
        if default.items.iter().any(|i| {
            i.attributes.get("app_id").map(String::as_str) == Some(id.as_str()) && i.secret.value != key.secret.value
        }) {
            out.push(id.clone());
        }
    }
    out
}

/// Replaces the vault with a backup, after checking that the backup opens
/// with its password and is intact. The replaced vault is kept beside it.
pub async fn restore(file: &Path, opts: Options) -> ExitCode {
    if let Err(e) = harden() {
        return fail(e);
    }
    let dir = &opts.data_dir;
    let (Some(parent), Some(name)) = (dir.parent(), dir.file_name()) else {
        return fail("the data directory has no parent");
    };
    let name = name.to_string_lossy();
    // The time, and a random part: another restore started in the same
    // second must not pick the same names.
    let mut random = [0u8; 4];
    if getrandom::fill(&mut random).is_err() {
        return fail("randomness unavailable");
    }
    let tag = format!(
        "{:x}-{:08x}",
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
        u32::from_be_bytes(random)
    );
    let staging = parent.join(format!(".{name}.restore-{tag}"));
    let result = restore_into(file, dir, parent, &name, &tag, &staging, &opts.pinentry).await;
    match result {
        Ok(msg) => {
            println!("{msg}");
            ExitCode::SUCCESS
        }
        Err(e) => fail(e),
    }
}

/// Puts `staging` in place of `dir` and moves the old vault to `kept`.
/// Both directories are swapped in one step, so a crash leaves one vault
/// or the other at `dir`, never none; until the old one is renamed to
/// `kept` it is at `staging`. The parent is synced in between, so the swap
/// is on disk before anything else happens. Filesystems that cannot swap
/// get two renames, synced, and a short window without a vault.
fn swap_in(staging: &Path, dir: &Path, kept: &Path) -> Result<(), String> {
    use rustix::fs::{CWD, RenameFlags, renameat_with};
    let parent = dir.parent().unwrap_or(Path::new("/"));
    let sync_parent = || std::fs::File::open(parent).and_then(|d| d.sync_all());
    match renameat_with(CWD, staging, CWD, dir, RenameFlags::EXCHANGE) {
        Ok(()) => {
            sync_parent().map_err(|e| format!("cannot sync {}: {e}", parent.display()))?;
            std::fs::rename(staging, kept).map_err(|e| {
                format!("the backup is in place, but the previous vault stays in {}: {e}", staging.display())
            })
        }
        Err(rustix::io::Errno::INVAL | rustix::io::Errno::NOSYS | rustix::io::Errno::OPNOTSUPP) => {
            std::fs::rename(dir, kept).map_err(|e| format!("cannot move the current vault aside: {e}"))?;
            sync_parent().map_err(|e| format!("cannot sync {}: {e}", parent.display()))?;
            if let Err(e) = std::fs::rename(staging, dir) {
                let _ = std::fs::rename(kept, dir);
                return Err(format!("cannot put the backup in place: {e}"));
            }
            Ok(())
        }
        Err(e) => Err(format!("cannot put the backup in place: {e}")),
    }
}

/// A staging directory to remove when dropped, unless taken (`None`).
struct Staging<'a>(Option<&'a Path>);

impl Drop for Staging<'_> {
    fn drop(&mut self) {
        if let Some(p) = self.0 {
            let _ = std::fs::remove_dir_all(p);
        }
    }
}

async fn restore_into(
    file: &Path,
    dir: &Path,
    parent: &Path,
    name: &str,
    tag: &str,
    staging: &Path,
    cfg: &PinentryConfig,
) -> Result<String, String> {
    // A running daemon would keep using the old files.
    let current = if Vault::exists(dir) { Some(open(dir)?) } else { None };

    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    std::fs::DirBuilder::new().mode(0o700).create(staging).map_err(|e| format!("{}: {e}", staging.display()))?;
    // Removed again unless it is put in place; only what this run created.
    let mut cleanup = Staging(Some(staging));
    {
        let mut src = std::fs::File::open(file).map_err(|e| format!("cannot read {}: {e}", file.display()))?;
        let mut dst = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(staging.join(scopevault::store::db::DB_FILE))
            .map_err(|e| e.to_string())?;
        std::io::copy(&mut src, &mut dst).map_err(|e| e.to_string())?;
        dst.flush().and_then(|()| dst.sync_all()).map_err(|e| e.to_string())?;
    }
    let summary = {
        let mut v = Vault::open(staging).map_err(|e| format!("{} is not a usable backup: {e}", file.display()))?;
        let what =
            format!("scopevault-admin wants to restore the backup {}. Enter the backup's password.", file.display());
        unlock(&mut v, cfg, &what).await?;
        // Unlocking checks the metadata only; a damaged secret would show
        // only when an app reads it.
        v.verify_secrets().map_err(|e| format!("{} is not a usable backup: {e}", file.display()))?;
        let scopes = v.scope_summaries(&AdminAuthority::offline()).map_err(|e| e.to_string())?;
        format!("{} scopes, {} items", scopes.len(), scopes.iter().map(|s| s.items).sum::<usize>())
    };
    let sync_parent = || std::fs::File::open(parent).and_then(|d| d.sync_all());
    let kept = if dir.exists() {
        let kept = parent.join(format!("{name}.before-restore-{tag}"));
        swap_in(staging, dir, &kept)?;
        cleanup.0 = None;
        Some(kept)
    } else {
        std::fs::rename(staging, dir).map_err(|e| format!("cannot put the backup in place: {e}"))?;
        cleanup.0 = None;
        None
    };
    sync_parent().map_err(|e| format!("cannot sync {}: {e}", parent.display()))?;
    drop(current);
    Ok(match kept {
        Some(k) => format!("restored {summary}; the previous vault is kept in {}", k.display()),
        None => format!("restored {summary}"),
    })
}
