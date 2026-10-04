//! On-disk layout: a private directory holding one SQLite database.
//!
//! The database contains only key wraps (KDF parameters, salt, wrapped
//! key: the master password's in `vault`, others in `key_slots`) and
//! records of `(id, kind, namespace, nonce, ciphertext)`. IDs and
//! namespace IDs are random; labels, attributes, scope names and secrets are
//! only ever inside ciphertext, so the database, its WAL and its shared
//! memory file hold no plaintext. What remains visible is described in
//! docs/STORE.md.

use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use rustix::fs::{FlockOperation, Mode, OFlags};

use super::StoreError;
use crate::crypto::{KdfParams, KeyWrap, NONCE_LEN, SALT_LEN};

pub const DB_FILE: &str = "vault.db";
const LOCK_FILE: &str = "lock";
/// "SVLT" — marks the file as ours.
const APPLICATION_ID: i64 = 0x5356_4c54;
pub const SCHEMA_VERSION: i64 = 1;

pub type RecordId = [u8; 16];

/// The largest ciphertext a record may have. The largest plaintexts are a
/// 512 KiB secret and an item whose 64 attributes JSON-escape to about
/// 1.7 MiB; this leaves room above both.
pub const MAX_CIPHERTEXT_BYTES: usize = 4 * 1024 * 1024;

/// Key wraps other than the master password's. Created with the first one.
const KEY_SLOTS_TABLE: &str = "CREATE TABLE IF NOT EXISTS key_slots (
    kind INTEGER PRIMARY KEY CHECK (kind BETWEEN 1 AND 255),
    kdf_m INTEGER NOT NULL, kdf_t INTEGER NOT NULL, kdf_p INTEGER NOT NULL,
    salt BLOB NOT NULL, nonce BLOB NOT NULL, wrapped BLOB NOT NULL);";

#[derive(Debug, Clone)]
pub struct RawRecord {
    pub id: RecordId,
    pub kind: u8,
    pub namespace: RecordId,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// A value of the wrong SQL type means the file was altered outside the
/// vault; report it as corruption, not as a database failure.
fn typed(e: rusqlite::Error) -> StoreError {
    match e {
        rusqlite::Error::InvalidColumnType(..)
        | rusqlite::Error::FromSqlConversionFailure(..)
        | rusqlite::Error::IntegralValueOutOfRange(..) => StoreError::Corrupt("stored value has the wrong type".into()),
        other => StoreError::Db(other),
    }
}

pub struct Db {
    conn: Connection,
    dir: PathBuf,
    /// Held for the lifetime of the store; a second opener fails.
    _lock: OwnedFd,
}

fn uid() -> u32 {
    rustix::process::getuid().as_raw()
}

/// Creates `dir` (mode 0700) if needed and checks that it is a real
/// directory owned by us and not accessible to others. Returns an fd.
fn private_dir(dir: &Path) -> Result<OwnedFd, StoreError> {
    match std::fs::symlink_metadata(dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = dir.parent() {
                std::fs::create_dir_all(parent)?;
            }
            rustix::fs::mkdir(dir, Mode::RWXU).map_err(std::io::Error::from)?;
        }
        Err(e) => return Err(e.into()),
        Ok(_) => {}
    }
    let fd =
        rustix::fs::open(dir, OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty())
            .map_err(|e| StoreError::InsecurePath(format!("{}: {e}", dir.display())))?;
    let st = rustix::fs::fstat(&fd).map_err(std::io::Error::from)?;
    if st.st_uid != uid() || st.st_mode & 0o077 != 0 {
        return Err(StoreError::InsecurePath(format!(
            "{} must be owned by you with mode 0700 (is {:o})",
            dir.display(),
            st.st_mode & 0o7777
        )));
    }
    Ok(fd)
}

/// Checks a file in the private directory, if it exists: regular, ours,
/// not accessible to others.
fn check_file(dir_fd: &OwnedFd, name: &str) -> Result<(), StoreError> {
    match rustix::fs::statat(dir_fd, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => Ok(()),
        Err(e) => Err(std::io::Error::from(e).into()),
        Ok(st) => {
            let regular = rustix::fs::FileType::from_raw_mode(st.st_mode) == rustix::fs::FileType::RegularFile;
            if !regular || st.st_uid != uid() || st.st_mode & 0o077 != 0 {
                return Err(StoreError::InsecurePath(format!("{name} must be a regular file with mode 0600")));
            }
            Ok(())
        }
    }
}

/// One opener per vault. Note that `flock` belongs to the open file
/// description, so a child forked while the lock is held keeps it until the
/// child execs (the descriptor is close-on-exec).
fn take_lock(dir_fd: &OwnedFd) -> Result<OwnedFd, StoreError> {
    let fd = rustix::fs::openat(
        dir_fd,
        LOCK_FILE,
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(std::io::Error::from)?;
    rustix::fs::flock(&fd, FlockOperation::NonBlockingLockExclusive).map_err(|_| StoreError::InUse)?;
    Ok(fd)
}

impl Db {
    pub fn exists(dir: &Path) -> bool {
        dir.join(DB_FILE).exists()
    }

    /// Opens the database under `dir_fd`, which the caller has locked.
    fn connect(dir_fd: &OwnedFd, dir: &Path) -> Result<Connection, StoreError> {
        for name in [DB_FILE, "vault.db-wal", "vault.db-shm", "vault.db-journal"] {
            check_file(dir_fd, name)?;
        }
        let conn = Connection::open_with_flags(
            dir.join(DB_FILE),
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        // Durable commits; no temporary files on disk; overwrite freed pages
        // so deleted ciphertext does not linger in the file.
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             PRAGMA secure_delete = ON;
             PRAGMA temp_store = MEMORY;
             PRAGMA trusted_schema = OFF;
             PRAGMA cell_size_check = ON;",
        )?;
        Ok(conn)
    }

    /// Creates the database. A failure after the file was created removes
    /// it again, while the lock is still held: only a file this call
    /// created is ever removed, so a vault another opener holds or created
    /// meanwhile is left alone.
    pub fn create(dir: &Path, wrap: &KeyWrap) -> Result<Db, StoreError> {
        let dir_fd = private_dir(dir)?;
        let lock = take_lock(&dir_fd)?;
        // Create the file ourselves so its mode is 0600 from the start;
        // SQLite gives the WAL and shm files the same mode.
        rustix::fs::openat(
            &dir_fd,
            DB_FILE,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|e| match e {
            rustix::io::Errno::EXIST => StoreError::Exists,
            e => std::io::Error::from(e).into(),
        })?;
        match Self::initialise(&dir_fd, dir, wrap) {
            Ok(conn) => Ok(Db { conn, dir: dir.to_owned(), _lock: lock }),
            Err(e) => {
                for name in [DB_FILE, "vault.db-wal", "vault.db-shm", "vault.db-journal"] {
                    let _ = rustix::fs::unlinkat(&dir_fd, name, rustix::fs::AtFlags::empty());
                }
                Err(e)
            }
        }
    }

    fn initialise(dir_fd: &OwnedFd, dir: &Path, wrap: &KeyWrap) -> Result<Connection, StoreError> {
        let mut conn = Self::connect(dir_fd, dir)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Exclusive)?;
        tx.execute_batch(&format!(
            "PRAGMA application_id = {APPLICATION_ID};
             PRAGMA user_version = {SCHEMA_VERSION};
             CREATE TABLE vault (
                 id INTEGER PRIMARY KEY CHECK (id = 1),
                 kdf_m INTEGER NOT NULL, kdf_t INTEGER NOT NULL, kdf_p INTEGER NOT NULL,
                 salt BLOB NOT NULL, nonce BLOB NOT NULL, wrapped BLOB NOT NULL);
             CREATE TABLE records (
                 id BLOB NOT NULL, kind INTEGER NOT NULL, namespace BLOB NOT NULL,
                 nonce BLOB NOT NULL, ciphertext BLOB NOT NULL,
                 PRIMARY KEY (id, kind)) WITHOUT ROWID;"
        ))?;
        tx.execute(
            "INSERT INTO vault (id, kdf_m, kdf_t, kdf_p, salt, nonce, wrapped) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6)",
            params![wrap.kdf.m_kib, wrap.kdf.t, wrap.kdf.p, &wrap.salt[..], &wrap.nonce[..], &wrap.wrapped],
        )?;
        tx.commit()?;
        Ok(conn)
    }

    pub fn open(dir: &Path) -> Result<Db, StoreError> {
        let dir_fd = private_dir(dir)?;
        let lock = take_lock(&dir_fd)?;
        if !Self::exists(dir) {
            return Err(StoreError::NotFound);
        }
        let conn = Self::connect(&dir_fd, dir)?;
        let app_id: i64 = conn.query_row("PRAGMA application_id", [], |r| r.get(0))?;
        if app_id != APPLICATION_ID {
            return Err(StoreError::NotAVault);
        }
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version != SCHEMA_VERSION {
            return Err(StoreError::UnsupportedVersion(version));
        }
        Ok(Db { conn, dir: dir.to_owned(), _lock: lock })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn key_wrap(&self) -> Result<KeyWrap, StoreError> {
        let row = self
            .conn
            .query_row("SELECT kdf_m, kdf_t, kdf_p, salt, nonce, wrapped FROM vault WHERE id = 1", [], |r| {
                Ok((
                    r.get::<_, u32>(0)?,
                    r.get::<_, u32>(1)?,
                    r.get::<_, u32>(2)?,
                    r.get::<_, Vec<u8>>(3)?,
                    r.get::<_, Vec<u8>>(4)?,
                    r.get::<_, Vec<u8>>(5)?,
                ))
            })
            .optional()
            .map_err(typed)?
            .ok_or_else(|| StoreError::Corrupt("missing key wrap".into()))?;
        let (m_kib, t, p, salt, nonce, wrapped) = row;
        let salt: [u8; SALT_LEN] = salt.try_into().map_err(|_| StoreError::Corrupt("bad salt length".into()))?;
        let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| StoreError::Corrupt("bad nonce length".into()))?;
        Ok(KeyWrap { kdf: KdfParams { m_kib, t, p }, salt, nonce, wrapped })
    }

    /// The wrap stored for key slot `kind`, if any. The `key_slots` table
    /// is created with the first slot; older vaults do not have it, and
    /// older builds ignore it.
    pub fn key_slot(&self, kind: u8) -> Result<Option<KeyWrap>, StoreError> {
        if !self.has_key_slots()? {
            return Ok(None);
        }
        let row = self
            .conn
            .query_row(
                "SELECT kdf_m, kdf_t, kdf_p, salt, nonce, wrapped FROM key_slots WHERE kind = ?1",
                params![kind],
                |r| {
                    Ok((
                        r.get::<_, u32>(0)?,
                        r.get::<_, u32>(1)?,
                        r.get::<_, u32>(2)?,
                        r.get::<_, Vec<u8>>(3)?,
                        r.get::<_, Vec<u8>>(4)?,
                        r.get::<_, Vec<u8>>(5)?,
                    ))
                },
            )
            .optional()
            .map_err(typed)?;
        let Some((m_kib, t, p, salt, nonce, wrapped)) = row else { return Ok(None) };
        let salt: [u8; SALT_LEN] = salt.try_into().map_err(|_| StoreError::Corrupt("bad salt length".into()))?;
        let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| StoreError::Corrupt("bad nonce length".into()))?;
        Ok(Some(KeyWrap { kdf: KdfParams { m_kib, t, p }, salt, nonce, wrapped }))
    }

    fn has_key_slots(&self) -> Result<bool, StoreError> {
        let n: i64 = self.conn.query_row(
            "SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = 'key_slots'",
            [],
            |r| r.get(0),
        )?;
        Ok(n == 1)
    }

    /// Stores (or replaces) the wrap of key slot `kind`.
    pub fn set_key_slot(&mut self, kind: u8, wrap: &KeyWrap) -> Result<(), StoreError> {
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(KEY_SLOTS_TABLE)?;
        tx.execute(
            "INSERT INTO key_slots (kind, kdf_m, kdf_t, kdf_p, salt, nonce, wrapped) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT (kind) DO UPDATE SET kdf_m = excluded.kdf_m, kdf_t = excluded.kdf_t,
                 kdf_p = excluded.kdf_p, salt = excluded.salt, nonce = excluded.nonce, wrapped = excluded.wrapped",
            params![kind, wrap.kdf.m_kib, wrap.kdf.t, wrap.kdf.p, &wrap.salt[..], &wrap.nonce[..], &wrap.wrapped],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Removes key slot `kind`. Returns whether there was one.
    pub fn delete_key_slot(&mut self, kind: u8) -> Result<bool, StoreError> {
        if !self.has_key_slots()? {
            return Ok(false);
        }
        let n = self.conn.execute("DELETE FROM key_slots WHERE kind = ?1", params![kind])?;
        Ok(n > 0)
    }

    pub fn set_key_wrap(&mut self, wrap: &KeyWrap) -> Result<(), StoreError> {
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let n = tx.execute(
            "UPDATE vault SET kdf_m = ?1, kdf_t = ?2, kdf_p = ?3, salt = ?4, nonce = ?5, wrapped = ?6 WHERE id = 1",
            params![wrap.kdf.m_kib, wrap.kdf.t, wrap.kdf.p, &wrap.salt[..], &wrap.nonce[..], &wrap.wrapped],
        )?;
        if n != 1 {
            return Err(StoreError::Corrupt("missing key wrap".into()));
        }
        tx.commit()?;
        Ok(())
    }

    /// Refuses the vault if any record has an ID, namespace or nonce of
    /// the wrong length or a ciphertext over [`MAX_CIPHERTEXT_BYTES`].
    /// `length()` does not read the value, so a damaged or tampered file
    /// can't make the loading below allocate without bound.
    pub fn check_record_sizes(&self) -> Result<(), StoreError> {
        let bad: bool = self
            .conn
            .query_row(
                "SELECT EXISTS (SELECT 1 FROM records WHERE length(id) != 16 OR length(namespace) != 16
                     OR length(nonce) != ?1 OR length(ciphertext) > ?2)",
                params![NONCE_LEN as i64, MAX_CIPHERTEXT_BYTES as i64],
                |r| r.get(0),
            )
            .map_err(typed)?;
        if bad { Err(StoreError::Corrupt("record of the wrong size".into())) } else { Ok(()) }
    }

    /// Every record except those of kind `except`. Call
    /// [`Db::check_record_sizes`] first.
    pub fn load_all_except(&self, except: u8) -> Result<Vec<RawRecord>, StoreError> {
        let mut stmt =
            self.conn.prepare("SELECT id, kind, namespace, nonce, ciphertext FROM records WHERE kind != ?1")?;
        let rows = stmt.query_map(params![except], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, Vec<u8>>(3)?,
                r.get::<_, Vec<u8>>(4)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, kind, namespace, nonce, ciphertext) = row.map_err(typed)?;
            let bad = |what: &str| StoreError::Corrupt(format!("record with malformed {what}"));
            out.push(RawRecord {
                id: id.try_into().map_err(|_| bad("id"))?,
                kind: u8::try_from(kind).map_err(|_| bad("kind"))?,
                namespace: namespace.try_into().map_err(|_| bad("namespace"))?,
                nonce,
                ciphertext,
            });
        }
        Ok(out)
    }

    /// The IDs and namespaces of the records of one kind, without their
    /// contents.
    pub fn ids_of_kind(&self, kind: u8) -> Result<Vec<(RecordId, RecordId)>, StoreError> {
        let mut stmt = self.conn.prepare("SELECT id, namespace FROM records WHERE kind = ?1")?;
        let rows = stmt.query_map(params![kind], |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?)))?;
        let mut out = Vec::new();
        for row in rows {
            let (id, namespace) = row.map_err(typed)?;
            let bad = |what: &str| StoreError::Corrupt(format!("record with malformed {what}"));
            out.push((id.try_into().map_err(|_| bad("id"))?, namespace.try_into().map_err(|_| bad("namespace"))?));
        }
        Ok(out)
    }

    pub fn load_one(&self, id: &RecordId, kind: u8) -> Result<Option<RawRecord>, StoreError> {
        self.conn
            .query_row(
                "SELECT namespace, nonce, ciphertext FROM records WHERE id = ?1 AND kind = ?2",
                params![&id[..], kind],
                |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?, r.get::<_, Vec<u8>>(2)?)),
            )
            .optional()
            .map_err(typed)?
            .map(|(ns, nonce, ciphertext)| -> Result<RawRecord, StoreError> {
                Ok(RawRecord {
                    id: *id,
                    kind,
                    namespace: ns
                        .try_into()
                        .map_err(|_| StoreError::Corrupt("record with malformed namespace".into()))?,
                    nonce,
                    ciphertext,
                })
            })
            .transpose()
    }

    /// Writes a consistent copy of the database (ciphertext and the master
    /// key wrap, as stored) to `dest`, which must not exist. Other key
    /// slots are left out, so the copy opens with the master password only.
    pub fn backup_into(&self, dest: &Path) -> Result<(), StoreError> {
        let name = dest.to_str().ok_or(StoreError::Invalid("backup path is not UTF-8"))?;
        self.conn.execute("VACUUM INTO ?1", params![name])?;
        if self.has_key_slots()? {
            let copy = Connection::open_with_flags(
                dest,
                OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )?;
            // The final VACUUM rewrites the file, so no page of the dropped
            // table is left in it.
            copy.execute_batch(
                "PRAGMA journal_mode = DELETE;
                 PRAGMA secure_delete = ON;
                 DROP TABLE key_slots;
                 VACUUM;",
            )?;
        }
        Ok(())
    }

    /// Applies writes and deletes atomically.
    pub fn apply(&mut self, writes: &[RawRecord], deletes: &[(RecordId, u8)]) -> Result<(), StoreError> {
        let ops: Vec<Op<'_>> =
            writes.iter().map(Op::Put).chain(deletes.iter().map(|(id, k)| Op::Delete(*id, *k))).collect();
        self.apply_ops(&ops)
    }

    /// Applies operations atomically, in order.
    pub fn apply_ops(&mut self, ops: &[Op<'_>]) -> Result<(), StoreError> {
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        {
            let mut put = tx.prepare_cached(
                "INSERT INTO records (id, kind, namespace, nonce, ciphertext) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT (id, kind) DO UPDATE SET namespace = excluded.namespace,
                     nonce = excluded.nonce, ciphertext = excluded.ciphertext",
            )?;
            let mut del = tx.prepare_cached("DELETE FROM records WHERE id = ?1 AND kind = ?2")?;
            for op in ops {
                match op {
                    Op::Put(r) => put.execute(params![&r.id[..], r.kind, &r.namespace[..], &r.nonce, &r.ciphertext])?,
                    Op::Delete(id, kind) => del.execute(params![&id[..], kind])?,
                };
            }
        }
        tx.commit()?;
        Ok(())
    }
}

/// One change to the records table.
pub enum Op<'a> {
    Put(&'a RawRecord),
    Delete(RecordId, u8),
}
