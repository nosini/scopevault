# The encrypted vault

All secrets live in one SQLite database that holds nothing but ciphertext.
The code is in `src/crypto.rs` and `src/store/`; the password dialog is in
`src/prompts/`.

## Keys

The vault key is 32 random bytes, made once when the vault is created. It
never touches the disk unencrypted: on disk it is wrapped with
XChaCha20-Poly1305 under a key derived from the master password with
Argon2id, using a random 32-byte salt and the cost parameters recorded next
to it. The record key that encrypts everything else is derived from the
vault key with HKDF-SHA256.

The wrap's associated data covers the format version, the cost parameters
and the salt. A wrong password and a tampered header therefore look the
same. Changing the password wraps the same vault key again with a fresh
salt; the records themselves are not re-encrypted.

The default cost is 256 MiB of memory, 3 passes and 1 lane.
When the daemon creates a vault, it measures the machine and picks the
number of passes so that unlocking takes about a second.
Whatever the header says, the parameters must stay within fixed bounds
(19 MiB to 2 GiB, 1 to 20 passes, 1 to 16 lanes), so a tampered or
imported vault cannot make the daemon allocate unbounded memory or run for
hours.

### The login slot

The vault key can also be wrapped under the login password, so that
logging in can unlock the vault (see [LOGIN-UNLOCK.md](LOGIN-UNLOCK.md)).
Either password opens the vault. The slot's associated data starts
differently from the master wrap's, so neither can be passed off as the
other, and the master wrap is unchanged from vaults without a slot.

While the vault is unlocked the daemon keeps the vault key in memory, so it
can wrap it for the login slot without asking for the master password
again. Changing the master password leaves the slot alone, and backups
leave it out: a backup only opens with the master password.

The cryptography comes from RustCrypto's `chacha20poly1305`, `argon2`,
`hkdf` and `sha2`, pinned to exact versions in `Cargo.toml`, plus
`zeroize`. SQLite is bundled through `rusqlite`.

## Records

Each record is encrypted with XChaCha20-Poly1305 under the record key, with
a fresh random 192-bit nonce. The associated data is

```
"scopevault/record\0" ‖ format version (u16) ‖ kind (u8) ‖ namespace ID (16) ‖ record ID (16)
```

so a ciphertext only decrypts as the record it was written as. Moving it to
another ID, kind or namespace, or swapping two of them, fails.

| Kind | What it holds, encrypted |
| --- | --- |
| 1, namespace | The scope (`host`, `flatpak/<app-id>`, `portal`) and its aliases |
| 2, collection | Name, label, creation and modification time |
| 3, item | Its collection, label, attributes, creation and modification time |
| 4, secret | Content type and value, under the same ID as its item |
| 5, grant | The shared item, the scope it is shared with, write access, creation time |

Grants were added without changing the format version. An older build
refuses a vault that holds one ("unknown kind"), which is the safe way
round. When unlocking, every grant is checked: its item must exist in the
same namespace, and it must name a valid scope other than the owner's.

Metadata is stored as JSON that rejects unknown fields; secrets use a
small binary format. Unlocking decrypts and cross-checks all metadata.
Secrets stay on disk: unlocking only checks that every item has one, and a
secret is read and decrypted when it is asked for. Before reading
anything, unlocking checks every record's size: IDs and nonces must have
their exact length and no ciphertext may exceed 4 MiB, so a damaged file
can't make it allocate without bound.

## On disk

The vault lives in `$XDG_DATA_HOME/scopevault` unless the daemon is given
`--data-dir`.
The directory must be a real directory, not a symlink, owned by you and
closed to everyone else. It holds `vault.db` with SQLite's `-wal` and
`-shm` files, all mode 0600, and a `lock` file whose exclusive `flock`
keeps a second process from opening the vault.

```sql
vault     (id = 1, kdf_m, kdf_t, kdf_p, salt, nonce, wrapped)
records   (id, kind, namespace, nonce, ciphertext, PRIMARY KEY (id, kind))
key_slots (kind PRIMARY KEY, kdf_m, kdf_t, kdf_p, salt, nonce, wrapped)
```

`key_slots` only appears with the first slot. Older builds don't look at
it and still open the vault with the master password.

SQLite runs with a write-ahead log, `synchronous = FULL`, `secure_delete`
on (freed pages are overwritten), temporary data in memory only and
`trusted_schema` off. Every change is one transaction, and the in-memory
index changes only after the commit went through.

### What someone with the files can see

Without the password, someone who has the files can tell:

- that it is a scopevault vault, and its cost parameters;
- whether it has a login slot;
- how many namespaces, collections, items and secrets there are, and which
  records belong to the same namespace, because the namespace ID is stored
  in the clear (which app it belongs to is not);
- roughly how long labels, attributes and secrets are;
- when something changes, by watching the file.

App IDs, labels, attribute names and values, secrets and collection names
stay hidden. A test plants known strings and checks that none of them
appear in the database or its WAL and shm files.

## Lock states

When the vault is locked, the daemon holds no key and nothing decrypted
that it could still reach, and nothing can be listed or read. Keys and
secret values are wiped as they are dropped; labels, attributes and names
are freed without being wiped (see "Memory" below). When it is unlocked, an app can
still lock one of its collections: secrets in it then can't be read and its
items can't be changed, until the master password is entered again. That
logical lock affects nothing else and is not saved; after a restart the
whole vault is locked anyway.

The whole vault is locked by `scopevault-admin lock`
and, automatically, before the system suspends or hibernates
(`src/sleep.rs`). It does not lock with the screen.

Unlocking never changes who may see what.

## The `session` collection

Each scope can have one collection under the alias and name `session`. It
lives in memory only: neither it nor its items or secrets are ever written
to disk, and it is gone after a global lock or a restart. A stored
collection with that name counts as corruption.

The `session` alias only ever names that collection, and no other alias
names it, so whatever is stored through `default` or another alias reaches
the disk. The alias can't be removed or pointed elsewhere; it goes away
with the collection.

## The `login` collection

The first time a scope uses the unlocked vault, it gets a collection named
`login`, labelled "Login", with its `default` alias pointing there, as
gnome-keyring does with its login keyring. Some clients assume it exists:
Cryptomator's Secret Service library never creates a collection. A scope
that already has data is left as it is, so deleting `login` or moving
`default` sticks, across restarts too.

## The unlock dialog

The daemon runs `pinentry` as a child process and reads the password from
its output pipe into memory that is wiped after use. The password never
passes through the app that asked, the bus, command-line arguments or the
environment. The dialog's text comes from the daemon, and the only part
that depends on the request is the scope, which comes from identification.
App-supplied labels are never shown.

- Only one dialog at a time; concurrent requests wait for it.
- After a cancelled or failed dialog, requests that did not explicitly ask
  for one open no new dialog for 30 seconds. They wait, up to five minutes
  from their arrival, for something else to unlock the vault. Explicit
  unlock prompts still show the dialog.
- When every waiting request has gone away, pinentry is killed.
- Three wrong passwords count as a cancel.
- Without a vault, the dialog asks for a new password twice and creates
  one. Empty passwords are refused.
- The key derivation runs on a separate thread without holding the vault
  lock.
- Unlocking through the login slot serves every waiting request and closes
  an unlock dialog that is open.

## Process hardening

A process that holds the vault calls `harden_process()` first: it sets the
umask to 077, turns off core dumps and makes the process non-dumpable, so
other processes of the same user cannot attach to it or read its memory
through `/proc`.

## Limits

| What | Limit |
| --- | --- |
| Collections per scope | 256 |
| Items per collection | 10 000 |
| Aliases per scope | 64 |
| Label | 4 KiB |
| Attributes per item | 64, each name up to 256 bytes and value up to 4 KiB |
| Secret | 512 KiB |
| Secrets in a scope's `session` collection, together | 8 MiB |
| Content type | 128 bytes |
| Plaintext in one `GetSecrets` reply | 16 MiB; repeated paths are answered once |

## What this does not protect against

- Rollback. Anyone who can write the files, which includes any program
  running as you, can replace the database or single records with older
  valid copies. Encryption cannot detect that.
- Deletion. A missing secret record is noticed at unlock, and the vault
  then refuses to open rather than quietly losing an item. Whole items,
  collections or namespaces removed consistently go unnoticed.
- History. Deleting a secret does not remove it from older backups,
  filesystem snapshots or blocks the SSD remapped. `secure_delete` only
  covers the live file.
- Memory. Keys and secret values are wiped when the code drops them, and
  so are the hash functions' states. Not wiped: decrypted labels,
  attributes and names, which are freed as they are; Argon2's working
  memory, which goes back to the kernel; intermediate values on the stack
  inside the crypto libraries; and copies made by the allocator, the
  kernel or swap. Memory is not locked with `mlock`, because Argon2's
  256 MiB would exceed the usual limits.
- Root, or programs running as you. They can read the daemon's memory by
  other means, replace the daemon, or capture the password as you type it.
