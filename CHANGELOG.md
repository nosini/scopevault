# Changelog

## 0.10.1

- The PAM helper no longer logs a failed delivery at every login when the
  daemon simply isn't running yet.

## 0.10.0

- Logging in, or unlocking the screen, can open the vault with your login
  password. This needs the new PAM module and helper, set up by hand as
  root; see docs/LOGIN-UNLOCK.md.
- The vault can hold a second key wrap for the login password, and a
  changed login password is picked up at the next unlock.
- `scopevault-admin login-unlock enable | disable | status`.

## 0.9.2

- `--version` for the daemon and the CLI, with the commit they were built
  from. The daemon logs it at startup.

## 0.9.1

- Creating a vault could delete an existing one when it raced another
  process or failed on permissions.
- One app could make the daemon decrypt and hold gigabytes with a single
  `GetSecrets`. Replies are now capped at 16 MiB.
- Resetting a scope that held nothing left grants to it in place.
- Connections refused by the per-app limit kept their slot.
- An item's label could rewrite the text of the daemon's share dialog,
  and a long one could crash the request.
- `restore` accepted backups with damaged secrets.
- `export` added a changed item next to its old version in gnome-keyring
  instead of replacing it.
- Migrating from another scopevault failed for large secrets.
- `import`, `export` and `restore` now harden the process like the daemon.

## 0.9.0

- A graphical front end, `scopevault-gui`, for the administration tasks.
- Every `scopevault-admin` command that talks to the daemon accepts
  `--json`, and errors come back as JSON too.

## 0.8.1

- At login, gnome-shell can dismiss the unlock dialog before showing it.
  `scopevault-admin unlock --wait` now opens it again.
- Successful portal requests are logged at debug level, since some apps
  ask every second.

## 0.8.0

- Requests made while the vault is locked wait for an unlock, for up to
  five minutes, instead of failing after a cancelled dialog. Apps starting
  at login no longer lose their secrets because the first dialog went
  wrong.
- A pinentry that fails because GNOME's prompt isn't ready yet is retried.
- `scopevault-admin unlock` and `scopevault-unlock.service`, which opens
  the dialog right after login.

## 0.7.0

- Single items can be shared with another scope, read-only or
  read-write: `scopevault-admin share`, `unshare` and `grants`. Shared
  items appear in a `Shared` collection.

## 0.6.0

- scopevault can be the Secret portal backend. Per-app portal keys live in
  a reserved `portal` scope, and `import` moves gnome-keyring's keys there
  unchanged.
- `scopevault-admin portal init` and `portal new-key`.

## 0.5.0

- `scopevault-admin`: status, global lock, password change, listing
  scopes and items, moving items between scopes, resetting a scope,
  backup and restore.
- Import from gnome-keyring and export back to it.
- Installation files and instructions, and a warning when gnome-keyring
  queues for the Secret Service name.

## 0.4.1

- Each scope gets a `login` collection as its default, as with
  gnome-keyring. Cryptomator could not save passwords without it.

## 0.4.0

- Limits on request sizes, connections per app and repeatedly cancelled
  prompts.
- A request waiting for the unlock dialog is dropped when its client
  disconnects, together with everything the client had queued.
- Adversarial tests, fuzzing, and checks with real Flatpak sandboxes.

## 0.3.0

- The daemon: the complete Secret Service API on the encrypted vault,
  with plain and encrypted transfer sessions, prompts and per-collection
  locking.

## 0.2.0

- The encrypted vault: Argon2id and XChaCha20-Poly1305 in SQLite, with a
  pinentry password dialog.

## 0.1.0

- Identifying callers as a Flatpak app, a host program or neither, and
  routing Secret Service requests per scope.
