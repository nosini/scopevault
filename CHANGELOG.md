# Changelog

## 0.12.8

- The GUI stops a refresh that an operation overtook. Locking the vault
  while the window was still reading it could ask for the grants or a
  listing afterwards, which opened the unlock dialog again.
- `scripts/host-flatpak-check.sh --app` gives the app a fresh profile:
  its `~/.var/app` directory is moved aside for the run and put back
  afterwards. The app used to keep its real data while talking to a
  temporary vault, so a key it created there was lost with that vault.
  A running app now stops the script.
- `scripts/activation-check.sh` finds the portal configuration in
  xdg-desktop-portal's search order instead of looking only at the
  user's `gnome-portals.conf`.
- The SecretStorage interoperability check runs again against a new
  vault (it expected an old collection path), and the isolated bus it
  runs on is torn down when its helper is interrupted.

## 0.12.7

- The daemon reads its Secret Service connection from the moment it
  starts serving. Startup could hang at login when many other
  connections came and went on the bus before it had taken its name.
- Locking the vault, before the system sleeps or with `scopevault-admin
  lock`, also closes an unlock dialog that is still open, so answering it
  afterwards no longer unlocks the vault again.
- `scopevault-admin lock`, which locks the vault at logout, tries again
  for up to ten seconds while the daemon's client slots are busy instead
  of failing at once.
- INSTALL.md: the portal configuration is a copy of the system's
  `gnome-portals.conf` with the Secret line changed. xdg-desktop-portal
  1.20 reads only the first such file, so a file naming only the Secret
  portal dropped the system's settings for the other portals. The upgrade
  from before 0.12.0 now reloads systemd before restarting the daemon.
- DESIGN.md lists one more limit: while the vault is locked, one app can
  fill the request queue that all apps share.

## 0.12.6

- The Secret portal backend writes an app's key without tying up a
  thread, and no longer changes the flags of the fd the app passed. An
  app could otherwise occupy the threads that caller identification, the
  login socket and key derivation need, or leave a write blocked for
  good. Closing a request stops its write, and only pipes and sockets
  receive a key.
- The check for an app's own keyring file no longer follows symlinks in
  the app's directory; a symlink anywhere on the path counts as a file.
  A dangling `data` symlink could get an app a fresh key that cannot
  decrypt its data. The check no longer holds the vault lock.
- Keys are created automatically only for Flatpak apps. Snaps and host
  apps keep their keyring files elsewhere, so they need an imported key
  or `scopevault-admin portal new-key`.
- A portal request is dropped, and its dialog closed, when its frontend
  no longer owns `org.freedesktop.portal.Desktop`. A Close that arrives
  while the request is still being checked is no longer lost.
- Caller identification checks that `/.flatpak-info` and Flatpak's
  instance records are regular files before opening them for reading.

## 0.12.5

- `scopevault-admin restore` swaps the backup in for the vault in one
  step and syncs the directory, so a crash can no longer leave the data
  directory without a vault. A restore that fails removes only its own
  staging directory, not that of another restore started in the same
  second.
- `export` writes the default collection only into the provider's
  default collection (creating one if needed), and checks portal keys
  there. Portal keys could otherwise land in a collection that merely had
  the same label, where gnome-keyring's portal backend does not look.
- An admin request is cancelled when its client goes away: its dialog
  closes, nothing is changed and its slot is free again. An interrupted
  `reset-scope` no longer deletes the scope once the password is entered.
- `scopevault-admin` escapes control, line break and bidirectional
  formatting characters in app-chosen text it prints.
- `reset-scope portal` is refused: it would make every Flatpak app's own
  encrypted files unreadable. The GUI no longer offers it.

## 0.12.4

- The PAM module delivers the password kept from authentication only to
  the account it was entered for. An application that switched the PAM
  user before opening the session (sudo does) could otherwise pass one
  user's password to another user's helper.
- An unlock still deriving its key when the vault is locked (before the
  system sleeps, for example) no longer completes after the lock, and a
  login unlock no longer completes with a slot that was replaced
  meanwhile.
- A login password kept for repairing the login slot is wiped when its
  five minutes are over and at every lock, not only at the next unlock.
- A new master password and the login slot keep the key derivation cost
  of the vault's master wrap; the daemon used the lower default for
  vaults it had not created itself in this run.
- `unix_chkpwd` is stopped after 10 seconds instead of holding up login
  requests for as long as it hangs.
- The PAM module kills and reaps a helper that does not finish within
  five seconds, and does not start the helper at all when `close_range`
  is unavailable (Linux before 5.9), since it could not close every
  descriptor of the host process.
- Password buffers on the login path are allocated in full before any
  password is copied in, so no unwiped copies are left behind.

## 0.12.3

- An `Unlock` prompt kept every path of its request until it completed,
  so one app could make the daemon hold gigabytes and get it killed. A
  prompt now keeps only the distinct paths that can name an object, and
  an app's pending prompts hold at most 4096 of them.
- An app that started many unlock prompts at once got a password dialog
  for each, past the limit of three cancelled dialogs. The limit is now
  checked when each dialog's turn comes.
- Locking or unlocking a collection now signals each of its items'
  `Locked` change; libsecret caches it per item and skipped unlocked
  items as still locked.
- Apps that an item is shared with are told when the owner's lock hides
  or shows it, and when `CreateItem` replaces it.
- A request caught by a lock right after an unlock is answered with
  `IsLocked` instead of "No such object".
- Every copy of a transfer session's shared value is wiped.

## 0.12.2

- Moving an item into a scope whose `default` alias pointed at its
  in-memory `session` collection lost the item at the next lock. The
  `session` alias now only ever names that collection, and no other alias
  can; a `session` alias saved by an older version that names a stored
  collection is dropped at unlock.
- Unlocking read every secret into memory, so an app that stored enough
  data could make the vault impossible to open. It now reads only the
  metadata, and checks every record's size first.
- A scope's `session` collection may hold at most 8 MiB of secrets, and a
  write no longer copies the scope's whole index, which slowed every app
  down as one app's data grew.
- A daemon that died while making a backup left a full copy of the vault,
  login slot included, in the vault directory. The copy never contains
  the slot now, and leftovers are removed when the vault opens.
- A record write can no longer replace a record of another namespace.
- Hash states are wiped from memory; docs/STORE.md now lists exactly what
  is and isn't wiped.

## 0.12.1

- The daemon logs a warning when an installed `scopevault.portal` names
  another bus name than the one it serves, such as the old
  `page.codeberg.nosini.ScopeVault.Portal` after an update that kept the
  file. xdg-desktop-portal then sends every Secret portal request to a
  name nobody owns.
- `scripts/activation-check.sh` fails in that case too, and when the bus
  cannot start the portal backend because dbus-broker was not reloaded
  after the activation file was installed. It also lists activation files
  left over from older versions.
- The update steps in docs/INSTALL.md have their own section, reload
  dbus-broker, and say that a dash pin of the old desktop entry has to be
  made again.

## 0.12.0

- The D-Bus names and the application ID now start with
  `eu.nosini.ScopeVault` instead of `page.codeberg.nosini.ScopeVault`.
  The portal backend's activation file and the GUI's desktop entry were
  renamed to match. An existing installation needs the new files; see
  "Updating from a version before 0.12.0" in docs/INSTALL.md.

## 0.11.1

- The daemon keeps running when you log out, and the vault is locked
  instead. Programs that outlive a logout, such as GNOME Online Accounts,
  lost their libsecret session whenever the Secret Service went away and
  then failed every request until restarted.
- The daemon logs which program uses a transfer session it never opened,
  so it is clear what needs restarting after the daemon restarts.

## 0.11.0

- The vault locks before the system suspends or hibernates. With login
  unlocking, unlocking the screen after resume opens it again.

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
