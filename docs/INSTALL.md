# Installing scopevault

This guide switches a GNOME desktop from gnome-keyring to scopevault, and
back again if you change your mind. It is written for openSUSE Tumbleweed;
on other distributions the steps are the same once the paths match.

Nothing here happens automatically, and nothing needs root except the
optional login unlocking at the end.

## What gets installed

Build the daemon and the command-line tool, and put them in `~/.local/bin`:

```sh
cargo build --release
install -m 755 target/release/scopevault-daemon target/release/scopevault-admin ~/.local/bin/
```

The configuration files are in `packaging/`. Each one says in its first
lines where it belongs:

```sh
install -D -m 644 packaging/scopevault.service ~/.config/systemd/user/scopevault.service
install -D -m 644 packaging/scopevault-unlock.service ~/.config/systemd/user/scopevault-unlock.service
install -D -m 644 packaging/org.freedesktop.secrets.service ~/.local/share/dbus-1/services/org.freedesktop.secrets.service
install -D -m 644 packaging/page.codeberg.nosini.ScopeVault.Portal.service ~/.local/share/dbus-1/services/page.codeberg.nosini.ScopeVault.Portal.service
install -D -m 644 packaging/gnome-keyring-secrets.desktop ~/.config/autostart/gnome-keyring-secrets.desktop
install -D -m 644 packaging/scopevault.portal ~/.local/share/xdg-desktop-portal/portals/scopevault.portal
install -D -m 644 packaging/gnome-portals.conf ~/.config/xdg-desktop-portal/gnome-portals.conf
```

If you already have a `~/.config/xdg-desktop-portal/gnome-portals.conf`,
add the `org.freedesktop.impl.portal.Secret=scopevault` line to its
`[preferred]` group instead of replacing the file.

What they do:

- `scopevault.service` starts the daemon when you log in, before
  applications and autostart entries run. Password dialogs use
  pinentry-gnome3, which shows GNOME's own prompt.
- `org.freedesktop.secrets.service` makes D-Bus start that unit, rather
  than gnome-keyring, when something asks for the Secret Service. Files in
  your own services directory win over the ones in `/usr/share`.
- `gnome-keyring-secrets.desktop` hides the autostart entry that would
  start gnome-keyring's Secret Service.
- `scopevault.portal` and `gnome-portals.conf` make scopevault the Secret
  portal backend, which hands Flatpak apps the keys they encrypt their own
  files with. Your `gnome-portals.conf` only names the Secret portal;
  everything else still comes from the system's configuration. The
  backend has its own bus name, `page.codeberg.nosini.ScopeVault.Portal`, and
  its activation file starts the same unit.
- `scopevault-unlock.service` opens the unlock dialog as soon as you are
  logged in, so the vault is usually open before apps ask for it. Apps
  that ask while the dialog is up wait for it, but apps that talk to the
  Secret Service directly give up after about 25 seconds, so don't leave
  it waiting long.

gnome-keyring's own systemd user units get masked as well. They are
disabled by default, but a single `systemctl --user restart
gnome-keyring-daemon` starts the socket unit, and from then on the next
connection to gnome-keyring, for example PAM when you unlock the screen,
starts a second gnome-keyring that queues for the Secret Service name.

PAM keeps starting gnome-keyring at login, for SSH keys and certificates.
As long as nothing asks it for its Secret Service it doesn't claim the
name, and it exits after two minutes.

## Switching over

1. Build and install the binaries as above.

2. Optionally, back up gnome-keyring's data, and keep it either way:
   switching back uses it.

   ```sh
   cp -a ~/.local/share/keyrings ~/keyrings-backup
   ```

3. Install the files as above, but don't log out yet. While gnome-keyring
   still runs the session and scopevault doesn't run, import everything:

   ```sh
   scopevault-admin import --pinentry /usr/bin/pinentry-gnome3
   ```

   This creates the vault in `~/.local/share/scopevault`, asking for a new
   master password twice, and copies all collections into the `host`
   scope. gnome-keyring may ask you to unlock its collections first. It is
   not changed.

   The Secret portal's keys ("Application key for <app-id>" in
   gnome-keyring's default collection) go into the `portal` scope instead,
   byte for byte, and the import lists the apps they belong to. Import as
   the very last step before logging out: an app that uses the portal for
   the first time before then gets a new key from gnome-keyring, which the
   vault wouldn't have. Running the import again only adds what is new. If
   it stops because gnome-keyring has several items for one app, delete
   the wrong one in Seahorse and import again.

4. Enable scopevault and mask gnome-keyring's units:

   ```sh
   systemctl --user daemon-reload
   systemctl --user enable scopevault.service scopevault-unlock.service
   systemctl --user mask gnome-keyring-daemon.socket gnome-keyring-daemon.service
   ```

5. Log out and back in. gnome-keyring keeps the name until the end of the
   current session; at the next login scopevault takes it, and
   xdg-desktop-portal reads its new configuration.

6. Give Flatpak apps that use the Secret Service directly their items
   back. The import put everything into `host`, but a Flatpak app only
   sees its own scope, so such an app now finds nothing. Apps that use the
   Secret portal are fine, their keys are already in place. scopevault
   never guesses which item belongs to which app, so this is up to you:
   `flatpak list --app` shows the app IDs, and `scopevault-admin list
   host` shows the items with their labels and attributes, never the
   secrets. Then move them:

   ```sh
   scopevault-admin move host flatpak/APP-ID COLLECTION/ITEM...
   ```

   `move` asks for the master password and needs the daemon running,
   which is why it comes after the switch. Cryptomator's items, for
   example, are labelled "Cryptomator" and have a `Vault` attribute:

   ```sh
   scopevault-admin move host flatpak/org.cryptomator.Cryptomator login/ITEM...
   ```

   Do this before starting such an app. If it already ran and saved new
   items, for example because you entered a password again,
   `scopevault-admin reset-scope flatpak/APP-ID` clears its scope first.

## Checking it

- `scripts/activation-check.sh` should end with "scopevault serves the
  Secret Service".
- `secret-tool lookup` with the attributes of an item you know opens
  scopevault's unlock dialog and returns the secret.
- Flatpak apps that use the Secret portal still open their data. If one
  can't, the daemon's log says why. "The application has a keyring file
  of its own" means its key wasn't imported; `scopevault-admin portal
  new-key APP-ID` gives it a new one, but its old file can't be read
  after that. "Neither imported nor initialised" means no import ran.
  `scopevault-admin list portal` shows which apps have keys, without the
  keys.
- The daemon logs to the journal: `journalctl --user -u scopevault`.
- `scopevault-daemon --version` and `scopevault-admin --version` show the
  version and the commit they were built from. The daemon logs the same
  when it starts, so the journal tells you whether the running daemon is
  the one you installed. After installing new binaries, run
  `systemctl --user restart scopevault.service`, which locks the vault.

On a desktop that never had gnome-keyring, run `scopevault-admin portal
init` instead of importing. From then on every app without a keyring file
of its own gets a new key when it first asks.

## Known risk

Whenever something starts gnome-keyring's Secret Service, gnome-keyring
waits in the bus queue for the name. If scopevault then stops or
restarts, gnome-keyring gets the name immediately, and apps start storing
new secrets there without telling you.
With scopevault as the portal backend, the portal no longer does this,
but gnome-keyring's own D-Bus name still does if a program asks for it.

The daemon checks every minute and logs "another process is queued for
org.freedesktop.secrets" when that happens, and
`scripts/activation-check.sh` shows the queue as well. To recover, log out
and back in. Don't restart scopevault while something is queued.

## Switching back

The order matters. As long as the D-Bus activation file is installed, any
request for the name starts scopevault again, and the export would end up
writing into scopevault itself.
Keep the portal configuration until step 4: while it is in place and
scopevault is stopped, portal requests fail, instead of gnome-keyring
creating new keys that would clash with the ones you export.

1. Disable the units, unmask gnome-keyring's, and remove the files you
   installed (except the two portal files). dbus-broker only reads service files when asked to, so reload it
   along with systemd:

   ```sh
   systemctl --user disable scopevault.service scopevault-unlock.service
   systemctl --user unmask gnome-keyring-daemon.socket gnome-keyring-daemon.service
   systemctl --user daemon-reload
   gdbus call --session -d org.freedesktop.DBus -o /org/freedesktop/DBus -m org.freedesktop.DBus.ReloadConfig
   ```

2. Stop the daemon: `systemctl --user stop scopevault.service`.

3. If you want to keep secrets you stored since the switch, make
   gnome-keyring serve the name again with `gnome-keyring-daemon --start
   --components=secrets`, check with `scripts/activation-check.sh` that
   it does, and export:

   ```sh
   scopevault-admin export --pinentry /usr/bin/pinentry-gnome3
   ```

   It writes the items gnome-keyring doesn't have and skips the ones it
   has.
   An item you changed in scopevault replaces gnome-keyring's older
   version instead of ending up next to it. If gnome-keyring has several
   items that could be that older version, the export writes nothing and
   names them; delete the obsolete ones in Seahorse and run it again.

   If apps got new portal keys from scopevault, export those as well:

   ```sh
   scopevault-admin export --scope portal --pinentry /usr/bin/pinentry-gnome3
   ```

   They go into gnome-keyring's default collection, where its portal
   backend looks for them. If gnome-keyring already has a different key
   for one of the apps, nothing is written.

4. Remove `~/.local/share/xdg-desktop-portal/portals/scopevault.portal`
   and the Secret line in `~/.config/xdg-desktop-portal/gnome-portals.conf`,
   or the whole file if nothing else is in it.

5. Log out and back in. The vault stays in `~/.local/share/scopevault`
   until you delete it.

## Backups

`scopevault-admin backup FILE` writes an encrypted copy of the vault while
the daemon runs. It opens with the master password you have at that
moment. `scopevault-admin restore` needs the daemon stopped.
The portal keys are in the vault and therefore in its backups, but the
files they decrypt stay in `~/.var/app/<app-id>/`. Back those up as well,
and restore them together with the vault.

## The graphical front end

`gui/scopevault-gui` shows the vault's state, the scopes with their items
(labels and attributes, never secrets) and the grants. It can lock and
unlock, change the password, move items, reset a scope, share and unshare,
and make backups. It needs Python 3 with PyGObject, GTK 4 and libadwaita
1.5 or newer. Every password still goes to the daemon's own dialog, and
restoring, importing and exporting stay on the command line.

```sh
install -m 755 gui/scopevault-gui ~/.local/bin/
sed "s|@BINDIR@|$HOME/.local/bin|" packaging/page.codeberg.nosini.ScopeVault.desktop \
    > ~/.local/share/applications/page.codeberg.nosini.ScopeVault.desktop
```

To check that PyGObject and the libraries are there:

```sh
python3 -c 'import gi; gi.require_version("Gtk", "4.0"); gi.require_version("Adw", "1"); from gi.repository import Adw; print(Adw.get_major_version(), Adw.get_minor_version())'
```

It runs the `scopevault-admin` next to it, or else the one on `PATH`;
`--admin PATH` and `--socket PATH` override that. Don't package it as a
Flatpak: the admin socket refuses sandboxed programs on purpose.

## Unlocking with the login password (optional)

With this, logging in at GDM opens the vault without a second dialog, and
so does unlocking the screen if the vault was locked in the meantime. The
master password keeps working. How it works and what it changes is
described in [LOGIN-UNLOCK.md](LOGIN-UNLOCK.md).

It needs root and changes two PAM files. Keep a root shell open while you
try it: the module can't block a login, but a typo in a PAM file can.

1. Build and install the daemon, the CLI, the helper and the module:

   ```sh
   cargo build --release
   cargo build --release --manifest-path pam/Cargo.toml
   install -m 755 target/release/scopevault-daemon target/release/scopevault-admin ~/.local/bin/
   systemctl --user restart scopevault.service   # locks the vault; unlock it again
   sudo install -o root -g root -m 755 target/release/scopevault-pam-helper /usr/local/libexec/
   sudo install -o root -g root -m 755 pam/target/release/libpam_scopevault.so /usr/lib64/security/pam_scopevault.so
   sudo restorecon -v /usr/local/libexec/scopevault-pam-helper /usr/lib64/security/pam_scopevault.so
   ```

   The helper has to belong to root and must not be writable by you,
   because the module starts it from processes running as root.

2. If `/etc/pam.d/gdm-password` doesn't exist, copy
   `/usr/lib/pam.d/gdm-password` there. Then add

   ```
   auth     optional       pam_scopevault.so
   ```

   right after `auth substack common-auth`, and

   ```
   session  optional       pam_scopevault.so
   ```

   right after `session substack common-session`.

3. For password changes, which GNOME Settings also makes through
   `passwd`, copy `/usr/lib/pam.d/passwd` to `/etc/pam.d/passwd` and add

   ```
   password optional       pam_scopevault.so
   ```

   after `password include common-password`. Like the `gdm-password`
   copy, it then hides future vendor changes to that file. Without this
   step, a new login password is picked up at the next unlock instead.

4. Run `scopevault-admin login-unlock enable`. It asks for the master
   password, then for your login password, checks the latter and lets it
   open the vault.

To check, log out and back in. No scopevault dialog should appear, and
`journalctl -b -t scopevault-pam-helper` shows "login password
delivered: unlocked". `scopevault-admin login-unlock status` shows when it
last unlocked. Keep `scopevault-unlock.service`: it still asks when the
login password couldn't open the vault, such as after a fingerprint or
automatic login.

If the login password changed in a way PAM didn't pass on, say root reset
it or step 3 is missing, the next login shows the master-password dialog
once. When the vault opens, the daemon checks the new login password and
updates the slot.

To undo it, remove the lines (or the copied `passwd` file), then

```sh
scopevault-admin login-unlock disable
sudo rm /usr/lib64/security/pam_scopevault.so /usr/local/libexec/scopevault-pam-helper
```

Backups never contain the login slot; they only open with the master
password.
