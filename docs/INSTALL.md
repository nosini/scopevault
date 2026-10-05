# Installing scopevault

This guide switches a GNOME desktop from gnome-keyring to scopevault, and
back again if you change your mind. It is written for openSUSE Tumbleweed;
on other distributions the steps are the same once the paths match.

Nothing here happens automatically, and nothing needs root except
installing the packages and the optional login unlocking at the end.

## Installing the packages

On openSUSE Tumbleweed, scopevault can be installed as RPMs instead of
the manual installation below. Build them from the repository, then
install them:

```sh
scripts/build-rpm.sh
sudo zypper install --allow-unsigned-rpm target/rpm/RPMS/x86_64/scopevault-*.rpm \
    target/rpm/RPMS/noarch/scopevault-gui-*.rpm
```

`pam_scopevault-*.rpm` (in the same directory) adds the PAM module and its
helper for the login unlock, in `/usr/libexec/scopevault-pam-helper`. The
packages don't change anything for anyone by themselves: they install the
programs, the systemd user units (not enabled) and the GUI's desktop
entry. Each user switches with `scopevault-admin setup`, as in "Switching
over" below, skipping step 1.

After installing a newer version, each user who switched restarts the
daemon (which locks the vault) and GNOME Online Accounts:

```sh
systemctl --user daemon-reload
systemctl --user restart scopevault.service
pkill -x goa-daemon
```

Coming from a manual installation, remove its copies, which would take
precedence over the packages' (`scopevault-admin setup` names any it
finds), and the manual PAM helper:

```sh
rm ~/.local/bin/scopevault-daemon ~/.local/bin/scopevault-admin ~/.local/bin/scopevault-gui
rm ~/.config/systemd/user/scopevault.service ~/.config/systemd/user/scopevault-unlock.service
rm ~/.local/share/applications/eu.nosini.ScopeVault.desktop
sudo rm /usr/local/libexec/scopevault-pam-helper
```

The package's PAM module replaces the manually installed one at the same
path; the lines in `/etc/pam.d` stay as they are. Then run
`scopevault-admin setup`: on an account that scopevault already serves,
it takes over the files and enables the packaged units, and there is
nothing left to import. Restart the daemon as after an update.

## What gets installed

Build the daemon and the command-line tool, and put them in `~/.local/bin`:

```sh
cargo build --release
install -m 755 target/release/scopevault-daemon target/release/scopevault-admin ~/.local/bin/
```

The configuration files are in `packaging/`. The two systemd units go
into `~/.config/systemd/user/`:

```sh
install -D -m 644 packaging/scopevault.service ~/.config/systemd/user/scopevault.service
install -D -m 644 packaging/scopevault-unlock.service ~/.config/systemd/user/scopevault-unlock.service
```

`scopevault-admin setup` installs the rest when you switch over (see
"Switching over"). To do it by hand instead, each file says in its first
lines where it belongs:

```sh
install -D -m 644 packaging/org.freedesktop.secrets.service ~/.local/share/dbus-1/services/org.freedesktop.secrets.service
install -D -m 644 packaging/eu.nosini.ScopeVault.Portal.service ~/.local/share/dbus-1/services/eu.nosini.ScopeVault.Portal.service
install -D -m 644 packaging/gnome-keyring-secrets.desktop ~/.config/autostart/gnome-keyring-secrets.desktop
install -D -m 644 packaging/scopevault.portal ~/.local/share/xdg-desktop-portal/portals/scopevault.portal
```

Your own `gnome-portals.conf` selects scopevault for the Secret portal.
xdg-desktop-portal reads it instead of the system's (version 1.20 reads
only the first one it finds), so it has to keep the system's settings
too. Start from a copy of the system file:

```sh
mkdir -p ~/.config/xdg-desktop-portal
cp /usr/share/xdg-desktop-portal/gnome-portals.conf ~/.config/xdg-desktop-portal/
```

Then, in its `[preferred]` group, change the
`org.freedesktop.impl.portal.Secret=` line to
`org.freedesktop.impl.portal.Secret=scopevault`, or add that line. If you
already have a `~/.config/xdg-desktop-portal/gnome-portals.conf`, only
make that change in it. If the system has no `gnome-portals.conf`, install
`packaging/gnome-portals.conf` instead.

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
  files with. Your `gnome-portals.conf` is the system's with the Secret
  portal changed, so the other portals stay as they were. The
  backend has its own bus name, `eu.nosini.ScopeVault.Portal`, and
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

3. Install the files, but don't log out yet: run `scopevault-admin
   setup`, which also does step 4 (or install them by hand as above). It
   keeps a `gnome-portals.conf` of your own aside as
   `gnome-portals.conf.before-scopevault`. While gnome-keyring still runs
   the session and scopevault doesn't run, import everything:

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

4. Enable scopevault and mask gnome-keyring's units (`setup` did this):

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
- After restarting the daemon, also restart programs that keep running and
  use libsecret, above all GNOME Online Accounts: `pkill -x goa-daemon`.
  D-Bus starts it again when it's needed. libsecret opens one encrypted
  session per process and never another, and a restarted daemon doesn't
  know the old one, so such a program fails every request until it
  restarts ("sign in failed" for every account). The daemon logs it once
  per program. gnome-keyring behaves the same way.
- The daemon keeps running when you log out, with the vault locked, for
  the same reason. After changing the unit files,
  `systemctl --user daemon-reload` is enough.

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

`scopevault-admin setup --revert` does steps 1, 2 and 4 in the right
order, puts your own `gnome-portals.conf` back, and prints the commands
for step 3. xdg-desktop-portal reads its configuration only at login, so
the export still works afterwards. Otherwise, by hand:

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

4. Remove `~/.local/share/xdg-desktop-portal/portals/scopevault.portal`,
   and `~/.config/xdg-desktop-portal/gnome-portals.conf` if you made it
   for scopevault (otherwise set its Secret line back).

5. Log out and back in. The vault stays in `~/.local/share/scopevault`
   until you delete it.

## Backups

`scopevault-admin backup FILE` writes an encrypted copy of the vault while
the daemon runs. It opens with the master password you have at that
moment. `scopevault-admin restore` needs the daemon stopped. It checks the
backup, swaps it in for the vault in one step and keeps the previous vault
beside it as `<data dir>.before-restore-<time>-<random>`.
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
sed "s|@BINDIR@|$HOME/.local/bin|" packaging/eu.nosini.ScopeVault.desktop \
    > ~/.local/share/applications/eu.nosini.ScopeVault.desktop
```

To check that PyGObject and the libraries are there:

```sh
python3 -c 'import gi; gi.require_version("Gtk", "4.0"); gi.require_version("Adw", "1"); from gi.repository import Adw; print(Adw.get_major_version(), Adw.get_minor_version())'
```

It runs the `scopevault-admin` next to it, or else the one on `PATH`;
`--admin PATH` and `--socket PATH` override that. Don't package it as a
Flatpak: the admin socket refuses sandboxed programs on purpose.

## Updating from a version before 0.12.0

The D-Bus names and the files named after them used to start with
`page.codeberg.nosini.ScopeVault`. Nothing in the vault depends on the
name, but the installed files do:

1. Remove the old activation file and desktop entry:

   ```sh
   rm ~/.local/share/dbus-1/services/page.codeberg.nosini.ScopeVault.Portal.service
   rm ~/.local/share/applications/page.codeberg.nosini.ScopeVault.desktop
   ```

2. Install the new binaries and files as in "What gets installed",
   `scopevault.portal` included, and the GUI's desktop entry as in "The
   graphical front end".

3. dbus-broker only reads activation files when asked to, and systemd
   keeps using the old unit files until it reloads them, so reload both,
   then restart the daemon and GNOME Online Accounts:

   ```sh
   gdbus call --session -d org.freedesktop.DBus -o /org/freedesktop/DBus -m org.freedesktop.DBus.ReloadConfig
   systemctl --user daemon-reload
   systemctl --user restart scopevault.service
   pkill -x goa-daemon
   ```

4. Log out and back in, so xdg-desktop-portal reads the new
   `scopevault.portal`. `scripts/activation-check.sh` should then end with
   "scopevault serves the Secret Service". While the installed
   `scopevault.portal` still names the old bus name, the daemon logs a
   warning when it starts.

If you pinned ScopeVault to the dash, pin it again: the pin refers to the
old desktop entry.

## Unlocking with the login password (optional)

With this, logging in at GDM opens the vault without a second dialog, and
so does unlocking the screen if the vault was locked in the meantime. The
master password keeps working. How it works and what it changes is
described in [LOGIN-UNLOCK.md](LOGIN-UNLOCK.md).

It needs root and changes two PAM files. Keep a root shell open while you
try it: the module can't block a login, but a typo in a PAM file can.

1. With the packages, install `pam_scopevault-*.rpm` and go on with
   step 2. Otherwise build and install the daemon, the CLI, the helper
   and the module:

   ```sh
   cargo build --release
   cargo build --release --manifest-path pam/Cargo.toml
   install -m 755 target/release/scopevault-daemon target/release/scopevault-admin ~/.local/bin/
   systemctl --user restart scopevault.service   # locks the vault; unlock it again
   pkill -x goa-daemon                           # see "Checking it"
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
