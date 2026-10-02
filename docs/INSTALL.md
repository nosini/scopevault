# Installing scopevault

This guide switches a GNOME desktop from gnome-keyring to scopevault, and
back again if you change your mind. It is written for openSUSE Tumbleweed;
on other distributions the steps are the same once the paths match.

Nothing here happens automatically, and nothing needs root.

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
install -D -m 644 packaging/org.freedesktop.secrets.service ~/.local/share/dbus-1/services/org.freedesktop.secrets.service
install -D -m 644 packaging/gnome-keyring-secrets.desktop ~/.config/autostart/gnome-keyring-secrets.desktop
```

What they do:

- `scopevault.service` starts the daemon when you log in, before
  applications and autostart entries run. Password dialogs use
  pinentry-gnome3, which shows GNOME's own prompt.
- `org.freedesktop.secrets.service` makes D-Bus start that unit, rather
  than gnome-keyring, when something asks for the Secret Service. Files in
  your own services directory win over the ones in `/usr/share`.
- `gnome-keyring-secrets.desktop` hides the autostart entry that would
  start gnome-keyring's Secret Service.

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
   systemctl --user enable scopevault.service
   systemctl --user mask gnome-keyring-daemon.socket gnome-keyring-daemon.service
   ```

5. Log out and back in. gnome-keyring keeps the name until the end of the
   current session; at the next login scopevault takes it.

## Checking it

- `scripts/activation-check.sh` should end with "scopevault serves the
  Secret Service".
- `secret-tool lookup` with the attributes of an item you know opens
  scopevault's unlock dialog and returns the secret.
- The daemon logs to the journal: `journalctl --user -u scopevault`.

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

1. Disable the units, unmask gnome-keyring's, and remove the files you
   installed. dbus-broker only reads service files when asked to, so reload it
   along with systemd:

   ```sh
   systemctl --user disable scopevault.service
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

4. Log out and back in. The vault stays in `~/.local/share/scopevault`
   until you delete it.

## Backups

`scopevault-admin backup FILE` writes an encrypted copy of the vault while
the daemon runs. It opens with the master password you have at that
moment. `scopevault-admin restore` needs the daemon stopped.
