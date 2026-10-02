# scopevault

scopevault replaces gnome-keyring as the Secret Service
(`org.freedesktop.secrets`) on a GNOME desktop, with one that keeps
Flatpak apps apart. Each Flatpak app gets its own private part of the
keyring, while ordinary desktop programs keep sharing theirs as before.
Apps use the standard Secret Service API and need no changes.

gnome-keyring doesn't tell its clients apart. Any Flatpak app that is
allowed to talk to the Secret Service can read every password stored
there while the keyring is unlocked, which on GNOME means from login on,
including the passwords of all other apps.

## Status

The daemon implements the whole Secret Service API on an encrypted vault,
and works with libsecret, `secret-tool`, Seahorse and Python's
`secretstorage`. It can be tried on a private bus, but there is no
installation or migration from gnome-keyring yet.

It is written in Rust and needs a session bus that hands out process file
descriptors, which dbus-broker does.

## What it does

- Every Flatpak app has its own scope. Host programs share one scope,
  `host`. Callers that can't be identified reliably are refused.
- Foreign objects look exactly like missing ones, and signals only reach
  the scope they concern.
- Secrets are stored in one encrypted vault, opened with a master password
  through pinentry.

It does not protect secrets from unsandboxed programs running as you;
nothing that runs as you can. [docs/DESIGN.md](docs/DESIGN.md) explains
what it does protect and why.

## Documentation

- [docs/DESIGN.md](docs/DESIGN.md): how callers are identified, how scopes
  work, and the limits.
- [docs/STORE.md](docs/STORE.md): the encrypted vault.
- [docs/TESTING.md](docs/TESTING.md): the tests, and checking scopevault
  against real Flatpak apps without touching your keyring.
- [CHANGELOG.md](CHANGELOG.md)

## Building

```sh
cargo build --release
cargo test
```

The tests start their own private D-Bus daemon; see
[docs/TESTING.md](docs/TESTING.md) for what they need.

## Licence

GNU AGPL v3, see `LICENSE`. Identifying Flatpak apps follows
xdg-desktop-portal (LGPL-2.1-or-later); see the comments in
`src/identity/flatpak.rs`.
