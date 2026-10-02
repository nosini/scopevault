# Testing

## The test suite

```sh
cargo test
```

The integration tests start a private `dbus-daemon`, taken from
`$DBUS_DAEMON` or `PATH`. It has to report the caller's process file
descriptor (`ProcessFD` in `GetConnectionCredentials`): dbus 1.15.8 or
newer built where `SO_PEERPIDFD` is defined, or dbus-broker 35 or newer.
The identity tests also need unprivileged user namespaces
(`unshare -Urm` must work), because they build sandboxes that look like
Flatpak's from the outside.

Those simulated sandboxes copy Flatpak's mechanisms, namespaces,
`/.flatpak-info` and instance records, not Flatpak itself. That is why
the scripts below check the same things against real Flatpak apps.

`tests/libsecret.rs` drives the daemon with libsecret's `secret-tool` and
is skipped when `secret-tool` isn't installed.

## Checks on a real desktop

These checks run against real programs but leave your keyring alone.
Apart from the identity probe, each script starts its own private
dbus-broker bus with a temporary vault. dbus-broker is needed because
openSUSE's `dbus-daemon` doesn't report `ProcessFD`.

### Identity probe

`scopevault-probe` owns only `page.codeberg.nosini.ScopeVault.IdentityProbe`,
stores nothing and doesn't touch gnome-keyring. It reports how scopevault
would classify each caller.

```sh
cargo build --release --bin scopevault-probe
./target/release/scopevault-probe serve           # terminal 1
./scripts/probe-host-checks.sh APP_ID_A APP_ID_B  # terminal 2
```

Pick two installed Flatpak apps (`flatpak list --app`). The script runs
`gdbus` inside each app's sandbox with a one-off permission to talk to the
probe. The apps themselves are not started, and their permissions are not
changed.

### libsecret and Seahorse

```sh
cargo build --bins
./scripts/host-libsecret-check.sh          # scripted dialogs
./scripts/host-libsecret-check.sh --real   # real pinentry dialogs
```

This runs `secret-tool` store, lookup, search, clear, lock, a restart and
a cancelled unlock. With `--seahorse` it opens Seahorse on the same
private bus afterwards. `scripts/interop-secretstorage.sh` does the same
with Python's `secretstorage` library; set `PYTHON` to an interpreter that
has it.
