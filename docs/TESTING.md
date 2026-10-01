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

## Checks on a real desktop

These checks run against real programs but leave your keyring alone.

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
