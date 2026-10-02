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

The adversarial tests in `tests/adversarial.rs` go through the real
identity code with separate client processes on the host and in simulated
sandboxes, and check each isolation requirement: identical attributes in
two apps, foreign paths in every method and inside batch requests, forged
app IDs, malformed identities, signals, sessions and prompts used from
other connections, connection churn and per-app locks.

## Fuzzing

`tests/fuzz_dbus.rs` sends random but well-formed requests to the running
service from several apps, a second instance of one of them, the host and
an unidentified caller. Every request has to be answered with a proper
D-Bus error or a result, and nothing of another app may leak or change.
`cargo test` sends 3000; `SCOPEVAULT_FUZZ_ITERATIONS` asks for more and
`SCOPEVAULT_FUZZ_SEED` repeats a run.

The byte-level decoders (`.flatpak-info`, transfer-session input, object
paths and vault records) have cargo-fuzz targets in `fuzz/`. They need a
nightly toolchain and `cargo install cargo-fuzz`:

```sh
cd fuzz && cargo +nightly fuzz run flatpak_info   # or transfer, object_path, records
```

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

### Real Flatpak sandboxes

```sh
cargo build --bins
./scripts/host-flatpak-check.sh APP_ID_A APP_ID_B     # isolation checks
./scripts/host-flatpak-check.sh --real --app APP_ID   # a real app
```

`flatpak run` puts its D-Bus proxy in front of whatever bus
`DBUS_SESSION_BUS_ADDRESS` names. The script first checks that with the
identity probe, then runs `scopevault-client` inside both apps' sandboxes
and compares what each app, the host and an unsupported sandbox can see.
The client has to run on the Flatpak runtimes' glibc, so build it on a
system with a glibc no newer than theirs.

With `--app`, it starts the real app on the private bus. Use it, save a
password, quit it, and the script lists what the app asked for. It then
offers a second run on the same vault with the daemon restarted, to check
that the app finds what it stored. `scripts/sandbox-secret-check.sh`
stores, reads, searches and deletes a test secret from a shell inside a
sandbox, for apps that have a terminal.

### Migration and rollback

`scripts/host-migration-check.sh` fills a private gnome-keyring with
three items, imports them into a new vault, adds a fourth in scopevault
and exports everything back.

`scripts/activation-check.sh` is read-only. It shows who serves the
Secret Service in your real session, what is queued for the name, and
which files decide that.

### The Secret portal

`scripts/host-portal-check.sh APP_ID` runs the real xdg-desktop-portal on
a private bus, first with gnome-keyring as the portal backend: the app
stores a value with its own libsecret. Then the key is imported,
gnome-keyring stops, scopevault takes over as the backend, and the app has
to read the old value and store a new one. The app's keyring file is
redirected into a temporary directory, and its real data is checked to be
unchanged at the end.
