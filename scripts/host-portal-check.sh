#!/bin/sh
# Portal check: a real Flatpak app's libsecret data, encrypted with a key
# from gnome-keyring's Secret portal backend, must still decrypt after that
# key was migrated into a scopevault vault and scopevault serves the Secret
# portal instead (the acceptance check is that re-read).
#
# On one private dbus-broker bus it runs gnome-keyring (temporary data) and
# xdg-desktop-portal configured, through a private XDG_DESKTOP_PORTAL_DIR, to
# use gnome-keyring's portal backend. From inside the app's sandbox (the app
# itself is never started; only `flatpak run --command`) it stores a test
# secret with libsecret, which then lands in the app's own keyring file,
# encrypted with the key the portal gave it. The key is imported into a fresh
# vault with scopevault-admin, gnome-keyring is stopped, and
# xdg-desktop-portal is restarted on scopevault's backend; the app must then
# read the stored secret again and store a new one.
#
# Nothing real is touched: the real session bus's names, the user's
# gnome-keyring data, the real vault and any file under ~/.var/app are never
# used. The app's keyring file is redirected into the work directory
# (SECRET_FILE_TEST_PATH, checked before anything is stored), and the state
# of the app's real keyrings directory is recorded at the start and verified
# to be unchanged at the end. (dbus-broker's launcher does connect to the
# real session bus as a client, to subscribe to systemd, as it always does.)
#
# Why dbus-broker: the daemon requires the bus to report the caller's
# process FD (`ProcessFD`), and refuses everyone otherwise.
#
# Needs: flatpak, gnome-keyring-daemon (gnome-keyring), secret-tool
# (libsecret-tools, for checking gnome-keyring from the host), gdbus
# (glib2-tools), dbus-broker, systemd-socket-activate (systemd),
# xdg-desktop-portal, diffutils, and built binaries (cargo build --bins).
# APP_ID: an installed Flatpak app whose runtime has secret-tool or Python
# gi with libsecret (--devel runs with the SDK, which usually has more).
#
#   scripts/host-portal-check.sh [--real] [--devel] APP_ID
#
# --real uses the real pinentry ($PINENTRY or pinentry), printing a
# ">>> dialog: ..." line before each expected dialog; by default the fake
# pinentry answers everything by itself.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
real=
devel=
app_id=
while [ $# -gt 0 ]; do
    case $1 in
        --real) real=--real ;;
        --devel) devel=--devel ;;
        -*) echo "unknown option $1" >&2; exit 2 ;;
        *) [ -z "$app_id" ] || { echo "usage: $0 [--real] [--devel] APP_ID" >&2; exit 2; }; app_id=$1 ;;
    esac
    shift
done
[ -n "$app_id" ] || { echo "usage: $0 [--real] [--devel] APP_ID" >&2; exit 2; }

need() { command -v "$1" >/dev/null || { echo "$1 not found ($2)" >&2; exit 2; }; }
need flatpak "install flatpak"
need gnome-keyring-daemon "install gnome-keyring"
need secret-tool "install libsecret-tools"
need gdbus "install glib2-tools"
need dbus-broker-launch "install dbus-broker"
need cmp "install diffutils"
need diff "install diffutils"
activate=$(command -v systemd-socket-activate || echo /usr/lib/systemd/systemd-socket-activate)
[ -x "$activate" ] || { echo "systemd-socket-activate not found" >&2; exit 2; }
# The Secret backend of xdg-desktop-portal: the packagers' paths first,
# XDP_BIN as the override.
xdp=${XDP_BIN:-}
if [ -z "$xdp" ]; then
    for p in /usr/libexec/xdg-desktop-portal /usr/lib/xdg-desktop-portal; do
        if [ -x "$p" ]; then xdp=$p; break; fi
    done
fi
if [ -z "$xdp" ] || [ ! -x "$xdp" ]; then
    echo "xdg-desktop-portal not found (set XDP_BIN)" >&2
    exit 2
fi
# The newer of the release and debug builds: a stale one must not win.
# shellcheck disable=SC2012 # two fixed paths
newest() { ls -t "$root/target/release/$1" "$root/target/debug/$1" 2>/dev/null | head -n 1; }
daemon=$(newest scopevault-daemon)
[ -n "$daemon" ] || { echo "build the binaries first: cargo build --bins" >&2; exit 2; }
admin=$(newest scopevault-admin)
[ -n "$admin" ] || { echo "build the binaries first: cargo build --bins" >&2; exit 2; }
flatpak info "$app_id" >/dev/null 2>&1 ||
    { echo "$app_id is not an installed Flatpak (see 'flatpak list --app')" >&2; exit 2; }

work=$(mktemp -d "${TMPDIR:-/tmp}/scopevault-portal.XXXXXX")
bus_pid=
gk_pid=
xdp_pid=
daemon_pid=
cleanup() {
    for p in "$xdp_pid" "$daemon_pid" "$gk_pid" "$bus_pid"; do
        [ -n "$p" ] || continue
        kill "$p" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    rm -rf "$work"
}
trap cleanup EXIT INT TERM
# Empty logs up front, so the failure dump can always print them.
for f in client daemon gk import xdp-gk xdp-sv bus; do : >"$work/$f.log"; done
real_bus=${DBUS_SESSION_BUS_ADDRESS-}

# ---- the app's real keyrings directory, recorded before anything runs ----
snap() {
    if [ -d "$HOME/.var/app/$app_id/data/keyrings" ]; then
        ls -la --time-style=full-iso "$HOME/.var/app/$app_id/data/keyrings"
    else
        echo "(the directory does not exist)"
    fi
}
snap > "$work/var-app.before"

# ---- pinentry (as in host-flatpak-check.sh) ----
mkdir "$work/pinentry"
pinentry=$work/pinentry.sh
if [ "$real" = "--real" ]; then
    cat > "$pinentry" <<EOF
#!/bin/sh
DBUS_SESSION_BUS_ADDRESS='$real_bus' exec '${PINENTRY:-pinentry}' "\$@"
EOF
else
    cat > "$pinentry" <<EOF
#!/bin/sh
FAKE_PINENTRY_DIR='$work/pinentry' exec '$root/tests/support/fake-pinentry.sh' "\$@"
EOF
fi
chmod 700 "$pinentry"
pins() { printf '%s\n' "$@" > "$work/pinentry/pins"; rm -f "$work/pinentry/count"; }
say() { [ "$real" != "--real" ] || echo ">>> dialog: $1"; }

# ---- the private bus (as in host-migration-check.sh) ----
cat > "$work/bus.conf" <<EOF
<busconfig>
  <type>session</type>
  <policy context="default">
    <!-- dbus-broker denies whatever no rule allows, receiving included -->
    <allow send_destination="*"/>
    <allow receive_sender="*"/>
    <allow own="*"/>
  </policy>
</busconfig>
EOF
bus_pid=
env_flags=
for v in DBUS_SESSION_BUS_ADDRESS XDG_RUNTIME_DIR; do
    eval "[ -n \"\${$v-}\" ]" && env_flags="$env_flags -E $v"
done
# shellcheck disable=SC2086 # env_flags is a list of options
"$activate" -l "$work/bus" --fdname=dbus.socket $env_flags \
    dbus-broker-launch --scope user --config-file "$work/bus.conf" 2>>"$work/bus.log" &
bus_pid=$!
for _ in $(seq 50); do [ -S "$work/bus" ] && break; sleep 0.1; done
dbus() { # dbus METHOD ARG: a call to the bus daemon on the private bus
    DBUS_SESSION_BUS_ADDRESS="unix:path=$work/bus" \
        gdbus call --session -d org.freedesktop.DBus -o /org/freedesktop/DBus -m "org.freedesktop.DBus.$1" "$2"
}
if ! dbus NameHasOwner org.freedesktop.DBus >/dev/null 2>&1; then
    echo "the private bus did not start:" >&2
    cat "$work/bus.log" >&2
    exit 1
fi
owns() { # owns NAME: whether NAME has an owner on the private bus
    dbus NameHasOwner "$1" 2>/dev/null | grep -q true
}
echo "private bus: $work/bus (dbus-broker)"
echo "binaries: $daemon, $admin"
echo "portal frontend: $xdp"

pass=0
fail=0
ok() { pass=$((pass + 1)); echo "ok    $1"; }
bad() { fail=$((fail + 1)); echo "FAIL  $1"; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got '$2', expected '$3')"; fi }
has() { if grep -q "$3" "$2"; then ok "$1"; else bad "$1"; fi }
limit=60
[ "$real" != "--real" ] || limit=300

# ---- the app's sandbox: data redirected for this run only ----
mkdir -p "$work/appdata" "$work/helper"
# A client inside the sandbox that speaks libsecret; the Python fallback
# needs the values as arguments, which also keeps them off any command log.
cat > "$work/helper/portal-check.py" <<'EOF'
import sys

import gi
gi.require_version("Secret", "1")
from gi.repository import Secret

SCHEMA = Secret.Schema.new("org.scopevault.PortalCheck", Secret.SchemaFlags.NONE,
                           {"check": Secret.SchemaAttributeType.STRING})


def store(label, value, check):
    Secret.password_store_sync(SCHEMA, {"check": check}, Secret.COLLECTION_DEFAULT, label, value, None)


def lookup(check):
    value = Secret.password_lookup_sync(SCHEMA, {"check": check}, None)
    print(value if value is not None else "")


if sys.argv[1] == "store":
    store(sys.argv[2], sys.argv[3], sys.argv[4])
else:
    lookup(sys.argv[2])
EOF
app_run() { # app_run COMMAND [ARG]...: one run inside the app's sandbox
    app_cmd=$1
    shift
    # shellcheck disable=SC2086 # $devel is one optional option
    DBUS_SESSION_BUS_ADDRESS="unix:path=$work/bus" timeout "$limit" \
        flatpak run $devel --env="SECRET_FILE_TEST_PATH=$work/appdata/keyrings/default.keyring" \
        --filesystem="$work/appdata" --filesystem="$work/helper:ro" \
        --no-talk-name=org.freedesktop.secrets \
        --command="$app_cmd" "$app_id" "$@" 2>>"$work/client.log"
}

# 2. libsecret's file backend would use the app's real keyring file
#    (Flatpak sets XDG_DATA_HOME to ~/.var/app/<id>/data itself, and an
#    --env override of it does not take effect). SECRET_FILE_TEST_PATH,
#    which libsecret reads before XDG_DATA_HOME, points it into the work
#    directory instead. It must be proven to reach the sandbox here, and to
#    be honoured by the runtime's libsecret before anything is stored
#    (step 4): the app's real data must never be touched.
# shellcheck disable=SC2016 # expanded inside the sandbox, not here
seen=$(app_run sh -c 'printf %s "$SECRET_FILE_TEST_PATH"') || true
if [ "$seen" != "$work/appdata/keyrings/default.keyring" ]; then
    echo "the sandbox's SECRET_FILE_TEST_PATH is '$seen', not $work/appdata/keyrings/default.keyring;" >&2
    echo "the app's real data under ~/.var/app must not be touched; aborting. Output:" >&2
    tail -n 20 "$work/client.log" >&2
    exit 2
fi
echo "the sandbox's SECRET_FILE_TEST_PATH points into \$work/appdata"
# A client that speaks libsecret: secret-tool, else Python with gi.
if [ -n "$(app_run sh -c 'command -v secret-tool')" ]; then
    client=secret-tool
elif app_run python3 -c 'import gi; gi.require_version("Secret", "1"); from gi.repository import Secret' >/dev/null 2>&1; then
    client=python3
else
    echo "neither secret-tool nor Python gi with libsecret is available in $app_id's runtime;" >&2
    echo "try --devel (runs with the SDK) or another app" >&2
    exit 2
fi
echo "client in the sandbox: $client"

app_store() { # app_store LABEL VALUE CHECKVALUE: store under attribute check=CHECKVALUE
    echo "+ app store (check=$3)" >>"$work/client.log"
    if [ "$client" = secret-tool ]; then
        printf '%s' "$2" | app_run secret-tool store --label="$1" check "$3" || true
    else
        app_run python3 "$work/helper/portal-check.py" store "$1" "$2" "$3" || true
    fi
}
app_lookup() { # app_lookup CHECKVALUE: the stored value for attribute check=CHECKVALUE
    if [ "$client" = secret-tool ]; then
        app_run secret-tool lookup check "$1" || true
    else
        app_run python3 "$work/helper/portal-check.py" lookup "$1" || true
    fi
}

# ---- gnome-keyring and xdg-desktop-portal with its portal backend ----
start_gk() { # start_gk [restart]: a fresh gnome-keyring, or again on its data
    if [ "${1-}" != restart ]; then
        mkdir -m 700 "$work/gk-data" "$work/gk-run"
        if [ -n "$(ls -A "$work/gk-data")" ]; then
            echo "$work/gk-data is not empty: refusing to work on existing keyring data" >&2
            exit 2
        fi
    fi
    printf 'gk test' | env -u GNOME_KEYRING_CONTROL \
        XDG_DATA_HOME="$work/gk-data" XDG_RUNTIME_DIR="$work/gk-run" \
        DBUS_SESSION_BUS_ADDRESS="unix:path=$work/bus" \
        gnome-keyring-daemon --foreground --components=secrets --unlock >>"$work/gk.log" 2>&1 &
    gk_pid=$!
    for _ in $(seq 100); do
        if owns org.freedesktop.secrets; then return 0; fi
        sleep 0.1
    done
    echo "gnome-keyring did not start:" >&2
    cat "$work/gk.log" >&2
    exit 1
}
# --replace is never passed: a second frontend must fail loudly, not steal
# the name. The proxies it cannot find on this bus (permission store,
# document portal) are expected to be harmless.
start_xdp() { # start_xdp PORTALS_DIR LOG
    XDG_DESKTOP_PORTAL_DIR="$1" DBUS_SESSION_BUS_ADDRESS="unix:path=$work/bus" \
        "$xdp" --verbose 2>>"$2" &
    xdp_pid=$!
    for _ in $(seq 100); do
        if owns org.freedesktop.portal.Desktop; then return 0; fi
        if ! kill -0 "$xdp_pid" 2>/dev/null; then break; fi
        sleep 0.1
    done
    echo "xdg-desktop-portal did not start or never owned org.freedesktop.portal.Desktop:" >&2
    cat "$2" >&2
    return 1
}
stop_xdp() {
    [ -n "$xdp_pid" ] || return 0
    kill "$xdp_pid" 2>/dev/null || true
    wait "$xdp_pid" 2>/dev/null || true
    xdp_pid=
}
introspect_portal() { # introspect_portal FILE: what /org/freedesktop/portal/desktop exports
    echo "+ gdbus introspect --dest org.freedesktop.portal.Desktop" >>"$work/client.log"
    DBUS_SESSION_BUS_ADDRESS="unix:path=$work/bus" timeout "$limit" \
        gdbus introspect --session --dest org.freedesktop.portal.Desktop \
            --object-path /org/freedesktop/portal/desktop >"$1" 2>>"$work/client.log" || true
}
wait_secret_portal() { # wait_secret_portal FILE: until the Secret interface is listed
    for _ in $(seq 50); do
        introspect_portal "$1"
        if grep -q org.freedesktop.portal.Secret "$1"; then return 0; fi
        sleep 0.1
    done
    return 1
}
write_portal_conf() { # write_portal_conf DIR BACKEND
    mkdir "$1"
    cat > "$1/portals.conf" <<EOF
[preferred]
default=none
org.freedesktop.impl.portal.Secret=$2
EOF
    cat > "$1/gnome-keyring.portal" <<EOF
[portal]
DBusName=org.freedesktop.secrets
Interfaces=org.freedesktop.impl.portal.Secret
EOF
    cp "$root/packaging/scopevault.portal" "$1/scopevault.portal"
}
write_portal_conf "$work/portals-gk" gnome-keyring
write_portal_conf "$work/portals-sv" scopevault

# 3. The Secret portal of gnome-keyring.
start_gk
start_xdp "$work/portals-gk" "$work/xdp-gk.log" || exit 1
ok "org.freedesktop.portal.Desktop is owned (gnome-keyring backend)"
if wait_secret_portal "$work/introspect-gk.txt"; then
    ok "the Secret portal is exported at /org/freedesktop/portal/desktop"
else
    bad "the Secret portal is exported at /org/freedesktop/portal/desktop"
fi

# 4. The app stores and reads its own file, encrypted with gnome-keyring's
#    portal key; the host sees that key in gnome-keyring.
# First a lookup, which stores nothing: opening the file backend creates
# the keyring file's directory, so $work/appdata/keyrings shows that the
# runtime's libsecret honours SECRET_FILE_TEST_PATH. Without it, stop
# before the store would write into the app's real keyring file.
app_lookup scopevault-portal-check-absent >/dev/null
if [ ! -d "$work/appdata/keyrings" ]; then
    echo "the app's libsecret did not use SECRET_FILE_TEST_PATH (no $work/appdata/keyrings);" >&2
    echo "aborting before anything is stored. The app's real keyrings directory, before and now:" >&2
    cat "$work/var-app.before" >&2
    snap >&2
    tail -n 20 "$work/client.log" >&2
    exit 2
fi
ok "the app's libsecret uses the redirected keyring file"
v1="portal-check-one"
v2="portal-check-two"
app_store "scopevault portal check" "$v1" scopevault-portal-check
check "the app reads back what it stored" "$(app_lookup scopevault-portal-check)" "$v1"
if [ -f "$work/appdata/keyrings/default.keyring" ]; then
    ok "the app's keyring file exists (the portal path was used)"
else
    bad "the app's keyring file exists (the portal path was used)"
fi
# gnome-keyring's Secret Service cannot open an item its portal backend
# created in the same run (the search lists its path, reading it fails with
# "No such secret item"); after a restart, which loads it from disk, it
# can. On a real desktop the keys come from earlier sessions, so restart.
kill "$gk_pid"
wait "$gk_pid" 2>/dev/null || true
gk_pid=
# The old connection's name must be gone, or start_gk would see it.
for _ in $(seq 50); do owns org.freedesktop.secrets || break; sleep 0.1; done
start_gk restart
ok "gnome-keyring restarted on its data"
# The key gnome-keyring made for the app. Counted by its schema, not its
# label, which gnome-keyring translates. Nothing is written down: the
# binary key bytes after `secret = ` can span several lines.
host_st() { # host_st ARGS...: secret-tool on the host, against the private bus
    echo "+ secret-tool (host) $*" >>"$work/client.log"
    DBUS_SESSION_BUS_ADDRESS="unix:path=$work/bus" timeout "$limit" secret-tool "$@" 2>>"$work/client.log"
}
n=$(host_st search --all app_id "$app_id" | grep -c '^schema = org.freedesktop.portal.Secret$') || true
check "gnome-keyring holds exactly one portal key for $app_id" "$n" 1

# 5. The key migrates into a fresh vault (new password, entered twice).
stop_xdp
pw="scopevault test"
pins "$pw" "$pw"
say "a new vault: choose the password \"$pw\" when asked (twice)"
if timeout "$limit" "$admin" import --data-dir "$work/vault" --bus "unix:path=$work/bus" \
    --pinentry "$pinentry" >"$work/import.log" 2>&1; then
    ok "import exits 0"
else
    bad "import exits 0"
fi
has "import names $app_id on the 'portal keys for' line, 1 imported" "$work/import.log" \
    "portal keys for $app_id: 1 imported"

# 6. gnome-keyring goes away for good; scopevault serves both names.
kill "$gk_pid"
wait "$gk_pid" 2>/dev/null || true
gk_pid=
pins "$pw"
DBUS_SESSION_BUS_ADDRESS="unix:path=$work/bus" RUST_LOG=${RUST_LOG:-scopevault=info} \
    "$daemon" --data-dir "$work/vault" --pinentry "$pinentry" --admin-socket "$work/admin/socket" \
        2>>"$work/daemon.log" &
daemon_pid=$!
for _ in $(seq 100); do
    if owns org.freedesktop.secrets && owns eu.nosini.ScopeVault.Portal; then break; fi
    sleep 0.1
done
if ! owns org.freedesktop.secrets || ! owns eu.nosini.ScopeVault.Portal; then
    echo "scopevault-daemon did not take org.freedesktop.secrets and its portal name:" >&2
    cat "$work/daemon.log" >&2
    exit 1
fi
ok "scopevault-daemon owns org.freedesktop.secrets and the portal backend name"
start_xdp "$work/portals-sv" "$work/xdp-sv.log" || exit 1
ok "org.freedesktop.portal.Desktop is owned again (scopevault backend)"
if wait_secret_portal "$work/introspect-sv.txt"; then
    ok "the Secret portal is exported again"
else
    bad "the Secret portal is exported again"
fi

# 7. The acceptance check: the app's existing file still decrypts. The first
#    request unlocks the new vault (one pin), the rest find it unlocked.
say "unlock the keyring: enter \"$pw\" when asked (once)"
check "the app still reads the value stored under gnome-keyring" "$(app_lookup scopevault-portal-check)" "$v1"
app_store "scopevault portal check 2" "$v2" scopevault-portal-check-2
check "a new value is stored and read through scopevault" "$(app_lookup scopevault-portal-check-2)" "$v2"
has "the daemon served RetrieveSecret calls" "$work/daemon.log" "RetrieveSecret finished"
total=$(grep -c 'RetrieveSecret finished' "$work/daemon.log") || true
served=$(grep 'RetrieveSecret finished' "$work/daemon.log" | grep -c "app_id=$app_id response=0") || true
check "every portal call was served for $app_id with response=0" "$served" "$total"
if grep -q "refused a caller" "$work/daemon.log"; then
    bad "the daemon refused a portal caller"
else
    ok "the daemon refused no portal caller"
fi

# 8. The key lives in the portal scope, not in host.
timeout "$limit" "$admin" --socket "$work/admin/socket" list portal >"$work/list-portal.log" 2>&1 || true
has "the portal scope lists $app_id" "$work/list-portal.log" "$app_id"
timeout "$limit" "$admin" --socket "$work/admin/socket" list host >"$work/list-host.log" 2>&1 || true
if grep -q "Application key for" "$work/list-host.log"; then
    bad "the host scope holds no portal key"
else
    ok "the host scope holds no portal key"
fi

# 9. The app's real data was never touched.
snap > "$work/var-app.after"
if cmp -s "$work/var-app.before" "$work/var-app.after"; then
    ok "the app's real ~/.var/app keyrings directory is unchanged"
else
    bad "the app's real ~/.var/app keyrings directory is unchanged"
fi

[ "$real" = "--real" ] || echo "dialogs shown: $(grep -c STARTED "$work/pinentry/log" 2>/dev/null || echo 0)"
if [ "$fail" != 0 ]; then
    echo "--- client errors:"; cat "$work/client.log"
    echo "--- daemon log:"; cat "$work/daemon.log"
    echo "--- gnome-keyring log:"; cat "$work/gk.log"
    echo "--- xdg-desktop-portal (gnome-keyring backend):"; cat "$work/xdp-gk.log"
    echo "--- xdg-desktop-portal (scopevault backend):"; cat "$work/xdp-sv.log"
    echo "--- import:"; cat "$work/import.log"
    echo "--- bus log:"; cat "$work/bus.log"
    echo "--- the app's real keyrings directory (before/after):"
    diff "$work/var-app.before" "$work/var-app.after" || true
fi
echo "passed $pass, failed $fail"
[ "$fail" = 0 ]
