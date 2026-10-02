#!/bin/sh
# Migration check gnome-keyring -> scopevault -> back (rollback), for the
# desktop host.
#
# Seeds a private gnome-keyring with three secret-tool items, imports them
# into a fresh vault with scopevault-admin, serves that vault with
# scopevault-daemon, adds a fourth item there, and exports everything back
# into gnome-keyring (the rollback). The real keyring and the real session
# bus's names are never touched: each daemon runs on its own private
# dbus-broker bus, with temporary data directories. (dbus-broker's launcher
# does connect to the real session bus as a client, to subscribe to
# systemd, as it always does.)
#
# Why dbus-broker: the daemon requires the bus to report the caller's
# process FD (`ProcessFD`), and refuses everyone otherwise.
#
# Needs: gnome-keyring-daemon (gnome-keyring), secret-tool (libsecret-tools),
# dbus-broker, systemd-socket-activate (systemd), gdbus (glib2-tools), and
# built binaries (cargo build --bins).
#
#   scripts/host-migration-check.sh
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
[ "$#" -eq 0 ] || { echo "usage: $0" >&2; exit 2; }

need() { command -v "$1" >/dev/null || { echo "$1 not found ($2)" >&2; exit 2; }; }
need gnome-keyring-daemon "install gnome-keyring"
need secret-tool "install libsecret-tools"
need gdbus "install glib2-tools"
need dbus-broker-launch "install dbus-broker"
activate=$(command -v systemd-socket-activate || echo /usr/lib/systemd/systemd-socket-activate)
[ -x "$activate" ] || { echo "systemd-socket-activate not found" >&2; exit 2; }
# The newer of the release and debug builds: a stale one must not win.
# shellcheck disable=SC2012 # two fixed paths
newest() { ls -t "$root/target/release/$1" "$root/target/debug/$1" 2>/dev/null | head -n 1; }
daemon=$(newest scopevault-daemon)
[ -n "$daemon" ] || { echo "build the binaries first: cargo build --bins" >&2; exit 2; }
admin=$(newest scopevault-admin)
[ -n "$admin" ] || { echo "build the binaries first: cargo build --bins" >&2; exit 2; }

work=$(mktemp -d "${TMPDIR:-/tmp}/scopevault-migration.XXXXXX")
bus1_pid=
bus2_pid=
gk_pid=
daemon_pid=
cleanup() {
    [ -z "$daemon_pid" ] || kill "$daemon_pid" 2>/dev/null || true
    [ -z "$gk_pid" ] || kill "$gk_pid" 2>/dev/null || true
    [ -z "$bus1_pid" ] || kill "$bus1_pid" 2>/dev/null || true
    [ -z "$bus2_pid" ] || kill "$bus2_pid" 2>/dev/null || true
    wait 2>/dev/null || true
    rm -rf "$work"
}
trap cleanup EXIT INT TERM
# Empty logs up front, so the failure dump can always print them.
for f in client daemon gk import import2 export; do : >"$work/$f.log"; done

mkdir "$work/pinentry"
pinentry=$work/pinentry.sh
cat > "$pinentry" <<EOF
#!/bin/sh
FAKE_PINENTRY_DIR='$work/pinentry' exec '$root/tests/support/fake-pinentry.sh' "\$@"
EOF
chmod 700 "$pinentry"

# ---- the two private buses ----
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
# The launcher starts on the first connection, with the socket passed in.
# systemd-socket-activate gives it a minimal environment; it needs the real
# session bus (or XDG_RUNTIME_DIR) to reach systemd. This script never
# exports a private address, so those variables keep their real values;
# every command below sets DBUS_SESSION_BUS_ADDRESS itself.
bus_pid=
env_flags=
for v in DBUS_SESSION_BUS_ADDRESS XDG_RUNTIME_DIR; do
    eval "[ -n \"\${$v-}\" ]" && env_flags="$env_flags -E $v"
done
dbus() { # dbus BUS METHOD ARG: a call to the bus daemon on BUS
    DBUS_SESSION_BUS_ADDRESS="unix:path=$1" \
        gdbus call --session -d org.freedesktop.DBus -o /org/freedesktop/DBus -m "org.freedesktop.DBus.$2" "$3"
}
start_bus() { # start_bus SOCKET: a private dbus-broker on SOCKET; sets bus_pid
    # shellcheck disable=SC2086 # env_flags is a list of options
    "$activate" -l "$1" --fdname=dbus.socket $env_flags \
        dbus-broker-launch --scope user --config-file "$work/bus.conf" 2>>"$work/bus.log" &
    bus_pid=$!
    for _ in $(seq 50); do [ -S "$1" ] && break; sleep 0.1; done
    if ! dbus "$1" NameHasOwner org.freedesktop.DBus >/dev/null 2>&1; then
        echo "the private bus on $1 did not start:" >&2
        cat "$work/bus.log" >&2
        exit 1
    fi
}
start_bus "$work/bus1"; bus1_pid=$bus_pid
start_bus "$work/bus2"; bus2_pid=$bus_pid
echo "private buses: $work/bus1 (gnome-keyring), $work/bus2 (scopevault)"
echo "binaries: $daemon, $admin"

# ---- the checks ----
pass=0
fail=0
ok() { pass=$((pass + 1)); echo "ok    $1"; }
bad() { fail=$((fail + 1)); echo "FAIL  $1"; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got '$2', expected '$3')"; fi }
has() { if grep -q "$3" "$2"; then ok "$1"; else bad "$1"; fi }
pins() { printf '%s\n' "$@" > "$work/pinentry/pins"; rm -f "$work/pinentry/count"; }
# Every client call is bounded, so a hang shows up as a failure.
limit=30
st() { # st BUS ARGS...: secret-tool on that bus, never the session's
    st_bus=$1; shift
    echo "+ secret-tool $*" >>"$work/client.log"
    DBUS_SESSION_BUS_ADDRESS="unix:path=$st_bus" timeout "$limit" secret-tool "$@"
}
lookup() { # lookup BUS KIND: the secret of that item of the migration app
    st "$1" lookup app scopevault-migration kind "$2" 2>>"$work/client.log" || true
}
store() { # store BUS LABEL SECRET KINDPAIR...: an item of the migration app
    store_bus=$1; store_label=$2; store_secret=$3; shift 3
    printf '%s' "$store_secret" | st "$store_bus" store --label="$store_label" \
        app scopevault-migration "$@" 2>>"$work/client.log"
}
pw="scopevault test"
uni=$(printf 'p\303\244ssw\303\266rd \360\237\224\221')

start() {
    DBUS_SESSION_BUS_ADDRESS="unix:path=$work/bus2" RUST_LOG=${RUST_LOG:-scopevault=debug} \
        "$daemon" --data-dir "$work/vault" --pinentry "$pinentry" --admin-socket "$work/admin/socket" \
            2>>"$work/daemon.log" &
    daemon_pid=$!
    for _ in $(seq 100); do
        if dbus "$work/bus2" NameHasOwner org.freedesktop.secrets 2>/dev/null | grep -q true; then return 0; fi
        sleep 0.1
    done
    echo "daemon did not start:" >&2
    cat "$work/daemon.log" >&2
    exit 1
}
stop() { kill "$daemon_pid"; wait "$daemon_pid" 2>/dev/null || true; daemon_pid=; }

# 1. gnome-keyring on bus1, with its own data and runtime directory (never
#    --replace, --start or --login: those act on the real session).
mkdir -m 700 "$work/gk-data" "$work/gk-run"
if [ -n "$(ls -A "$work/gk-data")" ]; then
    echo "$work/gk-data is not empty: refusing to work on existing keyring data" >&2
    exit 2
fi
printf 'gk test' | env -u GNOME_KEYRING_CONTROL \
    XDG_DATA_HOME="$work/gk-data" XDG_RUNTIME_DIR="$work/gk-run" \
    DBUS_SESSION_BUS_ADDRESS="unix:path=$work/bus1" \
    gnome-keyring-daemon --foreground --components=secrets --unlock >"$work/gk.log" 2>&1 &
gk_pid=$!
for _ in $(seq 100); do
    if dbus "$work/bus1" NameHasOwner org.freedesktop.secrets 2>/dev/null | grep -q true; then break; fi
    sleep 0.1
done
if ! dbus "$work/bus1" NameHasOwner org.freedesktop.secrets 2>/dev/null | grep -q true; then
    echo "gnome-keyring did not start:" >&2
    cat "$work/gk.log" >&2
    exit 1
fi

# 2. Three items in the default collection (the only one gnome-keyring uses
#    without its prompter), all tagged app scopevault-migration.
store "$work/bus1" 'migration ascii' 'secret one' kind ascii || true
store "$work/bus1" 'Ünïcödé' "$uni" kind unicode || true
store "$work/bus1" 'migration attributes' 'secret three' kind attrs flavor multi || true
check "ascii item stored in gnome-keyring" "$(lookup "$work/bus1" ascii)" "secret one"
check "unicode item stored in gnome-keyring" "$(lookup "$work/bus1" unicode)" "$uni"
check "three-attribute item stored in gnome-keyring" "$(lookup "$work/bus1" attrs)" "secret three"

# 3. Import into a fresh vault (new password, entered twice), twice: the
#    second run must skip everything.
pins "$pw" "$pw"
if timeout "$limit" "$admin" import --data-dir "$work/vault" --bus "unix:path=$work/bus1" \
    --pinentry "$pinentry" >"$work/import.log" 2>&1; then
    ok "import exits 0"
else
    bad "import exits 0"
fi
has "import reports the 3 items" "$work/import.log" "imported 3 items"
pins "$pw"
timeout "$limit" "$admin" import --data-dir "$work/vault" --bus "unix:path=$work/bus1" \
    --pinentry "$pinentry" >"$work/import2.log" 2>&1 || true
has "second import skips everything" "$work/import2.log" "imported 0 items"
has "second import finds the 3 items already there" "$work/import2.log" "3 already there"

# 4. The daemon serves the vault on bus2; a fourth item is added there.
start
creds=$(dbus "$work/bus2" GetConnectionCredentials org.freedesktop.secrets)
case $creds in
    *ProcessFD*) ;;
    *)
        echo "this bus does not report ProcessFD, so every caller would be refused:" >&2
        echo "  $creds" >&2
        exit 1
        ;;
esac
pins "$pw"
check "ascii item reads the same" "$(lookup "$work/bus2" ascii)" "secret one"
check "unicode item reads the same" "$(lookup "$work/bus2" unicode)" "$uni"
check "three-attribute item reads the same" "$(lookup "$work/bus2" attrs)" "secret three"
n=$(st "$work/bus2" search --all app scopevault-migration 2>/dev/null | grep -c '^\[/' || true)
check "search finds the 3 migrated items" "$n" 3
check "all three attributes kept" \
    "$(st "$work/bus2" lookup app scopevault-migration kind attrs flavor multi 2>>"$work/client.log" || true)" "secret three"
store "$work/bus2" 'added in scopevault' 'secret four' kind added || true
check "4th item stored in scopevault" "$(lookup "$work/bus2" added)" "secret four"
stop

# 5. Rollback: export back into gnome-keyring, which must keep its own 3
#    items and gain exactly the fourth.
pins "$pw"
if timeout "$limit" "$admin" export --data-dir "$work/vault" --bus "unix:path=$work/bus1" \
    --pinentry "$pinentry" >"$work/export.log" 2>&1; then
    ok "export exits 0"
else
    bad "export exits 0"
fi
has "export writes the item scopevault added" "$work/export.log" "wrote 1 items"
has "export skips the 3 items gnome-keyring already has" "$work/export.log" "3 already there"
check "4th item rolled back to gnome-keyring" "$(lookup "$work/bus1" added)" "secret four"
n=$(st "$work/bus1" search --all app scopevault-migration 2>/dev/null | grep -c '^\[/' || true)
check "search on gnome-keyring finds 4 items, no duplicates" "$n" 4

echo "dialogs shown: $(grep -c STARTED "$work/pinentry/log" 2>/dev/null || echo 0)"
if [ "$fail" != 0 ]; then
    echo "--- client errors:"; cat "$work/client.log"
    echo "--- daemon log:"; cat "$work/daemon.log"
    echo "--- gnome-keyring log:"; cat "$work/gk.log"
    echo "--- import (first run):"; cat "$work/import.log"
    echo "--- import (second run):"; cat "$work/import2.log"
    echo "--- export:"; cat "$work/export.log"
fi
echo "passed $pass, failed $fail"
[ "$fail" = 0 ]
