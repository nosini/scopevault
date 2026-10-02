#!/bin/sh
# Compatibility check with libsecret's `secret-tool`, for the desktop host.
#
# Runs scopevault-daemon on a PRIVATE dbus-broker bus with a temporary vault.
# gnome-keyring and its data are not touched, and nothing is registered on
# the real session bus. (dbus-broker's launcher does connect to the real
# session bus as a client, to subscribe to systemd, as it always does; the
# private bus's configuration has no activatable services.)
#
#   scripts/host-libsecret-check.sh            fake pinentry, no typing needed
#   scripts/host-libsecret-check.sh --real     real pinentry dialogs
#   ... --seahorse                             afterwards, open Seahorse on the
#                                              same private bus and vault
#
# Why dbus-broker: the daemon requires the bus to report the caller's
# process FD (`ProcessFD`), and refuses everyone otherwise. openSUSE's
# dbus-daemon (used by dbus-run-session) does not report it.
#
# Needs: secret-tool (libsecret-tools), dbus-broker, systemd-socket-activate
# (systemd), gdbus (glib2-tools), and a built daemon
# (cargo build --bin scopevault-daemon). PINENTRY overrides the dialog
# program for --real (default: pinentry).
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
real=
seahorse=
for a in "$@"; do
    case $a in
        --real) real=--real ;;
        --seahorse) seahorse=1 ;;
        *) echo "usage: $0 [--real] [--seahorse]" >&2; exit 2 ;;
    esac
done

need() { command -v "$1" >/dev/null || { echo "$1 not found ($2)" >&2; exit 2; }; }
need secret-tool "install libsecret-tools"
need gdbus "install glib2-tools"
need dbus-broker-launch "install dbus-broker"
[ -z "$seahorse" ] || need seahorse "install seahorse"
activate=$(command -v systemd-socket-activate || echo /usr/lib/systemd/systemd-socket-activate)
[ -x "$activate" ] || { echo "systemd-socket-activate not found" >&2; exit 2; }
daemon=$root/target/release/scopevault-daemon
[ -x "$daemon" ] || daemon=$root/target/debug/scopevault-daemon
[ -x "$daemon" ] || { echo "build the daemon first: cargo build --bin scopevault-daemon" >&2; exit 2; }

work=$(mktemp -d "${TMPDIR:-/tmp}/scopevault-libsecret.XXXXXX")
bus_pid=
daemon_pid=
monitor_pid=
cleanup() {
    [ -z "$monitor_pid" ] || kill "$monitor_pid" 2>/dev/null || true
    [ -z "$daemon_pid" ] || kill "$daemon_pid" 2>/dev/null || true
    [ -z "$bus_pid" ] || kill "$bus_pid" 2>/dev/null || true
    wait 2>/dev/null || true
    rm -rf "$work"
}
trap cleanup EXIT INT TERM

mkdir "$work/pinentry"
if [ "$real" = "--real" ]; then
    # pinentry-gnome3 asks gnome-shell's prompter on the session bus. The
    # daemon's bus here is the private one, so hand pinentry the real one
    # (in normal use both are the same bus).
    pinentry=$work/pinentry.sh
    cat > "$pinentry" <<EOF
#!/bin/sh
DBUS_SESSION_BUS_ADDRESS='${DBUS_SESSION_BUS_ADDRESS-}' exec '${PINENTRY:-pinentry}' "\$@"
EOF
    chmod 700 "$pinentry"
else
    pinentry=$work/pinentry.sh
    cat > "$pinentry" <<EOF
#!/bin/sh
FAKE_PINENTRY_DIR='$work/pinentry' exec '$root/tests/support/fake-pinentry.sh' "\$@"
EOF
    chmod 700 "$pinentry"
fi

# ---- the private bus ----
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
# session bus (or XDG_RUNTIME_DIR) to reach systemd, so pass those through.
set --
for v in DBUS_SESSION_BUS_ADDRESS XDG_RUNTIME_DIR; do
    eval "[ -n \"\${$v-}\" ]" && set -- "$@" -E "$v"
done
"$activate" -l "$work/bus" --fdname=dbus.socket "$@" \
    dbus-broker-launch --scope user --config-file "$work/bus.conf" 2>"$work/bus.log" &
bus_pid=$!
for _ in $(seq 50); do [ -S "$work/bus" ] && break; sleep 0.1; done
DBUS_SESSION_BUS_ADDRESS="unix:path=$work/bus"
export DBUS_SESSION_BUS_ADDRESS
dbus() { gdbus call --session -d org.freedesktop.DBus -o /org/freedesktop/DBus -m "org.freedesktop.DBus.$1" "$2"; }
if ! dbus NameHasOwner org.freedesktop.DBus >/dev/null 2>&1; then
    echo "the private bus did not start:" >&2
    cat "$work/bus.log" >&2
    exit 1
fi
echo "private bus: $DBUS_SESSION_BUS_ADDRESS (dbus-broker)"

# ---- the checks ----
pass=0
fail=0
ok() { pass=$((pass + 1)); echo "ok    $1"; }
bad() { fail=$((fail + 1)); echo "FAIL  $1"; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got '$2', expected '$3')"; fi; }
pins() { printf '%s\n' "$@" > "$work/pinentry/pins"; rm -f "$work/pinentry/count"; }
say() { [ "$real" != "--real" ] || echo ">>> dialog: $1"; }
# Every client call is bounded, so a hang shows up as a failure. With real
# dialogs the limit leaves time for typing.
limit=30
[ "$real" != "--real" ] || limit=300
st() { echo "+ secret-tool $*" >>"$work/client.log"; timeout "$limit" secret-tool "$@"; }
lookup() { st lookup app scopevault-check kind "$1" 2>>"$work/client.log" || true; }
store() { printf '%s' "$3" | st store --label="$1" app scopevault-check kind "$2" 2>>"$work/client.log"; }
pw="scopevault test"

start() {
    RUST_LOG=${RUST_LOG:-scopevault=debug} \
        "$daemon" --data-dir "$work/vault" --pinentry "$pinentry" 2>>"$work/daemon.log" &
    daemon_pid=$!
    for _ in $(seq 100); do
        if dbus NameHasOwner org.freedesktop.secrets 2>/dev/null | grep -q true; then return 0; fi
        sleep 0.1
    done
    echo "daemon did not start:" >&2
    cat "$work/daemon.log" >&2
    exit 1
}
stop() { kill "$daemon_pid"; wait "$daemon_pid" 2>/dev/null || true; daemon_pid=; }

# Record the private bus's traffic for diagnosis.
if command -v dbus-monitor >/dev/null; then
    dbus-monitor --session >"$work/monitor.log" 2>&1 &
    monitor_pid=$!
fi

start
creds=$(dbus GetConnectionCredentials org.freedesktop.secrets)
case $creds in
    *ProcessFD*) ;;
    *)
        echo "this bus does not report ProcessFD, so every caller would be refused:" >&2
        echo "  $creds" >&2
        exit 1
        ;;
esac

# 1. First store: creates the vault (new password, entered twice), then
#    libsecret creates the default collection.
pins "$pw"
say "choose the password \"$pw\" (enter it twice)"
if store 'scopevault check' one 'secret one'; then ok "store creates vault and default collection"
else bad "store creates vault and default collection: $(tail -n1 "$work/client.log")"; fi
check "lookup" "$(lookup one)" "secret one"
store 'scopevault check' one 'replaced' || true
check "store replaces" "$(lookup one)" "replaced"
n=$(st search --all app scopevault-check kind one 2>/dev/null | grep -c '^\[/' || true)
check "search finds the one item" "$n" 1
uni=$(printf 'p\303\244ssw\303\266rd \360\237\224\221')
store 'Ünïcödé' unicode "$uni" || true
check "unicode secret" "$(lookup unicode)" "$uni"
store gone gone 'bye' || true
check "item to clear exists" "$(lookup gone)" "bye"
st clear app scopevault-check kind gone 2>>"$work/client.log" || true
check "clear" "$(lookup gone)" ""

# 2. Logical lock: lookup must unlock the collection, asking for the
#    password again. Locked through the D-Bus API: `secret-tool lock` takes
#    a collection *name* before libsecret 0.21.8 and a full path after, and
#    crashes before 0.21.3.
locked=$(timeout "$limit" gdbus call --session -d org.freedesktop.secrets -o /org/freedesktop/secrets \
    -m org.freedesktop.Secret.Service.Lock "['/org/freedesktop/secrets/aliases/default']" 2>&1 || true)
case $locked in
    *"/org/freedesktop/secrets/collection/"*) ok "lock the default collection" ;;
    *) bad "lock the default collection: $locked" ;;
esac
pins "$pw"
say "confirm the password \"$pw\" to reopen the collection"
check "lookup in the locked collection (password confirmed)" "$(lookup one)" "replaced"

# 3. Restart: the vault is locked; lookup opens the unlock dialog.
stop
start
pins "wrong" "$pw"
say "enter a wrong password first, then \"$pw\""
check "lookup after restart (wrong, then right password)" "$(lookup one)" "replaced"

# 4. Cancel: no secret, a "locked" error.
stop
start
pins CANCEL
say "press Cancel"
if out=$(st lookup app scopevault-check kind one 2>"$work/err"); then
    bad "cancelled unlock returned a secret: '$out'"
elif grep -qi lock "$work/err"; then
    ok "cancelled unlock gives an error: $(head -n1 "$work/err")"
else
    bad "cancelled unlock gives an unexpected error: $(head -n1 "$work/err")"
fi

if [ "$real" = "--real" ]; then
    echo "dialogs: real pinentry (${PINENTRY:-pinentry})"
else
    echo "dialogs shown: $(grep -c STARTED "$work/pinentry/log" 2>/dev/null || echo 0)"
fi
if [ -n "$seahorse" ]; then
    # A fresh daemon on the same vault (locked), so Seahorse starts with the
    # unlock dialog rather than inside the post-cancel pause.
    stop
    start
    pins "$pw" "$pw" "$pw" "$pw" "$pw" "$pw"
    echo
    echo "Starting Seahorse on the private bus (vault password \"$pw\")."
    say "Seahorse needs the vault unlocked: enter \"$pw\""
    echo "Close Seahorse to finish. dconf warnings are expected (no dconf here)."
    before=$(wc -l < "$work/daemon.log")
    seahorse 2>>"$work/seahorse.log" || true
    echo "--- Seahorse's requests and their outcomes (daemon log):"
    tail -n "+$((before + 1))" "$work/daemon.log" | grep -o 'path=[^ ]* .*member=[^ ]* outcome=[^ ]*' \
        | sed 's/interface=[^ ]* //' | sort | uniq -c | sort -rn | head -n 40 || true
fi
if [ "$fail" != 0 ]; then
    echo "--- client errors:"; cat "$work/client.log"
    echo "--- daemon log:"; cat "$work/daemon.log"
    if [ -s "$work/monitor.log" ]; then
        cp "$work/monitor.log" "${TMPDIR:-/tmp}/scopevault-libsecret-monitor.log"
        echo "--- bus traffic: ${TMPDIR:-/tmp}/scopevault-libsecret-monitor.log (last 60 lines below)"
        tail -n 60 "$work/monitor.log"
    fi
fi
echo "passed $pass, failed $fail"
[ "$fail" = 0 ]
