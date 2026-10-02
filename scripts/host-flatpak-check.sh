#!/bin/sh
# Real Flatpak sandboxes against the daemon, on a desktop host.
#
#   scripts/host-flatpak-check.sh [--real] APP_ID_A APP_ID_B
#   scripts/host-flatpak-check.sh [--real] --app APP_ID [-- ARGS]
#                                                (a real app, with arguments)
#
# Everything runs on a PRIVATE dbus-broker bus with a temporary vault, as in
# host-libsecret-check.sh: gnome-keyring, its data and the real session bus
# are not touched. `flatpak run` builds its xdg-dbus-proxy for the bus named
# in DBUS_SESSION_BUS_ADDRESS, so with that set to the private bus every
# Flatpak below talks to the test daemon through its real sandbox and proxy.
# Part 1 verifies exactly that before relying on it.
#
# APP_ID_A and APP_ID_B: two installed Flatpak apps whose runtime ships gdbus
# (for part 1). The apps themselves are not started: the checks run
# `scopevault-client` inside each app's sandbox (`flatpak run --command`),
# with two extra permissions for that run only: talking to
# org.freedesktop.secrets (or the probe), and read-only access to the
# directory holding the client binary. Nothing is installed or changed.
#
# --app APP_ID starts the real app on the private bus (close it first if it
# is running: many apps hand over to a running instance). Use it, then quit
# the app; the script summarises what the app asked the daemon. It then
# offers to restart the daemon and the app on the same vault, to check that
# the app finds what it stored.
#
# Needs: flatpak, dbus-broker, systemd-socket-activate, gdbus, and built
# binaries (cargo build --bins). The client must run inside Flatpak runtimes,
# so it needs a glibc no newer than theirs: binaries built in the development
# container (glibc 2.36) work with current runtimes.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
real=
app=
apps=
while [ $# -gt 0 ]; do
    case $1 in
        --real) real=--real ;;
        --app) app=${2:?--app needs an app ID}; shift ;;
        --) shift; break ;;
        -*) echo "unknown option $1" >&2; exit 2 ;;
        *) apps="$apps $1" ;;
    esac
    shift
done
app_args=$*
set -- $apps
if [ -z "$app" ] && [ $# -ne 2 ]; then
    echo "usage: $0 [--real] APP_ID_A APP_ID_B | $0 [--real] --app APP_ID" >&2
    exit 2
fi

need() { command -v "$1" >/dev/null || { echo "$1 not found ($2)" >&2; exit 2; }; }
need flatpak "install flatpak"
need gdbus "install glib2-tools"
need dbus-broker-launch "install dbus-broker"
activate=$(command -v systemd-socket-activate || echo /usr/lib/systemd/systemd-socket-activate)
[ -x "$activate" ] || { echo "systemd-socket-activate not found" >&2; exit 2; }
# The newer of the release and debug builds: a stale one must not win.
# shellcheck disable=SC2012 # two fixed paths
newest() { ls -t "$root/target/release/$1" "$root/target/debug/$1" 2>/dev/null | head -n 1; }
bindir=$(dirname "$(newest scopevault-daemon)")
if ! [ -x "$bindir/scopevault-client" ] || ! [ -x "$bindir/scopevault-probe" ]; then
    echo "build the binaries first: cargo build --bins" >&2
    exit 2
fi
for a in "$@" $app; do
    flatpak info "$a" >/dev/null 2>&1 || { echo "$a is not an installed Flatpak (see 'flatpak list --app')" >&2; exit 2; }
done

work=$(mktemp -d "${TMPDIR:-/tmp}/scopevault-flatpak.XXXXXX")
bus_pid=
daemon_pid=
probe_pid=
cleanup() {
    for p in $probe_pid $daemon_pid $bus_pid; do kill "$p" 2>/dev/null || true; done
    wait 2>/dev/null || true
    rm -rf "$work"
}
trap cleanup EXIT INT TERM
real_bus=${DBUS_SESSION_BUS_ADDRESS-}

# ---- pinentry (as in host-libsecret-check.sh) ----
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

# ---- the private bus (as in host-libsecret-check.sh) ----
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
set --
for v in DBUS_SESSION_BUS_ADDRESS XDG_RUNTIME_DIR; do
    eval "[ -n \"\${$v-}\" ]" && set -- "$@" -E "$v"
done
"$activate" -l "$work/bus" --fdname=dbus.socket "$@" \
    dbus-broker-launch --scope user --config-file "$work/bus.conf" 2>"$work/bus.log" &
bus_pid=$!
set -- $apps
for _ in $(seq 50); do [ -S "$work/bus" ] && break; sleep 0.1; done
DBUS_SESSION_BUS_ADDRESS="unix:path=$work/bus"
export DBUS_SESSION_BUS_ADDRESS
dbus() { gdbus call --session -d org.freedesktop.DBus -o /org/freedesktop/DBus -m "org.freedesktop.DBus.$1" "$2"; }
if ! dbus NameHasOwner org.freedesktop.DBus >/dev/null 2>&1; then
    echo "the private bus did not start:" >&2
    cat "$work/bus.log" >&2
    exit 1
fi
wait_name() {
    for _ in $(seq 100); do
        if dbus NameHasOwner "$1" 2>/dev/null | grep -q true; then return 0; fi
        sleep 0.1
    done
    return 1
}
echo "private bus: $DBUS_SESSION_BUS_ADDRESS (dbus-broker)"
echo "flatpak: $(flatpak --version)"
for a in "$@" $app; do
    echo "$a: $(flatpak info "$a" | sed -n 's/^ *\(Version\|Runtime\): *//p' | tr '\n' ' ')"
done

pass=0
fail=0
ok() { pass=$((pass + 1)); echo "ok    $1"; }
bad() { fail=$((fail + 1)); echo "FAIL  $1"; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got '$2', expected '$3')"; fi; }
# Field 3 of the client's output line for step number $2 (1-based).
field() { sed -n "${2}p" "$1" | cut -f3-; }
status() { sed -n "${2}p" "$1" | cut -f2; }

# ---- part 1: does `flatpak run` put its proxy in front of the private bus? ----
if [ -z "$app" ]; then
    echo
    echo "== part 1: Flatpak's proxy on the private bus (identity probe)"
    probe_name=page.codeberg.nosini.ScopeVault.IdentityProbe
    probe_obj=/page/codeberg/nosini/ScopeVault/IdentityProbe
    "$bindir/scopevault-probe" serve >"$work/probe.log" 2>&1 &
    probe_pid=$!
    wait_name $probe_name || { echo "the probe did not start:" >&2; cat "$work/probe.log" >&2; exit 1; }
    whoami() { "$@" call --session --dest $probe_name --object-path $probe_obj --method $probe_name.WhoAmI 2>&1; }
    verdict() { grep -o -E '"(verdict|scope|relation)": "[^"]*"' | tr '\n' ' '; }
    # has TEXT FIELD VALUE: whether the probe's answer has "FIELD": "VALUE"
    # (the probe prints fields in alphabetical order, so test each one).
    has() { printf '%s' "$1" | grep -q "\"$2\": \"$3\""; }
    v=$(whoami gdbus | verdict)
    if has "$v" verdict allowed && has "$v" scope host; then ok "host shell: $v"; else bad "host shell: $v"; fi
    for a in "$@"; do
        v=$(whoami flatpak run --talk-name=$probe_name --command=gdbus "$a" | verdict)
        if has "$v" verdict allowed && has "$v" scope "flatpak/$a" && has "$v" relation proxy; then
            ok "$a through its own proxy on the private bus: $v"
        else
            bad "$a: $v (expected allowed, flatpak/$a, relation proxy)"
        fi
    done
    kill $probe_pid; wait $probe_pid 2>/dev/null || true; probe_pid=
    if [ "$fail" != 0 ]; then
        echo "--- probe output:"; cat "$work/probe.log"
        echo "The private-bus setup does not reach Flatpak's proxy as assumed; stopping."
        exit 1
    fi
fi

# ---- the daemon ----
start() {
    RUST_LOG=${RUST_LOG:-scopevault=debug} \
        "$bindir/scopevault-daemon" --data-dir "$work/vault" --pinentry "$pinentry" --admin-socket "$work/admin/socket" \
            2>>"$work/daemon.log" &
    daemon_pid=$!
    wait_name org.freedesktop.secrets || { echo "daemon did not start:" >&2; cat "$work/daemon.log" >&2; exit 1; }
}
start
pw="scopevault test"
limit=60
[ "$real" != "--real" ] || limit=300
client=$bindir/scopevault-client
host() { timeout "$limit" "$client" "$@" 2>>"$work/client.log" || true; }
# In APP's sandbox, through its proxy. Only org.freedesktop.secrets and the
# client's own directory (read-only) are added to its permissions.
in_app() {
    _app=$1; shift
    timeout "$limit" flatpak run --talk-name=org.freedesktop.secrets --filesystem="$bindir:ro" \
        --command="$client" "$_app" "$@" 2>>"$work/client.log" || true
}

if [ -n "$app" ]; then
    echo
    echo "== $app's permissions"
    flatpak info --show-permissions "$app" | sed 's/^/    /'
    flatpak info --show-permissions "$app" | grep -q 'org.freedesktop.secrets=talk' ||
        echo "note: $app has no talk access to org.freedesktop.secrets, so it cannot use the Secret Service directly"
    pins "$pw" "$pw" "$pw" "$pw" "$pw" "$pw"
    say "a new vault: choose \"$pw\" when asked (twice)"
    if flatpak ps --columns=application 2>/dev/null | grep -qx "$app"; then
        echo "note: $app is already running; a new start may just hand over to that instance,"
        echo "      which uses the real session bus. Quit it first for a meaningful run."
    fi
    run=1
    while :; do
        echo "Starting $app on the private bus (run $run). Use it (log in, save a password...), then quit it."
        echo "Services it may expect on the session bus (portals, notifications...) are absent here."
        before=$(wc -l < "$work/daemon.log")
        started=$(date +%s)
        flatpak run "$app" $app_args >"$work/app.log" 2>&1 || true
        # Some launchers return at once (handing over to a running instance, or
        # leaving the app running in the background). Keep the daemon up until
        # the user is done either way.
        if [ $(($(date +%s) - started)) -lt 10 ]; then
            echo "note: 'flatpak run' returned after less than 10 s."
            echo "Running instances of $app: $(flatpak ps --columns=application 2>/dev/null | grep -cx "$app")"
        fi
        printf 'Press Enter once you have quit %s. ' "$app"
        read -r _ </dev/tty || true
        tail -n "+$((before + 1))" "$work/daemon.log" > "$work/run.log"
        echo "--- requests to the daemon, by caller scope (daemon log):"
        grep -o 'scope=[^ ]* .*member=[^ ]* outcome=[^ ]*' "$work/run.log" \
            | sed 's/interface=[^ ]* //; s/path=[^ ]* //' | sort | uniq -c | sort -rn | head -n 40 || true
        echo "--- the same requests in order (first 60):"
        grep -o 'sender=[^ ]* .*member=[^ ]* outcome=[^ ]*' "$work/run.log" \
            | sed 's/scope=[^ ]* //; s/interface=[^ ]* //; s/path=Some(\("[^"]*"\))/\1/; s/member=Some(\("[^"]*"\))/\1/' \
            | head -n 60 || true
        echo "--- identification (denials would be listed here):"
        grep -E 'identified caller|denied caller' "$work/run.log" | sed 's/.*\(identified\|denied\)/\1/' | sort | uniq -c
        echo "--- the app's own output (last 30 lines):"
        tail -n 30 "$work/app.log"
        # A second run checks that the app finds what it stored: the daemon is
        # restarted, so the vault is read back from disk and starts locked.
        printf '\nRestart the daemon and start %s again on the same vault? [y/N] ' "$app"
        read -r again </dev/tty || again=
        case $again in [yY]*) ;; *) break ;; esac
        kill "$daemon_pid"
        wait "$daemon_pid" 2>/dev/null || true
        for _ in $(seq 50); do
            dbus NameHasOwner org.freedesktop.secrets 2>/dev/null | grep -q true || break
            sleep 0.1
        done
        start
        say "the existing vault: enter \"$pw\" when asked (once)"
        run=$((run + 1))
        echo
    done
    exit 0
fi

A=$1 B=$2
echo
echo "== part 2: scope isolation through real sandboxes ($A, $B)"
attrs="test=scopevault,user=alice"

# 1. Vault creation (first request), then the same attributes in three scopes.
pins "$pw" "$pw"
say "choose the password \"$pw\" (enter it twice)"
host create Login default store default Host host-secret "$attrs" > "$work/h1"
check "host stores an item" "$(status "$work/h1" 2)" ok
if [ "$(status "$work/h1" 2)" != ok ]; then
    echo "--- client output:"; cat "$work/h1"; echo "--- daemon log:"; tail -n 30 "$work/daemon.log"; exit 1
fi
in_app "$A" create Login default store default A alpha-secret "$attrs" > "$work/a1"
if [ "$(status "$work/a1" 2)" != ok ]; then
    bad "the client in $A's sandbox: $(cat "$work/a1") $(tail -n 3 "$work/client.log")"
    echo "If it failed to start (e.g. a GLIBC version error), build it in the development container."
    exit 1
fi
ok "$A stores an item with the same attributes"
a_item=$(field "$work/a1" 2)
in_app "$B" create Login default store default B beta-secret "$attrs" > "$work/b1"
check "$B stores an item with the same attributes" "$(status "$work/b1" 2)" ok
b_item=$(field "$work/b1" 2)

# 2. Each reads its own value, in new instances.
check "host reads its own value" "$(host lookup "$attrs" | cut -f3)" host-secret
check "$A reads its own value" "$(in_app "$A" lookup "$attrs" | cut -f3)" alpha-secret
check "$B reads its own value" "$(in_app "$B" lookup "$attrs" | cut -f3)" beta-secret

# 3. Foreign paths, batches, enumeration.
col=/org/freedesktop/secrets/collection
in_app "$B" secret "$a_item" secret "$col/login/i00000000000000000000000000000000" \
    secrets "$a_item,$b_item" introspect "$col" search "$attrs" lock "$a_item" delete "$a_item" \
    get "$a_item" org.freedesktop.Secret.Item Label getall "$col/login" org.freedesktop.Secret.Collection \
    > "$work/b2"
check "$B: A's item path gives the same error as a missing one" "$(field "$work/b2" 1)" "$(field "$work/b2" 2)"
check "$B: GetSecrets with A's and B's items returns B's only" "$(field "$work/b2" 3)" "$b_item=beta-secret"
check "$B: introspection lists its own collection only" "$(field "$work/b2" 4)" login
check "$B: search with A's attributes finds B's item only" "$(field "$work/b2" 5)" "$b_item | "
check "$B: Lock on A's item locks nothing" "$(field "$work/b2" 6)" ""
check "$B: Delete on A's item" "$(field "$work/b2" 7)" "org.freedesktop.DBus.Error.UnknownObject: No such object"
check "$B: Get on A's item" "$(field "$work/b2" 8)" "org.freedesktop.DBus.Error.UnknownObject: No such object"
case $(field "$work/b2" 9) in
    *'"B"'*|*Items*) ok "$B: GetAll on its own collection works" ;;
    *) bad "$B: GetAll on its own collection: $(field "$work/b2" 9)" ;;
esac
check "$A's item is intact" "$(in_app "$A" secret "$a_item" | cut -f3)" alpha-secret
check "the host sees none of the apps' items" "$(host search test=scopevault | cut -f3 | tr ',' '\n' | grep -c . )" 1

# 4. Forged attributes.
forged="app_id=$A,xdg:schema=$A.Password,flatpak-id=$A"
in_app "$B" store default "$A" forged-by-b "$forged" >/dev/null
check "$A does not find B's item labelled with A's ID" "$(in_app "$A" search "$forged" | cut -f3)" " | "

# 5. Sessions belong to their connection.
in_app "$A" session sleep 4000 > "$work/holder" &
holder=$!
for _ in $(seq 100); do [ -s "$work/holder" ] && break; sleep 0.1; done
session=$(field "$work/holder" 1)
check "$A's other instance cannot use the session" \
    "$(in_app "$A" use-session "$session" secret "$a_item" | sed -n 2p | cut -f3)" \
    "org.freedesktop.Secret.Error.NoSession: No such session"
check "$B cannot use A's session" \
    "$(in_app "$B" use-session "$session" secrets "$b_item" | sed -n 2p | cut -f3)" \
    "org.freedesktop.Secret.Error.NoSession: No such session"
wait $holder || true

# 6. Signals: A's changes reach A's other instance only. Monitoring is
#    refused by the proxy.
in_app "$A" list watch 6000 > "$work/wa" &
wa=$!
in_app "$B" list watch 6000 > "$work/wb" &
wb=$!
host list watch 6000 > "$work/wh" &
wh=$!
sleep 4
in_app "$A" store default A2 changed "$attrs,n=2" set-label "$col/login" Renamed > "$work/a3"
wait $wa $wb $wh || true
case $(field "$work/wa" 2) in
    *ItemCreated*) ok "$A's other instance receives A's signals" ;;
    *) bad "$A's other instance: $(field "$work/wa" 2)" ;;
esac
check "$B receives none of A's signals" "$(field "$work/wb" 2)" "0 message(s)"
check "the host receives none of A's signals" "$(field "$work/wh" 2)" "0 message(s)"
case $(in_app "$B" eavesdrop 500 | cut -f2-) in
    error*AccessDenied*) ok "$B cannot eavesdrop (the proxy refuses)" ;;
    *) bad "$B eavesdrop: $(in_app "$B" eavesdrop 500)" ;;
esac
case $(in_app "$B" monitor 500 | cut -f2-) in
    error*AccessDenied*) ok "$B cannot become a monitor (the proxy refuses)" ;;
    *) bad "$B monitor: $(in_app "$B" monitor 500)" ;;
esac

# 7. Logical locks stay within the scope.
in_app "$A" lock "$col/login" >/dev/null
check "$A's collection is locked" "$(in_app "$A" get "$col/login" org.freedesktop.Secret.Collection Locked | cut -f3)" true
check "$B's collection is not" "$(in_app "$B" get "$col/login" org.freedesktop.Secret.Collection Locked | cut -f3)" false
check "$B still reads its value" "$(in_app "$B" lookup "$attrs" | cut -f3)" beta-secret
pins "$pw"
say "confirm the password \"$pw\" to reopen $A's collection"
check "$A reopens its collection with the password" "$(in_app "$A" lookup "$attrs" | cut -f3)" alpha-secret

# 8. Unsupported sandbox: denied, not host.
if command -v bwrap >/dev/null; then
    out=$(timeout "$limit" bwrap --dev-bind / / --unshare-user -- "$client" list 2>&1 | cut -f3 || true)
    case $out in
        *AccessDenied*) ok "plain bwrap sandbox is denied" ;;
        *) bad "plain bwrap sandbox: $out" ;;
    esac
fi

# 9. What the daemon saw.
echo "--- identified callers (daemon log):"
grep -E 'identified caller|denied caller' "$work/daemon.log" | grep -o -E 'scope=[^ ]*|error=.*' | sort | uniq -c
[ "$real" = "--real" ] || echo "dialogs shown: $(grep -c STARTED "$work/pinentry/log" 2>/dev/null || echo 0)"
if [ "$fail" != 0 ]; then
    echo "--- client errors:"; tail -n 40 "$work/client.log"
    echo "--- daemon log (last 60 lines):"; tail -n 60 "$work/daemon.log"
fi
echo "passed $pass, failed $fail"
[ "$fail" = 0 ]
