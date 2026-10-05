#!/bin/sh
# Runs COMMAND with a private session bus and XDG_RUNTIME_DIR, then tears
# both down. Uses DBUS_DAEMON (default: dbus-daemon on PATH).
#
#   with-isolated-bus.sh COMMAND...
set -eu
dir=$(mktemp -d "${TMPDIR:-/tmp}/scopevault-bus.XXXXXX")
bus_pid=
cmd_pid=
# Also when the helper itself is interrupted or terminated: the bus and the
# directory must not outlive it.
# shellcheck disable=SC2317 # run by the EXIT trap
cleanup() {
    [ -z "$cmd_pid" ] || kill "$cmd_pid" 2>/dev/null || true
    [ -z "$bus_pid" ] || kill "$bus_pid" 2>/dev/null || true
    wait 2>/dev/null || true
    rm -rf "$dir"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir -m 700 "$dir/run"
cat > "$dir/bus.conf" <<CONF
<busconfig>
  <type>session</type>
  <listen>unix:path=$dir/bus</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>
CONF
"${DBUS_DAEMON:-dbus-daemon}" --config-file="$dir/bus.conf" --nofork &
bus_pid=$!
for _ in $(seq 50); do [ -S "$dir/bus" ] && break; sleep 0.1; done
# In the background: a signal interrupts `wait`, while a command in the
# foreground would hold the traps back until it ended. Its stdin goes
# through fd 3, since sh gives background commands /dev/null otherwise.
exec 3<&0
DBUS_SESSION_BUS_ADDRESS="unix:path=$dir/bus" XDG_RUNTIME_DIR="$dir/run" "$@" <&3 3<&- &
cmd_pid=$!
status=0
wait "$cmd_pid" || status=$?
cmd_pid=
exit $status
