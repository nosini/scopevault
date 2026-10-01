#!/bin/sh
# Runs COMMAND with a private session bus and XDG_RUNTIME_DIR, then tears
# both down. Uses DBUS_DAEMON (default: dbus-daemon on PATH).
#
#   with-isolated-bus.sh COMMAND...
set -eu
dir=$(mktemp -d "${TMPDIR:-/tmp}/scopevault-bus.XXXXXX")
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
"${DBUS_DAEMON:-dbus-daemon}" --config-file="$dir/bus.conf" --nofork --print-pid=3 3>"$dir/pid" &
for _ in $(seq 50); do [ -S "$dir/bus" ] && break; sleep 0.1; done
status=0
DBUS_SESSION_BUS_ADDRESS="unix:path=$dir/bus" XDG_RUNTIME_DIR="$dir/run" "$@" || status=$?
kill "$(cat "$dir/pid")" 2>/dev/null || true
wait 2>/dev/null || true
rm -rf "$dir"
exit $status
