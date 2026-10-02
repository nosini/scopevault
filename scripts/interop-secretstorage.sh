#!/bin/sh
# Interoperability check with an independent client: runs scopevault-daemon
# on a private bus with a temporary vault and the fake pinentry, and drives it
# with the Python `secretstorage` library (scripts/interop/secretstorage_client.py).
# Never touches the real session bus or keyring.
#
#   PYTHON=/path/to/python scripts/interop-secretstorage.sh
#
# PYTHON must have `secretstorage` installed (python3 -m venv DIR &&
# DIR/bin/pip install secretstorage). DBUS_DAEMON selects the bus daemon.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
python=${PYTHON:-python3}
"$python" -c 'import secretstorage' 2>/dev/null || { echo "secretstorage is not installed for $python" >&2; exit 2; }
(cd "$root" && cargo build --quiet --bin scopevault-daemon)

work=$(mktemp -d "${TMPDIR:-/tmp}/scopevault-interop.XXXXXX")
trap 'rm -rf "$work"' EXIT
mkdir "$work/pinentry"
cat > "$work/pinentry.sh" <<EOF
#!/bin/sh
FAKE_PINENTRY_DIR='$work/pinentry' exec '$root/tests/support/fake-pinentry.sh' "\$@"
EOF
chmod 700 "$work/pinentry.sh"

export ROOT="$root" WORK="$work" PYTHON="$python"
"$root/tests/support/with-isolated-bus.sh" sh -eu -c '
    pins() { printf "%s\n" "$@" > "$WORK/pinentry/pins"; rm -f "$WORK/pinentry/count"; }
    run() {
        "$ROOT/target/debug/scopevault-daemon" --data-dir "$WORK/vault" --pinentry "$WORK/pinentry.sh" \
            --admin-socket "$WORK/admin/socket" \
            2>>"$WORK/daemon.log" &
        pid=$!
        "$PYTHON" "$ROOT/scripts/interop/secretstorage_client.py" "$1" || { kill $pid; cat "$WORK/daemon.log" >&2; exit 1; }
        kill $pid; wait $pid || true
    }
    # Phase 1: create the vault (new password, entered twice by one GETPIN),
    # then confirm the password to reopen a locked collection.
    pins "interop password" "interop password"
    run store
    # Phase 2: restarted daemon, locked vault: one wrong attempt, then right.
    pins "wrong" "interop password"
    run read
    echo "dialogs shown: $(grep -c STARTED "$WORK/pinentry/log")"
'
