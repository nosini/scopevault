#!/bin/sh
# Stores, reads, searches and deletes one test secret through the Secret
# Service, from wherever it runs: meant for a shell inside a Flatpak app's
# sandbox (for example a terminal inside the app, with the app started by
# `scripts/host-flatpak-check.sh --app`, so the sandbox's session bus is the
# private test bus).
#
# Uses the first client available: libsecret's `secret-tool`, Python with
# libsecret (gi), or this repository's `scopevault-client`. The first two
# are real libsecret clients from the app's runtime.
set -u
root=$(cd "$(dirname "$0")/.." && pwd)
attr=scopevault-sandbox-check
value="sandbox check $(date +%s)"

echo "sandbox: $(sed -n 's/^name=//p' /.flatpak-info 2>/dev/null | head -n1)"
echo "session bus: ${DBUS_SESSION_BUS_ADDRESS:-unset}"
if [ ! -e /.flatpak-info ]; then
    echo "warning: not inside a Flatpak sandbox (no /.flatpak-info)"
fi

pass=0
fail=0
check() { if [ "$2" = "$3" ]; then pass=$((pass + 1)); echo "ok    $1"; else fail=$((fail + 1)); echo "FAIL  $1 (got '$2', expected '$3')"; fi; }

if command -v secret-tool >/dev/null; then
    echo "client: secret-tool (libsecret)"
    printf '%s' "$value" | secret-tool store --label="scopevault sandbox check" check "$attr"
    check "store and lookup" "$(secret-tool lookup check "$attr")" "$value"
    check "search finds one item" "$(secret-tool search --all check "$attr" 2>/dev/null | grep -c '^\[/')" 1
    secret-tool clear check "$attr"
    check "clear" "$(secret-tool lookup check "$attr")" ""
elif command -v python3 >/dev/null && python3 -c 'import gi; gi.require_version("Secret", "1")' 2>/dev/null; then
    echo "client: python3 + libsecret (gi)"
    out=$(ATTR=$attr VALUE=$value python3 - <<'EOF'
import os
import gi
gi.require_version("Secret", "1")
from gi.repository import Secret

schema = Secret.Schema.new("page.codeberg.nosini.ScopeVault.Check", Secret.SchemaFlags.DONT_MATCH_NAME,
                           {"check": Secret.SchemaAttributeType.STRING})
attrs = {"check": os.environ["ATTR"]}
Secret.password_store_sync(schema, attrs, Secret.COLLECTION_DEFAULT, "scopevault sandbox check", os.environ["VALUE"], None)
print("lookup=" + (Secret.password_lookup_sync(schema, attrs, None) or ""))
service = Secret.Service.get_sync(Secret.ServiceFlags.LOAD_COLLECTIONS, None)
print("collections=" + ",".join(sorted(c.get_object_path() for c in service.get_collections())))
Secret.password_clear_sync(schema, attrs, None)
print("after-clear=" + (Secret.password_lookup_sync(schema, attrs, None) or ""))
EOF
)
    echo "$out" | sed 's/^/    /'
    check "store and lookup" "$(echo "$out" | sed -n 's/^lookup=//p')" "$value"
    check "clear" "$(echo "$out" | sed -n 's/^after-clear=//p')" ""
else
    client=
    for d in "$root/target/release" "$root/target/debug"; do
        [ -x "$d/scopevault-client" ] && client=$d/scopevault-client && break
    done
    if [ -z "$client" ]; then
        echo "no client found: no secret-tool, no python3 with libsecret, no built scopevault-client" >&2
        exit 2
    fi
    echo "client: $client (no libsecret client in this runtime)"
    # `create` with the default alias reuses the default collection if any.
    out=$("$client" create Default default store default "scopevault sandbox check" "$value" "check=$attr" \
        lookup "check=$attr" list)
    echo "$out" | sed 's/^/    /'
    check "store and lookup" "$(echo "$out" | sed -n 3p | cut -f3)" "$value"
    item=$(echo "$out" | sed -n 2p | cut -f3)
    "$client" delete "$item" >/dev/null
    check "delete" "$("$client" lookup "check=$attr" | cut -f3)" ""
fi
echo "passed $pass, failed $fail"
[ "$fail" = 0 ]
