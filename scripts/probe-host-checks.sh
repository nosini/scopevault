#!/bin/sh
# Runs the identity checks against real Flatpak apps on a desktop host.
#
#   1. In one terminal:  ./target/release/scopevault-probe serve
#   2. In another:       ./scripts/probe-host-checks.sh APP_ID_A APP_ID_B
#
# APP_ID_A and APP_ID_B are two installed Flatpak apps (`flatpak list --app`)
# whose runtime ships `gdbus` (GNOME, KDE and freedesktop runtimes do). The
# apps themselves are not started: `flatpak run --command=gdbus` runs gdbus
# inside each app's sandbox, and `--talk-name` grants access to the probe for
# that run only. Nothing is installed or changed.
#
# The probe terminal shows the full evidence for every call; this script
# prints only the verdicts.
set -u
NAME=page.codeberg.nosini.ScopeVault.IdentityProbe
OBJ=/page/codeberg/nosini/ScopeVault/IdentityProbe
ARGS="call --session --dest $NAME --object-path $OBJ --method"

# Prints the verdict fields, or the raw output if there are none (an error).
summary() {
    out=$(cat)
    v=$(printf '%s\n' "$out" | grep -o -E '"(verdict|scope|reason|relation)": "[^"]*"' | tr '\n' ' ')
    if [ -n "$v" ]; then echo "$v"; else echo "NO VERDICT, output was:"; printf '%s\n' "$out" | sed 's/^/    /'; fi
}

[ $# -eq 2 ] || { echo "usage: $0 APP_ID_A APP_ID_B" >&2; exit 2; }
gdbus introspect --session --dest $NAME --object-path $OBJ >/dev/null 2>&1 ||
    { echo "start 'scopevault-probe serve' first" >&2; exit 1; }
for app in "$1" "$2"; do
    flatpak info "$app" >/dev/null 2>&1 || { echo "$app is not an installed Flatpak (see 'flatpak list --app')" >&2; exit 2; }
    flatpak run --command=sh "$app" -c 'command -v gdbus' >/dev/null 2>&1 ||
        { echo "$app's runtime has no gdbus; pick another app" >&2; exit 2; }
done

echo "== host shell (expect: allowed, host)"
gdbus $ARGS $NAME.WhoAmI | summary

for app in "$1" "$2"; do
    echo "== flatpak $app (expect: allowed, flatpak/$app)"
    flatpak run --talk-name=$NAME --command=gdbus "$app" $ARGS $NAME.WhoAmI 2>&1 | summary
done

echo "== two instances of $1 at once (expect: both allowed, same scope)"
flatpak run --talk-name=$NAME --command=sh "$1" -c "sleep 3" >/dev/null 2>&1 &
sleep 1
flatpak run --talk-name=$NAME --command=gdbus "$1" $ARGS $NAME.WhoAmI 2>&1 | summary
wait

if command -v bwrap >/dev/null; then
    echo "== plain bwrap sandbox (expect: denied, user namespace differs)"
    bwrap --dev-bind / / --unshare-user -- gdbus $ARGS $NAME.WhoAmI 2>&1 | summary
fi

echo "== caller exits before the probe looks (expect: denied, see probe terminal)"
gdbus $ARGS $NAME.WhoAmIDelayed 1500 >/dev/null 2>&1 &
sleep 0.3
kill $! 2>/dev/null
sleep 2

echo "== Flatpak instance records"
"$(dirname "$0")/../target/release/scopevault-probe" instances
