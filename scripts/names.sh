# shellcheck shell=sh disable=SC2034
# The project's own D-Bus names, sourced by the other scripts. The prefix
# is DBUS_PREFIX in src/lib.rs; tests/names.rs checks that they agree.
prefix=eu.nosini.ScopeVault
portal_name=$prefix.Portal
probe_name=$prefix.IdentityProbe
probe_obj=/$(printf '%s' "$prefix" | tr . /)/IdentityProbe
