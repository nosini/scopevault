#!/bin/sh
# Reports who serves the Secret Service in this session, and which files
# decide it: the owner of org.freedesktop.secrets and anything queued for
# it, the owners of org.gnome.keyring and the Secret portal backends, the
# state of the scopevault unit and of gnome-keyring's own units, the D-Bus
# activation files, the autostart override, the portal configuration and
# the PAM lines that start gnome-keyring. It also compares the portal
# frontend's (xdg-desktop-portal's) namespaces, root and LSM label with
# this shell's: scopevault serves the frontend only if it is a host process.
#
# Read-only. Only the bus daemon (org.freedesktop.DBus) is talked to: no
# method is ever called on org.freedesktop.secrets, org.gnome.keyring or
# org.freedesktop.impl.portal.Secret themselves, because calling a
# well-known name can activate its service. systemctl is only asked
# is-enabled and is-active, which start nothing.
#
# Ends with "scopevault serves the Secret Service" (exit 0) when
# scopevault-daemon owns the name, nothing is queued for it, and, if the
# portal configuration selects scopevault, scopevault-daemon owns its portal
# backend name, the installed scopevault.portal names that name, and the bus
# can start it; otherwise a one-line reason (exit 1).
#
# Needs: gdbus (glib2-tools).
#
#   scripts/activation-check.sh
set -eu
[ "$#" -eq 0 ] || { echo "usage: $0" >&2; exit 2; }

need() { command -v "$1" >/dev/null || { echo "$1 not found ($2)" >&2; exit 2; }; }
need gdbus "install glib2-tools"
# shellcheck source=scripts/names.sh
. "$(dirname "$0")/names.sh"

bus() { # bus METHOD ARG: a call to the bus daemon, the only service talked to
    gdbus call --session -d org.freedesktop.DBus -o /org/freedesktop/DBus -m "org.freedesktop.DBus.$1" "$2"
}
names() { # names REPLY: the strings of a gdbus string or string-array reply
    printf '%s\n' "$1" | tr -d "()[]'" | tr ',' '\n' | sed 's/^ *//;s/ *$//' | grep . || true
}
pid_of() { # pid_of UNIQUE-NAME: the process id behind it, empty if unknown
    printf '%s' "$(bus GetConnectionUnixProcessID "$1" 2>/dev/null || true)" | sed 's/.* //' | tr -cd '0-9'
}
command_of() { # command_of PID: /proc/PID/cmdline with NULs as spaces
    # (procfs reports size 0 for every file, so read it rather than test -s)
    c=$(tr '\0' ' ' <"/proc/$1/cmdline" 2>/dev/null | sed 's/ *$//' || true)
    if [ -n "$c" ]; then printf '%s' "$c"; else printf '(no readable command line)'; fi
}
describe() { # describe UNIQUE-NAME: "pid N: command" for a report line
    p=$(pid_of "$1")
    if [ -n "$p" ]; then printf 'pid %s: %s' "$p" "$(command_of "$p")"; else printf 'pid unknown'; fi
}
show() { # show FILE LINE...: whether the file exists, and its deciding lines
    f=$1; shift
    if [ -f "$f" ]; then
        echo "$f: exists"
        for pat in "$@"; do grep -h "^$pat" "$f" | sed 's/^/    /'; done
    else
        echo "$f: missing"
    fi
}

if ! bus NameHasOwner org.freedesktop.DBus >/dev/null 2>&1; then
    echo "cannot reach the session bus (DBUS_SESSION_BUS_ADDRESS is ${DBUS_SESSION_BUS_ADDRESS-unset})" >&2
    exit 1
fi

echo "-- the name"
owner=$(names "$(bus GetNameOwner org.freedesktop.secrets 2>/dev/null || true)")
owner_cmd=
if [ -n "$owner" ]; then
    owner_cmd=$(command_of "$(pid_of "$owner")")
    echo "owner of org.freedesktop.secrets: $owner ($(describe "$owner"))"
else
    echo "owner of org.freedesktop.secrets: none"
fi
# ListQueuedOwners includes the primary owner; the others take the name at
# once if the owner exits.
queued=$(names "$(bus ListQueuedOwners org.freedesktop.secrets 2>/dev/null || true)" | grep -vxF "${owner:-none}" || true)
if [ -n "$queued" ]; then
    echo "queued for org.freedesktop.secrets (takes the name at once if the owner exits):"
    printf '%s\n' "$queued" | while IFS= read -r q; do
        echo "  $q ($(describe "$q"))"
    done
else
    echo "nothing is queued for org.freedesktop.secrets"
fi

echo
echo "-- the other names"
portal_owner_cmd=
for name in org.gnome.keyring org.freedesktop.impl.portal.Secret "$portal_name"; do
    o=$(names "$(bus GetNameOwner "$name" 2>/dev/null || true)")
    if [ -n "$o" ]; then
        echo "owner of $name: $o ($(describe "$o"))"
        [ "$name" = "$portal_name" ] && portal_owner_cmd=$(command_of "$(pid_of "$o")")
    else
        echo "owner of $name: none"
    fi
done
# The bus only starts names whose activation files it has read; dbus-broker
# reads new ones only when asked to (ReloadConfig).
portal_activatable=
gdbus call --session -d org.freedesktop.DBus -o /org/freedesktop/DBus \
    -m org.freedesktop.DBus.ListActivatableNames 2>/dev/null | grep -qF "'$portal_name'" && portal_activatable=yes
echo "the bus can start $portal_name: ${portal_activatable:-no}"

echo
echo "-- the portal frontend"
frontend=$(names "$(bus GetNameOwner org.freedesktop.portal.Desktop 2>/dev/null || true)")
if [ -n "$frontend" ]; then
    echo "owner of org.freedesktop.portal.Desktop: $frontend ($(describe "$frontend"))"
    fp=$(pid_of "$frontend")
    if [ -n "$fp" ]; then
        # The daemon requires a host frontend: same namespaces, root and LSM
        # label as itself. This shell stands in for the daemon here.
        diffs=
        for ns in cgroup ipc mnt net pid user uts; do
            a=$(readlink "/proc/$fp/ns/$ns" 2>/dev/null || echo unreadable)
            b=$(readlink "/proc/self/ns/$ns" 2>/dev/null || echo unreadable)
            [ "$a" = "$b" ] || diffs="$diffs $ns"
        done
        [ "$(stat -L -c %d:%i "/proc/$fp/root" 2>/dev/null || echo unreadable)" = "$(stat -L -c %d:%i /)" ] \
            || diffs="$diffs root"
        a=$(tr -d '\0' <"/proc/$fp/attr/current" 2>/dev/null || echo unreadable)
        b=$(tr -d '\0' </proc/self/attr/current 2>/dev/null || echo unreadable)
        [ "$a" = "$b" ] || diffs="$diffs label($a)"
        if [ -z "$diffs" ]; then
            echo "the frontend looks like a host process (same namespaces, root and label as this shell)"
        else
            echo "the frontend differs from this shell in:$diffs; scopevault would refuse it"
        fi
    fi
else
    echo "owner of org.freedesktop.portal.Desktop: none (xdg-desktop-portal starts on demand)"
fi

echo
echo "-- the files that decide activation"
config=${XDG_CONFIG_HOME:-$HOME/.config}
data=${XDG_DATA_HOME:-$HOME/.local/share}
show "$config/systemd/user/scopevault.service" 'ExecStart='
show "$data/dbus-1/services/org.freedesktop.secrets.service" 'SystemdService=' 'Exec='
show /usr/share/dbus-1/services/org.freedesktop.secrets.service 'Exec='
show "$config/autostart/gnome-keyring-secrets.desktop" 'Hidden='
show /etc/xdg/autostart/gnome-keyring-secrets.desktop 'Exec='
show "$data/dbus-1/services/$portal_name.service" 'SystemdService='
show "$data/xdg-desktop-portal/portals/scopevault.portal" 'DBusName=' 'Interfaces='
portal_file_name=$(sed -n 's/^DBusName=//p' "$data/xdg-desktop-portal/portals/scopevault.portal" 2>/dev/null | sed -n 1p)
# Activation files of older versions start the same unit under a name
# nobody owns any more.
for f in "$data"/dbus-1/services/*.service; do
    case $f in */org.freedesktop.secrets.service|*/"$portal_name".service) continue ;; esac
    grep -qs '^SystemdService=scopevault.service' "$f" && echo "$f: also starts scopevault.service (left over from an older version?)"
done
show "$config/xdg-desktop-portal/gnome-portals.conf" 'default=' 'org.freedesktop.impl.portal.Secret='
show /usr/share/xdg-desktop-portal/gnome-portals.conf 'default=' 'org.freedesktop.impl.portal.Secret='
# xdg-desktop-portal reads the user file instead of the system's (1.20
# reads only the first one it finds), so the user file should be a copy of
# the system file with the Secret line changed.
portal_selected=
grep -qs '^org.freedesktop.impl.portal.Secret=scopevault' "$config/xdg-desktop-portal/gnome-portals.conf" \
    && portal_selected=yes

echo
echo "-- the systemd units"
if command -v systemctl >/dev/null; then
    # Neither is-enabled nor is-active starts anything.
    echo "systemctl --user is-enabled scopevault.service: $(systemctl --user is-enabled scopevault.service 2>&1 || true)"
    echo "systemctl --user is-active scopevault.service:  $(systemctl --user is-active scopevault.service 2>&1 || true)"
    # gnome-keyring's own units: if the socket runs, a connection to the
    # control socket starts a second gnome-keyring that queues for the name.
    for u in gnome-keyring-daemon.socket gnome-keyring-daemon.service; do
        echo "systemctl --user is-enabled $u: $(systemctl --user is-enabled "$u" 2>&1 || true)"
        echo "systemctl --user is-active $u:  $(systemctl --user is-active "$u" 2>&1 || true)"
    done
else
    echo "systemctl not found"
fi

echo
echo "-- PAM (informational; scopevault does not change it)"
pam=$(grep -H pam_gnome_keyring /etc/pam.d/* 2>/dev/null || true)
if [ -n "$pam" ]; then
    printf '%s\n' "$pam" | sed 's/^/    /'
else
    echo "    no pam_gnome_keyring lines in /etc/pam.d"
fi

echo
reason=
if [ -z "$owner" ]; then
    reason="nobody owns org.freedesktop.secrets"
elif ! printf '%s' "$owner_cmd" | grep -q scopevault-daemon; then
    reason="org.freedesktop.secrets is served by something else: $owner_cmd"
elif [ -n "$queued" ]; then
    reason="$(describe "$(printf '%s\n' "$queued" | sed -n 1p)") is queued for org.freedesktop.secrets and takes the name if scopevault exits"
elif [ -n "$portal_selected" ] && ! printf '%s' "$portal_owner_cmd" | grep -q scopevault-daemon; then
    reason="the portal configuration selects scopevault, but $portal_name is not owned by scopevault-daemon"
elif [ -n "$portal_selected" ] && [ "$portal_file_name" != "$portal_name" ]; then
    reason="scopevault.portal names ${portal_file_name:-no bus name}, but scopevault-daemon serves $portal_name; install packaging/scopevault.portal"
elif [ -n "$portal_selected" ] && [ -z "$portal_activatable" ]; then
    reason="the bus cannot start $portal_name; install its activation file and reload the bus (see docs/INSTALL.md)"
fi
if [ -z "$reason" ]; then
    echo "scopevault serves the Secret Service"
    exit 0
fi
echo "$reason"
exit 1
