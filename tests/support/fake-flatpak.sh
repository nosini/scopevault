#!/bin/sh
# Test helper: runs a command in a Flatpak-like sandbox without Flatpak.
#
#   fake-flatpak.sh MODE APP_ID INSTANCE_ID RUNTIME_DIR -- COMMAND...
#
# MODE is one of
#   ok          /.flatpak-info and a matching Flatpak instance record
#   no-record   /.flatpak-info but no instance record
#   mismatch    instance record whose info differs from /.flatpak-info
#   runtime     a [Runtime] sandbox instead of an application
#   symlink     /.flatpak-info is a symlink to a valid-looking file
#   plain       a private root with no /.flatpak-info (an unknown sandbox)
#   proxy       /.flatpak-info for an instance already started with `ok`,
#               in a separate mount namespace (like xdg-dbus-proxy)
#
# The sandbox is a new user and mount namespace whose root is a tmpfs with
# the host's /usr, /etc, /home, /tmp and /proc bound in. The command runs in
# a nested user namespace that maps the original UID back, as bwrap does,
# so the bus sees the real UID.
set -eu
mode=$1 app=$2 inst=$3 rundir=$4; shift 4; [ "$1" = "--" ] && shift
uid=$(id -u) gid=$(id -g)

info=$(mktemp)
if [ "$mode" = runtime ]; then group=Runtime; else group=Application; fi
printf '[%s]\nname=%s\n\n[Instance]\ninstance-id=%s\nsession-bus-proxy=true\n\n[Context]\nsockets=wayland;\n' \
    "$group" "$app" "$inst" > "$info"

record="$rundir/.flatpak/$inst"
if [ "$mode" != no-record ] && [ "$mode" != plain ] && [ "$mode" != proxy ]; then
    mkdir -p "$record"
    if [ "$mode" = mismatch ]; then
        sed 's/^sockets=.*/sockets=x11;/' "$info" > "$record/info"
    else
        cp "$info" "$record/info"
    fi
fi

export FAKE_INFO="$info" FAKE_MODE="$mode" FAKE_RECORD="$record" FAKE_UID="$uid" FAKE_GID="$gid"
exec unshare -Urm sh -euc '
    root=$(mktemp -d)
    mount -t tmpfs tmpfs "$root"
    for d in usr etc home tmp proc dev; do mkdir "$root/$d"; mount --rbind "/$d" "$root/$d"; done
    for l in bin lib lib64 sbin; do [ -e "/$l" ] && ln -s "usr/$l" "$root/$l"; done
    case $FAKE_MODE in
        plain) ;;
        symlink) cp "$FAKE_INFO" "$root/real-info"; ln -s /real-info "$root/.flatpak-info" ;;
        *) cp "$FAKE_INFO" "$root/.flatpak-info" ;;
    esac
    cd "$root"; mkdir old; pivot_root . old; umount -l /old; rmdir /old; cd /
    if [ -d "$FAKE_RECORD" ] && [ "$FAKE_MODE" != proxy ]; then
        mnt=$(stat -L -c %i /proc/self/ns/mnt)
        printf "{\"child-pid\": %s, \"mnt-namespace\": %s}\n" $$ "$mnt" > "$FAKE_RECORD/bwrapinfo.json"
    fi
    exec unshare -U --map-user="$FAKE_UID" --map-group="$FAKE_GID" "$@"
' fake-flatpak "$@"
