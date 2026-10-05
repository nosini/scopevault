#!/bin/sh
# Builds the RPMs (scopevault, scopevault-gui, pam_scopevault) from HEAD,
# with packaging/scopevault.spec, into target/rpm/RPMS.
#
#   scripts/build-rpm.sh
#
# Needs rpmbuild and cargo. The crates are vendored into a second source
# tarball, so the build itself runs offline. Tracked files go in as they
# are in the working tree (then the version says `-dirty`); untracked files
# do not.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
command -v rpmbuild >/dev/null || { echo "rpmbuild not found" >&2; exit 2; }
version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | sed -n 1p)
commit=$(git rev-parse --short=7 HEAD)
tree=HEAD
# A commit object for the working tree's tracked files; nothing is changed.
if stash=$(git stash create) && [ -n "$stash" ]; then
    tree=$stash
    commit=$commit-dirty
fi

top=$root/target/rpm
rm -rf "$top"
mkdir -p "$top/SOURCES" "$top/vendor-work"
git archive --format=tar.gz --prefix="scopevault-$version/" -o "$top/SOURCES/scopevault-$version.tar.gz" "$tree"
# One vendor directory for the daemon's and the PAM module's crates.
cargo vendor --quiet --locked --sync pam/Cargo.toml "$top/vendor-work/vendor" >/dev/null
tar -C "$top/vendor-work" -cJf "$top/SOURCES/scopevault-$version-vendor.tar.xz" vendor
rm -rf "$top/vendor-work"

# --nodeps: the build requirements are checked against this system's rpm
# database, which a non-RPM distribution does not fill.
rpmbuild -bb --nodeps \
    --define "_topdir $top" \
    --define "sv_version $version" \
    --define "sv_commit $commit" \
    packaging/scopevault.spec
echo
find "$top/RPMS" -name '*.rpm' | sort
