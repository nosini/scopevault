# RPM spec for scopevault, for openSUSE Tumbleweed. Build it with
# scripts/build-rpm.sh, which makes the two source tarballs (the sources at
# HEAD and the vendored crates) and passes the version and commit.
#
# The packages change nothing for anyone by themselves: each user switches
# from gnome-keyring with `scopevault-admin setup` (see docs/INSTALL.md).
# The PAM lines are added by hand as well (docs/LOGIN-UNLOCK.md).

%{!?sv_version: %global sv_version 0}
%{!?sv_commit: %global sv_commit unknown}
# Not every rpm defines these (Debian's, where the packages are built).
%global sv_userunitdir /usr/lib/systemd/user
%global sv_docdir %{_datadir}/doc/packages
%global sv_licensedir %{_datadir}/licenses
%global debug_package %{nil}
%global _build_id_links none

Name:           scopevault
Version:        %{sv_version}
Release:        1
Summary:        Secret Service that keeps each Flatpak app's secrets apart
License:        AGPL-3.0-or-later
URL:            https://github.com/nosini/scopevault
Source0:        %{name}-%{version}.tar.gz
Source1:        %{name}-%{version}-vendor.tar.xz
ExclusiveArch:  x86_64
Requires:       pinentry-gnome3

%description
scopevault replaces gnome-keyring's Secret Service with one that gives
every Flatpak app its own scope: an app sees only the secrets it stored.
Host programs share one scope. It is also a Secret portal backend.

Installing it changes nothing: each user switches with
`scopevault-admin setup`.

%package gui
Summary:        Graphical front end for scopevault-admin
Requires:       %{name} = %{version}-%{release}
Requires:       python3
Requires:       python3-gobject
Requires:       typelib(Gtk) = 4.0
Requires:       typelib(Adw) = 1
BuildArch:      noarch

%description gui
A GTK window for what scopevault-admin does: the vault's state, the
scopes and their items, moving items between scopes, and sharing.

%package -n pam_scopevault
Summary:        PAM module that unlocks scopevault with the login password
Requires:       %{name} = %{version}-%{release}
Requires:       pam

%description -n pam_scopevault
Hands the password entered at login, screen unlock and password change to
scopevault's daemon, so the vault opens without its own dialog. Add the
module to /etc/pam.d/gdm-password and /etc/pam.d/passwd by hand (see
docs/LOGIN-UNLOCK.md).

%prep
%setup -q
%setup -q -T -D -a 1
mkdir -p .cargo
cat > .cargo/config.toml <<EOF
[source.crates-io]
replace-with = "vendored"
[source.vendored]
directory = "vendor"
EOF

%build
export SCOPEVAULT_COMMIT=%{sv_commit}
export CARGO_PROFILE_RELEASE_STRIP=symbols
cargo build --release --offline --locked \
    --bin scopevault-daemon --bin scopevault-admin --bin scopevault-pam-helper
export SCOPEVAULT_PAM_HELPER=%{_libexecdir}/scopevault-pam-helper
cargo build --release --offline --locked --manifest-path pam/Cargo.toml --lib

%install
install -D -m 755 target/release/scopevault-daemon %{buildroot}%{_bindir}/scopevault-daemon
install -D -m 755 target/release/scopevault-admin %{buildroot}%{_bindir}/scopevault-admin
install -D -m 755 target/release/scopevault-pam-helper %{buildroot}%{_libexecdir}/scopevault-pam-helper
install -D -m 755 pam/target/release/libpam_scopevault.so %{buildroot}%{_libdir}/security/pam_scopevault.so
install -D -m 755 gui/scopevault-gui %{buildroot}%{_bindir}/scopevault-gui
for unit in scopevault.service scopevault-unlock.service; do
    sed 's|%%h/.local/bin/|%{_bindir}/|g' packaging/$unit > unit.tmp
    install -D -m 644 unit.tmp %{buildroot}%{sv_userunitdir}/$unit
done
sed 's|@BINDIR@|%{_bindir}|' packaging/eu.nosini.ScopeVault.desktop > desktop.tmp
install -D -m 644 desktop.tmp %{buildroot}%{_datadir}/applications/eu.nosini.ScopeVault.desktop
for doc in README.md CHANGELOG.md docs/DESIGN.md docs/INSTALL.md docs/LOGIN-UNLOCK.md docs/STORE.md; do
    install -D -m 644 $doc %{buildroot}%{sv_docdir}/%{name}/$(basename $doc)
done
install -D -m 644 LICENSE %{buildroot}%{sv_licensedir}/%{name}/LICENSE

%files
%{_bindir}/scopevault-daemon
%{_bindir}/scopevault-admin
%{sv_userunitdir}/scopevault.service
%{sv_userunitdir}/scopevault-unlock.service
%{sv_docdir}/%{name}
%{sv_licensedir}/%{name}

%files gui
%{_bindir}/scopevault-gui
%{_datadir}/applications/eu.nosini.ScopeVault.desktop

%files -n pam_scopevault
%{_libdir}/security/pam_scopevault.so
%{_libexecdir}/scopevault-pam-helper

%changelog
