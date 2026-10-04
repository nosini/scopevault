# Unlocking with the login password

Typing two passwords at every login is tedious, so the vault can also be
opened with your login password. When you log in at GDM, or unlock the
screen, a small PAM module hands the password to scopevault, and the vault
opens without a dialog. The master password keeps working everywhere.

Setting it up needs root and two lines in PAM files; see
[INSTALL.md](INSTALL.md). Nothing is changed in PAM unless you do it.

Logins that don't involve a password, like fingerprint, smartcard or
automatic login, still show the usual dialog, and so do SSH and console
logins.

## Why this way

The login password unlocks a second copy of the vault key, the login
slot. Using the same password for both was the alternative, but then there
would be no separate recovery password, and root resetting your login
password would lock you out of the vault.

The password comes from scopevault's own PAM module. `pam_exec` only sees
the password during authentication, not when it changes, so the vault
would fall out of step after every password change. Speaking
gnome-keyring's control protocol is not an option either, because that
socket belongs to the gnome-keyring that PAM still starts for SSH and
PKCS#11. The kernel keyring would expose the password to every process of
the user while it is there.

If the login password was changed in a way PAM didn't see, the slot is
repaired the next time the vault is opened with the master password, but
only with a password that `unix_chkpwd` confirms is your current login
password. Without that check, any program that can reach the socket could
set the slot to a password of its own choosing.

A TPM-bound slot would be a natural next step; the slot table leaves room
for it.

## How gnome-keyring does it

gnome-keyring's PAM module takes the password during authentication. If
its daemon already runs, it sends the password over a control socket in
`$XDG_RUNTIME_DIR/keyring/`. Otherwise it keeps the password until the
session opens, then starts the daemon and passes the password through a
pipe. On a password change it sends the old and the new password over the
socket.

The only check on the socket is that the other end runs as the same user.
So the password is protected from other processes only at the first
login, when PAM starts the daemon itself. Whenever the daemon already
runs, any program of the user that bound the socket first receives the
password. scopevault ends up in the same position, as explained below.

## The login slot

The vault key is wrapped twice: under the master password, as before, and
under the login password, with the same Argon2id cost. Either one opens
the vault.

- The slot lives in its own table, one row per kind. Kind 1 is the login
  slot. Its associated data binds the kind, so a slot can't be moved into
  the master password's place or the other way round.
- An older build ignores the table and opens the vault with the master
  password as before.
- Backups leave the slot out and only open with the master password, so a
  backup is never weaker than the master password.
- `change-password` only changes the master password.
- An attacker who copies the live vault file can attack whichever of the
  two passwords is weaker.

## The daemon's login socket

The daemon listens on `$XDG_RUNTIME_DIR/scopevault/login`, next to the
admin socket. It is a separate socket because the admin protocol promises
that no password ever crosses it. The framing is binary, so passwords are
never copied through a JSON parser.

A delivered password that opens the slot unlocks the vault and closes any
unlock dialog that is open. One that doesn't is kept, wiped after at most
five minutes, in case the slot is out of date: once the vault is opened
with the master password, the daemon checks it with `unix_chkpwd`, and if
it is the current login password, wraps the slot under it. A password
change sends the old and the new password; the slot is rewrapped if the
old one opens it and `unix_chkpwd` confirms the new one.

`unix_chkpwd` is pam_unix's small helper that checks the calling user's
own password; it is installed with just enough privilege to read
`/etc/shadow`. The daemon runs it as your user, by its full path
`/usr/sbin/unix_chkpwd`, with the password on its standard input. It
refuses to run from a terminal, so trying it by hand needs a pipe:
`printf 'wrong\0' | /usr/sbin/unix_chkpwd $USER nonull; echo $?` prints
7 for a wrong password. It only knows accounts in `/etc/shadow`, not SSSD,
LDAP or systemd-homed. If it can't give an answer, or takes longer than
10 seconds (it is stopped then), nothing is repaired and
no dialog opens; `scopevault-admin login-unlock enable` sets the slot
again.

Who may connect: same user, not a Flatpak, and the same namespaces and
root as the daemon. Unlike the admin socket, the SELinux label is not
compared, because the helper runs in GDM's or `passwd`'s domain. That is
acceptable here because the socket can only unlock with a correct password
and only rewrap with the current login password.

Only one request is handled at a time, with at most one key derivation per
five seconds. That limits the memory and CPU a caller can use, and makes
guessing through the socket no faster than attacking a copy of the file.

`scopevault-admin login-unlock enable` adds the slot (it asks for the
master password in the daemon's dialog, then for the login password),
`disable` removes it, and `status` shows whether there is one and when it
last opened the vault.

## The PAM module

`pam_scopevault.so` runs inside GDM's session worker and `passwd`, as
root, so it does as little as possible. It never checks the password and
never connects to anything itself: it hands the password to a helper that
runs as you. It is written in Rust, catches every panic, always returns
`PAM_IGNORE`, and is listed as `optional`, so it can't block a login. It
only acts for the account it runs for.

| PAM phase | What it does |
| --- | --- |
| `auth` | Keeps the password for the session, and starts the helper in `--if-running` mode, which delivers only if the daemon is already up. This is the screen-unlock case. |
| `open_session` | Starts the helper in `--wait` mode with the kept password, then forgets it. This is the login case: the daemon starts with the graphical session, a little later. The password is kept with the account it was entered for; if the application switched the PAM user to another account in between (sudo does), it is dropped instead. |
| `chauthtok` | In the update phase only, passes the old and the new password with `--change`. |

Starting the helper: everything that isn't safe after `fork` happens
before it. The child closes every other file descriptor with
`close_range` (Linux 5.9 or later; without it the helper isn't started,
since nothing else can find every descriptor after `fork`), switches to your
user and group and checks that this can't be undone, and runs
`/usr/local/libexec/scopevault-pam-helper` with nothing in its
environment but `HOME` and `XDG_RUNTIME_DIR`. The password goes over a
socket pair rather than a pipe, so the host process can never get a
`SIGPIPE`.

## The helper

`scopevault-pam-helper` is owned by root, because the module runs it from
root processes and must not run anything you could replace. It runs as
you and refuses to run as root. It reads at most two passwords, forks into
the background so the login doesn't wait for it, and connects to the
daemon's socket: once with `--if-running` or `--change`, and for up to two
minutes with `--wait`. Before sending, it checks that the socket belongs
to your user. It logs what happened to the journal, never the password.

## openSUSE's PAM files

On openSUSE Tumbleweed, `common-auth`, `common-session` and
`common-password` are generated by `pam-config` and must not be edited.
GDM's login and screen unlock both use the `gdm-password` service, whose
vendor file is `/usr/lib/pam.d/gdm-password`; a copy in `/etc/pam.d/`
takes precedence. `passwd` only exists as `/usr/lib/pam.d/passwd`. The two
module lines therefore go into copies of those two files in `/etc/pam.d/`.

## SELinux

With SELinux enforcing, the helper's domain depends on the phase. At login
it runs unconfined, from the context `pam_selinux open` prepared. At a
screen unlock it stays in GDM's `xdm_t` domain, and the policy allows that
to connect to the daemon's socket. During a password change it runs in
`passwd_t`, which the policy is likely to deny; then the repair at the
next unlock takes over, at the cost of one master-password dialog.

## What this changes in the threat model

- The vault opens with either password, so the live vault file is only as
  strong as the weaker one. Backups stay as strong as the master password.
- The login password, which is usually also your `sudo` password, reaches
  a helper running as you and a socket in your runtime directory. A
  program running as you could bind that socket before the daemon does
  and receive the password. That is gnome-keyring's position whenever its
  daemon runs; here it applies at the first login too, because the daemon
  is a systemd user service rather than started from PAM. Such a program
  could equally wrap `sudo` in your shell, so this adds a way, not a new
  kind of attack. Flatpak apps can't reach the runtime directory, and the
  daemon refuses them anyway.
- The module runs as root in GDM's worker and in `passwd`, which is why it
  is kept small enough to read in one go.
