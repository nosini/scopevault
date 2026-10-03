# Unlocking with the login password

Typing two passwords at every login is tedious, so the vault can also be
opened with your login password. When you log in at GDM, or unlock the
screen, a small PAM module hands the password to scopevault, and the vault
opens without a dialog. The master password keeps working everywhere.

So far only part of it exists: the login slot
and the daemon's login socket. The PAM module that hands over the password
comes next.

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
LDAP or systemd-homed. If it can't give an answer, nothing is repaired and
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
