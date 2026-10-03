# Unlocking with the login password

Typing two passwords at every login is tedious, so the vault can also be
opened with your login password. When you log in at GDM, or unlock the
screen, a small PAM module hands the password to scopevault, and the vault
opens without a dialog. The master password keeps working everywhere.

So far only part of it exists: the login slot
and unlocking through it. The socket that receives the password and the
PAM module come next.

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
