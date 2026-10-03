# How scopevault works

On a normal GNOME desktop, every application that talks to the Secret
Service (`org.freedesktop.secrets`) sees the same keyring. gnome-keyring
only uses a caller's bus name to keep track of its sessions and prompts;
it never checks who the caller is. That includes Flatpak apps that were
given permission to talk to it: one of them can list, read and change the
passwords of all the others. scopevault replaces
the Secret Service with one that gives each Flatpak app its own private
part of the keyring, while ordinary host applications keep sharing theirs
as before. Apps keep using the standard API and need no changes.

This file explains the design and the reasons behind it. How the vault is
encrypted is in [STORE.md](STORE.md).

## What it adds, and what it doesn't

The benefit is for Flatpak apps that store their passwords directly in
the desktop's Secret Service. With gnome-keyring, every host program and
every Flatpak app with the same permission can read them. With scopevault
each Flatpak app only sees its own scope. Host programs still share the
`host` scope with each other, as they do now, but they can't reach the
apps' scopes through the Secret Service.

Many Flatpak apps don't use the Secret Service directly. libsecret inside a
sandbox prefers the Secret portal: the app gets one key from the portal and
encrypts its own file under `~/.var/app/<app-id>/` with it. Those apps are
already separated from each other, and scopevault adds little isolation for
them.
What it does add is that their keys live in scopevault's vault, out of
reach of host applications that use the Secret Service.

It is password storage, not a hardware keystore. An app that can read its
own secret can also leak it. Code running unsandboxed as your user is
trusted: it can read the daemon's memory, replace the daemon, or watch you
type the password. scopevault does not pretend otherwise.

## Scopes

Every caller is put into one scope, and every collection and item belongs
to exactly one scope.

| Caller | Scope |
| --- | --- |
| A Flatpak app, identified reliably | `flatpak/<app-id>`, its own |
| An unsandboxed host program, positively identified as one | `host`, shared by all host programs |
| Anything else: unknown sandboxes, malformed metadata, processes that cannot be inspected | none, refused |

There is also a reserved scope, `portal`, that holds the Secret portal's
per-app keys. No caller is ever put into it.

`host` is shared on purpose. Host programs can read each other's memory and
files anyway, so separating them in the keyring would only break things
that work today without making anything safer.

A Flatpak app ID names an installed app, not its publisher. An update keeps
the scope. A different program installed later under the same ID inherits
it, unless the scope is reset. Uninstalling an app does not delete its
secrets.
`scopevault-admin reset-scope` does that on request.

## Identifying callers

Everything depends on telling a Flatpak app from a host program from
something else, so this part is deliberately strict. scopevault never
believes what a caller says about itself: no PIDs, app IDs, environment
variables or attributes from the request count.

What it uses is what the bus daemon reports for the sender
(`GetConnectionCredentials`: user ID, process ID, a pidfd and the security
label) and what the kernel shows for that process:

1. The user ID must be the daemon's own, and so must all four user IDs in
   `/proc/<pid>/status`.
2. The bus must hand over a pidfd (`ProcessFD`). A plain PID could be
   reused by another process before it is looked at, so a caller without
   one is refused.
3. `/proc/<pid>` is opened as a directory, and only then is the pidfd
   checked to still be alive. A PID cannot be reused while its process is
   unreaped, so the directory really belongs to the caller. Every later
   read goes through that directory and is followed by another liveness
   check.
4. `/.flatpak-info` is read from the process's root without following
   symlinks.
   - If it exists, the process must not be in the host's mount namespace,
     the file must parse cleanly and describe an app (runtime-only
     sandboxes are refused), and it must be byte-identical to the record
     Flatpak keeps in `$XDG_RUNTIME_DIR/.flatpak/<instance>/info`. The
     process named in that instance's `bwrapinfo.json` must be alive in
     the recorded mount namespace and see the same file. The caller is
     then `flatpak/<app-id>`.
   - If it doesn't exist, the caller has to prove it is a host program: it
     must share all seven namespaces, the root directory and the security
     label with the daemon. Only then is it `host`. Any difference is
     refused, with a message saying what differed.
5. Anything else, such as a process that exited or a file that cannot be
   read, is refused. Nothing falls back to `host`.

The result is cached per bus connection and dropped when the connection
goes away.

This follows the way xdg-desktop-portal identifies apps, with three
differences. The portal reads `/proc/<pid>/root/.flatpak-info` by PID even
when it has a pidfd (there is a TODO about that race in its code). It
treats any caller without Flatpak, Snap or similar metadata as a host app.
And it follows symlinks to the metadata file. scopevault reaches `/proc`
only through the pidfd-bound directory, requires host status to be proven,
and cross-checks Flatpak's instance record, which the portal does not.

### Why the Flatpak metadata can be trusted

Flatpak writes `/.flatpak-info` from outside the sandbox, both into the
app's sandbox and into the sandbox of its D-Bus proxy (for a Flatpak app,
the process the bus sees is the proxy). The app cannot change either copy.
To fake the file it would need a mount namespace of its own, which needs a
user namespace, and Flatpak's seccomp filter blocks creating one.

Unsandboxed host code can fake it, for example with
`bwrap --ro-bind fake /.flatpak-info`. That is acceptable: host code is
trusted anyway and has easier ways in. The instance-record check at least
makes a forgery require a matching running app.

Other sandboxes are a real concern. A sandbox that can reach the session
bus and also allows nested user namespaces could pretend to be any Flatpak
app. A launcher that gives its sandbox no session bus, or disables user
namespaces in it, is safe. Any other custom sandbox needs checking.

### Apps that can escape anyway

Some Flatpak permissions make the sandbox meaningless:
`--socket=session-bus`, `--talk-name=org.freedesktop.Flatpak`,
`--filesystem=home` or `host`, and `--allow=devel`. Such apps still get
their own scope, but they can run code on the host and so reach `host` and
everything else. The identity probe points them out.

## The Secret Service, per caller

zbus's object server has one object tree for everyone, so it cannot show
different callers different objects. scopevault reads method calls itself
and routes them by the caller's scope:

- Object paths are resolved inside the caller's scope. Two apps can both
  have `/org/freedesktop/secrets/collection/login`, and neither can reach
  the other's. A path from another scope gets exactly the same error as a
  path that doesn't exist, so guessing tells an app nothing.
- Aliases such as `default`, the `Collections` property, property reads and
  writes, and introspection are all computed per caller.
- Signals are never broadcast. Each one is sent to the connections of the
  scope it concerns, addressed to them directly. xdg-dbus-proxy passes
  such signals on to Flatpak apps.
- Requests from one connection are handled in order, with limits on the
  queue, request size and number of connections.
- One table drives both argument checking and introspection, and a test
  compares it with the upstream interface description in `spec/`.

Every method of the specification is implemented: Service, Collection,
Item, Session and Prompt, on the encrypted vault.

- Transfer sessions support `plain` and
  `dh-ietf1024-sha256-aes128-cbc-pkcs7`, the encrypted one libsecret
  negotiates. Degenerate public keys are refused.
- A session or prompt belongs to the connection that opened it. Another
  connection, even of the same app, cannot use it.
- Each scope can have a `session` collection that lives in memory only.
- When a prompt is dismissed, the result still has the type the client
  expects. gnome-keyring returns an empty string there, which trips up
  libsecret and Python's `secretstorage`.
- Unlocking with a prompt lists all the requested objects that ended up
  unlocked, because libsecret only looks at the prompt's result.
- `GetSecrets` answers with the paths the client sent, aliases included,
  because libsecret looks results up by its own item paths.

Each scope gets a `login` collection, set as its `default`, the first time
it uses the vault, just as gnome-keyring creates a login keyring. Some
clients rely on it. Cryptomator's Secret Service library never creates a
collection: it points `default` at `/collection/login` and expects it to be
there. A scope that already has data keeps it as it is, so deleting
`login` or moving `default` sticks.

## Locking and unlocking

The vault is one encrypted file with one master password. Unlocking it
gives the daemon the key; it does not change who may see what. An app
still only sees its own scope.

When an app asks for something while the vault is locked, the daemon opens
the unlock dialog. Concurrent requests share one dialog. `CreateItem` is
the exception: it answers `IsLocked`, because libsecret then unlocks and
retries by itself.
After a dialog was cancelled or failed, requests that would open another
one don't, for 30 seconds, so an app retrying in a loop cannot keep the
dialog coming back. They wait instead, up to five minutes from when they
arrived, until something else unlocks the vault: another request's
dialog, an explicit unlock prompt, or `scopevault-admin unlock`. At login
that matters, because applications start while the first dialog is still
open. A direct Secret Service client gives up after its own D-Bus timeout,
usually 25 seconds, whatever the daemon does. The portal waits without a
timeout.

An app can also ask for a dialog explicitly. If it gets three of those
cancelled within two minutes, its further prompts are dismissed without a
dialog for a while. Other apps still get theirs.

An app can lock its own collections. That locks them for every connection
of its scope, and reading secrets from them then needs the master password
again. Other collections and other scopes are not affected.
Locking the whole vault is only possible through the administrative
interface.

A global lock keeps transfer sessions open. libsecret opens one session per
process and never opens another, so closing them would break every running
application until it restarts. A session only protects secrets on their
way to its own connection, so keeping it gives nothing away.

## Administration

Ordinary Secret Service requests from host programs stay limited to
`host`, Seahorse included. Working across scopes needs the administrative
interface: a Unix socket in `$XDG_RUNTIME_DIR/scopevault/`, used by
`scopevault-admin`. Its peers are identified the same way as D-Bus callers,
and only host programs are served. A socket with mode 0600 alone would not
be enough, since Flatpak apps run as the same user.

Commands that hand secrets to another scope or destroy data, such as
`move` and `reset-scope`, ask for the master password in the daemon's own
dialog. No password ever passes through the CLI or the socket.

`restore`, `import` and `export` work on the vault file directly and need
the daemon stopped.

### Moving from gnome-keyring

`scopevault-admin import` reads everything from gnome-keyring through its
Secret Service API, not its files, and puts it into `host`.
The Secret portal's per-app keys are the exception: they go into
`portal`, byte for byte.
scopevault never guesses which item belongs to which app from labels or
attributes, since apps control those. Moving items to an app's scope is a
deliberate `scopevault-admin move`. There is also no fallback from an app's
scope to `host` when something is missing: that would undo the isolation.

`scopevault-admin export` goes the other way, for switching back. It writes
what gnome-keyring doesn't have and skips what it has.
An item changed in scopevault replaces its older version in gnome-keyring
instead of being added next to it. If that older version is ambiguous,
export writes nothing.

### gnome-keyring and the bus name

Only one process can own `org.freedesktop.secrets`. gnome-keyring's login
daemon, started by PAM, only claims the name when something asks for its
`secrets` component: its autostart entry, its D-Bus activation file, its
Secret portal backend or its own systemd units. The installation hides or
overrides the first two and masks the units.

gnome-keyring asks for the name in a way that puts it in the bus's queue
while scopevault owns it. If scopevault then stops, the bus hands the name
to gnome-keyring at once, and applications start storing secrets there
without anyone noticing. The daemon checks the queue once a minute and logs
a warning while anything waits in it.

## The Secret portal backend

Flatpak apps that use the Secret portal get one key per app from
xdg-desktop-portal, which in turn asks a backend. Normally that is
gnome-keyring. scopevault can be the backend instead, so the keys live in
its vault, in the `portal` scope where no Secret Service caller can reach
them.

- Only xdg-desktop-portal is served. The caller must own
  `org.freedesktop.portal.Desktop` at that moment and be identified as a
  host program; everyone else is refused before anything is read or
  written. There is no check of the portal's executable: it would break
  during package updates and would not stop host code anyway. A host
  program that replaces xdg-desktop-portal does become the frontend for
  every app, but host code is trusted.
- The backend has its own bus name, `page.codeberg.nosini.ScopeVault.Portal`, on a
  separate connection. A Flatpak app allowed to talk to
  `org.freedesktop.secrets` can therefore not reach it through the same
  connection.
- Keys are moved from gnome-keyring byte for byte. A new key for an app
  that already has encrypted data would make that data unreadable, so no
  key is created until the keys were imported or `scopevault-admin portal
  init` was run, and none for an app that already has a libsecret keyring
  file of its own. `scopevault-admin portal new-key` overrides that
  explicitly.
- If gnome-keyring has several candidate keys for one app, the import
  stops and changes nothing: which one gnome-keyring hands out is not
  defined.

A key gnome-keyring creates during a session can't be read through its
Secret Service until gnome-keyring restarts. An import that hits one fails
cleanly; logging out and back in first avoids it.

The app's encrypted files stay in its own directory. They need to be
backed up together with the vault.

## Sharing

Nothing is shared by default. The administrator can give one scope read,
or read and write, access to a single item of another scope:
`scopevault-admin share`, and `unshare` to take it back. Apps can never
create grants, there are no wildcards, and `portal` is never involved.

The other app sees shared items in a collection called `Shared`. The
capital S keeps it apart from real collections, whose names are always
lower case. Shared items also show up in searches, because libsecret finds
secrets by searching every collection. Write access covers the secret
value only; the label, attributes and deleting the item stay with the
owner.

Deleting or moving the item, or resetting either scope, removes the grant.
If the owner locks the collection, the item disappears from the other
scope too. Grants are part of backups but not of export and import.

## The graphical front end

`scopevault-gui` is a GTK 4 window over `scopevault-admin --json`. It is a
host program only, never a Flatpak: the admin socket refuses sandboxed
callers, and an exception for one would be the weak point. It never sees a
password, since every password goes to the daemon's own dialog.

Labels and attributes come from apps, so the GUI treats them as untrusted:
it shows them as plain text only, never as markup, and replaces control
and bidirectional formatting characters so one label cannot pass for
another. Listing a locked vault would open the unlock dialog, so the GUI
asks for the status first.

## What scopevault does not protect against

- Host code running as your user, or root. It can read the daemon's
  memory, replace it, read the vault file and capture the password.
  Isolating Flatpak apps from each other is the point; hiding secrets from
  your own unsandboxed programs is not possible this way.
- Flatpak apps with permissions that escape the sandbox (see above).
- Rolling the vault file back to an older copy, and secrets surviving in
  old backups or snapshots. See [STORE.md](STORE.md).

## Compatibility notes

- libsecret reads all of the service's properties as soon as a client
  connects, so with a locked vault, merely connecting opens the dialog.
- `secret-tool lock` depends on the libsecret version: before 0.21.8 it
  takes a collection name rather than a path and can hang, and before
  0.21.3 it can crash.
- Collections created by libsecret are labelled "Default keyring", so
  their path is `/collection/default_keyring`. Clients reach them through
  the `default` alias.
- The bus must report `ProcessFD`. dbus-broker does. dbus-daemon only does
  from 1.15.8 on, and only when built where `SO_PEERPIDFD` is defined;
  openSUSE's `dbus-daemon` does not. On a bus without it every caller is
  refused.
- Tested with real Flatpak apps using their own credential code: MongoDB
  Compass (libsecret through Electron) and Cryptomator (its own Java
  client). Bitwarden could not be put through the private-bus test
  harness: it crashed there at startup, before talking to the daemon, so
  that test says nothing about it.
  Bitwarden uses the Secret portal and works with scopevault as the portal
  backend.
- gnome-keyring reports the generic schema for schema-less items only
  after reloading them from disk, so scopevault treats a missing schema
  and the generic one as the same when comparing items.
- Shortly after login, gnome-shell cannot show its password prompt yet and
  dismisses it, which pinentry reports as an ordinary cancel. The login
  unit (`scopevault-admin unlock --wait`) therefore reopens a dialog that
  was cancelled within five seconds.
- Some apps ask the portal for their key very often, Bitwarden about
  once a second, so successful portal requests are only logged at debug
  level to keep the journal readable.
