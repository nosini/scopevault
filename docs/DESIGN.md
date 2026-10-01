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

`host` is shared on purpose. Host programs can read each other's memory and
files anyway, so separating them in the keyring would only break things
that work today without making anything safer.

A Flatpak app ID names an installed app, not its publisher. An update keeps
the scope. A different program installed later under the same ID inherits
it, unless the scope is reset. Uninstalling an app does not delete its
secrets.

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

## What scopevault does not protect against

- Host code running as your user, or root. It can read the daemon's
  memory, replace it, read the vault file and capture the password.
  Isolating Flatpak apps from each other is the point; hiding secrets from
  your own unsandboxed programs is not possible this way.
- Flatpak apps with permissions that escape the sandbox (see above).
- Rolling the vault file back to an older copy, and secrets surviving in
  old backups or snapshots. See [STORE.md](STORE.md).
