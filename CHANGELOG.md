# Changelog

## 0.4.0

- Limits on request sizes, connections per app and repeatedly cancelled
  prompts.
- A request waiting for the unlock dialog is dropped when its client
  disconnects, together with everything the client had queued.
- Adversarial tests, fuzzing, and checks with real Flatpak sandboxes.

## 0.3.0

- The daemon: the complete Secret Service API on the encrypted vault,
  with plain and encrypted transfer sessions, prompts and per-collection
  locking.

## 0.2.0

- The encrypted vault: Argon2id and XChaCha20-Poly1305 in SQLite, with a
  pinentry password dialog.

## 0.1.0

- Identifying callers as a Flatpak app, a host program or neither, and
  routing Secret Service requests per scope.
