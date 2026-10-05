"""Exercises scopevault-daemon with the Python `secretstorage` library, an
independent Secret Service client (pure Python on jeepney; negotiates the
dh-ietf1024-sha256-aes128-cbc-pkcs7 session).

Run by scripts/interop-secretstorage.sh in two phases against one vault:

  store  first daemon run: creates the vault and items, edits, locks and
         unlocks a collection, uses the session collection
  read   after a daemon restart (vault locked): reads the items back

Prints "PASS <phase>" on success; any failure raises.
"""

import sys
import time

import secretstorage
from jeepney import DBusAddress, new_method_call
from secretstorage.exceptions import ItemNotFoundException, LockedException

BINARY = bytes(range(256))
UNICODE = "pässwörd 🔑 ünïcödé".encode()
ATTRS = {"application": "scopevault-interop"}


def wait_for_service(conn, timeout=15.0):
    bus = DBusAddress("/org/freedesktop/DBus", bus_name="org.freedesktop.DBus",
                      interface="org.freedesktop.DBus")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        reply = conn.send_and_get_reply(new_method_call(bus, "NameHasOwner", "s",
                                                        ("org.freedesktop.secrets",)))
        if reply.body[0]:
            return
        time.sleep(0.1)
    raise SystemExit("daemon did not take org.freedesktop.secrets")


def by_kind(items):
    return {i.get_attributes()["kind"]: i for i in items}


def read_alias(conn, alias):
    service = DBusAddress("/org/freedesktop/secrets", bus_name="org.freedesktop.secrets",
                          interface="org.freedesktop.Secret.Service")
    return conn.send_and_get_reply(new_method_call(service, "ReadAlias", "s", (alias,))).body[0]


def store(conn):
    # No vault yet: reading the default alias opens the creation dialog. The
    # new vault has a collection behind the alias, which secretstorage then
    # uses through the alias path.
    col = secretstorage.get_default_collection(conn)
    target = read_alias(conn, "default")
    assert target.startswith("/org/freedesktop/secrets/collection/"), target
    assert col.collection_path in (target, "/org/freedesktop/secrets/aliases/default"), col.collection_path
    assert not col.is_locked()

    col.create_item("binary", {**ATTRS, "kind": "binary"}, BINARY, content_type="application/octet-stream")
    col.create_item("Ünïcödé label", {**ATTRS, "kind": "unicode"}, UNICODE)
    col.create_item("empty", {**ATTRS, "kind": "empty"}, b"")
    gone = col.create_item("to delete", {**ATTRS, "kind": "gone"}, b"bye")

    items = by_kind(secretstorage.search_items(conn, ATTRS))
    assert set(items) == {"binary", "unicode", "empty", "gone"}, items
    assert items["binary"].get_secret() == BINARY
    assert items["binary"].get_secret_content_type() == "application/octet-stream"
    assert items["unicode"].get_secret() == UNICODE
    assert items["unicode"].get_label() == "Ünïcödé label"
    assert items["empty"].get_secret() == b""

    # Replace by identical attributes (replace=True) keeps one item.
    col.create_item("empty", {**ATTRS, "kind": "empty"}, b"", replace=True)
    assert len(list(col.search_items({"kind": "empty"}))) == 1

    # Edits.
    e = items["empty"]
    e.set_label("renamed")
    e.set_attributes({**ATTRS, "kind": "empty", "extra": "1"})
    e.set_secret(b"no longer empty")
    assert e.get_label() == "renamed"
    assert e.get_attributes()["extra"] == "1"
    assert e.get_secret() == b"no longer empty"
    e.set_secret(b"")

    gone.delete()
    assert not list(col.search_items({"kind": "gone"}))

    # Logical lock; unlocking it again asks for the password.
    col.lock()
    assert col.is_locked() and items["binary"].is_locked()
    try:
        items["binary"].get_secret()
        raise AssertionError("read from a locked collection")
    except LockedException:
        pass
    assert col.unlock() is False, "unlock prompt was dismissed"
    assert not col.is_locked()
    assert items["binary"].get_secret() == BINARY

    # The session collection exists in memory only.
    temp = secretstorage.create_collection(conn, "Temporary", "session")
    temp.create_item("temp", {**ATTRS, "kind": "temp"}, b"temporary")
    assert [i.get_secret() for i in temp.search_items({"kind": "temp"})] == [b"temporary"]


def read(conn):
    # The vault is locked after the restart; searching opens the dialog.
    items = by_kind(secretstorage.search_items(conn, ATTRS))
    assert set(items) == {"binary", "unicode", "empty"}, sorted(items)
    assert items["binary"].get_secret() == BINARY
    assert items["unicode"].get_secret() == UNICODE
    assert items["empty"].get_secret() == b""
    assert items["empty"].get_label() == "renamed"
    try:
        secretstorage.get_collection_by_alias(conn, "session")
        raise AssertionError("session collection survived a restart")
    except ItemNotFoundException:
        pass
    col = secretstorage.get_default_collection(conn)
    col.delete()
    assert not list(secretstorage.search_items(conn, ATTRS))


def main():
    phase = sys.argv[1]
    conn = secretstorage.dbus_init()
    wait_for_service(conn)
    {"store": store, "read": read}[phase](conn)
    print(f"PASS {phase}")


if __name__ == "__main__":
    main()
