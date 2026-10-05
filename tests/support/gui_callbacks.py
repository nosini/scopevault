"""The GUI's request ordering, without GTK.

Loads gui/scopevault-gui with a stand-in for `gi`, builds a Window without
its widgets, and answers its scopevault-admin requests in a chosen order.
Run by tests/gui.rs; prints what failed and exits non-zero.
"""

import importlib.machinery
import importlib.util
import pathlib
import sys
import types
from collections.abc import Callable
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[2]


class Anything:
    """Any attribute, call or subclass; stands in for GTK objects."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        pass

    def __getattr__(self, name: str) -> Any:
        return Anything()

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return Anything()

    def __or__(self, other: Any) -> Any:
        return Anything()


class Namespace(types.ModuleType):
    def __getattr__(self, name: str) -> Any:
        return type(name, (Anything,), {})


def load_gui() -> Any:
    # No __pycache__ next to the GUI.
    sys.dont_write_bytecode = True
    gi = types.ModuleType("gi")
    gi.require_version = lambda *_: None  # type: ignore[attr-defined]
    repository = types.ModuleType("gi.repository")
    for name in ["Adw", "Gio", "GLib", "Gtk", "Pango"]:
        setattr(repository, name, Namespace(name))
    gi.repository = repository  # type: ignore[attr-defined]
    sys.modules["gi"] = gi
    sys.modules["gi.repository"] = repository
    loader = importlib.machinery.SourceFileLoader("scopevault_gui", str(ROOT / "gui" / "scopevault-gui"))
    spec = importlib.util.spec_from_loader("scopevault_gui", loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class FakeAdmin:
    """Records requests; the test answers them in any order."""

    program = "scopevault-admin"

    def __init__(self) -> None:
        self.sent: list[str] = []
        self.pending: list[tuple[str, Callable[[dict[str, Any]], None]]] = []

    def run(self, args: list[str], done: Callable[[dict[str, Any]], None]) -> None:
        self.sent.append(args[0])
        self.pending.append((args[0], done))

    def answer(self, command: str, reply: dict[str, Any]) -> None:
        for i, (c, done) in enumerate(self.pending):
            if c == command:
                del self.pending[i]
                done(reply)
                return
        raise AssertionError(f"no {command} request is waiting; sent so far: {self.sent}")


def window(gui: Any) -> tuple[Any, FakeAdmin]:
    w = gui.Window.__new__(gui.Window)
    admin = FakeAdmin()
    state: dict[str, Any] = {
        "admin": admin,
        "status": None,
        "scopes": [],
        "grants": [],
        "selected": "host",
        "listing": None,
        "checked": set(),
        "busy": False,
        "generation": 0,
        "refreshing": False,
        "refresh_again": False,
        "listing_for": None,
        "listing_stale": False,
        "rebuilding": False,
        "banner": Anything(),
        "scopes_outer": Anything(),
        "scope_stack": Anything(),
        "scope_message": Anything(),
    }
    for k, v in state.items():
        setattr(w, k, v)

    def show_status(reply: dict[str, Any]) -> None:
        w.status = None if reply.get("reply") == "error" else reply

    w.show_status = show_status
    for name in ["show_scopes", "show_grants", "show_listing", "update_actions", "toast", "fail", "set_message"]:
        setattr(w, name, lambda *_: None)
    return w, admin


UNLOCKED = {"reply": "status", "vault": "unlocked"}
LOCKED = {"reply": "status", "vault": "locked"}
SCOPES = {"reply": "scopes", "scopes": []}
LOCK_DONE = {"reply": "done", "message": "locked"}


def lock_finishes_while_scopes_are_read(gui: Any) -> list[str]:
    w, admin = window(gui)
    w.refresh()
    admin.answer("status", UNLOCKED)
    w.do_lock()
    admin.answer("lock", LOCK_DONE)
    admin.answer("scopes", SCOPES)
    # The vault is locked now: only a fresh status may follow.
    admin.answer("status", LOCKED)
    return admin.sent


def scopes_arrive_while_the_lock_runs(gui: Any) -> list[str]:
    w, admin = window(gui)
    w.refresh()
    admin.answer("status", UNLOCKED)
    w.do_lock()
    admin.answer("scopes", SCOPES)
    admin.answer("lock", LOCK_DONE)
    admin.answer("status", LOCKED)
    return admin.sent


def an_unlocked_vault_is_still_listed(gui: Any) -> list[str]:
    w, admin = window(gui)
    w.refresh()
    admin.answer("status", UNLOCKED)
    admin.answer("scopes", SCOPES)
    admin.answer("grants", {"reply": "grants", "grants": []})
    admin.answer("list", {"reply": "list", "collections": []})
    return admin.sent


def main() -> int:
    gui = load_gui()
    expected = {
        lock_finishes_while_scopes_are_read: ["status", "scopes", "lock", "status"],
        scopes_arrive_while_the_lock_runs: ["status", "scopes", "lock", "status"],
        an_unlocked_vault_is_still_listed: ["status", "scopes", "grants", "list"],
    }
    failed = 0
    for case, want in expected.items():
        try:
            got = case(gui)
        except AssertionError as e:
            got = [f"error: {e}"]
        if got != want:
            failed += 1
            print(f"FAIL {case.__name__}: sent {got}, expected {want}")
        else:
            print(f"ok   {case.__name__}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
