//! The GUI's request ordering (`tests/support/gui_callbacks.py`), run with
//! a stand-in for GTK so it needs only Python.

use std::process::Command;

#[test]
fn the_gui_reads_nothing_more_after_an_operation_started() {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/support/gui_callbacks.py");
    let out = Command::new("python3").arg(script).output().expect("python3 runs");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stdout}{stderr}");
}
