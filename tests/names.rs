//! The project's D-Bus names are spelled out outside the Rust code too: in
//! the packaging files, the GUI and the shell scripts. These must all agree
//! with `DBUS_PREFIX`.

use std::path::Path;

use scopevault::DBUS_PREFIX;
use scopevault::portal_backend::BACKEND_NAME;

fn read(path: &str) -> String {
    let full = Path::new(env!("CARGO_MANIFEST_DIR")).join(path);
    std::fs::read_to_string(&full).unwrap_or_else(|e| panic!("cannot read {}: {e}", full.display()))
}

#[test]
fn the_portal_activation_file_is_named_after_the_backend() {
    let file = read(&format!("packaging/{BACKEND_NAME}.service"));
    assert!(file.lines().any(|l| l == format!("Name={BACKEND_NAME}")), "Name= is not {BACKEND_NAME}");
}

#[test]
fn the_desktop_entry_is_named_after_the_gui_application_id() {
    read(&format!("packaging/{DBUS_PREFIX}.desktop"));
    let gui = read("gui/scopevault-gui");
    assert!(gui.lines().any(|l| l == format!("APP_ID = \"{DBUS_PREFIX}\"")), "the GUI's APP_ID is not {DBUS_PREFIX}");
}

#[test]
fn the_scripts_use_the_prefix() {
    let names = read("scripts/names.sh");
    assert!(names.lines().any(|l| l == format!("prefix={DBUS_PREFIX}")), "scripts/names.sh has another prefix");
}
