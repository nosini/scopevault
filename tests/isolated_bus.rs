//! `tests/support/with-isolated-bus.sh`, the helper the interoperability
//! check runs in.

mod common;

use std::io::{BufRead as _, BufReader};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use common::tempdir::TempDir;

/// Processes whose command line mentions `needle`.
fn processes_mentioning(needle: &str) -> Vec<String> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir("/proc").unwrap().flatten() {
        let Ok(cmdline) = std::fs::read(entry.path().join("cmdline")) else { continue };
        let cmdline = String::from_utf8_lossy(&cmdline).replace('\0', " ");
        if cmdline.contains(needle) {
            found.push(format!("{}: {cmdline}", entry.file_name().to_string_lossy()));
        }
    }
    found
}

#[test]
fn a_terminated_helper_leaves_no_bus_behind() {
    let tmp = TempDir::new("isolated-bus");
    let mut helper = Command::new(common::support_script("with-isolated-bus.sh"))
        .args(["sh", "-c", "echo ready; exec sleep 30"])
        .env("TMPDIR", tmp.path())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(helper.stdout.take().unwrap()).read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "ready");
    let dirs: Vec<_> = std::fs::read_dir(tmp.path()).unwrap().flatten().map(|e| e.path()).collect();
    assert_eq!(dirs.len(), 1, "{dirs:?}");
    let dir = dirs[0].to_string_lossy().into_owned();
    assert!(!processes_mentioning(&dir).is_empty(), "the bus is not running");

    let pid = rustix::process::Pid::from_raw(helper.id() as i32).unwrap();
    rustix::process::kill_process(pid, rustix::process::Signal::TERM).unwrap();
    let started = Instant::now();
    helper.wait().unwrap();
    while started.elapsed() < Duration::from_secs(5)
        && (std::path::Path::new(&dir).exists() || !processes_mentioning(&dir).is_empty())
    {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(!std::path::Path::new(&dir).exists(), "{dir} is left behind");
    assert!(processes_mentioning(&dir).is_empty(), "still running: {:?}", processes_mentioning(&dir));
}
