//! Process hardening takes effect (checked in a child process, so the test
//! runner itself is not altered).

#[test]
fn hardening_helper() {
    if std::env::var_os("SCOPEVAULT_TEST_HARDEN").is_none() {
        return;
    }
    scopevault::hardening::harden_process().unwrap();
    let dumpable = rustix::process::dumpable_behavior().unwrap();
    let core = rustix::process::getrlimit(rustix::process::Resource::Core);
    let umask = rustix::process::umask(rustix::fs::Mode::empty());
    println!("RESULT dumpable={dumpable:?} core={:?}/{:?} umask={:o}", core.current, core.maximum, umask.bits());
}

#[test]
fn hardening_applies() {
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "hardening_helper", "--nocapture", "--test-threads=1"])
        .env("SCOPEVAULT_TEST_HARDEN", "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout.lines().find_map(|l| l.split_once("RESULT ").map(|(_, r)| r)).expect("child result");
    assert_eq!(line, "dumpable=NotDumpable core=Some(0)/Some(0) umask=77");
}
