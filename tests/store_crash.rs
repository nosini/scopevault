//! The vault survives being killed mid-write.
//!
//! Kept in its own test binary: it spawns child processes, and a child
//! forked while another test drops a vault briefly inherits that vault's
//! `flock` descriptor (until exec), which makes parallel reopen tests flaky.

mod common;

use std::collections::BTreeMap;
use std::path::Path;

use common::tempdir::TempDir;
use scopevault::crypto::KdfParams;
use scopevault::identity::Principal;
use scopevault::store::{Secret, Vault};

const PW: &[u8] = b"correct horse battery staple";
const KDF: KdfParams = KdfParams::MINIMUM;

fn attrs(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

/// Child side of the crash test: writes items until killed.
#[test]
fn crash_writer_helper() {
    let Ok(dir) = std::env::var("SCOPEVAULT_TEST_CRASH_DIR") else { return };
    let mut v = Vault::open(Path::new(&dir)).unwrap();
    v.unlock(PW).unwrap();
    let mut s = v.scoped(&Principal::Host).unwrap();
    let c = s.collection_names()[0].clone();
    println!("READY");
    use std::io::Write;
    std::io::stdout().flush().unwrap();
    // Runs until the parent kills it.
    for i in 0..u64::MAX {
        s.create_item(
            &c,
            &format!("item {i}"),
            attrs(&[("i", &i.to_string())]),
            &Secret::new(vec![7u8; 4096], ""),
            false,
        )
        .unwrap();
    }
}

#[test]
fn survives_kill_during_writes() {
    use std::io::BufRead;
    let tmp = TempDir::new("store");
    let dir = tmp.path().join("vault");
    {
        let mut v = Vault::create(&dir, PW, KDF).unwrap();
        v.scoped(&Principal::Host).unwrap().create_collection("c", "").unwrap();
    }
    for round in 0..3 {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "crash_writer_helper", "--nocapture", "--test-threads=1"])
            .env("SCOPEVAULT_TEST_CRASH_DIR", &dir)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut out = std::io::BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        while !line.contains("READY") {
            line.clear();
            assert!(out.read_line(&mut line).unwrap() > 0, "writer exited early");
        }
        std::thread::sleep(std::time::Duration::from_millis(150 + 100 * round));
        child.kill().unwrap(); // SIGKILL mid-write
        child.wait().unwrap();

        let mut v = Vault::open(&dir).unwrap();
        v.unlock(PW).unwrap();
        let s = v.scoped(&Principal::Host).unwrap();
        let c = s.collection_names()[0].clone();
        let items = s.collection(&c).unwrap().items;
        assert!(!items.is_empty(), "round {round}: writer made no progress");
        for i in &items {
            assert_eq!(s.read_secret(&c, i).unwrap().value.len(), 4096);
        }
    }
}
