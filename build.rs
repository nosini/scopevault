//! Records the git commit the binaries are built from, for `--version` and
//! the daemon's startup log: the short hash, with `-dirty` if tracked files
//! differ from it, or `unknown` outside a git checkout. A package build from
//! a source tarball sets it in `SCOPEVAULT_COMMIT` instead.

use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

fn main() {
    println!("cargo:rerun-if-env-changed=SCOPEVAULT_COMMIT");
    if let Some(commit) = std::env::var("SCOPEVAULT_COMMIT").ok().filter(|c| !c.is_empty()) {
        println!("cargo:rustc-env=SCOPEVAULT_COMMIT={commit}");
        return;
    }
    let commit = match git(&["rev-parse", "--short=7", "HEAD"]) {
        Some(hash) => match git(&["status", "--porcelain", "--untracked-files=no"]) {
            Some(changes) if changes.is_empty() => hash,
            _ => format!("{hash}-dirty"),
        },
        None => "unknown".to_owned(),
    };
    println!("cargo:rustc-env=SCOPEVAULT_COMMIT={commit}");

    // Run again when the commit or the sources change. Listing paths turns
    // off Cargo's default of rerunning on any change in the package.
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=src");
    let mut git_files = vec!["HEAD".to_owned(), "index".to_owned(), "packed-refs".to_owned()];
    if let Some(branch) = git(&["symbolic-ref", "-q", "HEAD"]) {
        git_files.push(branch);
    }
    for f in git_files {
        if let Some(path) = git(&["rev-parse", "--git-path", &f])
            && std::path::Path::new(&path).exists()
        {
            println!("cargo:rerun-if-changed={path}");
        }
    }
}
