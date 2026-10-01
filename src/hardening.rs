//! Process hardening for the daemon and the admin tool.
//!
//! - umask 077, so every file the process creates is private;
//! - no core dumps (`RLIMIT_CORE` = 0, both limits);
//! - not dumpable: other processes of the same user can no longer ptrace
//!   this one or read its memory through `/proc/<pid>/mem`, and its
//!   `/proc/<pid>` entries become owned by root.
//!
//! This does not keep secrets out of swap and does not stop root. Call it
//! after capturing the identity baseline and before handling any secret.

use rustix::fs::Mode;
use rustix::process::{DumpableBehavior, Resource, Rlimit};

pub fn harden_process() -> std::io::Result<()> {
    rustix::process::umask(Mode::RWXG | Mode::RWXO);
    rustix::process::setrlimit(Resource::Core, Rlimit { current: Some(0), maximum: Some(0) })?;
    rustix::process::set_dumpable_behavior(DumpableBehavior::NotDumpable)?;
    Ok(())
}
