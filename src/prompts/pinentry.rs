//! Asking the user for a password through pinentry.
//!
//! pinentry is GnuPG's password dialog (`pinentry-gnome3` on GNOME uses the
//! system prompt). The daemon starts it as a child process and talks the
//! Assuan protocol over the child's stdin and stdout, so the password
//! travels only over a pipe between the two processes: never through the
//! requesting application, the bus, the command line or the environment.
//!
//! Text shown in the dialog comes from the daemon. Application-supplied
//! strings (labels, window IDs) are never shown; the only per-request text
//! is the caller's scope, which comes from identification.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use zeroize::Zeroizing;

/// Assuan lines are at most 1000 bytes; allow some slack, then fail.
const MAX_LINE: usize = 4096;
/// GPG_ERR_CANCELED (99) and GPG_ERR_TIMEOUT (62), in the low 16 bits.
const ERR_CANCELED: u32 = 99;
const ERR_TIMEOUT: u32 = 62;

#[derive(Debug, Clone)]
pub struct PinentryConfig {
    pub program: PathBuf,
    /// How long the dialog may stay open.
    pub timeout: Duration,
}

impl Default for PinentryConfig {
    fn default() -> Self {
        PinentryConfig { program: "pinentry".into(), timeout: Duration::from_secs(300) }
    }
}

/// What to show. All strings come from the daemon.
#[derive(Debug, Clone, Default)]
pub struct PinRequest {
    pub title: String,
    pub description: String,
    pub prompt: String,
    /// Shown above the entry field, e.g. after a wrong password.
    pub error: Option<String>,
    /// Ask twice and require both entries to match (new passwords).
    pub repeat: Option<String>,
}

pub enum PinOutcome {
    Entered(Zeroizing<String>),
    Cancelled,
}

impl std::fmt::Debug for PinOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PinOutcome::Entered(_) => f.write_str("Entered(<redacted>)"),
            PinOutcome::Cancelled => f.write_str("Cancelled"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PinentryError {
    #[error("cannot start pinentry ({0}): {1}")]
    Spawn(String, std::io::Error),
    #[error("pinentry I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("pinentry protocol error: {0}")]
    Protocol(String),
    #[error("pinentry did not answer in time")]
    Timeout,
}

/// Percent-encodes what Assuan requires (`%`, CR, LF) and drops other
/// control characters.
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '%' => out.push_str("%25"),
            '\n' => out.push_str("%0A"),
            '\r' => out.push_str("%0D"),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out.truncate(900);
    out
}

/// Decodes `%XX` escapes into `out`.
fn unescape_into(data: &[u8], out: &mut Zeroizing<Vec<u8>>) -> Result<(), PinentryError> {
    let mut i = 0;
    while i < data.len() {
        if data[i] == b'%' {
            let hex = data.get(i + 1..i + 3).ok_or_else(|| PinentryError::Protocol("truncated escape".into()))?;
            let s = std::str::from_utf8(hex).map_err(|_| PinentryError::Protocol("bad escape".into()))?;
            out.push(u8::from_str_radix(s, 16).map_err(|_| PinentryError::Protocol("bad escape".into()))?);
            i += 3;
        } else {
            out.push(data[i]);
            i += 1;
        }
    }
    Ok(())
}

enum Reply {
    Ok,
    Err(u32, String),
}

struct Session {
    _child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
}

impl Session {
    /// Reads one line into a zeroizing buffer, byte by byte, so password
    /// data never sits in a buffer we cannot wipe.
    async fn line(&mut self) -> Result<Zeroizing<Vec<u8>>, PinentryError> {
        let mut line = Zeroizing::new(Vec::with_capacity(128));
        loop {
            let b = self.stdout.read_u8().await.map_err(|e| match e.kind() {
                std::io::ErrorKind::UnexpectedEof => PinentryError::Protocol("pinentry exited".into()),
                _ => PinentryError::Io(e),
            })?;
            if b == b'\n' {
                return Ok(line);
            }
            if line.len() >= MAX_LINE {
                return Err(PinentryError::Protocol("line too long".into()));
            }
            line.push(b);
        }
    }

    /// Waits for the final OK/ERR, collecting `D` lines into `data`.
    async fn reply(&mut self, mut data: Option<&mut Zeroizing<Vec<u8>>>) -> Result<Reply, PinentryError> {
        loop {
            let line = self.line().await?;
            if line.starts_with(b"OK") {
                return Ok(Reply::Ok);
            }
            if let Some(rest) = line.strip_prefix(b"ERR ") {
                let text = String::from_utf8_lossy(rest);
                let code = text.split_whitespace().next().and_then(|c| c.parse::<u32>().ok()).unwrap_or(0);
                return Ok(Reply::Err(code & 0xffff, text.into_owned()));
            }
            if let Some(rest) = line.strip_prefix(b"D ") {
                match data.as_deref_mut() {
                    Some(buf) => unescape_into(rest, buf)?,
                    None => return Err(PinentryError::Protocol("unexpected data".into())),
                }
                continue;
            }
            if line.starts_with(b"S ") || line.starts_with(b"#") || line.is_empty() {
                continue;
            }
            // INQUIRE and anything else are not part of this exchange.
            return Err(PinentryError::Protocol("unexpected response".into()));
        }
    }

    async fn command(&mut self, cmd: &str) -> Result<Reply, PinentryError> {
        self.stdin.write_all(cmd.as_bytes()).await?;
        self.stdin.write_all(b"\n").await?;
        self.stdin.flush().await?;
        self.reply(None).await
    }

    async fn set(&mut self, cmd: &str, value: &str) -> Result<(), PinentryError> {
        match self.command(&format!("{cmd} {}", escape(value))).await? {
            Reply::Ok => Ok(()),
            Reply::Err(_, text) => Err(PinentryError::Protocol(format!("{cmd} refused: {text}"))),
        }
    }
}

async fn run(config: &PinentryConfig, req: &PinRequest) -> Result<PinOutcome, PinentryError> {
    let mut child = Command::new(&config.program)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| PinentryError::Spawn(config.program.display().to_string(), e))?;
    let stdin = child.stdin.take().expect("piped");
    let stdout = child.stdout.take().expect("piped");
    let mut s = Session { _child: child, stdin, stdout };

    if !matches!(s.reply(None).await?, Reply::Ok) {
        return Err(PinentryError::Protocol("no greeting".into()));
    }
    s.set("SETTITLE", &req.title).await?;
    s.set("SETDESC", &req.description).await?;
    s.set("SETPROMPT", &req.prompt).await?;
    if let Some(err) = &req.error {
        s.set("SETERROR", err).await?;
    }
    if let Some(repeat) = &req.repeat {
        s.set("SETREPEAT", repeat).await?;
        s.set("SETREPEATERROR", "The passwords do not match").await?;
    }

    s.stdin.write_all(b"GETPIN\n").await?;
    s.stdin.flush().await?;
    let mut pin = Zeroizing::new(Vec::new());
    let outcome = match s.reply(Some(&mut pin)).await? {
        Reply::Ok => {
            // Validate in place: a conversion error would carry an
            // unzeroized copy of the bytes.
            let text =
                std::str::from_utf8(&pin).map_err(|_| PinentryError::Protocol("password is not UTF-8".into()))?;
            PinOutcome::Entered(Zeroizing::new(text.to_owned()))
        }
        Reply::Err(ERR_CANCELED | ERR_TIMEOUT, _) => PinOutcome::Cancelled,
        Reply::Err(_, text) => return Err(PinentryError::Protocol(format!("GETPIN failed: {text}"))),
    };
    let _ = s.stdin.write_all(b"BYE\n").await;
    Ok(outcome)
}

/// Shows one pinentry dialog. Dropping the returned future kills pinentry.
pub async fn ask(config: &PinentryConfig, req: &PinRequest) -> Result<PinOutcome, PinentryError> {
    tokio::time::timeout(config.timeout, run(config, req)).await.map_err(|_| PinentryError::Timeout)?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaping() {
        assert_eq!(escape("50% done\nnext\rx\u{7}"), "50%25 done%0Anext%0Dx");
        let mut out = Zeroizing::new(Vec::new());
        unescape_into(b"a%25b%0Ac", &mut out).unwrap();
        assert_eq!(&out[..], b"a%b\nc");
        assert!(unescape_into(b"%2", &mut Zeroizing::new(Vec::new())).is_err());
        assert!(unescape_into(b"%zz", &mut Zeroizing::new(Vec::new())).is_err());
    }
}
