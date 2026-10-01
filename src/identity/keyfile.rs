//! Strict parser for the GKeyFile subset Flatpak writes to `.flatpak-info`.
//!
//! The file is produced by `g_key_file_save_to_file()`, so a well-formed
//! instance never contains duplicate groups or keys, continuation lines or
//! stray text. Anything outside that subset is rejected instead of being
//! interpreted the way GLib's more forgiving parser would.

use std::collections::BTreeMap;

/// Upper bound for files we are willing to parse. Real `.flatpak-info`
/// files are a few KiB.
pub const MAX_KEYFILE_SIZE: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyFileError {
    #[error("key file exceeds {MAX_KEYFILE_SIZE} bytes")]
    TooLarge,
    #[error("key file is not valid UTF-8")]
    NotUtf8,
    #[error("key file contains a NUL byte")]
    Nul,
    #[error("line {0}: key outside any group")]
    KeyOutsideGroup(usize),
    #[error("line {0}: malformed group header")]
    BadGroup(usize),
    #[error("line {0}: duplicate group")]
    DuplicateGroup(usize),
    #[error("line {0}: malformed key")]
    BadKey(usize),
    #[error("line {0}: duplicate key")]
    DuplicateKey(usize),
    #[error("line {0}: invalid escape sequence")]
    BadEscape(usize),
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct KeyFile {
    groups: BTreeMap<String, BTreeMap<String, String>>,
}

impl KeyFile {
    pub fn parse(data: &[u8]) -> Result<Self, KeyFileError> {
        if data.len() > MAX_KEYFILE_SIZE {
            return Err(KeyFileError::TooLarge);
        }
        if data.contains(&0) {
            return Err(KeyFileError::Nul);
        }
        let text = std::str::from_utf8(data).map_err(|_| KeyFileError::NotUtf8)?;

        let mut groups: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
        let mut current: Option<String> = None;

        for (idx, raw) in text.lines().enumerate() {
            let lineno = idx + 1;
            let line = raw.trim_start_matches([' ', '\t']);
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(rest) = line.strip_prefix('[') {
                let name = rest.strip_suffix(']').ok_or(KeyFileError::BadGroup(lineno))?;
                if name.is_empty() || name.contains(['[', ']']) || name.chars().any(char::is_control) {
                    return Err(KeyFileError::BadGroup(lineno));
                }
                if groups.contains_key(name) {
                    return Err(KeyFileError::DuplicateGroup(lineno));
                }
                groups.insert(name.to_owned(), BTreeMap::new());
                current = Some(name.to_owned());
                continue;
            }

            let group = current.as_ref().ok_or(KeyFileError::KeyOutsideGroup(lineno))?;
            let (key, value) = line.split_once('=').ok_or(KeyFileError::BadKey(lineno))?;
            let key = key.trim_end_matches([' ', '\t']);
            if !is_valid_key(key) {
                return Err(KeyFileError::BadKey(lineno));
            }
            let value = unescape(value.trim_start_matches([' ', '\t']), lineno)?;
            let entries = groups.get_mut(group).expect("current group exists");
            if entries.insert(key.to_owned(), value).is_some() {
                return Err(KeyFileError::DuplicateKey(lineno));
            }
        }

        Ok(KeyFile { groups })
    }

    pub fn has_group(&self, group: &str) -> bool {
        self.groups.contains_key(group)
    }

    /// Raw (unescaped) string value.
    pub fn get(&self, group: &str, key: &str) -> Option<&str> {
        self.groups.get(group)?.get(key).map(String::as_str)
    }

    /// A `;`-separated list value. Escaped separators were already resolved
    /// by [`unescape`], so this splits on the separator byte GLib writes.
    pub fn get_list(&self, group: &str, key: &str) -> Vec<String> {
        match self.get(group, key) {
            None => Vec::new(),
            Some(v) => split_list(v),
        }
    }

    pub fn keys(&self, group: &str) -> impl Iterator<Item = (&str, &str)> {
        self.groups.get(group).into_iter().flat_map(|g| g.iter().map(|(k, v)| (k.as_str(), v.as_str())))
    }
}

fn is_valid_key(key: &str) -> bool {
    // GLib allows locale suffixes like `Name[de]`; Flatpak does not write
    // them into .flatpak-info, but they are harmless to accept as opaque keys.
    !key.is_empty() && !key.starts_with('[') && key.chars().all(|c| !c.is_control() && !c.is_whitespace() && c != '=')
}

/// Resolves GKeyFile escapes. `\;` is kept as a private marker so list
/// splitting can distinguish escaped separators; [`split_list`] restores it.
fn unescape(value: &str, lineno: usize) -> Result<String, KeyFileError> {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('s') => out.push(' '),
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('\\') => out.push('\\'),
            Some(';') => out.push(ESCAPED_SEMICOLON),
            _ => return Err(KeyFileError::BadEscape(lineno)),
        }
    }
    Ok(out)
}

/// U+FDD0 is a Unicode noncharacter; it never appears in valid Flatpak
/// metadata, so it is safe as an internal placeholder for `\;`.
const ESCAPED_SEMICOLON: char = '\u{FDD0}';

fn split_list(value: &str) -> Vec<String> {
    value.split(';').filter(|s| !s.is_empty()).map(|s| s.replace(ESCAPED_SEMICOLON, ";")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
[Application]
name=org.example.App
runtime=runtime/org.gnome.Platform/x86_64/49

[Instance]
instance-id=1234567890
session-bus-proxy=true

[Context]
shared=network;ipc;
sockets=x11;wayland;
filesystems=xdg-download;~/My\\sFiles;

[Session Bus Policy]
org.freedesktop.secrets=talk
";

    #[test]
    fn parses_flatpak_info() {
        let kf = KeyFile::parse(SAMPLE.as_bytes()).unwrap();
        assert_eq!(kf.get("Application", "name"), Some("org.example.App"));
        assert_eq!(kf.get("Instance", "instance-id"), Some("1234567890"));
        assert_eq!(kf.get_list("Context", "shared"), vec!["network", "ipc"]);
        assert_eq!(kf.get_list("Context", "filesystems"), vec!["xdg-download", "~/My Files"]);
        assert_eq!(kf.get("Session Bus Policy", "org.freedesktop.secrets"), Some("talk"));
    }

    #[test]
    fn escaped_semicolon_is_not_a_separator() {
        let kf = KeyFile::parse(b"[G]\nk=a\\;b;c;\n").unwrap();
        assert_eq!(kf.get_list("G", "k"), vec!["a;b", "c"]);
    }

    #[test]
    fn rejects_ambiguous_input() {
        for bad in [
            &b"name=x\n"[..],
            b"[A]\n[A]\n",
            b"[A]\nk=1\nk=2\n",
            b"[A\nk=1\n",
            b"[A]\nnot a key value\n",
            b"[A]\nk=\\x\n",
            b"[A]\nk=a\0b\n",
            b"[A]\nk=\xff\n",
            b"[A]\n=v\n",
        ] {
            assert!(KeyFile::parse(bad).is_err(), "accepted {:?}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn rejects_oversized() {
        let big = vec![b'#'; MAX_KEYFILE_SIZE + 1];
        assert_eq!(KeyFile::parse(&big), Err(KeyFileError::TooLarge));
    }
}
