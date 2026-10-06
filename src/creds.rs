//! Resolving a stream key, and keeping it out of everything else.
//!
//! An RTMP publish URL is `rtmp://host/app/<key>`, so the key *is* the URL.
//! Anything that prints a URL prints the credential with it, and a panic or an
//! I/O error will happily carry a URL in its message.
//!
//! So the key is held apart from the host and app it belongs with. The relay
//! speaks RTMP itself, sends the key only in the publish request, and shows the
//! ingest as host and app alone.
//!
//! # Where a key may come from
//!
//! In descending order of how much they can be trusted, and that is the order
//! [`StreamKey::resolve`] tries them in:
//!
//! 1. **A file**, or `-` for stdin. What a service should use: systemd's
//!    `LoadCredential=` puts the secret on a tmpfs readable only by the unit,
//!    and Docker and Compose secrets appear as files too. Nothing else on the
//!    machine can read it and it never enters the process table.
//! 2. **The OS credential store**: Credential Manager on Windows, Keychain on
//!    macOS, Secret Service on Linux. Not wired yet; the lookup always falls
//!    through (see `from_os_store`). Right for a desktop, but not available on
//!    a headless Linux box, so it cannot be the only route.
//! 3. **An environment variable**, `TRUSS_STREAM_KEY`. Convenient and weaker:
//!    on Linux the environment of a process is readable through `/proc`, and it
//!    lands in crash dumps.
//! 4. **A prompt**, when stdin is a terminal and nothing above resolved.
//!
//! **Not from a command-line argument.** That is visible in `ps`, in shell
//! history, and in the Windows process list, and it is visible to every other
//! user on the machine. There is no flag for it and adding one would undo the
//! rest of this.

use std::io::{IsTerminal, Read};

use anyhow::{Context, Result, bail};

/// Environment variable read when no file is given.
pub const ENV_VAR: &str = "TRUSS_STREAM_KEY";

/// A stream key, kept apart from the URL it belongs in.
///
/// There is deliberately no `Display`, no `Debug` that prints it, and no
/// `to_string`. Getting at the characters takes [`StreamKey::expose`], which is
/// named to be conspicuous at a call site and in review.
#[derive(Clone)]
pub struct StreamKey(String);

impl std::fmt::Debug for StreamKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Length only. Enough to tell "empty" from "present" while debugging a
        // resolution problem, without putting the value in a log.
        write!(f, "StreamKey(<{} chars>)", self.0.len())
    }
}

impl StreamKey {
    /// The key itself. Every call site is a place the credential can escape, so
    /// there should be few and they should be obvious.
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Take a key from a caller that already has one in hand.
    pub fn new(key: impl Into<String>) -> Result<Self> {
        let key = key.into().trim().to_owned();
        if key.is_empty() {
            bail!("stream key is empty");
        }
        // A key that arrived with a newline still attached composes a URL that
        // fails in a way that looks nothing like "your key has a newline in it".
        if key.contains(char::is_whitespace) {
            bail!("stream key contains whitespace, which a publish URL cannot carry");
        }
        Ok(Self(key))
    }

    /// Work through the sources in order and return the first that yields one.
    ///
    /// `file` is a path, or `-` for stdin. `service` and `account` name the
    /// entry in the OS credential store.
    pub fn resolve(file: Option<&str>, service: &str, account: &str) -> Result<Self> {
        if let Some(path) = file {
            return Self::from_file(path);
        }
        if let Some(key) = Self::from_os_store(service, account)? {
            return Ok(key);
        }
        if let Ok(value) = std::env::var(ENV_VAR) {
            return Self::new(value).with_context(|| format!("reading {ENV_VAR}"));
        }
        if std::io::stdin().is_terminal() {
            return Self::prompt();
        }
        bail!(
            "no stream key. Give --stream-key-file (or `-` for stdin), or set {ENV_VAR}. \
             There is deliberately no flag that takes the key itself: it would be visible \
             to anything that can list processes"
        )
    }

    fn from_file(path: &str) -> Result<Self> {
        let raw = if path == "-" {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .context("reading the stream key from stdin")?;
            buf
        } else {
            std::fs::read_to_string(path)
                .with_context(|| format!("reading the stream key from {path}"))?
        };
        Self::new(raw).with_context(|| format!("stream key from {path}"))
    }

    /// The OS credential store, when one is reachable.
    ///
    /// A missing entry and an unreachable store are both `Ok(None)`: on a
    /// headless Linux box there is usually no Secret Service to talk to, and
    /// that is an ordinary situation to fall through rather than an error to
    /// report at the caller.
    fn from_os_store(_service: &str, _account: &str) -> Result<Option<Self>> {
        // Deliberately not wired for the first release. The file and stdin route
        // is what a server needs and it works everywhere; the credential store
        // is desktop convenience on top. Wiring it means a dependency whose
        // Linux backend needs a session bus, so it wants its own change with its
        // own testing on a headless box rather than riding along here.
        Ok(None)
    }

    fn prompt() -> Result<Self> {
        eprint!("Stream key: ");
        let mut buf = String::new();
        std::io::stdin()
            .read_line(&mut buf)
            .context("reading the stream key from the terminal")?;
        eprintln!();
        Self::new(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_never_prints_itself() {
        let key = StreamKey::new("super-secret-key-value").unwrap();
        let shown = format!("{key:?}");
        assert!(
            !shown.contains("super-secret"),
            "Debug leaked the key: {shown}"
        );
        assert!(shown.contains("22 chars"), "{shown}");
    }

    #[test]
    fn whitespace_in_a_key_is_refused_rather_than_carried() {
        // A key read from a file arrives with a trailing newline, which trims.
        assert!(StreamKey::new("abc123def\n").is_ok());
        // One with a space in the middle would compose a broken URL, and the
        // failure would look nothing like its cause.
        assert!(StreamKey::new("abc 123").is_err());
        assert!(StreamKey::new("   ").is_err());
    }
}
