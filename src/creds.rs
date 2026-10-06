//! Resolving a stream key, and keeping it out of everything else.
//!
//! An RTMP publish URL is `rtmp://host/app/<key>`, so the key *is* the URL.
//! Anything that prints a URL prints the credential with it, and the obvious
//! places that happens are not ones a caller controls: ffmpeg writes the publish
//! URL into its stderr, and a panic or an I/O error will happily carry a URL in
//! its message.
//!
//! So the key is held apart from the host and app it belongs with. The relay
//! speaks RTMP itself, sends the key only in the publish request, and shows the
//! ingest as host and app alone. [`Redactor`] is for a caller that has to show
//! text which might contain the key, such as a child process's stderr.
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

/// Rewrites a secret out of text before it is shown.
///
/// For a caller that surfaces a child process's stderr. Swallowing ffmpeg's
/// output turns "ffmpeg refused the stream" into a report identical to "nothing
/// arrived", but ffmpeg prints the URL it was given, and a publish URL has the
/// key in it. Passing the output through here lets both hold.
#[derive(Clone)]
pub struct Redactor {
    secrets: Vec<String>,
}

/// What a redacted secret is replaced with.
pub const REDACTED: &str = "<redacted>";

impl Redactor {
    pub fn new() -> Self {
        Self {
            secrets: Vec::new(),
        }
    }

    /// Add a secret to strip. Short values are ignored: a two-character secret
    /// would match half the words in a log and redact the very message that
    /// explains what went wrong.
    pub fn hide(&mut self, secret: &str) -> &mut Self {
        if secret.len() >= 6 {
            self.secrets.push(secret.to_owned());
        }
        self
    }

    pub fn hide_key(&mut self, key: &StreamKey) -> &mut Self {
        self.hide(key.expose())
    }

    /// Replace every known secret in `text`.
    pub fn apply(&self, text: &str) -> String {
        let mut out = text.to_owned();
        for secret in &self.secrets {
            if out.contains(secret.as_str()) {
                out = out.replace(secret.as_str(), REDACTED);
            }
        }
        out
    }

    /// Print to stderr with the secrets removed. The one function child output
    /// should reach the console through.
    pub fn eprintln(&self, text: &str) {
        eprintln!("{}", self.apply(text));
    }
}

impl Default for Redactor {
    fn default() -> Self {
        Self::new()
    }
}

/// An RTMP publish target, held in pieces so the key is never sitting in a
/// string that something might decide to log.
#[derive(Clone)]
pub struct PublishTarget {
    pub host: String,
    pub app: String,
    key: StreamKey,
}

impl std::fmt::Debug for PublishTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Safe to print anywhere: everything but the key.
        write!(f, "rtmp://{}/{}/{REDACTED}", self.host, self.app)
    }
}

impl PublishTarget {
    pub fn new(host: impl Into<String>, app: impl Into<String>, key: StreamKey) -> Self {
        Self {
            host: host.into(),
            app: app.into(),
            key,
        }
    }

    /// The full URL. Composed here and nowhere else, and not to be stored,
    /// logged, or put in an error message.
    pub fn publish_url(&self) -> String {
        format!("rtmp://{}/{}/{}", self.host, self.app, self.key.expose())
    }

    /// The same target with the key removed, for anything a human will read.
    pub fn display_url(&self) -> String {
        format!("rtmp://{}/{}/{REDACTED}", self.host, self.app)
    }

    pub fn key(&self) -> &StreamKey {
        &self.key
    }

    /// A redactor primed with this target's key.
    pub fn redactor(&self) -> Redactor {
        let mut r = Redactor::new();
        r.hide_key(&self.key);
        r
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
    fn a_target_never_prints_its_key() {
        let target = PublishTarget::new(
            "ingest.example.net",
            "live",
            StreamKey::new("super-secret-key-value").unwrap(),
        );
        for shown in [format!("{target:?}"), target.display_url()] {
            assert!(!shown.contains("super-secret"), "leaked: {shown}");
            assert!(shown.contains("ingest.example.net"), "{shown}");
        }
        // The composed URL is the one place it appears, and only on request.
        assert!(target.publish_url().contains("super-secret-key-value"));
    }

    #[test]
    fn ffmpeg_style_output_is_scrubbed() {
        // The shape ffmpeg actually prints, which is how the key escaped before.
        let target = PublishTarget::new(
            "ingest.example.net",
            "live",
            StreamKey::new("super-secret-key-value").unwrap(),
        );
        let line = format!(
            "[rtmp @ 0000] Opening '{}' for writing",
            target.publish_url()
        );
        let scrubbed = target.redactor().apply(&line);
        assert!(!scrubbed.contains("super-secret-key-value"), "{scrubbed}");
        assert!(scrubbed.contains(REDACTED), "{scrubbed}");
        // The rest of the message survives, which is the point of redacting
        // rather than suppressing.
        assert!(scrubbed.contains("Opening"), "{scrubbed}");
        assert!(scrubbed.contains("ingest.example.net"), "{scrubbed}");
    }

    #[test]
    fn a_short_secret_is_not_redacted() {
        let mut r = Redactor::new();
        r.hide("abc");
        assert_eq!(
            r.apply("abc is a common substring"),
            "abc is a common substring"
        );
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
