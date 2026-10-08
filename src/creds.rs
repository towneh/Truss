//! Resolving a secret, and keeping it out of everything else.
//!
//! An RTMP publish URL is `rtmp://host/app/<key>`, so the key *is* the URL.
//! Anything that prints a URL prints the credential with it, and a panic or an
//! I/O error will happily carry a URL in its message.
//!
//! So the key is held apart from the host and app it belongs with. The relay
//! speaks RTMP itself, sends the key only in the publish request, and shows the
//! ingest as host and app alone. An RTSP source's password is held the same
//! way and handed to the RTSP client alone, never put in its URL.
//!
//! # Where a secret may come from
//!
//! In descending order of how much they can be trusted, and that is the order
//! [`Secret::resolve`] tries them in:
//!
//! 1. **A file**, or `-` for stdin. What a service should use: systemd's
//!    `LoadCredential=` puts the secret on a tmpfs readable only by the unit,
//!    and Docker and Compose secrets appear as files too. Nothing else on the
//!    machine can read it and it never enters the process table.
//! 2. **The OS credential store**: Credential Manager on Windows, Keychain on
//!    macOS, Secret Service on Linux. Not wired yet; the lookup always falls
//!    through (see `from_os_store`). Right for a desktop, but not available on
//!    a headless Linux box, so it cannot be the only route.
//! 3. **An environment variable**, `TRUSS_STREAM_KEY` or
//!    `TRUSS_SOURCE_PASSWORD`. Convenient and weaker: on Linux the environment
//!    of a process is readable through `/proc`, and it lands in crash dumps.
//! 4. **A prompt**, when stdin is a terminal and nothing above resolved.
//!
//! **Not from a command-line argument.** That is visible in `ps`, in shell
//! history, and in the Windows process list, and it is visible to every other
//! user on the machine. There is no flag for it and adding one would undo the
//! rest of this.

use std::io::{IsTerminal, Read};

use anyhow::{Context, Result, bail};

/// One kind of secret: what it is called, and where it is looked for.
#[derive(Debug)]
pub struct Kind {
    /// What it is, in messages: "stream key".
    pub name: &'static str,
    /// The flag naming a file that holds it.
    pub flag: &'static str,
    /// The environment variable read when no file is given.
    pub env: &'static str,
    prompt: &'static str,
    /// Whether it goes into a URL, where whitespace cannot stand. A password
    /// is sent in an authorisation header and may have spaces in it.
    in_url: bool,
}

pub static STREAM_KEY: Kind = Kind {
    name: "stream key",
    flag: "--stream-key-file",
    env: "TRUSS_STREAM_KEY",
    prompt: "Stream key: ",
    in_url: true,
};

pub static SOURCE_PASSWORD: Kind = Kind {
    name: "source password",
    flag: "--source-password-file",
    env: "TRUSS_SOURCE_PASSWORD",
    prompt: "Source password: ",
    in_url: false,
};

/// A secret, kept apart from the URL it belongs with.
///
/// There is deliberately no `Display`, no `Debug` that prints it, and no
/// `to_string`. Getting at the characters takes [`Secret::expose`], which is
/// named to be conspicuous at a call site and in review.
#[derive(Clone)]
pub struct Secret {
    value: String,
    kind: &'static Kind,
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Length only. Enough to tell "empty" from "present" while debugging a
        // resolution problem, without putting the value in a log.
        write!(f, "{}(<{} chars>)", self.kind.name, self.value.len())
    }
}

impl Secret {
    /// The secret itself. Every call site is a place the credential can
    /// escape, so there should be few and they should be obvious.
    pub fn expose(&self) -> &str {
        &self.value
    }

    /// Take a secret from a caller that already has one in hand.
    pub fn new(kind: &'static Kind, value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        let name = kind.name;
        let value = if kind.in_url {
            value.trim()
        } else {
            value.trim_end_matches(['\r', '\n'])
        }
        .to_owned();
        if value.is_empty() {
            bail!("{name} is empty");
        }
        // A key that arrived with a newline still attached composes a URL that
        // fails in a way that looks nothing like "your key has a newline in it".
        if kind.in_url && value.contains(char::is_whitespace) {
            bail!("{name} contains whitespace, which a URL cannot carry");
        }
        Ok(Self { value, kind })
    }

    /// Work through the sources in order and return the first that yields one.
    ///
    /// `file` is a path, or `-` for stdin. `service` and `account` name the
    /// entry in the OS credential store.
    pub fn resolve(
        kind: &'static Kind,
        file: Option<&str>,
        service: &str,
        account: &str,
    ) -> Result<Self> {
        if let Some(path) = file {
            return Self::from_file(kind, path);
        }
        if let Some(secret) = Self::from_os_store(service, account)? {
            return Ok(secret);
        }
        if let Ok(value) = std::env::var(kind.env) {
            return Self::new(kind, value).with_context(|| format!("reading {}", kind.env));
        }
        if std::io::stdin().is_terminal() {
            return Self::prompt(kind);
        }
        bail!(
            "no {name}. Give {flag} (or `-` for stdin), or set {env}. There is deliberately \
             no flag that takes the {name} itself: it would be visible to anything that can \
             list processes",
            name = kind.name,
            flag = kind.flag,
            env = kind.env,
        )
    }

    fn from_file(kind: &'static Kind, path: &str) -> Result<Self> {
        let name = kind.name;
        let raw = if path == "-" {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .with_context(|| format!("reading the {name} from stdin"))?;
            buf
        } else {
            std::fs::read_to_string(path)
                .with_context(|| format!("reading the {name} from {path}"))?
        };
        Self::new(kind, raw).with_context(|| format!("{name} from {path}"))
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

    fn prompt(kind: &'static Kind) -> Result<Self> {
        eprint!("{}", kind.prompt);
        let mut buf = String::new();
        std::io::stdin()
            .read_line(&mut buf)
            .with_context(|| format!("reading the {} from the terminal", kind.name))?;
        eprintln!();
        Self::new(kind, buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_never_prints_itself() {
        for kind in [&STREAM_KEY, &SOURCE_PASSWORD] {
            let secret = Secret::new(kind, "super-secret-key-value").unwrap();
            let shown = format!("{secret:?}");
            assert!(
                !shown.contains("super-secret"),
                "Debug leaked the secret: {shown}"
            );
            assert!(shown.contains("22 chars"), "{shown}");
        }
    }

    #[test]
    fn whitespace_in_a_key_is_refused_rather_than_carried() {
        // A key read from a file arrives with a trailing newline, which trims.
        assert!(Secret::new(&STREAM_KEY, "abc123def\n").is_ok());
        // One with a space in the middle would compose a broken URL, and the
        // failure would look nothing like its cause.
        assert!(Secret::new(&STREAM_KEY, "abc 123").is_err());
        assert!(Secret::new(&STREAM_KEY, "   ").is_err());
    }

    #[test]
    fn a_password_loses_its_line_ending_and_nothing_else() {
        let password = Secret::new(&SOURCE_PASSWORD, " pass word \r\n").unwrap();
        assert_eq!(password.expose(), " pass word ");
        assert!(Secret::new(&SOURCE_PASSWORD, "\n").is_err());
    }
}
