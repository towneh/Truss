//! Pulling video from an RTSP source, for the relay's `--source`.
//!
//! RTSP is spoken by retina, which is async. The rest of the crate is not,
//! and stays that way: the source runs on one thread with its own runtime and
//! hands the relay ready-aligned access units over a channel.
//!
//! Nothing is sent until the streams' timelines are aligned on their RTCP
//! sender reports, once two in a row agree on each stream: a session started
//! soon after another on the same server can begin with a stale frame and a
//! stale report. After that, nothing goes out before a video keyframe, so the
//! publish starts on a picture that decodes.

mod session;
pub mod timing;

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Result, bail};
use tokio::sync::mpsc;

use crate::creds;

/// An RTSP source to pull from.
#[derive(Clone, Debug)]
pub struct Spec {
    url: url::Url,
    login: Option<Login>,
    audio: bool,
}

/// A user and password for a source that asks for them. Retina answers
/// Basic and Digest challenges with it; it never goes in the URL.
#[derive(Clone, Debug)]
pub struct Login {
    pub user: String,
    pub password: creds::Secret,
}

impl Spec {
    /// Read `--source`: `rtsp://host[:port]/path`, with `rtspt://` taken
    /// as a synonym. RTP always runs over the RTSP connection.
    ///
    /// No error quotes the URL. A query can carry a token, and a user and
    /// password are refused without being shown: an argument is visible to
    /// anything that can list processes, and so is an error that repeats it.
    pub fn parse(source: &str) -> Result<Self> {
        let Some((scheme, rest)) = source.trim().split_once("://") else {
            bail!(
                "--source is a URL: rtsp://host/path, with the port after the host when it is not 554"
            );
        };
        match scheme.to_ascii_lowercase().as_str() {
            "rtsp" | "rtspt" => {}
            "rtsps" => bail!("rtsps:// is not supported: the relay speaks plain RTSP"),
            _ => bail!("--source takes an rtsp:// URL"),
        }
        let Ok(url) = url::Url::parse(&format!("rtsp://{rest}")) else {
            bail!("--source is not a URL the relay can read");
        };
        if !url.username().is_empty() || url.password().is_some() {
            bail!(
                "--source carries a user and password, which the relay will not print or \
                 pass in a URL. Give the user with --source-user and the password with \
                 --source-password-file or TRUSS_SOURCE_PASSWORD"
            );
        }
        if url.host_str().is_none_or(str::is_empty) {
            bail!("--source names no host");
        }
        Ok(Self {
            url,
            login: None,
            audio: true,
        })
    }

    /// Leave the source's audio out, AAC included, for a publish of the
    /// picture alone. Audio is not set up, so it costs nothing to receive.
    pub fn without_audio(self) -> Self {
        Self {
            audio: false,
            ..self
        }
    }

    /// Log in to the source with `login` when it asks.
    pub fn with_login(self, login: Login) -> Self {
        Self {
            login: Some(login),
            ..self
        }
    }

    /// The URL to show: scheme, host, port and path, nothing after them.
    pub fn display(&self) -> String {
        let mut shown = format!("rtsp://{}", self.url.host_str().unwrap_or(""));
        if let Some(port) = self.url.port() {
            shown.push_str(&format!(":{port}"));
        }
        shown.push_str(self.url.path());
        shown
    }
}

/// What the source sends the relay.
#[derive(Debug)]
pub enum SourceEvent {
    /// The source moved on; shown on the panel and logged.
    State(SourceState),
    /// Something the operator should know, logged once.
    Note(String),
    /// The video's parameters: before the first frame and whenever they
    /// change. `avcc` is the AVCDecoderConfigurationRecord.
    Video {
        avcc: Vec<u8>,
        width: u32,
        height: u32,
        fps: Option<f64>,
    },
    /// The audio's parameters, before its first frame. `asc` is the
    /// AudioSpecificConfig.
    Audio {
        asc: Vec<u8>,
        sample_rate: u32,
        channels: u16,
    },
    /// One H.264 access unit, NAL units with 4-byte lengths, at its
    /// presentation time on the aligned timeline.
    VideoFrame {
        data: Vec<u8>,
        pts_us: i64,
        key: bool,
    },
    /// One raw AAC frame on the same timeline.
    AudioFrame { data: Vec<u8>, pts_us: i64 },
    /// The session ended, and why. The source reconnects, and the next
    /// frames start a timeline of their own, after fresh parameters.
    Lost(String),
    /// The quick reconnects have all failed. Attempts carry on every
    /// [`RECONNECT_CAP`] or so; the relay closes its publish until one plays.
    Down,
    /// The source refused the login, or asked for one the relay was not
    /// given. Nothing more is tried: the same password cannot succeed, and a
    /// camera that counts failed logins would lock the account.
    Refused(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceState {
    Connecting,
    /// Playing, waiting for sender reports to agree.
    Aligning,
    WaitingForKeyframe,
    Relaying,
    /// Waiting to try again after a session ended.
    Retrying {
        attempt: u32,
    },
    /// Past the quick reconnects, trying every [`RECONNECT_CAP`] or so.
    Down,
}

impl SourceState {
    pub fn describe(self) -> String {
        match self {
            Self::Connecting => "connecting".into(),
            Self::Aligning => "aligning on sender reports".into(),
            Self::WaitingForKeyframe => "waiting for a keyframe".into(),
            Self::Relaying => "relaying".into(),
            Self::Retrying { attempt } => {
                format!("reconnecting, attempt {attempt} of {RECONNECT_ATTEMPTS}")
            }
            Self::Down => format!("down, retrying every {}s", RECONNECT_CAP.as_secs()),
        }
    }
}

/// Reconnects tried quickly after a session ends, before the source is
/// declared down, after waits of 0.5, 1, 2, 4, 8 and 8 s: about 24 s of
/// waiting, as the Basis media player does, plus whatever the attempts take.
pub const RECONNECT_ATTEMPTS: u32 = 6;
const RECONNECT_BASE: Duration = Duration::from_millis(500);
/// The longest wait between attempts, and the pace once the source is down.
pub const RECONNECT_CAP: Duration = Duration::from_secs(8);

/// The wait before reconnect `attempt` (from 1). `jitter` in [0, 1) spreads
/// it by 25 % either way, so relays that lost the same server do not all
/// come back at once.
pub fn reconnect_delay(attempt: u32, jitter: f64) -> Duration {
    let doublings = attempt.saturating_sub(1).min(16);
    let base = RECONNECT_BASE
        .saturating_mul(1 << doublings)
        .min(RECONNECT_CAP);
    base.mul_f64(0.75 + 0.5 * jitter.clamp(0.0, 1.0))
}

fn jitter() -> f64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    // The whole fraction of a second, which varies however coarse the clock.
    f64::from(nanos) / 1e9
}

/// Events in flight between the source thread and the relay. Enough for a
/// few seconds of video and audio; past it the source waits, and TCP holds
/// the server back.
const CHANNEL_DEPTH: usize = 512;

/// Start pulling `spec` on its own thread. When a session ends the thread
/// sends [`SourceEvent::Lost`] and reconnects, quickly at first and then
/// every [`RECONNECT_CAP`], until the receiver is dropped or the source
/// refuses the login ([`SourceEvent::Refused`]).
pub fn spawn(spec: Spec) -> Result<mpsc::Receiver<SourceEvent>> {
    let (tx, rx) = mpsc::channel(CHANNEL_DEPTH);
    std::thread::Builder::new()
        .name("rtsp-source".into())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(e) => {
                    let why = format!("starting the source's runtime: {e}");
                    let _ = tx.blocking_send(SourceEvent::Lost(why));
                    return;
                }
            };
            // Sessions in a row that ended without reaching the relay. One
            // that relayed starts the quick reconnects afresh.
            let mut failures = 0;
            loop {
                let mut relayed = false;
                let why = match runtime.block_on(session::run(&spec, &tx, &mut relayed)) {
                    Ok(()) => "the source ended the session".to_string(),
                    // Retina follows its message with the connection and
                    // message ids on lines of their own.
                    Err(session::End::Lost(e)) => {
                        e.lines().next().unwrap_or_default().trim_end().to_string()
                    }
                    Err(session::End::Refused(why)) => {
                        let _ = tx.blocking_send(SourceEvent::Refused(why));
                        return;
                    }
                };
                failures = if relayed { 1 } else { failures + 1 };
                let attempt = failures;
                let mut events = vec![SourceEvent::Lost(why)];
                if attempt > RECONNECT_ATTEMPTS {
                    if attempt == RECONNECT_ATTEMPTS + 1 {
                        events.push(SourceEvent::Down);
                    }
                    events.push(SourceEvent::State(SourceState::Down));
                } else {
                    events.push(SourceEvent::State(SourceState::Retrying { attempt }));
                }
                if events.into_iter().any(|e| tx.blocking_send(e).is_err()) {
                    return;
                }
                // In short steps, so a relay that has gone is noticed.
                let until = Instant::now() + reconnect_delay(attempt, jitter());
                while Instant::now() < until {
                    if tx.is_closed() {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        })?;
    Ok(rx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconnects_double_from_half_a_second_to_eight_and_stay_there() {
        let secs: Vec<f64> = (1..=8)
            .map(|a| reconnect_delay(a, 0.5).as_secs_f64())
            .collect();
        assert_eq!(secs, [0.5, 1.0, 2.0, 4.0, 8.0, 8.0, 8.0, 8.0]);
        let budget: f64 = secs[..RECONNECT_ATTEMPTS as usize].iter().sum();
        assert_eq!(budget, 23.5);
        // Jitter spreads each wait by a quarter either way.
        assert_eq!(reconnect_delay(4, 0.0).as_secs_f64(), 3.0);
        assert_eq!(reconnect_delay(4, 1.0).as_secs_f64(), 5.0);
    }

    #[test]
    fn rtsp_and_rtspt_are_read_and_shown_without_the_query() {
        let spec = Spec::parse("rtsp://stream.example.net/live/channel?token=abc").unwrap();
        assert_eq!(spec.display(), "rtsp://stream.example.net/live/channel");
        let spec = Spec::parse("RTSPT://10.0.0.5:8554/cam").unwrap();
        assert_eq!(spec.display(), "rtsp://10.0.0.5:8554/cam");
    }

    #[test]
    fn what_cannot_be_pulled_is_refused_without_repeating_the_url() {
        for url in [
            "rtsp://user:sk_secret_123@host/path",
            "rtsps://host/sk_secret_123",
            "http://host/sk_secret_123",
            "host/sk_secret_123",
            "rtsp:///sk_secret_123",
        ] {
            let e = Spec::parse(url).unwrap_err().to_string();
            assert!(!e.contains("sk_secret"), "{url}: {e}");
        }
    }

    /// A server that answers every request with 401, asking for Basic auth,
    /// and passes on each request's head.
    fn refusing_server() -> (u16, std::sync::mpsc::Receiver<String>) {
        use std::io::{BufRead, BufReader, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (seen, requests) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(mut conn) = conn else { return };
                let seen = seen.clone();
                std::thread::spawn(move || {
                    let mut reader = BufReader::new(conn.try_clone().unwrap());
                    loop {
                        let mut head = String::new();
                        loop {
                            let mut line = String::new();
                            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                                return;
                            }
                            if line == "\r\n" {
                                break;
                            }
                            head.push_str(&line);
                        }
                        let cseq = head
                            .lines()
                            .find_map(|l| {
                                l.split_once(':')
                                    .filter(|(k, _)| k.eq_ignore_ascii_case("cseq"))
                            })
                            .map_or("0", |(_, v)| v.trim())
                            .to_owned();
                        let _ = seen.send(head);
                        let _ = write!(
                            conn,
                            "RTSP/1.0 401 Unauthorized\r\nCSeq: {cseq}\r\n\
                             WWW-Authenticate: Basic realm=\"truss\"\r\nContent-Length: 0\r\n\r\n"
                        );
                    }
                });
            }
        });
        (port, requests)
    }

    /// Everything the source thread sends, until it stops.
    fn events_until_stopped(spec: Spec) -> Vec<SourceEvent> {
        let mut rx = spawn(spec).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut events = Vec::new();
        loop {
            match rx.try_recv() {
                Ok(event) => events.push(event),
                Err(mpsc::error::TryRecvError::Disconnected) => return events,
                Err(mpsc::error::TryRecvError::Empty) => {
                    assert!(Instant::now() < deadline, "still running: {events:?}");
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        }
    }

    #[test]
    fn a_refused_login_is_sent_once_and_not_tried_again() {
        let (port, requests) = refusing_server();
        let spec = Spec::parse(&format!("rtsp://127.0.0.1:{port}/cam"))
            .unwrap()
            .with_login(Login {
                user: "user".into(),
                password: creds::Secret::new(&creds::SOURCE_PASSWORD, "sk_secret_pw").unwrap(),
            });
        let events = events_until_stopped(spec);
        let Some(SourceEvent::Refused(why)) = events.last() else {
            panic!("did not end on a refusal: {events:?}");
        };
        assert!(why.contains("refused the login"), "{why}");
        assert!(!why.contains("sk_secret"), "{why}");
        assert!(
            !events.iter().any(|e| matches!(e, SourceEvent::Lost(_))),
            "{events:?}"
        );

        let heads: Vec<String> = requests.try_iter().collect();
        let authorised: Vec<&String> = heads
            .iter()
            .filter(|h| h.contains("Authorization: Basic dXNlcjpza19zZWNyZXRfcHc="))
            .collect();
        assert_eq!(authorised.len(), 1, "{heads:?}");
    }

    #[test]
    fn a_source_that_wants_a_login_says_how_to_give_one() {
        let (port, _requests) = refusing_server();
        let spec = Spec::parse(&format!("rtsp://127.0.0.1:{port}/cam")).unwrap();
        let events = events_until_stopped(spec);
        let Some(SourceEvent::Refused(why)) = events.last() else {
            panic!("did not end on a refusal: {events:?}");
        };
        assert!(why.contains("--source-user"), "{why}");
    }
}
