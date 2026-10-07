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

use anyhow::{Result, bail};
use tokio::sync::mpsc;

/// An RTSP source to pull from.
#[derive(Clone, Debug)]
pub struct Spec {
    url: url::Url,
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
                 pass in a URL. Sources that need them are not supported yet"
            );
        }
        if url.host_str().is_none_or(str::is_empty) {
            bail!("--source names no host");
        }
        Ok(Self { url })
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
    /// The session is over, and why.
    Lost(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceState {
    Connecting,
    /// Playing, waiting for sender reports to agree.
    Aligning,
    WaitingForKeyframe,
    Relaying,
}

impl SourceState {
    pub fn describe(self) -> &'static str {
        match self {
            Self::Connecting => "connecting",
            Self::Aligning => "aligning on sender reports",
            Self::WaitingForKeyframe => "waiting for a keyframe",
            Self::Relaying => "relaying",
        }
    }
}

/// Events in flight between the source thread and the relay. Enough for a
/// few seconds of video and audio; past it the source waits, and TCP holds
/// the server back.
const CHANNEL_DEPTH: usize = 512;

/// Start pulling `spec` on its own thread. The thread ends when the session
/// does, sending [`SourceEvent::Lost`] last, or when the receiver is dropped.
pub fn spawn(spec: Spec) -> Result<mpsc::Receiver<SourceEvent>> {
    let (tx, rx) = mpsc::channel(CHANNEL_DEPTH);
    std::thread::Builder::new()
        .name("rtsp-source".into())
        .spawn(move || {
            let why = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => match runtime.block_on(session::run(spec, tx.clone())) {
                    Ok(()) => "the source ended the session".to_string(),
                    Err(e) => e,
                },
                Err(e) => format!("starting the source's runtime: {e}"),
            };
            let _ = tx.blocking_send(SourceEvent::Lost(why));
        })?;
    Ok(rx)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
