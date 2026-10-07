//! Plumbing for the relay: the outbound queue and the rate meter.
//!
//! Both were written inside the binary and neither could be tested there. The
//! queue took a `TcpStream`, so provoking a partial write meant arranging a real
//! socket to fill its send buffer on cue, and the meter read the clock itself.
//! Taking a `Write` and an explicit instant instead costs nothing at the call
//! site and makes both reachable from a test.
//!
//! That matters most for [`OutBuf`], because the case it exists for is one no
//! local run reproduces: over loopback a write is always accepted whole and
//! `write_all` looks correct, while over a real upload the kernel send buffer
//! fills within the first second and refuses part of the data. A regression
//! here would surface as a broken show rather than a failing test.

use std::collections::VecDeque;
use std::io::{ErrorKind, Write};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};

pub const DEFAULT_RTMP_PORT: u16 = 1935;
pub const DEFAULT_APP: &str = "live";

/// Where the relay publishes: an RTMP host and port, and the application.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ingest {
    /// `host:port`, the port filled in when the operator left it out.
    pub authority: String,
    pub app: String,
}

impl Ingest {
    /// Read `--publish`: `rtmp://host[:port]/app`, the port 1935 unless
    /// given and the application `live` unless given.
    ///
    /// The application is the only path the URL may carry. The stream key
    /// rides nowhere on the command line, so a URL with a second path
    /// segment, a query, a fragment or a user and password is refused. No
    /// error quotes anything after the scheme: an argument is visible to
    /// anything that can list processes, and so is an error message that
    /// repeats it.
    pub fn parse(publish: &str) -> Result<Self> {
        let Some((scheme, rest)) = publish.trim().split_once("://") else {
            bail!(
                "--publish is a URL: rtmp://host/app, with the port after the host when it is not 1935"
            );
        };
        match scheme.to_ascii_lowercase().as_str() {
            "rtmp" => {}
            "rtmps" => bail!(
                "rtmps:// is not supported: the relay speaks plain RTMP, so give rtmp://host/app"
            ),
            other => bail!("--publish {other}:// is not understood; give rtmp://host/app"),
        }
        if rest.contains('?') || rest.contains('#') {
            bail!(
                "--publish carries a query or a fragment, which is where some services put \
                 the stream key. Give the application only, rtmp://host/app, and the key \
                 through --stream-key-file"
            );
        }
        let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
        if authority.contains('@') {
            bail!(
                "--publish carries a user and password before the host, which the relay \
                 cannot pass on and will not print. Give rtmp://host/app and the key \
                 through --stream-key-file"
            );
        }
        let authority = parse_authority(authority)?;
        let mut segments = path.split('/').filter(|s| !s.is_empty());
        let app = segments.next().unwrap_or(DEFAULT_APP);
        if segments.next().is_some() {
            bail!(
                "--publish carries more than the application, which is where the stream key \
                 goes in a publish URL. Give rtmp://host/app and the key through \
                 --stream-key-file"
            );
        }
        Ok(Self {
            authority,
            app: app.to_string(),
        })
    }

    pub fn url(&self) -> String {
        format!("rtmp://{}/{}", self.authority, self.app)
    }
}

/// `host:port` from what stood between the scheme and the path: a host name
/// or address, an IPv6 address in brackets, and a port a socket can be given,
/// 1935 unless one is written.
fn parse_authority(authority: &str) -> Result<String> {
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let Some((inside, after)) = rest.split_once(']') else {
            bail!("--publish has an IPv6 address with no closing bracket");
        };
        inside.parse::<std::net::Ipv6Addr>().map_err(|_| {
            anyhow!("--publish has something in brackets that is not an IPv6 address")
        })?;
        let port = match after {
            "" => None,
            p => Some(p.strip_prefix(':').ok_or_else(|| {
                anyhow!("--publish has more than :port after the bracketed address")
            })?),
        };
        (format!("[{inside}]"), port)
    } else {
        match authority.rsplit_once(':') {
            Some((head, _)) if head.contains(':') => {
                bail!("--publish has an IPv6 address without brackets; write it as [address]:port")
            }
            Some((host, port)) => (host.to_string(), Some(port)),
            None => (authority.to_string(), None),
        }
    };
    if host.is_empty() {
        bail!("--publish names no host");
    }
    let hostname = |b: u8| b.is_ascii_alphanumeric() || b == b'-' || b == b'.';
    if !host.starts_with('[') && !host.bytes().all(hostname) {
        bail!("--publish has a host that is not a host name or an address");
    }
    let port = match port {
        None => DEFAULT_RTMP_PORT,
        Some(p) => match p.parse::<u16>() {
            Ok(n) if n != 0 => n,
            _ => bail!("--publish has a port that is not a number from 1 to 65535"),
        },
    };
    Ok(format!("{host}:{port}"))
}

/// Compaction threshold. Below this, consumed bytes are left in place and the
/// read cursor walks forward; above it the front is discarded, so a long-lived
/// connection does not carry a growing prefix of already-sent data.
const COMPACT_AFTER: usize = 256 * 1024;

/// A backlog this size means the upstream cannot carry the stream at all.
/// Reported rather than absorbed, because the alternative is growing until the
/// process is killed and leaving nothing to explain why.
const MAX_BACKLOG: usize = 32 * 1024 * 1024;

/// Bytes waiting to go out on a non-blocking socket.
///
/// Both of the relay's sockets are non-blocking so a single thread can poll
/// them, which means a write can refuse part of its data whenever the kernel
/// send buffer is full. Whatever is unsent stays here and is retried, so a
/// momentarily full socket costs milliseconds rather than the broadcast.
#[derive(Default)]
pub struct OutBuf {
    buf: Vec<u8>,
    pos: usize,
}

impl OutBuf {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Bytes accepted but not yet written out.
    pub fn pending(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.pending() == 0
    }

    /// Write as much as the sink will take, keeping the remainder for the next
    /// call. Returns without error when the sink refuses more, which is the
    /// ordinary case rather than a fault.
    pub fn pump<W: Write>(&mut self, sink: &mut W) -> Result<()> {
        while self.pos < self.buf.len() {
            match sink.write(&self.buf[self.pos..]) {
                Ok(0) => bail!("socket closed while writing"),
                Ok(n) => self.pos += n,
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(ref e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(e).context("writing to socket"),
            }
        }
        if self.pos == self.buf.len() {
            self.buf.clear();
            self.pos = 0;
        } else if self.pos > COMPACT_AFTER {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        if self.pending() > MAX_BACKLOG {
            bail!(
                "{} MB queued and not draining; the upstream connection cannot keep up \
                 with this bitrate",
                self.pending() / (1024 * 1024)
            );
        }
        Ok(())
    }
}

/// How much of the stream may queue for the ingest before the relay stops
/// reading from the encoder.
const HOLD_SECONDS: f64 = 0.5;
/// The least that may queue before holding, so a low bitrate does not hold
/// the encoder back over a single keyframe.
const HOLD_FLOOR: usize = 256 * 1024;

/// Whether to stop reading from the encoder because the ingest is behind.
///
/// Reading regardless hides a slow uplink from the encoder: it writes to a
/// local socket that never fills, so its own frame dropping and bitrate
/// control never engage, and the backlog grows in the relay instead. Not
/// reading lets TCP push back on the encoder, which then behaves as it would
/// publishing directly. Reading resumes once the queue is down to half the
/// limit, so the relay does not switch on every frame.
///
/// The limit is set from the rate when a hold starts and kept until it ends.
/// Nothing is read while holding, so the measured rate falls the longer a
/// hold lasts, and following it would keep pushing the release point down.
#[derive(Debug, Default)]
pub struct Backpressure {
    holding: bool,
    limit: usize,
}

impl Backpressure {
    /// Update for `queued` bytes waiting for the ingest with the stream at
    /// `kbps`, and return whether to hold off reading.
    pub fn hold(&mut self, queued: usize, kbps: f64) -> bool {
        if self.holding {
            self.holding = queued > self.limit / 2;
        } else {
            self.limit = HOLD_FLOOR.max((kbps.max(0.0) * 125.0 * HOLD_SECONDS) as usize);
            self.holding = queued > self.limit;
        }
        self.holding
    }

    pub fn holding(&self) -> bool {
        self.holding
    }
}

/// Bytes on the wire, averaged over a sliding window.
///
/// The relay adds to a stream the encoder has already sized, so a correctly
/// configured encoder can still be pushed past an ingest's combined limit.
/// Measuring what actually leaves is the only reliable way to know.
pub struct RateMeter {
    samples: VecDeque<(Instant, u64)>,
    window: Duration,
    total: u64,
}

impl RateMeter {
    pub fn new() -> Self {
        Self::with_window(Duration::from_secs(5))
    }

    pub fn with_window(window: Duration) -> Self {
        Self {
            samples: VecDeque::new(),
            window,
            total: 0,
        }
    }

    pub fn add(&mut self, bytes: usize) {
        self.add_at(Instant::now(), bytes);
    }

    /// Record bytes as at a given instant. The clock is a parameter so a test
    /// can cover the window eviction without waiting for it in real time.
    pub fn add_at(&mut self, now: Instant, bytes: usize) {
        self.samples.push_back((now, bytes as u64));
        self.total += bytes as u64;
        while let Some(&(t, b)) = self.samples.front() {
            if now.duration_since(t) > self.window {
                self.samples.pop_front();
                self.total -= b;
            } else {
                break;
            }
        }
    }

    pub fn kbps(&self) -> f64 {
        self.kbps_at(Instant::now())
    }

    /// Zero until the window covers at least a second. A rate derived from a
    /// couple of frames is noise, and acting on it would abort a healthy stream
    /// on the strength of one large keyframe.
    pub fn kbps_at(&self, now: Instant) -> f64 {
        let Some(&(oldest, _)) = self.samples.front() else {
            return 0.0;
        };
        let secs = now.duration_since(oldest).as_secs_f64();
        if secs < 1.0 {
            return 0.0;
        }
        (self.total as f64 * 8.0) / secs / 1000.0
    }
}

impl Default for RateMeter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A sink that accepts what it is told to, in order, so the awkward cases
    /// can be provoked deliberately instead of waited for.
    enum Step {
        Accept(usize),
        WouldBlock,
        Interrupted,
        Closed,
    }

    struct ScriptedSink {
        steps: VecDeque<Step>,
        written: Vec<u8>,
    }

    impl ScriptedSink {
        fn new(steps: Vec<Step>) -> Self {
            Self {
                steps: steps.into(),
                written: Vec::new(),
            }
        }
    }

    impl Write for ScriptedSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            match self.steps.pop_front() {
                // Runs off the end of the script as a sink that takes everything.
                None | Some(Step::Accept(0)) => {
                    self.written.extend_from_slice(buf);
                    Ok(buf.len())
                }
                Some(Step::Accept(n)) => {
                    let n = n.min(buf.len());
                    self.written.extend_from_slice(&buf[..n]);
                    Ok(n)
                }
                Some(Step::WouldBlock) => Err(std::io::Error::new(ErrorKind::WouldBlock, "full")),
                Some(Step::Interrupted) => {
                    Err(std::io::Error::new(ErrorKind::Interrupted, "signal"))
                }
                Some(Step::Closed) => Ok(0),
            }
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_refused_write_keeps_its_data_for_the_next_attempt() {
        // The case loopback never produces: the socket takes some of the data
        // and then refuses the rest.
        let mut out = OutBuf::new();
        out.push(b"abcdefghij");
        let mut sink = ScriptedSink::new(vec![Step::Accept(4), Step::WouldBlock]);

        out.pump(&mut sink).expect("a full socket is not an error");
        assert_eq!(sink.written, b"abcd");
        assert_eq!(out.pending(), 6, "the rest must be held, not dropped");

        // Next time round the socket has room.
        let mut sink = ScriptedSink::new(vec![]);
        out.pump(&mut sink).expect("drains");
        assert_eq!(sink.written, b"efghij");
        assert!(out.is_empty());
    }

    #[test]
    fn an_interrupted_write_is_retried_rather_than_lost() {
        let mut out = OutBuf::new();
        out.push(b"hello");
        let mut sink = ScriptedSink::new(vec![Step::Interrupted, Step::Accept(5)]);
        out.pump(&mut sink).expect("retries");
        assert_eq!(sink.written, b"hello");
        assert!(out.is_empty());
    }

    #[test]
    fn a_closed_socket_is_reported_rather_than_spun_on() {
        let mut out = OutBuf::new();
        out.push(b"hello");
        let mut sink = ScriptedSink::new(vec![Step::Closed]);
        let err = out.pump(&mut sink).unwrap_err().to_string();
        assert!(err.contains("closed"), "{err}");
    }

    #[test]
    fn the_encoder_is_held_past_half_a_second_queued_and_released_at_half_that() {
        let mut b = Backpressure::default();
        // 4,000 kb/s is 500,000 bytes a second, so the limit is 250,000,
        // under the floor: 256 kB holds and half of it releases.
        assert!(!b.hold(200_000, 4000.0));
        assert!(b.hold(300_000, 4000.0));
        assert!(b.hold(200_000, 4000.0), "still above half the limit");
        assert!(!b.hold(100_000, 4000.0));
        // At 8,000 kb/s the limit is half a second, 500,000 bytes.
        assert!(!b.hold(400_000, 8000.0));
        assert!(b.hold(600_000, 8000.0));
    }

    #[test]
    fn a_hold_keeps_the_limit_it_started_with_while_the_measured_rate_falls() {
        let mut b = Backpressure::default();
        assert!(b.hold(600_000, 8000.0), "past half a second at 8,000 kb/s");
        // Nothing is read while holding, so the meter reads lower each pass.
        // Releasing at half of 500,000 must not slide down to half the floor.
        assert!(b.hold(300_000, 1000.0));
        assert!(!b.hold(240_000, 500.0));
    }

    #[test]
    fn nothing_queued_is_not_an_error() {
        let mut out = OutBuf::new();
        let mut sink = ScriptedSink::new(vec![]);
        out.pump(&mut sink).expect("an empty queue pumps cleanly");
        assert!(sink.written.is_empty());
    }

    #[test]
    fn a_part_drained_buffer_is_compacted_rather_than_grown() {
        // Past the compaction threshold the consumed prefix is discarded. Without
        // it a long session carries every byte it has ever sent.
        let mut out = OutBuf::new();
        out.push(&vec![0u8; COMPACT_AFTER + 4096]);
        let mut sink = ScriptedSink::new(vec![Step::Accept(COMPACT_AFTER + 1), Step::WouldBlock]);
        out.pump(&mut sink).expect("partial write");

        assert_eq!(out.pending(), 4095);
        assert_eq!(out.pos, 0, "the consumed prefix should have been dropped");
        assert_eq!(out.buf.len(), 4095, "and the buffer shrunk with it");
    }

    #[test]
    fn a_backlog_that_will_never_drain_is_reported() {
        let mut out = OutBuf::new();
        out.push(&vec![7u8; MAX_BACKLOG + 1]);
        let mut sink = ScriptedSink::new(vec![Step::WouldBlock]);
        let err = out.pump(&mut sink).unwrap_err().to_string();
        assert!(err.contains("cannot keep up"), "{err}");
        assert!(err.contains("32 MB"), "the size is worth saying: {err}");
    }

    #[test]
    fn a_rate_needs_a_second_before_it_means_anything() {
        let t0 = Instant::now();
        let mut meter = RateMeter::new();
        meter.add_at(t0, 100_000);
        // A single large keyframe inside a fraction of a second would otherwise
        // read as a colossal rate and trip an abort on a healthy stream.
        assert_eq!(meter.kbps_at(t0 + Duration::from_millis(200)), 0.0);
        assert!(meter.kbps_at(t0 + Duration::from_secs(2)) > 0.0);
    }

    #[test]
    fn a_rate_is_averaged_over_the_window() {
        let t0 = Instant::now();
        let mut meter = RateMeter::new();
        // 125,000 bytes over 2 s is 1,000,000 bits over 2 s, so 500 kb/s.
        meter.add_at(t0, 125_000);
        let kbps = meter.kbps_at(t0 + Duration::from_secs(2));
        assert!(
            (kbps - 500.0).abs() < 1.0,
            "expected about 500 kb/s, got {kbps}"
        );
    }

    #[test]
    fn samples_older_than_the_window_stop_counting() {
        let t0 = Instant::now();
        let mut meter = RateMeter::with_window(Duration::from_secs(5));
        meter.add_at(t0, 1_000_000);
        // Well past the window, so the old sample should have been evicted and
        // the rate should reflect only what is recent.
        meter.add_at(t0 + Duration::from_secs(30), 125_000);
        let kbps = meter.kbps_at(t0 + Duration::from_secs(32));
        assert!(
            (kbps - 500.0).abs() < 1.0,
            "the stale megabyte is still being counted: {kbps}"
        );
    }

    #[test]
    fn an_empty_meter_reads_zero_rather_than_dividing_by_nothing() {
        let meter = RateMeter::new();
        assert_eq!(meter.kbps(), 0.0);
    }

    #[test]
    fn a_publish_url_names_host_port_and_application() {
        let i = Ingest::parse("rtmp://ingest.example.net/live").unwrap();
        assert_eq!(i.authority, "ingest.example.net:1935");
        assert_eq!(i.app, "live");
        assert_eq!(i.url(), "rtmp://ingest.example.net:1935/live");

        let i = Ingest::parse("RTMP://127.0.0.1:1936/show/").unwrap();
        assert_eq!(i.authority, "127.0.0.1:1936");
        assert_eq!(i.app, "show");

        let i = Ingest::parse("rtmp://ingest.example.net").unwrap();
        assert_eq!(i.app, "live", "the application when the URL names none");

        let i = Ingest::parse("rtmp://[::1]/live").unwrap();
        assert_eq!(i.authority, "[::1]:1935");
        let i = Ingest::parse("rtmp://[::1]:1936/live").unwrap();
        assert_eq!(i.authority, "[::1]:1936");
    }

    #[test]
    fn a_bare_host_is_told_what_a_publish_url_looks_like() {
        let e = Ingest::parse("ingest.example.net:1935")
            .unwrap_err()
            .to_string();
        assert!(e.contains("rtmp://host/app"), "{e}");
    }

    #[test]
    fn anything_that_could_carry_the_key_is_refused_and_not_repeated() {
        for url in [
            "rtmp://ingest.example.net/live/sk_secret_123",
            "rtmp://ingest.example.net/live?key=sk_secret_123",
            "rtmp://ingest.example.net/live#sk_secret_123",
            "rtmp://user:sk_secret_123@ingest.example.net/live",
        ] {
            let e = Ingest::parse(url).unwrap_err().to_string();
            assert!(e.contains("--stream-key-file"), "{url}: {e}");
            assert!(
                !e.contains("sk_secret"),
                "the error must not echo the key: {e}"
            );
        }
    }

    #[test]
    fn the_wrong_scheme_or_no_host_is_refused() {
        assert!(
            Ingest::parse("rtmps://ingest.example.net/live")
                .unwrap_err()
                .to_string()
                .contains("rtmps"),
        );
        assert!(
            Ingest::parse("http://ingest.example.net/live")
                .unwrap_err()
                .to_string()
                .contains("not understood"),
        );
        for url in ["rtmp:///live", "rtmp://:1935/live"] {
            let e = Ingest::parse(url).unwrap_err().to_string();
            assert!(e.contains("names no host"), "{url}: {e}");
        }
    }

    #[test]
    fn a_host_or_port_that_a_socket_could_not_be_given_is_refused_by_name() {
        for (url, says) in [
            ("rtmp://ingest.example.net:70000/live", "1 to 65535"),
            ("rtmp://ingest.example.net:0/live", "1 to 65535"),
            ("rtmp://ingest.example.net:abc/live", "1 to 65535"),
            ("rtmp://::1/live", "without brackets"),
            ("rtmp://[not-an-address]/live", "not an IPv6 address"),
            ("rtmp://[::1]x/live", "after the bracketed address"),
            ("rtmp://[::1/live", "no closing bracket"),
            ("rtmp://bad host/live", "not a host name"),
        ] {
            let e = Ingest::parse(url).unwrap_err().to_string();
            assert!(e.contains(says), "{url}: {e}");
        }
    }

    #[test]
    fn a_key_typed_into_the_host_or_port_is_not_repeated() {
        for url in [
            "rtmp://ingest.example.net:sk_secret_123/live",
            "rtmp://sk_secret_123!/live",
            "rtmp://[sk_secret_123]/live",
            "rtmp://[::1]sk_secret_123/live",
        ] {
            let e = Ingest::parse(url).unwrap_err().to_string();
            assert!(
                !e.contains("sk_secret"),
                "the error must not echo the key: {e}"
            );
        }
    }
}
