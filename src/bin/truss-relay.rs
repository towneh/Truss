//! An RTMP relay that sits between an encoder and an ingest server, planting DMX in
//! the video on the way past.
//!
//! The encoder publishes into this as if it were the ingest; this publishes onward
//! as if it were OBS. Both sides of the connection are terminated rather than
//! tapped, because RTMP splits message payloads across chunks with headers
//! interleaved: finding and editing a video payload in a passing byte stream is
//! not reliably possible, but reassembling messages, editing, and re-chunking
//! is straightforward.
//!
//! Terminating also means the real stream key lives here rather than in OBS,
//! which points at a local dummy key instead.
//!
//! Unlike the file rewriter, this knows when each frame goes out, so records
//! carry a real send time and the detector's latency column works.

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use clap::Parser;
use rml_rtmp::handshake::{Handshake, HandshakeProcessResult, PeerType};
use rml_rtmp::sessions::{
    ClientSession, ClientSessionConfig, ClientSessionEvent, ClientSessionResult,
    PublishRequestType, ServerSession, ServerSessionConfig, ServerSessionEvent,
    ServerSessionResult, StreamMetadata,
};
use rml_rtmp::time::RtmpTimestamp;
use truss::artnet;
use truss::carrier::{self, Carrier};
use truss::codec::VideoCodec;
use truss::console;
use truss::creds;
use truss::inject::{InjectOptions, Injector};
use truss::osc;
use truss::payload;
use truss::pull::timing::{AUDIO, Timeline, VIDEO};
use truss::pull::{self, SourceEvent, SourceState};
use truss::record::{DEFAULT_PAYLOAD_LEN, MAX_PAYLOAD_LEN};
use truss::recording::Recording;
use truss::relay::{Backpressure, Ingest, OutBuf, RateMeter};

#[derive(Parser, Clone)]
#[command(
    name = "truss-relay",
    about = "Relay RTMP, planting DMX in the video on the way through",
    group(clap::ArgGroup::new("output").args(["publish", "record"]).multiple(true))
)]
struct Cli {
    /// Address to accept the encoder on, 127.0.0.1:1935 unless given. Point
    /// the encoder at rtmp://<this>/live with any key.
    #[arg(long, requires = "output", value_name = "ADDRESS")]
    listen: Option<String>,
    /// Pull the video from this RTSP source instead of accepting an encoder:
    /// rtsp://host/path, with the port after the host when it is not 554.
    /// The publish starts once the source's audio and video are lined up and
    /// a keyframe arrives, 5 to 10 seconds in.
    #[arg(
        long,
        requires = "output",
        conflicts_with = "listen",
        value_name = "URL"
    )]
    source: Option<String>,
    #[arg(skip)]
    pull: Option<pull::Spec>,
    /// User to log in to the source as, when it asks for one, as a camera
    /// usually does. The password is never a flag: see --source-password-file.
    #[arg(long, requires = "source", value_name = "NAME")]
    source_user: Option<String>,
    /// File holding the source's password, or `-` to read it from stdin.
    /// Without it the password is looked for in TRUSS_SOURCE_PASSWORD, then
    /// asked for if this is a terminal.
    #[arg(long, requires = "source_user", value_name = "PATH")]
    source_password_file: Option<String>,
    /// What to do with Truss records the source already carries, as a stream
    /// that has been through a relay does: strip them, or keep them beside
    /// this relay's own, to measure a hop.
    #[arg(long, value_enum, default_value_t = SourceRecords::Strip, requires = "source", conflicts_with = "passthrough")]
    source_records: SourceRecords,
    /// What to do with the source's AAC audio: relay it, or drop it for a
    /// publish of the picture alone. Other audio is always left out, since
    /// an RTMP ingest wants AAC and the relay does not transcode.
    #[arg(long, value_enum, default_value_t = SourceAudio::Keep, requires = "source")]
    source_audio: SourceAudio,
    /// Where to publish the stream: rtmp://host/app, with the port after the
    /// host when it is not 1935, and "live" when no application is given.
    /// The stream key is never part of this: see --stream-key-file.
    ///
    /// Leave it out to record without publishing (--record), or to run the
    /// OSC lane alone, for testing against a desk with no encoder or ingest:
    /// then --artnet and --osc are needed, and nothing listens for an encoder.
    #[arg(long, required_unless_present_any = ["osc", "record"])]
    publish: Option<String>,
    /// Also write the stream, records and all, to an FLV file in this
    /// directory: one file per session, named for the local time it started.
    /// Without --publish the relay records and publishes nothing.
    #[arg(long, value_name = "DIR")]
    record: Option<std::path::PathBuf>,
    #[arg(skip)]
    target: Ingest,
    /// File holding the stream key, or `-` to read it from stdin. Suits
    /// systemd LoadCredential and container secrets, which both present a
    /// secret as a file. Without it the key is looked for in TRUSS_STREAM_KEY,
    /// then asked for if this is a terminal.
    ///
    /// There is deliberately no flag that takes the key itself: an argument is
    /// visible to anything that can list processes.
    #[arg(long, requires = "publish")]
    stream_key_file: Option<String>,
    /// Comma-separated carrier slugs.
    #[arg(long, default_value = DEFAULT_CARRIERS, requires = "output")]
    carriers: String,
    /// Inject on every Nth video frame.
    #[arg(long, default_value_t = 1, requires = "output")]
    every: u32,
    /// Payload bytes per record. Ignored with --artnet, which sizes each
    /// payload from the universes the desk is sending.
    #[arg(long, default_value_t = DEFAULT_PAYLOAD_LEN, requires = "output")]
    payload_len: usize,
    /// Carry live Art-Net DMX. On its own this listens on every adapter, port
    /// 6454, and hears a desk on this machine as well as one on the network.
    /// Give an address to listen on one adapter only, with :port after it
    /// when it is not 6454.
    #[arg(
        long,
        value_name = "ADDRESS",
        num_args = 0..=1,
        default_missing_value = "0.0.0.0",
    )]
    artnet: Option<String>,
    /// Largest DMX payload to put in one frame. The default sits below the
    /// 10,448 bytes measured crossing a remuxing CDN intact; more than that is
    /// untested rather than known to fail. Universes that do not fit are sent
    /// on the following frames.
    #[arg(long, default_value_t = DEFAULT_ARTNET_MAX_PAYLOAD)]
    artnet_max_payload: usize,
    /// Warn when the outgoing stream averages above this many kb/s.
    #[arg(long, default_value_t = 5500.0, requires = "publish")]
    warn_kbps: f64,
    /// Drop the session if the outgoing stream sustains this rate; the relay
    /// then waits for the encoder again. Off by default: see the note where
    /// this is used.
    #[arg(long, requires = "publish")]
    abort_kbps: Option<f64>,
    /// Relay without injecting, to measure what the relay itself costs.
    #[arg(long, requires = "output")]
    passthrough: bool,
    /// Also send every record to this OSC listener, as /truss/dmx with the
    /// record as a blob, so a tool on this network can watch the desk without
    /// reading the stream. Needs --artnet.
    #[arg(long)]
    osc: Option<String>,
    /// Records a second to send to --osc while no publisher is connected.
    /// With one connected the lane carries the payload of each record the
    /// stream carries, at the video's frame rate.
    #[arg(long, default_value_t = 30.0)]
    osc_rate: f64,
    /// Print a line for everything as it happens instead of a panel redrawn
    /// in place. Always the case when the output is not a terminal.
    #[arg(long)]
    show_logging: bool,
}

const DEFAULT_ARTNET_MAX_PAYLOAD: usize = 9216;
const DEFAULT_CARRIERS: &str = "sei-unreg";
const DEFAULT_LISTEN: &str = "127.0.0.1:1935";

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum SourceRecords {
    Strip,
    Keep,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum SourceAudio {
    Keep,
    Drop,
}

impl Cli {
    fn listen(&self) -> &str {
        self.listen.as_deref().unwrap_or(DEFAULT_LISTEN)
    }

    /// The application to point the encoder at: the ingest's, so the two
    /// URLs read alike, or "live" when recording without one.
    fn listen_app(&self) -> &str {
        match self.publish {
            Some(_) => &self.target.app,
            None => "live",
        }
    }
}

fn now_unix_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

fn parse_carriers(spec: &str) -> Result<Vec<Carrier>> {
    let mut out = Vec::new();
    for name in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let Some(c) = carrier::ALL.into_iter().find(|c| c.slug() == name) else {
            let known: Vec<&str> = carrier::ALL.iter().map(|c| c.slug()).collect();
            bail!("unknown carrier {name:?}; known: {}", known.join(", "));
        };
        out.push(c);
    }
    if out.is_empty() {
        bail!("no carriers selected");
    }
    Ok(out)
}

fn main() -> Result<()> {
    let mut cli = Cli::parse();
    if let Some(publish) = cli.publish.as_deref() {
        cli.target = Ingest::parse(publish)?;
    }
    if let Some(source) = cli.source.as_deref() {
        let spec = pull::Spec::parse(source)?;
        cli.pull = Some(match cli.source_audio {
            SourceAudio::Keep => spec,
            SourceAudio::Drop => spec.without_audio(),
        });
    }
    let carriers = parse_carriers(&cli.carriers)?;
    if let Some(dir) = cli.record.as_deref()
        && !dir.is_dir()
    {
        bail!("--record {}: no such directory", dir.display());
    }

    // Art-Net is unauthenticated by protocol design, so how many universes turn
    // up is not ours to decide. The budget is, and holding it under the record's
    // length field is what stops a busy desk being able to stop the relay.
    let budget_ceiling = MAX_PAYLOAD_LEN - payload::HEADER_LEN;
    if cli.artnet_max_payload > budget_ceiling {
        bail!(
            "--artnet-max-payload {} is above the {budget_ceiling} bytes that fit in \
             a record once the payload header is accounted for",
            cli.artnet_max_payload
        );
    }

    // Resolved before the listener is bound. A missing key or password should
    // fail while the operator is still watching, not on the first frame of a
    // show.
    if let Some(login) = source_login(&cli)? {
        cli.pull = cli.pull.take().map(|spec| spec.with_login(login));
    }
    let key = stream_key(&cli)?;

    // Bound once for the life of the relay rather than per session: a desk
    // keeps sending across an OBS reconnect, and rebinding would drop the
    // current state of every universe.
    let artnet = match (cli.artnet.as_deref(), cli.passthrough) {
        (Some(spec), false) => Some(artnet::Receiver::bind(artnet::parse_listen(spec)?)?),
        _ => None,
    };

    let mut osc = match cli.osc.as_deref() {
        Some(target) => {
            if artnet.is_none() {
                bail!("--osc carries the Art-Net lane, so it needs --artnet");
            }
            let addr = target
                .to_socket_addrs()
                .with_context(|| format!("resolving --osc {target:?}"))?
                .next()
                .ok_or_else(|| anyhow!("--osc {target:?} resolves to no address"))?;
            Some(osc::Sender::to(addr).context("opening the OSC socket")?)
        }
        None => None,
    };

    // The lane's idle clock, only with a lane to drive. Zero, a negative
    // number and a rate too low to express as a duration all fail here rather
    // than later in arithmetic.
    let tick = match osc {
        Some(_) => {
            let rate = cli.osc_rate;
            let tick = if rate.is_finite() && rate > 0.0 {
                Duration::try_from_secs_f64(1.0 / rate).ok()
            } else {
                None
            };
            // A tick of zero would send without pause and never sleep, which
            // an infinite rate, or a finite one past the clock's resolution,
            // would otherwise produce.
            match tick {
                Some(t) if !t.is_zero() => Some(t),
                _ => bail!("--osc-rate {rate:?} is not a usable number of records a second"),
            }
        }
        None => None,
    };

    let output = cli.publish.is_some() || cli.record.is_some();
    let forwarding = || match cli.publish.as_ref() {
        Some(_) => println!("  forwarding to {} (key hidden)", cli.target.url()),
        None => println!("  not publishing: recording only"),
    };
    let listener = match (output, &cli.pull) {
        (true, Some(spec)) => {
            match cli.source_user.as_deref() {
                Some(user) => println!("relay pulling from {} as {user}", spec.display()),
                None => println!("relay pulling from {}", spec.display()),
            }
            if cli.source_audio == SourceAudio::Drop {
                println!("  audio left out, as --source-audio drop asks");
            }
            forwarding();
            None
        }
        (true, None) => {
            let listener =
                bind_listener(cli.listen()).with_context(|| format!("binding {}", cli.listen()))?;
            println!(
                "relay listening on rtmp://{}/{}  (point the encoder here, any stream key)",
                cli.listen(),
                cli.listen_app()
            );
            forwarding();
            Some(listener)
        }
        (false, _) => {
            println!("relay running the OSC lane only: no encoder accepted, nothing published");
            None
        }
    };
    if let Some(dir) = cli.record.as_deref() {
        println!("  recording to {}, one FLV file per session", dir.display());
    }
    if cli.passthrough {
        println!("  passthrough: nothing injected");
    } else if cli.carriers.trim() != DEFAULT_CARRIERS {
        println!(
            "  carriers: {}",
            carriers
                .iter()
                .map(|c| c.slug())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if let Some(a) = artnet.as_ref() {
        match a.loopback_addr {
            Some(lo) => println!("  Art-Net on {} and {lo}", a.local_addr),
            None => println!("  Art-Net on {}", a.local_addr),
        }
        if cli.artnet_max_payload != DEFAULT_ARTNET_MAX_PAYLOAD {
            println!(
                "    up to {} payload bytes per frame",
                cli.artnet_max_payload
            );
        }
        if carriers.len() > 1 {
            // Every carrier ships the same bytes, which is the point when the
            // question is which of them survives and pure cost once that is
            // settled.
            println!(
                "    NOTE: {} carriers each carry the whole payload, so the DMX costs {}x the \
                 bandwidth. Pick one for a show.",
                carriers.len(),
                carriers.len()
            );
        }
    }

    if let Some(o) = osc.as_ref() {
        println!("  OSC to {} as {}", o.target(), osc::ADDRESS);
    }

    console::init(cli.show_logging);
    if console::panel() {
        println!();
    }
    let mut dash = Dashboard::default();
    let mut idle = IdleStatus::default();
    let mut next_tick = Instant::now();

    if let Some(spec) = cli.pull.clone() {
        // The source reconnects on its own; a session ends here only when
        // the ingest side fails, and then the relay starts again.
        loop {
            console::log("");
            console::event(format!("-- pulling from {}", spec.display()));
            match session_pull(
                spec.clone(),
                &cli,
                &carriers,
                artnet.as_ref(),
                &mut osc,
                key.as_ref(),
                &mut dash,
            ) {
                Ok(()) => console::event("-- session ended cleanly"),
                Err(e) if e.is::<SourceRefused>() => return Err(e),
                Err(e) => console::event(format!("-- session ended: {e:#}")),
            }
            std::thread::sleep(pull::RECONNECT_CAP);
        }
    }

    let Some(listener) = listener else {
        // --osc is required without --publish, and needs --artnet, both
        // checked above.
        let Some(a) = artnet.as_ref() else {
            bail!("the OSC lane needs --artnet");
        };
        loop {
            let nap = tend_lane(
                a,
                &mut osc,
                tick,
                &mut next_tick,
                &mut idle,
                "osc only",
                cli.artnet_max_payload,
            );
            dash.tick(&cli, None, Some(a), osc.as_ref());
            std::thread::sleep(nap);
        }
    };

    listener
        .set_nonblocking(true)
        .context("setting the listener non-blocking")?;
    loop {
        let stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                let nap = match artnet.as_ref() {
                    Some(a) => tend_lane(
                        a,
                        &mut osc,
                        tick,
                        &mut next_tick,
                        &mut idle,
                        "waiting for a publisher",
                        cli.artnet_max_payload,
                    ),
                    None => Duration::from_millis(200),
                };
                dash.tick(&cli, None, artnet.as_ref(), osc.as_ref());
                std::thread::sleep(nap);
                continue;
            }
            Err(e) => return Err(e).context("accepting connection"),
        };
        stream
            .set_nonblocking(false)
            .context("setting the publisher socket blocking")?;
        let peer = stream
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "?".into());
        console::log("");
        console::event(format!("-- publisher connected from {peer}"));
        match session_listen(
            stream,
            &cli,
            &carriers,
            artnet.as_ref(),
            &mut osc,
            key.as_ref(),
            &peer,
            &mut dash,
            PUBLISHER_IDLE_TIMEOUT,
        ) {
            Ok(()) => console::event("-- session ended cleanly"),
            Err(e) => console::event(format!("-- session ended: {e:#}")),
        }
        idle = IdleStatus::default();
    }
}

/// The key to publish with, whenever there is a publish: passthrough leaves
/// the stream alone but still has to be let in by the ingest.
fn stream_key(cli: &Cli) -> Result<Option<creds::Secret>> {
    if cli.publish.is_none() {
        return Ok(None);
    }
    creds::Secret::resolve(
        &creds::STREAM_KEY,
        cli.stream_key_file.as_deref(),
        "truss",
        &cli.target.authority,
    )
    .map(Some)
}

/// The login for the source, when --source-user names one. Resolved like the
/// stream key, with its own file flag and variable.
fn source_login(cli: &Cli) -> Result<Option<pull::Login>> {
    let (Some(user), Some(spec)) = (cli.source_user.as_deref(), cli.pull.as_ref()) else {
        return Ok(None);
    };
    if user.is_empty() {
        bail!("--source-user is empty");
    }
    if cli.source_password_file.as_deref() == Some("-")
        && cli.stream_key_file.as_deref() == Some("-")
    {
        bail!("--stream-key-file and --source-password-file cannot both read stdin");
    }
    let password = creds::Secret::resolve(
        &creds::SOURCE_PASSWORD,
        cli.source_password_file.as_deref(),
        "truss",
        &spec.display(),
    )?;
    Ok(Some(pull::Login {
        user: user.to_owned(),
        password,
    }))
}

/// One pass over the Art-Net lane while no publisher is connected: the status
/// line when it has changed, and a record to --osc when the lane's own clock
/// is due, so a desk can be watched with nothing else up. Returns how long to
/// sleep before the next pass.
fn tend_lane(
    artnet: &artnet::Receiver,
    osc: &mut Option<osc::Sender>,
    tick: Option<Duration>,
    next_tick: &mut Instant,
    idle: &mut IdleStatus,
    label: &str,
    max_payload: usize,
) -> Duration {
    idle.print(label, artnet, osc.as_ref());
    if let (Some(o), Some(tick)) = (osc.as_mut(), tick)
        && Instant::now() >= *next_tick
    {
        let blocks = artnet.latch().snapshot(Instant::now(), max_payload);
        if let Ok(body) = truss::payload::encode(&blocks) {
            o.send(&body, now_unix_nanos());
        }
        *next_tick = Instant::now() + tick;
    }
    match tick {
        Some(_) => next_tick
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(200)),
        None => Duration::from_millis(200),
    }
}

/// The Art-Net lane while no publisher is connected, printed when something
/// about it changes: a universe appears, a controller polls, the first DMX
/// arrives, the thread fails, late packets settle at a steady share. Counts
/// climbing on their own are not a change, so a desk that is steady is not
/// narrated.
#[derive(Default)]
struct IdleStatus {
    checked: Option<Instant>,
    last: Option<IdleKey>,
}

type IdleKey = (
    usize,
    bool,
    bool,
    Option<SocketAddr>,
    Option<String>,
    bool,
    bool,
    bool,
);

impl IdleStatus {
    fn print(&mut self, label: &str, artnet: &artnet::Receiver, osc: Option<&osc::Sender>) {
        if self
            .checked
            .is_some_and(|t| t.elapsed() < Duration::from_secs(1))
        {
            return;
        }
        self.checked = Some(Instant::now());
        let latch = artnet.latch();
        let key: IdleKey = (
            latch.universe_count(),
            latch.packets > 0,
            latch.polls > 0,
            latch.last_controller,
            latch.error.clone(),
            latch.reply_errors > 0,
            latch.two_senders(),
            osc.is_some_and(|o| o.failed > 0),
        );
        if self.last.as_ref() == Some(&key) {
            return;
        }
        let (mut line, note) = artnet_status(&latch);
        if let Some(o) = osc {
            line.push_str(&osc_status(o));
        }
        console::log(format!("{label} {line}"));
        if let Some(note) = note {
            console::log(format!("  {note}"));
        }
        self.last = Some(key);
    }
}

/// What a session shows on the panel.
struct SessionView<'a> {
    /// The publisher's address, or the source's state when pulling.
    peer: &'a str,
    since: Instant,
    publishing: bool,
    meter: &'a RateMeter,
    injector: Option<&'a Injector>,
    queued: usize,
    /// Whether the relay is holding the encoder back for the ingest to catch up.
    holding: bool,
    recording: Option<&'a Recording>,
    record_failed: Option<&'a str>,
}

#[derive(Default, Clone, Copy)]
struct Counts {
    packets: u64,
    late: u64,
    osc: u64,
    frames: u64,
}

/// The panel's side of the relay: when it last drew, and the counts it last
/// sampled, so each rate is over the last second or so rather than the run.
#[derive(Default)]
struct Dashboard {
    drawn: Option<Instant>,
    sampled: Option<(Instant, Counts)>,
    per_sec: [f64; 4],
}

impl Dashboard {
    fn tick(
        &mut self,
        cli: &Cli,
        session: Option<SessionView>,
        artnet: Option<&artnet::Receiver>,
        osc: Option<&osc::Sender>,
    ) {
        if !console::panel()
            || self
                .drawn
                .is_some_and(|t| t.elapsed() < Duration::from_secs(1))
        {
            return;
        }
        self.drawn = Some(Instant::now());
        let body = self.body(cli, session.as_ref(), artnet, osc);
        console::draw(body);
    }

    fn sample(&mut self, now: Counts) {
        let at = Instant::now();
        if let Some((then, before)) = self.sampled {
            let secs = at.duration_since(then).as_secs_f64();
            if secs < 0.5 {
                return;
            }
            let rate = |a: u64, b: u64| a.saturating_sub(b) as f64 / secs;
            self.per_sec = [
                rate(now.packets, before.packets),
                rate(now.late, before.late),
                rate(now.osc, before.osc),
                rate(now.frames, before.frames),
            ];
        }
        self.sampled = Some((at, now));
    }

    fn body(
        &mut self,
        cli: &Cli,
        session: Option<&SessionView>,
        artnet: Option<&artnet::Receiver>,
        osc: Option<&osc::Sender>,
    ) -> Vec<String> {
        let latch = artnet.map(|a| a.latch());
        self.sample(Counts {
            packets: latch.as_ref().map_or(0, |l| l.packets),
            late: latch.as_ref().map_or(0, |l| l.out_of_order),
            osc: osc.map_or(0, |o| o.sent),
            frames: session
                .and_then(|s| s.injector)
                .map_or(0, |i| i.stats.video_frames),
        });
        let [packets_s, late_s, osc_s, frames_s] = self.per_sec;
        let mut warnings = Vec::new();

        let mut lines = vec![format!(
            "truss-relay{}   up {}",
            match (&cli.publish, &cli.record) {
                (None, None) => "  (OSC lane only)",
                (None, Some(_)) => "  (recording only)",
                _ => "",
            },
            console::clock(console::uptime())
        )];

        if cli.publish.is_some() || cli.record.is_some() {
            let listen = format!("rtmp://{}/{}", cli.listen(), cli.listen_app());
            lines.push(match (&cli.pull, session) {
                (Some(spec), Some(s)) => format!(
                    "source    {}   {} for {}",
                    spec.display(),
                    s.peer,
                    console::clock(s.since.elapsed())
                ),
                (Some(spec), None) => format!("source    {}   starting", spec.display()),
                (None, Some(s)) => format!(
                    "encoder   {listen}   connected from {} for {}",
                    s.peer,
                    console::clock(s.since.elapsed())
                ),
                (None, None) => format!("encoder   {listen}   waiting for a publisher"),
            });
            if cli.publish.is_some() {
                lines.push(format!(
                    "ingest    {}   {}",
                    cli.target.url(),
                    match session {
                        None => "not connected",
                        Some(s) if s.publishing => "publishing",
                        Some(_) => "connecting",
                    }
                ));
            }
            if let Some(dir) = cli.record.as_deref() {
                let (line, failed) = record_status(dir, session);
                lines.push(line);
                if let Some(why) = failed {
                    warnings.push(why);
                }
            }
            if let Some(s) = session {
                let kbps = s.meter.kbps();
                let mut line = format!("stream    {kbps:.0} kb/s out");
                match s.injector {
                    Some(inj) => {
                        line.push_str(&format!(
                            "   frames {} ({frames_s:.1}/s)",
                            console::count(inj.stats.video_frames)
                        ));
                        for (carrier, n) in &inj.stats.injected {
                            line.push_str(&format!("   {carrier} {}", console::count(*n)));
                        }
                        line.push_str(&format!(
                            "   +{} kB added",
                            console::count(inj.stats.added_bytes / 1000)
                        ));
                    }
                    None => line.push_str("   passthrough, nothing injected"),
                }
                lines.push(line);
                if let Some(codec) = s.injector.and_then(|i| i.stats.unsupported_codec.as_ref()) {
                    warnings.push(format!(
                        "video is {codec}, which records cannot ride in: passing it through"
                    ));
                }
                if let Some(note) = s.injector.and_then(|i| oversize_note(i, cli)) {
                    warnings.push(note);
                }
                if let Some(note) = s.injector.and_then(|i| records_note(i, cli)) {
                    warnings.push(note);
                }
                if cli.publish.is_some() && kbps > cli.warn_kbps {
                    warnings.push(format!(
                        "{kbps:.0} kb/s is above {:.0}: lower the encoder bitrate or raise --every",
                        cli.warn_kbps
                    ));
                }
                if s.holding {
                    warnings.push(format!(
                        "{} kB queued: the upload is not keeping up, so the encoder is held \
                         back and drops frames as it would publishing directly",
                        s.queued / 1024
                    ));
                } else if s.queued > 64 * 1024 {
                    warnings.push(format!(
                        "{} kB queued: the upload is not keeping up",
                        s.queued / 1024
                    ));
                }
            }
        }

        if let Some(l) = latch.as_ref() {
            let mut line = format!(
                "art-net   {} universes   {packets_s:.0} pkt/s ({})   late {late_s:.0}/s ({})",
                l.universe_count(),
                console::count(l.packets),
                console::count(l.out_of_order)
            );
            if l.polls > 0 {
                line.push_str(&format!("   polls {}", console::count(l.polls)));
            }
            lines.push(line);
            if l.polls_unanswered > 0 {
                warnings.push(format!(
                    "{} polls unanswered: no route to the controller",
                    l.polls_unanswered
                ));
            }
            if l.reply_errors > 0 {
                warnings.push(format!("{} poll replies failed", l.reply_errors));
            }
            if let (_, Some(note)) = artnet_status(l) {
                warnings.push(note);
            }
        }
        drop(latch);

        if let Some(o) = osc {
            let mut line = format!(
                "osc       {} as {}   {osc_s:.1}/s ({})",
                o.target(),
                osc::ADDRESS,
                console::count(o.sent)
            );
            if o.failed > 0 {
                line.push_str(&format!("   {} failed", console::count(o.failed)));
            }
            lines.push(line);
        }

        if !warnings.is_empty() {
            lines.push(String::new());
            lines.extend(warnings.into_iter().map(|w| format!("! {w}")));
        }
        lines
    }
}

/// The panel's recording line, and a warning when the recording has stopped.
fn record_status(dir: &Path, session: Option<&SessionView>) -> (String, Option<String>) {
    let failed = |why: &str| Some(format!("recording stopped: {why}"));
    match (
        session.and_then(|s| s.recording),
        session.and_then(|s| s.record_failed),
    ) {
        (_, Some(why)) => (
            format!("record    {}   stopped", dir.display()),
            failed(why),
        ),
        (Some(r), None) => {
            let mut line = format!(
                "record    {}   {:.1} MB",
                r.path().display(),
                r.bytes() as f64 / 1e6
            );
            if let Some(codec) = r.codec() {
                line.push_str(&format!("   {}", codec.name()));
            }
            match r.stopped() {
                Some(why) => {
                    line.push_str("   stopped");
                    (line, failed(why))
                }
                None => (line, None),
            }
        }
        (None, None) => (
            format!("record    {}   waiting for the stream", dir.display()),
            None,
        ),
    }
}

fn osc_status(o: &osc::Sender) -> String {
    let mut s = format!("  osc {} sent", o.sent);
    if o.failed > 0 {
        s.push_str(&format!(" ({} failed)", o.failed));
    }
    s
}

/// The Art-Net fragment of a status line, and a note when the lane needs
/// explaining.
///
/// An empty lane and a dead lane look identical in the record counts, so the
/// note says which this is rather than leaving it to be inferred. A desk that
/// has polled and sent nothing is a third case, waiting on the operator rather
/// than on the network, and a steady share of late packets is a fourth: two
/// senders carrying the same universes, which a desk does when it is set to
/// send both to this node and to localhost.
fn artnet_status(latch: &artnet::Latch) -> (String, Option<String>) {
    let mut line = format!(
        " dmx {} universes {} packets",
        latch.universe_count(),
        latch.packets
    );
    if latch.out_of_order > 0 {
        line.push_str(&format!(" ({} late)", latch.out_of_order));
    }
    if latch.polls > 0 {
        line.push_str(&format!("  polls {}", latch.polls));
    }
    if latch.polls_unanswered > 0 {
        line.push_str(&format!(
            " ({} unanswered, no route to the controller)",
            latch.polls_unanswered
        ));
    }
    if latch.reply_errors > 0 {
        line.push_str(&format!(" ({} replies failed)", latch.reply_errors));
    }
    let note = latch.error.clone().or_else(|| {
        (latch.packets == 0).then(|| match latch.last_controller {
            Some(c) => format!(
                "a controller at {c} has found this node and sent no DMX yet: \
                 assign it a universe on the desk"
            ),
            None => "no Art-Net received yet: records are going out with empty payloads".into(),
        })
    });
    let note = note.or_else(|| {
        latch.two_senders().then(|| {
            "a steady share of packets arrive late: two senders are carrying the same \
             universes, as a desk does when set to send both to this node and to localhost"
                .into()
        })
    });
    (line, note)
}

/// The upstream leg: our RTMP client connection to the ingest server.
struct Upstream {
    socket: TcpStream,
    out: OutBuf,
    session: ClientSession,
    publishing: bool,
    /// A/V that arrived before the ingest server accepted the publish. OBS starts sending
    /// the moment it connects, and the upstream handshake plus connect round
    /// trip takes long enough that dropping these would lose the sequence
    /// header and leave the ingest server with an undecodable stream.
    pending: Vec<(bool, Bytes, RtmpTimestamp)>,
    pending_bytes: usize,
    /// OBS sends `onMetaData` immediately after its publish is accepted, which
    /// is well before ours is. It has to be held and sent ahead of the first
    /// A/V, not dropped: it carries the width, height and codec ids.
    pending_metadata: Option<StreamMetadata>,
}

/// The onward half of a session: injection, the publish to the ingest server,
/// the rate meter and the periodic report. The input side feeds it A/V and
/// metadata and calls [`Onward::pass`] once per loop.
struct Onward<'a> {
    cli: &'a Cli,
    artnet: Option<&'a artnet::Receiver>,
    osc: &'a mut Option<osc::Sender>,
    key: Option<&'a creds::Secret>,
    injector: Option<Injector>,
    upstream: Option<Upstream>,
    meter: RateMeter,
    last_report: Instant,
    /// The note under the status line is printed when it changes, not with
    /// every line: a desk sending the same way for an hour is said once.
    last_note: Option<String>,
    buf: Vec<u8>,
    /// Times the encoder was held back since the last report.
    held_back: u32,
    /// This session's file, from its first tag.
    recording: Option<Recording>,
    /// Why the file could not be created, when it could not.
    record_failed: Option<String>,
}

impl<'a> Onward<'a> {
    fn new(
        cli: &'a Cli,
        carriers: &[Carrier],
        artnet: Option<&'a artnet::Receiver>,
        osc: &'a mut Option<osc::Sender>,
        key: Option<&'a creds::Secret>,
    ) -> Result<Self> {
        let injector = (!cli.passthrough)
            .then(|| {
                Injector::new(&InjectOptions {
                    carriers: carriers.to_vec(),
                    every_n_frames: cli.every,
                    payload_len: cli.payload_len,
                    keyframes_only: false,
                })
                .map(|i| i.strip_existing(strips_records(cli)))
            })
            .transpose()?;
        Ok(Self {
            cli,
            artnet,
            osc,
            key,
            injector,
            upstream: None,
            meter: RateMeter::new(),
            last_report: Instant::now(),
            last_note: None,
            buf: vec![0u8; 32 * 1024],
            held_back: 0,
            recording: None,
            record_failed: None,
        })
    }

    /// Dial the ingest server, once per session, when there is one.
    fn connect(&mut self) -> Result<()> {
        if self.cli.publish.is_some() && self.upstream.is_none() {
            self.upstream = Some(connect_upstream(self.cli)?);
        }
        Ok(())
    }

    /// End the publish, so the ingest shows the stream as ended rather than
    /// holding it open with nothing in it, and the recording with it: the
    /// next [`Onward::connect`] publishes afresh, from a new timeline, and the
    /// next tag starts a new file.
    fn disconnect(&mut self) {
        self.upstream = None;
        self.close_recording();
    }

    fn close_recording(&mut self) {
        if let Some(r) = self.recording.take() {
            console::event(format!(
                "recorded {:.1} MB to {}",
                r.bytes() as f64 / 1e6,
                r.path().display()
            ));
        }
    }

    fn metadata(&mut self, metadata: &StreamMetadata) -> Result<()> {
        self.record(|r| r.metadata(metadata))?;
        if let Some(up) = self.upstream.as_mut() {
            forward_metadata(up, metadata)?;
        }
        Ok(())
    }

    /// Hand one write to this session's recording, opening the file on the
    /// first. A failed write stops the recording and the publish carries on;
    /// with nothing published it ends the session.
    fn record(&mut self, write: impl FnOnce(&mut Recording) -> Result<()>) -> Result<()> {
        let Some(dir) = self.cli.record.as_deref() else {
            return Ok(());
        };
        if self.record_failed.is_some() {
            return Ok(());
        }
        if self.recording.is_none() {
            match Recording::create(dir) {
                Ok(r) => {
                    console::event(format!("recording to {}", r.path().display()));
                    self.recording = Some(r);
                }
                Err(e) => return self.record_stopped(format!("{e:#}")),
            }
        }
        let Some(recording) = self.recording.as_mut() else {
            return Ok(());
        };
        match write(recording) {
            Ok(()) => Ok(()),
            Err(e) => self.record_stopped(format!("{e:#}")),
        }
    }

    fn record_stopped(&mut self, why: String) -> Result<()> {
        if self.cli.publish.is_none() {
            bail!("recording stopped: {why}");
        }
        console::event(format!("recording stopped: {why}; the publish carries on"));
        if self.recording.is_none() {
            self.record_failed = Some(why);
        }
        Ok(())
    }

    fn video(&mut self, data: Bytes, timestamp: RtmpTimestamp) -> Result<()> {
        let cli = self.cli;
        let payload = match self.injector.as_mut() {
            Some(inj) => {
                if matches!(truss::flv::video(&data), truss::flv::Video::Config { .. }) {
                    inj.note_sequence_header(&data)?;
                    data
                } else {
                    let dmx = self.artnet.map(|a| {
                        let blocks = a.latch().snapshot(Instant::now(), cli.artnet_max_payload);
                        truss::payload::encode(&blocks)
                    });
                    // Three states, and collapsing any two of them is wrong.
                    // No Art-Net at all means inject the sequence-derived
                    // body a measurement run wants. A lane that failed to
                    // encode must skip the frame instead: passing None there
                    // would put that test body on the wire mid-show.
                    //
                    // --artnet-max-payload is checked against the record
                    // limit at startup and snapshot honours it strictly, so
                    // the failing arm is unreachable today. It is written out
                    // because the cost of getting it wrong is a show carrying
                    // probe data instead of its lighting.
                    let rewritten = match dmx {
                        Some(Ok(bytes)) => {
                            let now = now_unix_nanos();
                            let written = inj.records_written();
                            let rewritten = inj.inject_tag_with(&data, now, Some(&bytes))?;
                            // The lane carries the payload the stream carries,
                            // so a frame that got no record of its own gets
                            // none on the lane, even if it was rewritten to
                            // strip records already in it.
                            if inj.records_written() > written
                                && let Some(o) = self.osc.as_mut()
                            {
                                o.send(&bytes, now);
                            }
                            rewritten
                        }
                        Some(Err(_)) => None,
                        None => inj.inject_tag_with(&data, now_unix_nanos(), None)?,
                    };
                    match rewritten {
                        Some(rewritten) => Bytes::from(rewritten),
                        None => data,
                    }
                }
            }
            None => data,
        };
        self.record(|r| r.video(timestamp.value, &payload))?;
        self.recorded_only(payload.len());
        forward_av(
            &mut self.upstream,
            &mut self.meter,
            true,
            payload,
            timestamp,
        )
    }

    fn audio(&mut self, data: Bytes, timestamp: RtmpTimestamp) -> Result<()> {
        self.record(|r| r.audio(timestamp.value, &data))?;
        self.recorded_only(data.len());
        forward_av(&mut self.upstream, &mut self.meter, false, data, timestamp)
    }

    /// With nothing published, the rate on the panel and in the report is
    /// what goes to the file.
    fn recorded_only(&mut self, len: usize) {
        if self.cli.publish.is_none() && self.recording.is_some() {
            self.meter.add(len);
        }
    }

    /// One pass over the ingest connection, then the report when it is due.
    /// Returns whether anything arrived from the ingest or is still queued
    /// for it, so the caller knows not to sleep.
    fn pass(&mut self) -> Result<bool> {
        let mut busy = false;
        if let Some(up) = self.upstream.as_mut() {
            // The ingest server sends acknowledgements and pings; ignoring
            // them stalls the connection once the window fills.
            busy |= service_upstream(up, self.key, &mut self.meter, &mut self.buf)?;
            // Drained every pass rather than at the point of each write, so
            // a momentarily full send buffer costs a millisecond instead of
            // ending the session.
            up.out
                .pump(&mut up.socket)
                .context("writing to the ingest server")?;
            busy |= up.out.pending() > 0;
        }
        if self.last_report.elapsed() >= Duration::from_secs(5) {
            self.last_report = Instant::now();
            self.report(self.queued())?;
        }
        Ok(busy)
    }

    fn queued(&self) -> usize {
        self.upstream.as_ref().map_or(0, |u| u.out.pending())
    }

    fn report(&mut self, queued: usize) -> Result<()> {
        let held_back = std::mem::take(&mut self.held_back);
        report(
            &self.meter,
            self.injector.as_ref(),
            self.cli,
            queued,
            held_back,
            self.artnet,
            self.osc.as_ref(),
            &mut self.last_note,
        )
    }

    /// The panel's view of this session.
    fn view<'v>(&'v self, peer: &'v str, since: Instant) -> SessionView<'v> {
        SessionView {
            peer,
            since,
            publishing: self.upstream.as_ref().is_some_and(|u| u.publishing),
            meter: &self.meter,
            injector: self.injector.as_ref(),
            queued: self.queued(),
            holding: false,
            recording: self.recording.as_ref(),
            record_failed: self.record_failed.as_deref(),
        }
    }
}

impl Drop for Onward<'_> {
    fn drop(&mut self) {
        self.close_recording();
    }
}

/// A session fed by an RTMP publisher: the encoder connected to `--listen`.
#[allow(clippy::too_many_arguments)]
fn session_listen(
    mut obs: TcpStream,
    cli: &Cli,
    carriers: &[Carrier],
    artnet: Option<&artnet::Receiver>,
    osc: &mut Option<osc::Sender>,
    key: Option<&creds::Secret>,
    peer: &str,
    dash: &mut Dashboard,
    idle_timeout: Duration,
) -> Result<()> {
    let started = Instant::now();
    obs.set_nodelay(true).ok();
    let leftover = server_handshake(&mut obs, HANDSHAKE_TIMEOUT)?;

    let (mut server, initial) = ServerSession::new(ServerSessionConfig::new())
        .map_err(|e| anyhow!("creating server session: {e:?}"))?;
    let mut obs_out = OutBuf::default();
    queue_server(&mut obs_out, initial);
    let first = server
        .handle_input(&leftover)
        .map_err(|e| anyhow!("server handle_input: {e:?}"))?;
    let mut events = Vec::new();
    for r in first {
        match r {
            ServerSessionResult::OutboundResponse(p) => obs_out.push(&p.bytes),
            ServerSessionResult::RaisedEvent(e) => events.push(e),
            ServerSessionResult::UnhandleableMessageReceived(_) => {}
        }
    }
    // Still blocking at this point, so this cannot short-write.
    obs_out.pump(&mut obs)?;

    let mut onward = Onward::new(cli, carriers, artnet, osc, key)?;
    let mut buf = vec![0u8; 32 * 1024];
    let mut heard = Instant::now();
    let mut backpressure = Backpressure::default();
    let mut hold_said: Option<Instant> = None;
    // When the queue last shrank during this hold, and how far.
    let mut drained: Option<(Instant, usize)> = None;
    obs.set_nonblocking(true)?;

    loop {
        let mut idle = true;

        // Drain anything already queued from the handshake bytes.
        for event in events.drain(..) {
            publisher_event(event, &mut server, &mut obs_out, &mut onward)?;
        }

        let held = backpressure.holding();
        let holding = backpressure.hold(onward.queued(), onward.meter.kbps());
        if holding && !held {
            // A marginal uplink holds and releases several times a second,
            // so this is said once in a while and counted in the report.
            onward.held_back += 1;
            if hold_said.is_none_or(|t: Instant| t.elapsed() >= HOLD_NOTICE_EVERY) {
                console::event(
                    "the upload is not keeping up: holding the encoder back, so it drops \
                     frames as it would publishing directly",
                );
                hold_said = Some(Instant::now());
            }
        }
        if holding {
            // While holding nothing is added, so a queue that has not shrunk
            // in this long has stopped draining: an ingest that has stopped
            // reading, which would otherwise hold the session for ever.
            let queued = onward.queued();
            let (since, lowest) = drained.get_or_insert((Instant::now(), queued));
            if queued < *lowest {
                *since = Instant::now();
                *lowest = queued;
            }
            if since.elapsed() >= idle_timeout {
                bail!(
                    "{} kB queued and not draining for {idle_timeout:?}; the upstream \
                     connection cannot keep up",
                    onward.queued() / 1024
                );
            }
            // Time spent not reading is not the publisher going quiet.
            heard = Instant::now();
        } else {
            drained = None;
            match obs.read(&mut buf) {
                Ok(0) => {
                    console::event("publisher disconnected");
                    break;
                }
                Ok(n) => {
                    idle = false;
                    heard = Instant::now();
                    let results = server
                        .handle_input(&buf[..n])
                        .map_err(|e| anyhow!("server handle_input: {e:?}"))?;
                    for r in results {
                        match r {
                            ServerSessionResult::OutboundResponse(p) => {
                                obs_out.push(&p.bytes);
                            }
                            ServerSessionResult::RaisedEvent(e) => {
                                publisher_event(e, &mut server, &mut obs_out, &mut onward)?;
                            }
                            ServerSessionResult::UnhandleableMessageReceived(_) => {}
                        }
                    }
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    if heard.elapsed() >= idle_timeout {
                        bail!("publisher sent nothing for {idle_timeout:?}");
                    }
                }
                Err(e) => return Err(e).context("reading from publisher"),
            }
        }

        obs_out.pump(&mut obs).context("writing to publisher")?;
        if onward.pass()? {
            idle = false;
        }

        dash.tick(
            cli,
            Some(SessionView {
                holding: backpressure.holding(),
                ..onward.view(peer, started)
            }),
            artnet,
            onward.osc.as_ref(),
        );

        if idle {
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    onward.report(0)
}

/// The source refused the login. The relay stops rather than start again.
#[derive(Debug)]
struct SourceRefused(String);

impl std::fmt::Display for SourceRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SourceRefused {}

/// A session fed by the RTSP source named in `--source`. It ends when the
/// source does.
#[allow(clippy::too_many_arguments)]
fn session_pull(
    spec: pull::Spec,
    cli: &Cli,
    carriers: &[Carrier],
    artnet: Option<&artnet::Receiver>,
    osc: &mut Option<osc::Sender>,
    key: Option<&creds::Secret>,
    dash: &mut Dashboard,
) -> Result<()> {
    let started = Instant::now();
    let mut source = pull::spawn(spec).context("starting the source thread")?;
    let mut onward = Onward::new(cli, carriers, artnet, osc, key)?;
    let mut state = SourceState::Connecting.describe();
    let mut timeline = Timeline::default();
    let mut records_said = false;
    let mut dropped: u64 = 0;
    let mut codec = VideoCodec::H264;
    // The relay writes the onMetaData an encoder would have sent, from what
    // the source's parameters say.
    let mut metadata = StreamMetadata::new();
    metadata.encoder = Some("truss-relay".into());

    loop {
        let mut idle = true;
        loop {
            let event = match source.try_recv() {
                Ok(event) => event,
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                    bail!("the source thread stopped")
                }
            };
            idle = false;
            match event {
                SourceEvent::State(s) => {
                    state = s.describe();
                    console::event(format!("source {state}"));
                }
                SourceEvent::Note(note) => console::event(format!("source: {note}")),
                SourceEvent::Video {
                    codec: video_codec,
                    config,
                    width,
                    height,
                    fps,
                } => {
                    codec = video_codec;
                    let depth = pull::timing::reorder_depth(codec, &config);
                    let frame_us = fps
                        .filter(|f| *f > 0.0)
                        .map_or(33_333, |f| (1e6 / f) as i64);
                    if timeline.video_parameters(depth, frame_us) {
                        console::log(format!(
                            "source video {} {width}x{height}, {}",
                            codec.name(),
                            match depth {
                                Some(0) => "no reordering".to_string(),
                                Some(d) => format!("reorders up to {d} frames"),
                                None => "reorder depth learnt as frames arrive".to_string(),
                            }
                        ));
                    }
                    metadata.video_width = Some(width);
                    metadata.video_height = Some(height);
                    metadata.video_codec_id = Some(match codec {
                        VideoCodec::H264 => 7,
                        // Enhanced RTMP gives the FourCC as a number.
                        VideoCodec::Hevc => u32::from_be_bytes(*b"hvc1"),
                    });
                    metadata.video_frame_rate = fps.map(|f| f as f32);
                    onward.connect()?;
                    onward.metadata(&metadata)?;
                    onward.video(
                        Bytes::from(truss::flv::video_sequence_header(codec, &config)),
                        RtmpTimestamp::new(timeline.last(VIDEO)),
                    )?;
                }
                SourceEvent::Audio {
                    asc,
                    sample_rate,
                    channels,
                } => {
                    metadata.audio_codec_id = Some(10);
                    metadata.audio_sample_rate = Some(sample_rate);
                    metadata.audio_channels = Some(u32::from(channels));
                    metadata.audio_is_stereo = Some(channels == 2);
                    onward.connect()?;
                    onward.metadata(&metadata)?;
                    onward.audio(
                        Bytes::from(truss::flv::aac_sequence_header(&asc)),
                        RtmpTimestamp::new(timeline.last(AUDIO)),
                    )?;
                }
                SourceEvent::VideoFrame { data, pts_us, key } => {
                    let held = timeline.held();
                    // A frame the publish cannot express is dropped, not the
                    // session: the source's next keyframe repairs the picture.
                    let tag = match timeline.video_tag(codec, key, pts_us, &data, Instant::now()) {
                        Ok(tag) => tag,
                        Err(e) => {
                            dropped += 1;
                            if dropped.is_power_of_two() {
                                console::event(format!(
                                    "source video frame dropped, {dropped} so far: {e:#}"
                                ));
                            }
                            continue;
                        }
                    };
                    if let Some(step) = tag.jump {
                        say_jump("video", step);
                    }
                    if tag.grew {
                        console::log(format!(
                            "source reorders frames: decode delay now {} frames",
                            timeline.depth()
                        ));
                    }
                    if timeline.held() > held && timeline.held().is_power_of_two() {
                        console::event(format!(
                            "source timestamps went back; {} frames held so far",
                            timeline.held()
                        ));
                    }
                    onward.video(Bytes::from(tag.data), RtmpTimestamp::new(tag.timestamp))?;
                    if !records_said
                        && let Some(note) =
                            onward.injector.as_ref().and_then(|i| records_note(i, cli))
                    {
                        console::event(format!("source: {note}"));
                        records_said = true;
                    }
                }
                SourceEvent::AudioFrame { data, pts_us } => {
                    let (out, jump) = timeline.audio(pts_us, Instant::now());
                    if let Some(step) = jump {
                        say_jump("audio", step);
                    }
                    onward.audio(
                        Bytes::from(truss::flv::aac_frame(&data)),
                        RtmpTimestamp::new(out),
                    )?;
                }
                SourceEvent::Lost(why) => {
                    // The publish stays open through the quick reconnects:
                    // an ingest commonly refuses a second publish while it
                    // still counts the first, and viewers see a pause.
                    console::event(format!("source lost: {why}"));
                    timeline.lost(Instant::now());
                }
                SourceEvent::Down => {
                    console::event("source down: ending the publish until it plays again");
                    onward.disconnect();
                    timeline = Timeline::default();
                }
                SourceEvent::Refused(why) => return Err(SourceRefused(why).into()),
            }
        }

        if onward.pass()? {
            idle = false;
        }
        dash.tick(
            cli,
            Some(onward.view(&state, started)),
            artnet,
            onward.osc.as_ref(),
        );
        if idle {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

/// A stream's timeline jumped by `step_us` and carries on from where the
/// publish is.
fn say_jump(stream: &str, step_us: i64) {
    console::event(format!(
        "source {stream} timeline jumped {} by {:.1} s; carrying on from the last timestamp",
        if step_us < 0 { "back" } else { "forward" },
        step_us.unsigned_abs() as f64 / 1e6
    ));
}

/// Act on one event from the publisher's RTMP session: accept its requests,
/// dial the ingest when it asks to publish, and hand its A/V onward.
fn publisher_event(
    event: ServerSessionEvent,
    server: &mut ServerSession,
    obs_out: &mut OutBuf,
    onward: &mut Onward,
) -> Result<()> {
    match event {
        ServerSessionEvent::ConnectionRequested { request_id, .. } => {
            let results = server
                .accept_request(request_id)
                .map_err(|e| anyhow!("accept_request: {e:?}"))?;
            queue_server(obs_out, results);
        }
        ServerSessionEvent::ReleaseStreamRequested { request_id, .. } => {
            let results = server
                .accept_request(request_id)
                .map_err(|e| anyhow!("accept_request: {e:?}"))?;
            queue_server(obs_out, results);
        }
        ServerSessionEvent::PublishStreamRequested {
            request_id,
            stream_key,
            ..
        } => {
            // OBS's key is ignored: the relay holds the real one. Any value
            // works locally, which keeps the real key out of OBS entirely.
            console::log(format!(
                "publisher requested stream key {stream_key:?} (ignored, relay holds the real key)"
            ));
            let results = server
                .accept_request(request_id)
                .map_err(|e| anyhow!("accept_request: {e:?}"))?;
            queue_server(obs_out, results);
            onward.connect()?;
        }
        ServerSessionEvent::StreamMetadataChanged { metadata, .. } => {
            onward.metadata(&metadata)?;
        }
        ServerSessionEvent::VideoDataReceived {
            data, timestamp, ..
        } => {
            onward.video(data, timestamp)?;
        }
        ServerSessionEvent::AudioDataReceived {
            data, timestamp, ..
        } => {
            onward.audio(data, timestamp)?;
        }
        ServerSessionEvent::PublishStreamFinished { .. } => {
            console::event("publisher stopped");
        }
        _ => {}
    }
    Ok(())
}

/// Read and act on whatever the ingest server has sent. Returns whether
/// anything arrived.
fn service_upstream(
    up: &mut Upstream,
    key: Option<&creds::Secret>,
    meter: &mut RateMeter,
    buf: &mut [u8],
) -> Result<bool> {
    let n = match up.socket.read(buf) {
        Ok(0) => bail!("the ingest server closed the connection"),
        Ok(n) => n,
        Err(ref e) if e.kind() == ErrorKind::WouldBlock => return Ok(false),
        Err(e) => return Err(e).context("reading from the ingest server"),
    };
    let results = up
        .session
        .handle_input(&buf[..n])
        .map_err(|e| anyhow!("client handle_input: {e:?}"))?;
    let mut just_accepted = false;
    for r in results {
        match r {
            ClientSessionResult::OutboundResponse(p) => {
                up.out.push(&p.bytes);
            }
            ClientSessionResult::RaisedEvent(e) => match e {
                ClientSessionEvent::ConnectionRequestAccepted => {
                    let res = up
                        .session
                        .request_publishing(
                            key.ok_or_else(|| anyhow!("no stream key resolved"))?
                                .expose()
                                .to_owned(),
                            PublishRequestType::Live,
                        )
                        .map_err(|e| anyhow!("request_publishing: {e:?}"))?;
                    queue_client(&mut up.out, res);
                }
                ClientSessionEvent::ConnectionRequestRejected { description } => {
                    bail!("the ingest server rejected the connection: {description}");
                }
                ClientSessionEvent::PublishRequestAccepted => {
                    console::event("ingest accepted the publish");
                    up.publishing = true;
                    just_accepted = true;
                }
                ClientSessionEvent::UnhandleableOnStatusCode { code } => {
                    // BadAuth here usually does not mean the key is wrong. An
                    // ingest commonly rejects a second publish while it still
                    // considers the previous one connected, which is what you
                    // hit reconnecting straight after a run.
                    if code.contains("BadAuth") || code.contains("BadName") {
                        bail!(
                            "the ingest server refused the publish ({code}). If the key is \
                             right, the previous session is probably still connected: wait \
                             for the stream to drop, or press Disconnect in the control panel."
                        );
                    }
                    console::event(format!("ingest status: {code}"));
                }
                _ => {}
            },
            ClientSessionResult::UnhandleableMessageReceived(_) => {}
        }
    }
    if just_accepted {
        flush_pending(up, meter)?;
    }
    Ok(true)
}

fn forward_av(
    upstream: &mut Option<Upstream>,
    meter: &mut RateMeter,
    is_video: bool,
    data: Bytes,
    timestamp: RtmpTimestamp,
) -> Result<()> {
    let Some(up) = upstream.as_mut() else {
        return Ok(());
    };
    if !up.publishing {
        // Cap the pre-publish buffer. If the ingest server has not accepted after a few
        // seconds of video something is wrong, and growing without bound would
        // turn that into an out-of-memory rather than an error message.
        if up.pending_bytes < 8 * 1024 * 1024 {
            up.pending_bytes += data.len();
            up.pending.push((is_video, data, timestamp));
        }
        return Ok(());
    }
    publish_one(up, meter, is_video, data, timestamp)
}

fn publish_one(
    up: &mut Upstream,
    meter: &mut RateMeter,
    is_video: bool,
    data: Bytes,
    timestamp: RtmpTimestamp,
) -> Result<()> {
    let len = data.len();
    let res = if is_video {
        up.session.publish_video_data(data, timestamp, false)
    } else {
        up.session.publish_audio_data(data, timestamp, false)
    }
    .map_err(|e| anyhow!("publishing: {e:?}"))?;
    meter.add(len);
    queue_client(&mut up.out, res);
    Ok(())
}

fn flush_pending(up: &mut Upstream, meter: &mut RateMeter) -> Result<()> {
    // Metadata first: it describes the media that follows.
    if let Some(metadata) = up.pending_metadata.take() {
        send_metadata_now(up, &metadata)?;
    }
    let pending = std::mem::take(&mut up.pending);
    up.pending_bytes = 0;
    if !pending.is_empty() {
        console::log(format!("flushing {} buffered messages", pending.len()));
    }
    for (is_video, data, ts) in pending {
        publish_one(up, meter, is_video, data, ts)?;
    }
    Ok(())
}

fn forward_metadata(up: &mut Upstream, metadata: &StreamMetadata) -> Result<()> {
    if !up.publishing {
        up.pending_metadata = Some(metadata.clone());
        return Ok(());
    }
    send_metadata_now(up, metadata)
}

fn send_metadata_now(up: &mut Upstream, metadata: &StreamMetadata) -> Result<()> {
    let res = up
        .session
        .publish_metadata(metadata)
        .map_err(|e| anyhow!("publish_metadata: {e:?}"))?;
    queue_client(&mut up.out, res);
    Ok(())
}

/// Queue a session result for the upstream socket. Blocking variant, used only
/// during connection setup while the socket is still in blocking mode.
fn send_client_blocking(socket: &mut TcpStream, result: ClientSessionResult) -> Result<()> {
    if let ClientSessionResult::OutboundResponse(p) = result {
        socket.write_all(&p.bytes).context("writing upstream")?;
    }
    Ok(())
}

fn queue_client(out: &mut OutBuf, result: ClientSessionResult) {
    if let ClientSessionResult::OutboundResponse(p) = result {
        out.push(&p.bytes);
    }
}

fn queue_server(out: &mut OutBuf, results: Vec<ServerSessionResult>) {
    for r in results {
        if let ServerSessionResult::OutboundResponse(p) = r {
            out.push(&p.bytes);
        }
    }
}

/// The publisher socket's receive buffer. Left to itself, Windows grows a
/// loopback socket's buffer into megabytes, which would hide a slow uplink
/// from the encoder for seconds after the relay stops reading. Set on the
/// listener, so accepted sockets start with it.
const PUBLISHER_RECV_BUFFER: usize = 256 * 1024;

/// The ingest socket's send buffer. Left to itself it grows into megabytes,
/// a backlog the relay cannot see and so cannot hold the encoder back for.
/// 512 kB covers about 13 Mb/s over a 300 ms round trip, so it does not cap
/// a real link.
const UPSTREAM_SEND_BUFFER: usize = 512 * 1024;

/// How often holding the encoder back is announced, at most.
const HOLD_NOTICE_EVERY: Duration = Duration::from_secs(30);

/// Bind the first of `addr`'s addresses that will, as std's
/// `TcpListener::bind` does: `localhost` can resolve to `::1` first on a host
/// without IPv6.
fn bind_listener(addr: &str) -> Result<TcpListener> {
    let mut last = None;
    for addr in addr.to_socket_addrs()? {
        match bind_one(addr) {
            Ok(listener) => return Ok(listener),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| anyhow!("resolves to no address")))
}

fn bind_one(addr: SocketAddr) -> Result<TcpListener> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(addr),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    // As std's TcpListener::bind does, so a restart is not refused while the
    // last session's connections are in TIME_WAIT. On Windows the option
    // lets another socket take the port, so it stays off there.
    #[cfg(not(windows))]
    socket.set_reuse_address(true)?;
    socket.set_recv_buffer_size(PUBLISHER_RECV_BUFFER)?;
    socket.bind(&addr.into())?;
    socket.listen(128)?;
    Ok(socket.into())
}

fn connect_upstream(cli: &Cli) -> Result<Upstream> {
    console::event(format!("connecting to {}...", cli.target.authority));
    let mut socket = connect_ingest(&cli.target.authority, INGEST_CONNECT_TIMEOUT)?;
    socket.set_nodelay(true).ok();
    socket2::SockRef::from(&socket)
        .set_send_buffer_size(UPSTREAM_SEND_BUFFER)
        .ok();
    let leftover = client_handshake(&mut socket, INGEST_HANDSHAKE_TIMEOUT)?;

    let mut config = ClientSessionConfig::new();
    config.tc_url = Some(cli.target.url());
    let (mut session, initial) =
        ClientSession::new(config).map_err(|e| anyhow!("creating client session: {e:?}"))?;
    for r in initial {
        send_client_blocking(&mut socket, r)?;
    }
    if !leftover.is_empty() {
        let results = session
            .handle_input(&leftover)
            .map_err(|e| anyhow!("client handle_input: {e:?}"))?;
        for r in results {
            send_client_blocking(&mut socket, r)?;
        }
    }
    let res = session
        .request_connection(cli.target.app.clone())
        .map_err(|e| anyhow!("request_connection: {e:?}"))?;
    send_client_blocking(&mut socket, res)?;
    socket.set_nonblocking(true)?;

    Ok(Upstream {
        socket,
        session,
        out: OutBuf::default(),
        publishing: false,
        pending: Vec::new(),
        pending_bytes: 0,
        pending_metadata: None,
    })
}

/// How long a publisher has to complete the RTMP handshake. Publishers are
/// served one at a time, so a connection that opens and then says nothing
/// would otherwise hold the only slot, and the Art-Net lane with it, for as
/// long as it stays open. The deadline covers the whole exchange rather than
/// each read, so a peer trickling a byte at a time runs out too.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a publisher can send nothing, once the handshake is done, before
/// it is dropped. Any stream key is accepted, so without this a connection
/// could complete the handshake, go quiet and hold the only slot. With no TCP
/// keepalive, it is also what notices a publisher that vanished without
/// closing the connection.
const PUBLISHER_IDLE_TIMEOUT: Duration = Duration::from_secs(15);

/// How long the ingest server has to complete the RTMP handshake. The relay
/// waits for it on its only thread, so an ingest that accepts the connection
/// and then stalls would otherwise stop everything. Longer than the
/// publisher's because the ingest is usually remote.
const INGEST_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the ingest has to accept the TCP connection, across every address
/// it resolves to. One that drops the connection attempt would otherwise hold
/// the relay's only thread for as long as the OS waits. The name lookup before
/// it is not covered: bounding that would take a thread of its own.
const INGEST_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Connect to `authority` within `budget`, trying the addresses it resolves
/// to in turn. Each attempt gets an even share of what is left, so an address
/// that swallows the attempt, as a broken IPv6 route does, cannot leave none
/// for the next.
fn connect_ingest(authority: &str, budget: Duration) -> Result<TcpStream> {
    let addrs: Vec<SocketAddr> = authority
        .to_socket_addrs()
        .with_context(|| format!("resolving {authority}"))?
        .collect();
    if addrs.is_empty() {
        bail!("{authority} resolves to no address");
    }
    connect_any(&addrs, budget).with_context(|| format!("connecting to {authority}"))
}

/// The first of `addrs` to accept within `budget`, in order, each attempt
/// taking an even share of what is left.
fn connect_any(addrs: &[SocketAddr], budget: Duration) -> std::io::Result<TcpStream> {
    let deadline = Instant::now() + budget;
    let mut last = None;
    for (i, addr) in addrs.iter().enumerate() {
        let left = deadline.saturating_duration_since(Instant::now());
        let share = left / u32::try_from(addrs.len() - i).unwrap_or(u32::MAX);
        if share.is_zero() {
            break;
        }
        match TcpStream::connect_timeout(addr, share) {
            Ok(socket) => return Ok(socket),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| std::io::Error::from(ErrorKind::TimedOut)))
}

fn server_handshake(socket: &mut TcpStream, timeout: Duration) -> Result<Vec<u8>> {
    let clock = HandshakeClock::start(timeout, "publisher");
    let mut handshake = Handshake::new(PeerType::Server);
    let mut buf = vec![0u8; 4096];
    let result = loop {
        let n = clock.read(socket, &mut buf)?;
        if n == 0 {
            bail!("publisher closed during handshake");
        }
        match handshake
            .process_bytes(&buf[..n])
            .map_err(|e| anyhow!("handshake: {e:?}"))?
        {
            HandshakeProcessResult::InProgress { response_bytes } => {
                clock.write(socket, &response_bytes)?;
            }
            HandshakeProcessResult::Completed {
                response_bytes,
                remaining_bytes,
            } => {
                if !response_bytes.is_empty() {
                    clock.write(socket, &response_bytes)?;
                }
                break remaining_bytes;
            }
        }
    };
    socket.set_read_timeout(None)?;
    socket.set_write_timeout(None)?;
    Ok(result)
}

/// One deadline across every read and write of a handshake, and the peer to
/// name when it runs out.
struct HandshakeClock {
    deadline: Instant,
    timeout: Duration,
    peer: &'static str,
}

impl HandshakeClock {
    fn start(timeout: Duration, peer: &'static str) -> Self {
        Self {
            deadline: Instant::now() + timeout,
            timeout,
            peer,
        }
    }

    fn read(&self, socket: &mut TcpStream, buf: &mut [u8]) -> Result<usize> {
        socket.set_read_timeout(Some(self.left()?))?;
        match socket.read(buf) {
            Err(ref e) if timed_out(e) => Err(self.expired()),
            other => other.context("handshake read"),
        }
    }

    fn write(&self, socket: &mut TcpStream, bytes: &[u8]) -> Result<()> {
        socket.set_write_timeout(Some(self.left()?))?;
        match socket.write_all(bytes) {
            Err(ref e) if timed_out(e) => Err(self.expired()),
            other => other.context("handshake write"),
        }
    }

    fn left(&self) -> Result<Duration> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(self.expired());
        }
        Ok(left)
    }

    fn expired(&self) -> anyhow::Error {
        anyhow!(
            "{} did not complete the handshake within {:?}",
            self.peer,
            self.timeout
        )
    }
}

/// A socket timeout is WouldBlock on Unix and TimedOut on Windows.
fn timed_out(e: &std::io::Error) -> bool {
    matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
}

fn client_handshake(socket: &mut TcpStream, timeout: Duration) -> Result<Vec<u8>> {
    let clock = HandshakeClock::start(timeout, "the ingest server");
    let mut handshake = Handshake::new(PeerType::Client);
    let start = handshake
        .generate_outbound_p0_and_p1()
        .map_err(|e| anyhow!("handshake start: {e:?}"))?;
    clock.write(socket, &start)?;

    let mut buf = vec![0u8; 4096];
    let result = loop {
        let n = clock.read(socket, &mut buf)?;
        if n == 0 {
            bail!("the ingest server closed during handshake");
        }
        match handshake
            .process_bytes(&buf[..n])
            .map_err(|e| anyhow!("handshake: {e:?}"))?
        {
            HandshakeProcessResult::InProgress { response_bytes } => {
                clock.write(socket, &response_bytes)?;
            }
            HandshakeProcessResult::Completed {
                response_bytes,
                remaining_bytes,
            } => {
                if !response_bytes.is_empty() {
                    clock.write(socket, &response_bytes)?;
                }
                break remaining_bytes;
            }
        }
    };
    socket.set_read_timeout(None)?;
    socket.set_write_timeout(None)?;
    Ok(result)
}

/// Whether the relay strips records the stream already carries: only when
/// pulling, since an encoder does not put them there.
fn strips_records(cli: &Cli) -> bool {
    cli.pull.is_some() && cli.source_records == SourceRecords::Strip
}

/// The warning for records an earlier relay left in the source, if any.
/// Fresh ones usually mean the source is this channel's own egress, which
/// feeds the relay its own output.
fn records_note(injector: &Injector, cli: &Cli) -> Option<String> {
    let n = injector.stats.existing_records;
    (n > 0).then(|| {
        let newest = injector.stats.existing_newest_nanos;
        let age = match now_unix_nanos().checked_sub(newest) {
            Some(ns) if newest > 0 && ns < 1_000_000_000 => {
                format!(", the newest sent {} ms ago", ns / 1_000_000)
            }
            Some(ns) if newest > 0 => format!(", the newest sent {:.1} s ago", ns as f64 / 1e9),
            _ => String::new(),
        };
        let fate = if strips_records(cli) {
            "stripped"
        } else {
            "kept beside this relay's own"
        };
        format!(
            "the source carries Truss records from an earlier relay ({} so far{age}), {fate}. \
             If it is this channel's own egress, the relay is feeding itself",
            console::count(n)
        )
    })
}

/// The warning for records the injector left out as too large, if it has.
/// The flags refuse a payload too long for a record, so these are ones too
/// long for the NAL length field the encoder chose.
fn oversize_note(injector: &Injector, cli: &Cli) -> Option<String> {
    let n = injector.stats.oversize_skipped;
    (n > 0).then(|| {
        format!(
            "{} records were too large for the encoder's NAL length field and were left out: lower {}",
            console::count(n),
            if cli.artnet.is_some() {
                "--artnet-max-payload"
            } else {
                "--payload-len"
            }
        )
    })
}

#[allow(clippy::too_many_arguments)]
fn report(
    meter: &RateMeter,
    injector: Option<&Injector>,
    cli: &Cli,
    queued_bytes: usize,
    held_back: u32,
    artnet: Option<&artnet::Receiver>,
    osc: Option<&osc::Sender>,
    last_note: &mut Option<String>,
) -> Result<()> {
    let kbps = meter.kbps();
    if kbps <= 0.0 {
        return Ok(());
    }
    let mut line = format!("out {kbps:.0} kb/s");
    if let Some(inj) = injector {
        let counts: Vec<String> = inj
            .stats
            .injected
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        line.push_str(&format!(
            "  frames {}  {}  (+{:.0} kB added)",
            inj.stats.video_frames,
            counts.join(" "),
            inj.stats.added_bytes as f64 / 1000.0
        ));
    }
    let mut artnet_note = None;
    if let Some(a) = artnet {
        let (fragment, note) = artnet_status(&a.latch());
        line.push(' ');
        line.push_str(&fragment);
        artnet_note = note;
    }
    if let Some(o) = osc {
        line.push_str(&osc_status(o));
    }
    if queued_bytes > 64 * 1024 {
        // A persistent queue means the upload is not keeping up, which shows
        // up to viewers as stutter long before it shows up as an error.
        line.push_str(&format!("  [{} kB queued]", queued_bytes / 1024));
    }
    if held_back > 0 {
        line.push_str(&format!("  [encoder held back {held_back}x]"));
    }
    console::log(&line);
    if artnet_note != *last_note {
        if let Some(note) = &artnet_note {
            console::log(format!("  {note}"));
        }
        *last_note = artnet_note;
    }

    if let Some(codec) = injector.and_then(|i| i.stats.unsupported_codec.as_ref()) {
        console::log(format!(
            "  WARNING: video is {codec}, which records cannot ride in: passing it through"
        ));
    }
    if let Some(note) = injector.and_then(|i| oversize_note(i, cli)) {
        console::log(format!("  WARNING: {note}"));
    }
    if cli.publish.is_some() && kbps > cli.warn_kbps {
        console::log(format!(
            "  WARNING: {kbps:.0} kb/s is above {:.0}. many ingests count video and audio \
             together against 6000 + 320 kb/s and warns for five minutes before \
             disconnecting. Lower the encoder bitrate or raise --every.",
            cli.warn_kbps
        ));
    }
    // Aborting is opt-in on purpose. A bitrate flag expires after 24 hours and
    // does not count towards the strike system, whereas killing the relay
    // kills a live stream. Dropping the show is the worse failure.
    if let Some(limit) = cli.abort_kbps
        && kbps > limit
    {
        bail!("outgoing rate {kbps:.0} kb/s exceeded --abort-kbps {limit:.0}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;

    use super::*;

    const SHORT: Duration = Duration::from_millis(200);

    /// Both ends of a loopback connection: the one that connected, then the
    /// one that accepted.
    fn connected() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let publisher = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (relay, _) = listener.accept().unwrap();
        (publisher, relay)
    }

    #[test]
    fn an_accepted_publisher_keeps_the_listeners_receive_buffer() {
        let listener = bind_listener("127.0.0.1:0").unwrap();
        let _publisher = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (relay, _) = listener.accept().unwrap();
        let size = socket2::SockRef::from(&relay).recv_buffer_size().unwrap();
        // Linux reports twice what was set, for its own bookkeeping.
        assert!(
            (PUBLISHER_RECV_BUFFER..=2 * PUBLISHER_RECV_BUFFER).contains(&size),
            "{size}"
        );
    }

    fn expired(err: &anyhow::Error) -> bool {
        err.to_string().contains("did not complete the handshake")
    }

    #[test]
    fn a_silent_publisher_runs_out_of_handshake_time() {
        let (_publisher, mut relay) = connected();
        let started = Instant::now();
        let err = server_handshake(&mut relay, SHORT).unwrap_err();
        assert!(expired(&err), "{err:#}");
        assert!(
            started.elapsed() < SHORT * 5,
            "took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn the_handshake_deadline_is_for_the_whole_exchange_not_each_read() {
        let (mut publisher, mut relay) = connected();
        let stop = Arc::new(AtomicBool::new(false));
        let trickle = thread::spawn({
            let stop = stop.clone();
            move || {
                // Version byte 3, then zeros a byte at a time: every read gets
                // data well inside a per-read timeout, and the handshake still
                // cannot finish in time.
                let mut byte = 3u8;
                while !stop.load(Ordering::Relaxed) && publisher.write_all(&[byte]).is_ok() {
                    byte = 0;
                    thread::sleep(Duration::from_millis(20));
                }
            }
        });
        let started = Instant::now();
        let err = server_handshake(&mut relay, SHORT).unwrap_err();
        stop.store(true, Ordering::Relaxed);
        trickle.join().unwrap();
        assert!(expired(&err), "{err:#}");
        assert!(
            started.elapsed() < SHORT * 5,
            "took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn a_completed_handshake_keeps_what_follows_and_clears_the_timeouts() {
        let (mut publisher, mut relay) = connected();
        let encoder = thread::spawn(move || {
            client_handshake(&mut publisher, Duration::from_secs(5)).unwrap();
            assert_eq!(publisher.read_timeout().unwrap(), None);
            assert_eq!(publisher.write_timeout().unwrap(), None);
            publisher.write_all(b"after").unwrap();
            publisher
        });
        let mut got = server_handshake(&mut relay, Duration::from_secs(5)).unwrap();
        assert_eq!(relay.read_timeout().unwrap(), None);
        assert_eq!(relay.write_timeout().unwrap(), None);
        // The bytes after C2 can arrive with it or after it, so whatever the
        // handshake did not hand back has to still be on the socket.
        relay
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut buf = [0u8; 16];
        while got.len() < 5 {
            let n = relay.read(&mut buf).unwrap();
            assert_ne!(n, 0, "closed after {got:?}");
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(got, b"after");
        drop(encoder.join().unwrap());
    }

    #[test]
    fn an_ingest_that_stalls_the_handshake_runs_out_of_time() {
        // The ingest end accepts and then never answers C0 and C1.
        let (mut relay, _ingest) = connected();
        let started = Instant::now();
        let err = client_handshake(&mut relay, SHORT).unwrap_err();
        assert!(expired(&err), "{err:#}");
        assert!(err.to_string().contains("ingest"), "{err:#}");
        assert!(
            started.elapsed() < SHORT * 5,
            "took {:?}",
            started.elapsed()
        );
    }

    fn passthrough_cli() -> Cli {
        // Nothing here gets as far as publishing, so the ingest is never dialled.
        let mut cli = Cli::try_parse_from([
            "truss-relay",
            "--publish",
            "rtmp://127.0.0.1:9/live",
            "--passthrough",
        ])
        .unwrap();
        cli.target = Ingest::parse(cli.publish.as_deref().unwrap()).unwrap();
        cli
    }

    fn run_session(relay: TcpStream, idle_timeout: Duration) -> Result<()> {
        let cli = passthrough_cli();
        let carriers = parse_carriers(&cli.carriers).unwrap();
        session_listen(
            relay,
            &cli,
            &carriers,
            None,
            &mut None,
            None,
            "test",
            &mut Dashboard::default(),
            idle_timeout,
        )
    }

    #[test]
    fn a_publisher_that_goes_quiet_after_the_handshake_is_dropped() {
        let (mut publisher, relay) = connected();
        let (done, wait) = std::sync::mpsc::channel::<()>();
        let encoder = thread::spawn(move || {
            client_handshake(&mut publisher, Duration::from_secs(5)).unwrap();
            // Holds the connection open, sending nothing, until the test ends.
            let _ = wait.recv();
        });
        let started = Instant::now();
        let err = run_session(relay, SHORT).unwrap_err();
        drop(done);
        encoder.join().unwrap();
        assert!(err.to_string().contains("sent nothing"), "{err:#}");
        assert!(
            started.elapsed() < SHORT * 10,
            "took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn a_publisher_that_keeps_sending_is_not_dropped() {
        let (mut publisher, relay) = connected();
        let idle_timeout = Duration::from_millis(300);
        let encoder = thread::spawn(move || {
            client_handshake(&mut publisher, Duration::from_secs(5)).unwrap();
            let (mut session, initial) = ClientSession::new(ClientSessionConfig::new()).unwrap();
            let mut bytes = Vec::new();
            let connect = session.request_connection("live".into()).unwrap();
            for r in initial.into_iter().chain([connect]) {
                if let ClientSessionResult::OutboundResponse(p) = r {
                    bytes.extend_from_slice(&p.bytes);
                }
            }
            // 12 pieces a third of the timeout apart: four timeouts in all,
            // with no gap long enough to end the session.
            for piece in bytes.chunks(bytes.len().div_ceil(12)) {
                publisher.write_all(piece).unwrap();
                thread::sleep(idle_timeout / 3);
            }
            // On Windows, closing with the relay's replies unread resets the
            // connection instead of ending it. Shut down the write side, then
            // drain until the relay hangs up.
            publisher.shutdown(std::net::Shutdown::Write).unwrap();
            let mut sink = [0u8; 4096];
            while matches!(publisher.read(&mut sink), Ok(n) if n > 0) {}
        });
        let started = Instant::now();
        run_session(relay, idle_timeout).unwrap();
        encoder.join().unwrap();
        assert!(
            started.elapsed() > idle_timeout * 3,
            "ended after {:?}, before the publisher did",
            started.elapsed()
        );
    }

    #[test]
    fn passthrough_still_resolves_the_key_it_publishes_with() {
        let path = std::env::temp_dir().join(format!("truss-relay-key-{}", std::process::id()));
        std::fs::write(&path, "abc123\n").unwrap();
        let mut cli = Cli::try_parse_from([
            "truss-relay",
            "--publish",
            "rtmp://127.0.0.1:9/live",
            "--passthrough",
            "--stream-key-file",
            path.to_str().unwrap(),
        ])
        .unwrap();
        cli.target = Ingest::parse(cli.publish.as_deref().unwrap()).unwrap();
        let key = stream_key(&cli);
        std::fs::remove_file(&path).unwrap();
        assert!(key.unwrap().is_some());
    }

    fn pull_cli(extra: &[&str]) -> Result<Cli> {
        let mut args = vec![
            "truss-relay",
            "--source",
            "rtsp://127.0.0.1:9/cam",
            "--publish",
            "rtmp://127.0.0.1:9/live",
        ];
        args.extend_from_slice(extra);
        let mut cli = Cli::try_parse_from(args)?;
        cli.pull = Some(pull::Spec::parse(cli.source.as_deref().unwrap())?);
        Ok(cli)
    }

    #[test]
    fn a_source_password_is_read_from_its_file_for_the_named_user() {
        let path =
            std::env::temp_dir().join(format!("truss-relay-source-pw-{}", std::process::id()));
        std::fs::write(&path, "pass word\n").unwrap();
        let cli = pull_cli(&[
            "--source-user",
            "admin",
            "--source-password-file",
            path.to_str().unwrap(),
        ])
        .unwrap();
        let login = source_login(&cli);
        std::fs::remove_file(&path).unwrap();
        let login = login.unwrap().unwrap();
        assert_eq!(login.user, "admin");
        assert_eq!(login.password.expose(), "pass word");
    }

    #[test]
    fn a_source_login_needs_a_source_and_a_user() {
        assert!(pull_cli(&[]).is_ok_and(|cli| source_login(&cli).unwrap().is_none()));
        assert!(pull_cli(&["--source-password-file", "pw"]).is_err());
        assert!(
            Cli::try_parse_from([
                "truss-relay",
                "--publish",
                "rtmp://127.0.0.1:9/live",
                "--source-user",
                "admin",
            ])
            .is_err()
        );
    }

    #[test]
    fn the_key_and_the_source_password_cannot_both_come_from_stdin() {
        let cli = pull_cli(&[
            "--stream-key-file",
            "-",
            "--source-user",
            "admin",
            "--source-password-file",
            "-",
        ])
        .unwrap();
        let e = source_login(&cli).unwrap_err().to_string();
        assert!(e.contains("both read stdin"), "{e}");
    }

    #[test]
    fn recording_alone_needs_no_publish_and_no_key() {
        for input in [
            &["--listen", "127.0.0.1:1935"][..],
            &["--source", "rtsp://h/p"],
        ] {
            let mut args = vec!["truss-relay", "--record", "."];
            args.extend_from_slice(input);
            args.extend_from_slice(&["--carriers", "sei-t35", "--passthrough"]);
            let cli = Cli::try_parse_from(&args).unwrap();
            assert!(stream_key(&cli).unwrap().is_none());
        }
        // The key belongs to a publish, so it is refused without one.
        assert!(
            Cli::try_parse_from(["truss-relay", "--record", ".", "--stream-key-file", "k"])
                .is_err()
        );
        // Neither an output nor the OSC lane: nothing to do.
        assert!(Cli::try_parse_from(["truss-relay", "--listen", "127.0.0.1:1935"]).is_err());
    }

    #[test]
    fn the_osc_lane_alone_needs_no_key() {
        let cli =
            Cli::try_parse_from(["truss-relay", "--artnet", "--osc", "127.0.0.1:12100"]).unwrap();
        assert!(stream_key(&cli).unwrap().is_none());
    }

    /// An ingest that accepts the connection and the publish, then stops
    /// reading, as a stalled one does. It keeps the connection open until
    /// `done` is dropped.
    fn stalled_ingest(done: std::sync::mpsc::Receiver<()>) -> (u16, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let ingest = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut input = server_handshake(&mut socket, Duration::from_secs(5)).unwrap();
            let (mut session, initial) = ServerSession::new(ServerSessionConfig::new()).unwrap();
            let mut out = OutBuf::default();
            queue_server(&mut out, initial);
            let mut buf = vec![0u8; 4096];
            let mut published = false;
            while !published {
                for r in session.handle_input(&input).unwrap() {
                    match r {
                        ServerSessionResult::OutboundResponse(p) => out.push(&p.bytes),
                        ServerSessionResult::RaisedEvent(
                            ServerSessionEvent::ConnectionRequested { request_id, .. }
                            | ServerSessionEvent::ReleaseStreamRequested { request_id, .. },
                        ) => queue_server(&mut out, session.accept_request(request_id).unwrap()),
                        ServerSessionResult::RaisedEvent(
                            ServerSessionEvent::PublishStreamRequested { request_id, .. },
                        ) => {
                            queue_server(&mut out, session.accept_request(request_id).unwrap());
                            published = true;
                        }
                        _ => {}
                    }
                }
                out.pump(&mut socket).unwrap();
                if !published {
                    let n = socket.read(&mut buf).unwrap();
                    input = buf[..n].to_vec();
                }
            }
            let _ = done.recv();
        });
        (port, ingest)
    }

    /// Publishes over `socket` until the relay stops taking it and closes.
    fn flooding_publisher(mut socket: TcpStream) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            client_handshake(&mut socket, Duration::from_secs(5)).unwrap();
            let (mut session, initial) = ClientSession::new(ClientSessionConfig::new()).unwrap();
            let send = |s: &mut TcpStream, r: ClientSessionResult| {
                if let ClientSessionResult::OutboundResponse(p) = r {
                    s.write_all(&p.bytes)
                } else {
                    Ok(())
                }
            };
            for r in initial {
                send(&mut socket, r).unwrap();
            }
            let connect = session.request_connection("live".into()).unwrap();
            send(&mut socket, connect).unwrap();
            let mut buf = vec![0u8; 4096];
            let mut publishing = false;
            while !publishing {
                let n = socket.read(&mut buf).unwrap();
                assert_ne!(n, 0, "the relay closed before the publish was accepted");
                for r in session.handle_input(&buf[..n]).unwrap() {
                    match r {
                        ClientSessionResult::RaisedEvent(
                            ClientSessionEvent::ConnectionRequestAccepted,
                        ) => {
                            let publish = session
                                .request_publishing("anykey".into(), PublishRequestType::Live)
                                .unwrap();
                            send(&mut socket, publish).unwrap();
                        }
                        ClientSessionResult::RaisedEvent(
                            ClientSessionEvent::PublishRequestAccepted,
                        ) => publishing = true,
                        other => send(&mut socket, other).unwrap(),
                    }
                }
            }
            // Once the relay holds back, writes time out; once it gives up,
            // they fail.
            socket
                .set_write_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            let frame = Bytes::from(vec![0u8; 64 * 1024]);
            for i in 0u32.. {
                let r = session
                    .publish_video_data(frame.clone(), RtmpTimestamp::new(i * 33), false)
                    .unwrap();
                match send(&mut socket, r) {
                    Ok(()) => {}
                    Err(ref e) if timed_out(e) => {}
                    Err(_) => return,
                }
            }
        })
    }

    #[test]
    fn the_ingest_connection_keeps_to_its_budget() {
        // 192.0.2.1 is reserved for documentation, so nothing should answer
        // it. Whatever the network does with it (drops it, refuses it, or a
        // proxy takes it), the attempt must end close to the budget rather
        // than when the OS gives up.
        let started = Instant::now();
        let _ = connect_ingest("192.0.2.1:1935", Duration::from_millis(300));
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "{:?}",
            started.elapsed()
        );

        // No budget: no attempt at all.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let open = listener.local_addr().unwrap();
        assert!(connect_any(&[open], Duration::ZERO).is_err());

        // A first address that refuses leaves the next its share.
        let closed = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        assert!(connect_any(&[closed, open], Duration::from_secs(2)).is_ok());
        assert!(connect_any(&[closed], Duration::from_millis(500)).is_err());
    }

    #[test]
    fn a_stalled_ingest_ends_the_session_rather_than_holding_for_ever() {
        let (done, wait) = std::sync::mpsc::channel::<()>();
        let (port, ingest) = stalled_ingest(wait);
        let url = format!("rtmp://127.0.0.1:{port}/live");
        let mut cli =
            Cli::try_parse_from(["truss-relay", "--publish", &url, "--passthrough"]).unwrap();
        cli.target = Ingest::parse(&url).unwrap();
        let key = creds::Secret::new(&creds::STREAM_KEY, "k").unwrap();
        let (publisher, relay) = connected();
        let encoder = flooding_publisher(publisher);
        let started = Instant::now();
        let err = session_listen(
            relay,
            &cli,
            &parse_carriers(&cli.carriers).unwrap(),
            None,
            &mut None,
            Some(&key),
            "test",
            &mut Dashboard::default(),
            Duration::from_millis(500),
        )
        .unwrap_err();
        drop(done);
        ingest.join().unwrap();
        encoder.join().unwrap();
        assert!(err.to_string().contains("not draining"), "{err:#}");
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "took {:?}",
            started.elapsed()
        );
    }

    fn injector_with_oversize(skipped: u64) -> Injector {
        let mut injector = Injector::new(&InjectOptions {
            carriers: vec![Carrier::SeiUnregistered],
            every_n_frames: 1,
            payload_len: DEFAULT_PAYLOAD_LEN,
            keyframes_only: false,
        })
        .unwrap();
        injector.stats.oversize_skipped = skipped;
        injector
    }

    #[test]
    fn the_oversize_warning_names_the_flag_that_sizes_the_payload() {
        let mut cli = passthrough_cli();
        assert_eq!(oversize_note(&injector_with_oversize(0), &cli), None);

        let note = oversize_note(&injector_with_oversize(1_234), &cli).unwrap();
        assert!(note.starts_with("1,234 records"), "{note}");
        assert!(note.ends_with("lower --payload-len"), "{note}");

        cli.artnet = Some("0.0.0.0".into());
        let note = oversize_note(&injector_with_oversize(1), &cli).unwrap();
        assert!(note.ends_with("lower --artnet-max-payload"), "{note}");
    }
}
