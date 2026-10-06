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
use truss::console;
use truss::creds;
use truss::inject::{InjectOptions, Injector};
use truss::osc;
use truss::payload;
use truss::record::{DEFAULT_PAYLOAD_LEN, MAX_PAYLOAD_LEN};
use truss::relay::{Ingest, OutBuf, RateMeter};

#[derive(Parser, Clone)]
#[command(
    name = "truss-relay",
    about = "Relay RTMP, planting DMX in the video on the way through"
)]
struct Cli {
    /// Address to accept the encoder on. Point it at rtmp://<this>/live with any key.
    #[arg(long, default_value = "127.0.0.1:1935", requires = "publish")]
    listen: String,
    /// Where to publish the stream: rtmp://host/app, with the port after the
    /// host when it is not 1935, and "live" when no application is given.
    /// The stream key is never part of this: see --stream-key-file.
    ///
    /// Leave it out to run the OSC lane alone, for testing against a desk
    /// with no encoder or ingest: then --artnet and --osc are needed, and
    /// nothing listens for an encoder.
    #[arg(long, required_unless_present = "osc")]
    publish: Option<String>,
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
    #[arg(long, default_value = DEFAULT_CARRIERS, requires = "publish")]
    carriers: String,
    /// Inject on every Nth video frame.
    #[arg(long, default_value_t = 1, requires = "publish")]
    every: u32,
    /// Payload bytes per record. Ignored with --artnet, which sizes each
    /// payload from the universes the desk is sending.
    #[arg(long, default_value_t = DEFAULT_PAYLOAD_LEN, requires = "publish")]
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
    #[arg(long, requires = "publish")]
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
    let carriers = parse_carriers(&cli.carriers)?;

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

    // Resolved before the listener is bound. A missing key should fail while
    // the operator is still watching, not on the first frame of a show.
    let key = if cli.passthrough || cli.publish.is_none() {
        None
    } else {
        Some(creds::StreamKey::resolve(
            cli.stream_key_file.as_deref(),
            "truss",
            &cli.target.authority,
        )?)
    };

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

    let listener = match cli.publish {
        Some(_) => {
            let listener = TcpListener::bind(&cli.listen)
                .with_context(|| format!("binding {}", cli.listen))?;
            println!(
                "relay listening on rtmp://{}/{}  (point the encoder here, any stream key)",
                cli.listen, cli.target.app
            );
            println!("  forwarding to {} (key hidden)", cli.target.url());
            Some(listener)
        }
        None => {
            println!("relay running the OSC lane only: no encoder accepted, nothing published");
            None
        }
    };
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
        match relay_one(
            stream,
            &cli,
            &carriers,
            artnet.as_ref(),
            &mut osc,
            key.as_ref(),
            &peer,
            &mut dash,
        ) {
            Ok(()) => console::event("-- session ended cleanly"),
            Err(e) => console::event(format!("-- session ended: {e:#}")),
        }
        idle = IdleStatus::default();
    }
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

/// What a connected publisher's session shows on the panel.
struct SessionView<'a> {
    peer: &'a str,
    since: Instant,
    publishing: bool,
    meter: &'a RateMeter,
    injector: Option<&'a Injector>,
    queued: usize,
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
            if cli.publish.is_none() {
                "  (OSC lane only)"
            } else {
                ""
            },
            console::clock(console::uptime())
        )];

        if cli.publish.is_some() {
            let listen = format!("rtmp://{}/{}", cli.listen, cli.target.app);
            lines.push(match session {
                Some(s) => format!(
                    "encoder   {listen}   connected from {} for {}",
                    s.peer,
                    console::clock(s.since.elapsed())
                ),
                None => format!("encoder   {listen}   waiting for a publisher"),
            });
            lines.push(format!(
                "ingest    {}   {}",
                cli.target.url(),
                match session {
                    None => "not connected",
                    Some(s) if s.publishing => "publishing",
                    Some(_) => "connecting",
                }
            ));
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
                if kbps > cli.warn_kbps {
                    warnings.push(format!(
                        "{kbps:.0} kb/s is above {:.0}: lower the encoder bitrate or raise --every",
                        cli.warn_kbps
                    ));
                }
                if s.queued > 64 * 1024 {
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

#[allow(clippy::too_many_arguments)]
fn relay_one(
    mut obs: TcpStream,
    cli: &Cli,
    carriers: &[Carrier],
    artnet: Option<&artnet::Receiver>,
    osc: &mut Option<osc::Sender>,
    key: Option<&creds::StreamKey>,
    peer: &str,
    dash: &mut Dashboard,
) -> Result<()> {
    let started = Instant::now();
    obs.set_nodelay(true).ok();
    let leftover = server_handshake(&mut obs)?;

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

    let mut injector = (!cli.passthrough)
        .then(|| {
            Injector::new(&InjectOptions {
                carriers: carriers.to_vec(),
                every_n_frames: cli.every,
                payload_len: cli.payload_len,
                keyframes_only: false,
            })
        })
        .transpose()?;

    let mut upstream: Option<Upstream> = None;
    let mut meter = RateMeter::new();
    let mut last_report = Instant::now();
    // The note under the status line is printed when it changes, not with
    // every line: a desk sending the same way for an hour is said once.
    let mut last_note: Option<String> = None;
    let mut buf = vec![0u8; 32 * 1024];
    obs.set_nonblocking(true)?;

    loop {
        let mut idle = true;

        // Drain anything already queued from the handshake bytes.
        for event in events.drain(..) {
            handle_publisher_event(
                event,
                &mut server,
                &mut obs_out,
                &mut upstream,
                &mut injector,
                &mut meter,
                cli,
                artnet,
                osc,
            )?;
        }

        match obs.read(&mut buf) {
            Ok(0) => {
                console::event("publisher disconnected");
                break;
            }
            Ok(n) => {
                idle = false;
                let results = server
                    .handle_input(&buf[..n])
                    .map_err(|e| anyhow!("server handle_input: {e:?}"))?;
                for r in results {
                    match r {
                        ServerSessionResult::OutboundResponse(p) => {
                            obs_out.push(&p.bytes);
                        }
                        ServerSessionResult::RaisedEvent(e) => {
                            handle_publisher_event(
                                e,
                                &mut server,
                                &mut obs_out,
                                &mut upstream,
                                &mut injector,
                                &mut meter,
                                cli,
                                artnet,
                                osc,
                            )?;
                        }
                        ServerSessionResult::UnhandleableMessageReceived(_) => {}
                    }
                }
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {}
            Err(e) => return Err(e).context("reading from publisher"),
        }

        // the ingest server sends acknowledgements and pings; ignoring them stalls the
        // connection once the window fills.
        if let Some(up) = upstream.as_mut() {
            match up.socket.read(&mut buf) {
                Ok(0) => bail!("the ingest server closed the connection"),
                Ok(n) => {
                    idle = false;
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
                                    bail!(
                                        "the ingest server rejected the connection: {description}"
                                    );
                                }
                                ClientSessionEvent::PublishRequestAccepted => {
                                    console::event("ingest accepted the publish");
                                    up.publishing = true;
                                    just_accepted = true;
                                }
                                ClientSessionEvent::UnhandleableOnStatusCode { code } => {
                                    // BadAuth here usually does not mean the key
                                    // is wrong. an ingest commonly rejects a second publish
                                    // while it still considers the previous one
                                    // connected, which is what you hit
                                    // reconnecting straight after a run.
                                    if code.contains("BadAuth") || code.contains("BadName") {
                                        bail!(
                                            "the ingest server refused the publish ({code}). If the key is                                              right, the previous session is probably still                                              connected: wait for the stream to drop, or press                                              Disconnect in the control panel."
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
                        flush_pending(up, &mut meter)?;
                    }
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) => return Err(e).context("reading from the ingest server"),
            }
        }

        // Drain whatever the sockets will take. Doing this every pass, rather
        // than at the point of each write, is what lets a momentarily full
        // send buffer cost a millisecond instead of ending the session.
        obs_out.pump(&mut obs).context("writing to publisher")?;
        if let Some(up) = upstream.as_mut() {
            up.out
                .pump(&mut up.socket)
                .context("writing to the ingest server")?;
            if up.out.pending() > 0 {
                idle = false;
            }
        }

        if last_report.elapsed() >= Duration::from_secs(5) {
            last_report = Instant::now();
            let queued = upstream.as_ref().map_or(0, |u| u.out.pending());
            report(
                &meter,
                injector.as_ref(),
                cli,
                queued,
                artnet,
                osc.as_ref(),
                &mut last_note,
            )?;
        }

        dash.tick(
            cli,
            Some(SessionView {
                peer,
                since: started,
                publishing: upstream.as_ref().is_some_and(|u| u.publishing),
                meter: &meter,
                injector: injector.as_ref(),
                queued: upstream.as_ref().map_or(0, |u| u.out.pending()),
            }),
            artnet,
            osc.as_ref(),
        );

        if idle {
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    report(
        &meter,
        injector.as_ref(),
        cli,
        0,
        artnet,
        osc.as_ref(),
        &mut last_note,
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn handle_publisher_event(
    event: ServerSessionEvent,
    server: &mut ServerSession,
    obs_out: &mut OutBuf,
    upstream: &mut Option<Upstream>,
    injector: &mut Option<Injector>,
    meter: &mut RateMeter,
    cli: &Cli,
    artnet: Option<&artnet::Receiver>,
    osc: &mut Option<osc::Sender>,
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
            if upstream.is_none() {
                *upstream = Some(connect_upstream(cli)?);
            }
        }
        ServerSessionEvent::StreamMetadataChanged { metadata, .. } => {
            if let Some(up) = upstream.as_mut() {
                forward_metadata(up, &metadata)?;
            }
        }
        ServerSessionEvent::VideoDataReceived {
            data, timestamp, ..
        } => {
            let payload = match injector.as_mut() {
                Some(inj) => {
                    if matches!(truss::flv::video(&data), truss::flv::Video::Config { .. }) {
                        inj.note_sequence_header(&data)?;
                        data
                    } else {
                        let dmx = artnet.map(|a| {
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
                                let rewritten = inj.inject_tag_with(&data, now, Some(&bytes))?;
                                // The lane carries the payload the stream carries,
                                // so a frame the injector left alone gets no record.
                                if rewritten.is_some()
                                    && let Some(o) = osc.as_mut()
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
            forward_av(upstream, meter, true, payload, timestamp)?;
        }
        ServerSessionEvent::AudioDataReceived {
            data, timestamp, ..
        } => {
            forward_av(upstream, meter, false, data, timestamp)?;
        }
        ServerSessionEvent::PublishStreamFinished { .. } => {
            console::event("publisher stopped");
        }
        _ => {}
    }
    Ok(())
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

fn connect_upstream(cli: &Cli) -> Result<Upstream> {
    console::event(format!("connecting to {}...", cli.target.authority));
    let mut socket = TcpStream::connect(&cli.target.authority)
        .with_context(|| format!("connecting to {}", cli.target.authority))?;
    socket.set_nodelay(true).ok();
    let leftover = client_handshake(&mut socket)?;

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

fn server_handshake(socket: &mut TcpStream) -> Result<Vec<u8>> {
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    let mut handshake = Handshake::new(PeerType::Server);
    let mut buf = vec![0u8; 4096];
    let result = loop {
        socket.set_read_timeout(Some(handshake_time_left(deadline)?))?;
        let n = match socket.read(&mut buf) {
            Ok(n) => n,
            Err(ref e) if timed_out(e) => return Err(handshake_expired()),
            Err(e) => return Err(e).context("handshake read"),
        };
        if n == 0 {
            bail!("publisher closed during handshake");
        }
        match handshake
            .process_bytes(&buf[..n])
            .map_err(|e| anyhow!("handshake: {e:?}"))?
        {
            HandshakeProcessResult::InProgress { response_bytes } => {
                handshake_write(socket, &response_bytes, deadline)?;
            }
            HandshakeProcessResult::Completed {
                response_bytes,
                remaining_bytes,
            } => {
                if !response_bytes.is_empty() {
                    handshake_write(socket, &response_bytes, deadline)?;
                }
                break remaining_bytes;
            }
        }
    };
    socket.set_read_timeout(None)?;
    socket.set_write_timeout(None)?;
    Ok(result)
}

/// Write a handshake response with no more than what is left of `deadline`,
/// so a publisher that stops reading runs out of time as one that stops
/// sending does.
fn handshake_write(socket: &mut TcpStream, bytes: &[u8], deadline: Instant) -> Result<()> {
    socket.set_write_timeout(Some(handshake_time_left(deadline)?))?;
    match socket.write_all(bytes) {
        Err(ref e) if timed_out(e) => Err(handshake_expired()),
        other => other.context("handshake write"),
    }
}

fn handshake_time_left(deadline: Instant) -> Result<Duration> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(handshake_expired());
    }
    Ok(left)
}

fn handshake_expired() -> anyhow::Error {
    anyhow!(
        "publisher did not complete the handshake within {}s",
        HANDSHAKE_TIMEOUT.as_secs()
    )
}

/// A socket timeout is WouldBlock on Unix and TimedOut on Windows.
fn timed_out(e: &std::io::Error) -> bool {
    matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
}

fn client_handshake(socket: &mut TcpStream) -> Result<Vec<u8>> {
    let mut handshake = Handshake::new(PeerType::Client);
    let start = handshake
        .generate_outbound_p0_and_p1()
        .map_err(|e| anyhow!("handshake start: {e:?}"))?;
    socket.write_all(&start).context("handshake write")?;

    let mut buf = vec![0u8; 4096];
    loop {
        let n = socket.read(&mut buf).context("handshake read")?;
        if n == 0 {
            bail!("the ingest server closed during handshake");
        }
        match handshake
            .process_bytes(&buf[..n])
            .map_err(|e| anyhow!("handshake: {e:?}"))?
        {
            HandshakeProcessResult::InProgress { response_bytes } => {
                socket
                    .write_all(&response_bytes)
                    .context("handshake write")?;
            }
            HandshakeProcessResult::Completed {
                response_bytes,
                remaining_bytes,
            } => {
                if !response_bytes.is_empty() {
                    socket
                        .write_all(&response_bytes)
                        .context("handshake write")?;
                }
                return Ok(remaining_bytes);
            }
        }
    }
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

fn report(
    meter: &RateMeter,
    injector: Option<&Injector>,
    cli: &Cli,
    queued_bytes: usize,
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
    if kbps > cli.warn_kbps {
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
