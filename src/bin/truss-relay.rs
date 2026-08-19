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
use std::net::{TcpListener, TcpStream};
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
use truss::creds;
use truss::inject::{InjectOptions, Injector};
use truss::payload;
use truss::record::{DEFAULT_PAYLOAD_LEN, MAX_PAYLOAD_LEN};
use truss::relay::{OutBuf, RateMeter};

#[derive(Parser, Clone)]
#[command(
    name = "truss-relay",
    about = "Relay RTMP, planting DMX in the video on the way through"
)]
struct Cli {
    /// Address to accept OBS on. Point OBS at rtmp://<this>/live with any key.
    #[arg(long, default_value = "127.0.0.1:1935")]
    listen: String,
    /// Ingest host and port to publish to.
    #[arg(long)]
    ingest: String,
    /// RTMP application name on the ingest server.
    #[arg(long, default_value = "live")]
    app: String,
    /// File holding the stream key, or `-` to read it from stdin. Suits
    /// systemd LoadCredential and container secrets, which both present a
    /// secret as a file. Without it the key is looked for in TRUSS_STREAM_KEY,
    /// then asked for if this is a terminal.
    ///
    /// There is deliberately no flag that takes the key itself: an argument is
    /// visible to anything that can list processes.
    #[arg(long)]
    stream_key_file: Option<String>,
    /// Comma-separated carrier slugs.
    #[arg(long, default_value = "sei-unreg")]
    carriers: String,
    /// Inject on every Nth video frame.
    #[arg(long, default_value_t = 1)]
    every: u32,
    /// Payload bytes per record. Ignored with --artnet, which sizes each
    /// payload from the universes the desk is sending.
    #[arg(long, default_value_t = DEFAULT_PAYLOAD_LEN)]
    payload_len: usize,
    /// Carry live Art-Net DMX instead of the sequence-derived test body.
    #[arg(long)]
    artnet: bool,
    /// Address to receive Art-Net on.
    #[arg(long, default_value_t = format!("0.0.0.0:{}", truss::artnet::DEFAULT_PORT))]
    artnet_listen: String,
    /// Largest DMX payload to put in one frame. The default is the largest
    /// size measured crossing a remuxing CDN intact; more is untested rather than known
    /// to fail. Universes that do not fit are sent on the following frames.
    #[arg(long, default_value_t = 9216)]
    artnet_max_payload: usize,
    /// Warn when the outgoing stream averages above this many kb/s.
    #[arg(long, default_value_t = 5500.0)]
    warn_kbps: f64,
    /// Stop the relay if the outgoing stream sustains this rate. Off by
    /// default: see the note where this is used.
    #[arg(long)]
    abort_kbps: Option<f64>,
    /// Relay without injecting, to measure what the relay itself costs.
    #[arg(long)]
    passthrough: bool,
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
    let cli = Cli::parse();
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
    let key = if cli.passthrough {
        None
    } else {
        Some(creds::StreamKey::resolve(
            cli.stream_key_file.as_deref(),
            "truss",
            &cli.ingest,
        )?)
    };

    // Bound once for the life of the relay rather than per session: a desk
    // keeps sending across an OBS reconnect, and rebinding would drop the
    // current state of every universe.
    let artnet = match (cli.artnet, cli.passthrough) {
        (true, false) => {
            let addr = cli
                .artnet_listen
                .parse()
                .with_context(|| format!("parsing --artnet-listen {:?}", cli.artnet_listen))?;
            Some(artnet::Receiver::bind(addr)?)
        }
        _ => None,
    };

    let listener =
        TcpListener::bind(&cli.listen).with_context(|| format!("binding {}", cli.listen))?;
    println!("relay listening on rtmp://{}/{}", cli.listen, cli.app);
    println!("  point OBS at that URL with any stream key");
    println!(
        "  forwarding to rtmp://{}/{} (key hidden)",
        cli.ingest, cli.app
    );
    if cli.passthrough {
        println!("  passthrough mode: no carriers injected");
    } else {
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
        println!("  receiving Art-Net on {}", a.local_addr);
        println!(
            "    up to {} payload bytes per frame; broadcast if another node shares this machine",
            cli.artnet_max_payload
        );
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

    for stream in listener.incoming() {
        let stream = stream.context("accepting connection")?;
        let peer = stream
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "?".into());
        println!("\n-- publisher connected from {peer}");
        match relay_one(stream, &cli, &carriers, artnet.as_ref(), key.as_ref()) {
            Ok(()) => println!("-- session ended cleanly"),
            Err(e) => println!("-- session ended: {e:#}"),
        }
    }
    Ok(())
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

fn relay_one(
    mut obs: TcpStream,
    cli: &Cli,
    carriers: &[Carrier],
    artnet: Option<&artnet::Receiver>,
    key: Option<&creds::StreamKey>,
) -> Result<()> {
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
            )?;
        }

        match obs.read(&mut buf) {
            Ok(0) => {
                println!("publisher disconnected");
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
                                    println!("ingest accepted the publish");
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
                                    println!("ingest status: {code}");
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
            report(&meter, injector.as_ref(), cli, queued, artnet)?;
        }

        if idle {
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    report(&meter, injector.as_ref(), cli, 0, artnet)?;
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
            println!(
                "publisher requested stream key {stream_key:?} (ignored, relay holds the real key)"
            );
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
                    if truss::flv::is_avc_sequence_header_data(&data) {
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
                                inj.inject_tag_with(&data, now_unix_nanos(), Some(&bytes))?
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
            println!("publisher stopped");
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
        println!("flushing {} buffered messages", pending.len());
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
    println!("connecting to {}...", cli.ingest);
    let mut socket =
        TcpStream::connect(&cli.ingest).with_context(|| format!("connecting to {}", cli.ingest))?;
    socket.set_nodelay(true).ok();
    let leftover = client_handshake(&mut socket)?;

    let mut config = ClientSessionConfig::new();
    config.tc_url = Some(format!("rtmp://{}/{}", cli.ingest, cli.app));
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
        .request_connection(cli.app.clone())
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

fn server_handshake(socket: &mut TcpStream) -> Result<Vec<u8>> {
    let mut handshake = Handshake::new(PeerType::Server);
    let mut buf = vec![0u8; 4096];
    loop {
        let n = socket.read(&mut buf).context("handshake read")?;
        if n == 0 {
            bail!("publisher closed during handshake");
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

fn report(
    meter: &RateMeter,
    injector: Option<&Injector>,
    cli: &Cli,
    queued_bytes: usize,
    artnet: Option<&artnet::Receiver>,
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
        let latch = a.latch();
        line.push_str(&format!(
            "  dmx {} universes {} packets",
            latch.universe_count(),
            latch.packets
        ));
        if latch.out_of_order > 0 {
            line.push_str(&format!(" ({} late)", latch.out_of_order));
        }
        // An empty lane and a dead lane look identical in the record counts,
        // so say which this is rather than leaving it to be inferred.
        artnet_note = latch.error.clone().or_else(|| {
            (latch.packets == 0).then(|| {
                "no Art-Net received yet: the carriers are crossing with empty payloads".into()
            })
        });
    }
    if queued_bytes > 64 * 1024 {
        // A persistent queue means the upload is not keeping up, which shows
        // up to viewers as stutter long before it shows up as an error.
        line.push_str(&format!("  [{} kB queued]", queued_bytes / 1024));
    }
    println!("{line}");
    if let Some(note) = artnet_note {
        println!("  {note}");
    }

    if kbps > cli.warn_kbps {
        println!(
            "  WARNING: {kbps:.0} kb/s is above {:.0}. many ingests count video and audio \
             together against 6000 + 320 kb/s and warns for five minutes before \
             disconnecting. Lower the OBS bitrate or raise --every.",
            cli.warn_kbps
        );
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
