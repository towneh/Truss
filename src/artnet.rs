//! Art-Net ingest: the live desk data the SEI lane carries.
//!
//! A lighting desk broadcasts `ArtDmx` packets, one per universe, at up to
//! 44 Hz. The video frame grid runs slower than that, so this is a latch rather
//! than a queue: the newest value for each universe wins and intermediate ones
//! are dropped. That is the same thing every other Art-Net node does, and it is
//! safe because DMX values are absolute.
//!
//! Not every desk broadcasts. Some discover nodes with `ArtPoll` and unicast
//! `ArtDmx` to the one the operator picks, and a receiver that never answers
//! the poll is not on the list to be picked. So this answers, as a node named
//! Truss with one output port, and advertises the address this machine would
//! use to reach the desk rather than whichever adapter happens to be first.
//!
//! The socket is bound with `SO_REUSEADDR` so another Art-Net consumer on the
//! same machine can keep running alongside this one. That only works for
//! broadcast traffic: if the desk is set to unicast to a single node's address,
//! exactly one process receives each packet and which one is undefined. Patch
//! both as separate nodes on the desk, or broadcast. The exception is a desk
//! on this machine sending to 127.0.0.1: bound to that address, this socket
//! receives those packets ahead of any socket bound to every address.

use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use socket2::{Domain, Protocol, Socket, Type};

use crate::payload::{BLOCK_HEADER_LEN, Block, HEADER_LEN as PAYLOAD_HEADER_LEN};

pub const DEFAULT_PORT: u16 = 6454;
pub const UNIVERSE_SLOTS: usize = 512;
/// An `ArtPollReply` is a fixed-size packet.
pub const POLL_REPLY_LEN: usize = 239;

const ID: &[u8; 8] = b"Art-Net\0";
const OP_DMX: u16 = 0x5000;
const OP_POLL: u16 = 0x2000;
const OP_POLL_REPLY: u16 = 0x2100;
const MIN_PROT_VER: u16 = 14;
const PACKET_HEADER_LEN: usize = 18;
const POLL_MIN_LEN: usize = 14;
const POLL_TARGETED_LEN: usize = 18;
const POLL_FLAG_TARGETED: u8 = 1 << 5;

/// What a desk sees when it lists nodes.
const PORT_NAME: &[u8] = b"Truss";
const LONG_NAME: &[u8] = b"Truss: DMX carried inside the video stream";
/// ESTA reserves this range for prototyping, so the reply claims no
/// manufacturer it is not.
const ESTA_EXPERIMENTAL: u16 = 0x7FF0;
/// The OEM code the specification sets aside for unregistered products.
const OEM_UNKNOWN: u16 = 0x00FF;

/// One `ArtDmx` packet, borrowed from the receive buffer.
#[derive(Debug, PartialEq, Eq)]
pub struct ArtDmx<'a> {
    /// 15-bit port address: net, sub-net and universe combined.
    pub universe: u16,
    /// 1..=255 in order, or 0 when the sender does not implement ordering.
    pub sequence: u8,
    pub values: &'a [u8],
}

/// Parse an `ArtDmx` packet, returning `None` for anything else.
///
/// Every other opcode is somebody else's business: `ArtPoll` in particular
/// arrives on the same port from any node on the network, so a parser that
/// treated unknown opcodes as errors would be noisy rather than informative.
pub fn parse_dmx(buf: &[u8]) -> Option<ArtDmx<'_>> {
    if buf.len() < PACKET_HEADER_LEN || &buf[..8] != ID {
        return None;
    }
    // The opcode is the one little-endian field in the protocol.
    if u16::from_le_bytes([buf[8], buf[9]]) != OP_DMX {
        return None;
    }
    if u16::from_be_bytes([buf[10], buf[11]]) < MIN_PROT_VER {
        return None;
    }
    let sequence = buf[12];
    let sub_uni = u16::from(buf[14]);
    let net = u16::from(buf[15]) & 0x7F;
    let universe = (net << 8) | sub_uni;

    let declared = u16::from_be_bytes([buf[16], buf[17]]) as usize;
    if declared == 0 || declared > UNIVERSE_SLOTS {
        return None;
    }
    // A short packet is truncated rather than rejected: the slots that did
    // arrive are still the desk's current values for those channels.
    let available = buf.len() - PACKET_HEADER_LEN;
    let len = declared.min(available);
    if len == 0 {
        return None;
    }
    Some(ArtDmx {
        universe,
        sequence,
        values: &buf[PACKET_HEADER_LEN..PACKET_HEADER_LEN + len],
    })
}

/// One `ArtPoll` packet: a controller asking who is on the network.
#[derive(Debug, PartialEq, Eq)]
pub struct ArtPoll {
    pub flags: u8,
    /// In targeted mode a node answers only if one of its port addresses is
    /// in this range, inclusive and ordered low to high.
    pub targeted: Option<(u16, u16)>,
}

/// Parse an `ArtPoll` packet, returning `None` for anything else.
pub fn parse_poll(buf: &[u8]) -> Option<ArtPoll> {
    if buf.len() < POLL_MIN_LEN || &buf[..8] != ID {
        return None;
    }
    if u16::from_le_bytes([buf[8], buf[9]]) != OP_POLL {
        return None;
    }
    if u16::from_be_bytes([buf[10], buf[11]]) < MIN_PROT_VER {
        return None;
    }
    let flags = buf[12];
    // The range is an Art-Net 4 addition and a shorter poll from an older
    // controller is still a poll, so its absence is not a fault.
    let targeted = (flags & POLL_FLAG_TARGETED != 0 && buf.len() >= POLL_TARGETED_LEN).then(|| {
        let top = u16::from_be_bytes([buf[14], buf[15]]);
        let bottom = u16::from_be_bytes([buf[16], buf[17]]);
        (top.min(bottom), top.max(bottom))
    });
    Some(ArtPoll { flags, targeted })
}

impl ArtPoll {
    /// Whether a node with these port addresses should answer.
    pub fn wants(&self, ports: impl IntoIterator<Item = u16>) -> bool {
        match self.targeted {
            None => true,
            Some((lo, hi)) => ports.into_iter().any(|p| (lo..=hi).contains(&p)),
        }
    }
}

/// The most universes a node advertises. Each reply packet names up to four, so
/// this is eight packets per poll, and a bound on how much a poll can cost
/// once a hostile sender has filled the latch with universes.
pub const MAX_ADVERTISED_PORTS: usize = 32;
const PORTS_PER_REPLY: usize = 4;

/// The port addresses this node advertises: the lowest universes the latch
/// holds, or universe 0 before it holds any.
///
/// The desk sends to the node's address with whatever port address the
/// operator assigned, and the latch takes every universe it is sent, so this
/// is what the node reports rather than what it accepts. Advertising the
/// latched universes keeps a desk that searches by universe able to find the
/// node, from the next poll after the first packet of that universe arrives.
pub fn advertised_ports(latched: impl IntoIterator<Item = u16>) -> Vec<u16> {
    let mut ports: Vec<u16> = latched.into_iter().take(MAX_ADVERTISED_PORTS).collect();
    if ports.is_empty() {
        ports.push(0);
    }
    ports
}

/// Build the `ArtPollReply` packets that make this process a node a desk can
/// pick.
///
/// `ip` and `port` are where the desk should send `ArtDmx`. `replies` is how
/// many polls have been answered, which the node report carries so a monitor
/// can see the node is alive rather than merely present. `latched` is how many
/// universes the latch holds, which decides whether the ports report data
/// flowing. `ports` is what [`advertised_ports`] returned.
///
/// A packet carries up to four ports, all on one net and sub-net, so a run of
/// ports is cut wherever either changes and each packet takes the next bind
/// index from 1, which is how the protocol expresses one node with many ports.
pub fn poll_replies(
    ip: Ipv4Addr,
    port: u16,
    replies: u64,
    latched: usize,
    ports: &[u16],
) -> Vec<[u8; POLL_REPLY_LEN]> {
    let mut out = Vec::new();
    let mut bind_index = 1u8;
    let mut rest = ports;
    while let Some(&first) = rest.first() {
        let n = rest
            .iter()
            .take(PORTS_PER_REPLY)
            .take_while(|p| *p >> 4 == first >> 4)
            .count();
        let (packet, next) = rest.split_at(n);
        out.push(poll_reply(ip, port, replies, latched, bind_index, packet));
        bind_index = bind_index.saturating_add(1);
        rest = next;
    }
    out
}

/// One packet of [`poll_replies`]: between one and four ports sharing a net
/// and sub-net.
fn poll_reply(
    ip: Ipv4Addr,
    port: u16,
    replies: u64,
    latched: usize,
    bind_index: u8,
    ports: &[u16],
) -> [u8; POLL_REPLY_LEN] {
    debug_assert!(!ports.is_empty() && ports.len() <= PORTS_PER_REPLY);
    let mut p = [0u8; POLL_REPLY_LEN];
    p[..8].copy_from_slice(ID);
    p[8..10].copy_from_slice(&OP_POLL_REPLY.to_le_bytes());
    p[10..14].copy_from_slice(&ip.octets());
    // The port is the other little-endian field in the protocol.
    p[14..16].copy_from_slice(&port.to_le_bytes());
    p[16] = env!("CARGO_PKG_VERSION_MAJOR").parse().unwrap_or(0);
    p[17] = env!("CARGO_PKG_VERSION_MINOR").parse().unwrap_or(0);
    // A port address is net, sub-net and universe: 7, 4 and 4 bits. The first
    // two are per packet, the last per port.
    p[18] = ((ports[0] >> 8) & 0x7F) as u8;
    p[19] = ((ports[0] >> 4) & 0x0F) as u8;
    p[20..22].copy_from_slice(&OEM_UNKNOWN.to_be_bytes());
    // 22 is UbeaVersion, not present.
    // Status1: indicators normal, port address authority unknown.
    p[23] = 0b1100_0000;
    p[24..26].copy_from_slice(&ESTA_EXPERIMENTAL.to_le_bytes());
    write_text(&mut p[26..44], PORT_NAME);
    write_text(&mut p[44..108], LONG_NAME);
    let report = format!(
        "#0001 [{:04}] Truss relay, {latched} universes latched",
        replies % 10_000
    );
    write_text(&mut p[108..172], report.as_bytes());
    p[172..174].copy_from_slice(&(ports.len() as u16).to_be_bytes());
    for (i, &port_address) in ports.iter().enumerate() {
        // PortTypes: an output port carrying DMX512, which is what a node that
        // takes DMX off the network and does something with it declares.
        p[174 + i] = 0x80;
        // GoodOutputA: whether data is being transmitted on that port.
        p[182 + i] = if latched > 0 { 0x80 } else { 0x00 };
        // SwOut: the universe within the packet's net and sub-net.
        p[190 + i] = (port_address & 0x0F) as u8;
    }
    // Style at 200 stays 0: a node, as opposed to a controller or a media server.
    // MAC at 201..207 stays 0: not available.
    p[207..211].copy_from_slice(&ip.octets());
    p[211] = bind_index;
    // Status2: 15-bit port addresses are understood.
    p[212] = 0b0000_1000;
    p
}

/// Fill a fixed-width text field, NUL-terminated and truncated to fit.
fn write_text(field: &mut [u8], text: &[u8]) {
    let n = text.len().min(field.len().saturating_sub(1));
    field[..n].copy_from_slice(&text[..n]);
    field[n..].fill(0);
}

#[derive(Debug, Clone)]
pub struct Universe {
    pub values: [u8; UNIVERSE_SLOTS],
    /// Slots this universe has actually received. Trailing slots the desk
    /// never sent stay zero and are not transmitted.
    pub len: usize,
    pub captured: Instant,
    pub packets: u64,
    sequence: u8,
}

/// The current value of every universe seen so far.
#[derive(Debug, Default)]
pub struct Latch {
    universes: BTreeMap<u16, Universe>,
    pub packets: u64,
    /// Packets discarded because their sequence number was older than the one
    /// already held. Worth reporting: a steady count means two senders are
    /// fighting over the same universe.
    pub out_of_order: u64,
    /// Datagrams on the port that were neither `ArtDmx` nor `ArtPoll`.
    pub ignored: u64,
    /// `ArtPoll` packets answered.
    pub polls: u64,
    /// `ArtPoll` packets from a controller this machine had no route to yet,
    /// left unanswered rather than answered with an address of 0.0.0.0. One
    /// is normal for a desk reached through a router; a steady count means
    /// the routing table never gives an answer for it.
    pub polls_unanswered: u64,
    /// Who sent the most recent `ArtPoll`. A controller that polls but sends
    /// no DMX has found the node and not yet been told to use it, which is
    /// a different thing to wait for than a desk that is not there.
    pub last_controller: Option<SocketAddr>,
    /// Replies that could not be sent. The desk polls again within seconds, so
    /// one failure costs nothing; a steady count means it never hears us.
    pub reply_errors: u64,
    /// Set when the receive thread stops early. The relay prints it rather
    /// than silently carrying an empty lane.
    pub error: Option<String>,
    /// Where the next budgeted snapshot starts, so universes take turns when
    /// they do not all fit.
    cursor: usize,
}

impl Latch {
    /// Take one datagram. Returns true when it updated a universe.
    pub fn accept(&mut self, datagram: &[u8], now: Instant) -> bool {
        let Some(dmx) = parse_dmx(datagram) else {
            self.ignored += 1;
            return false;
        };
        self.packets += 1;

        let entry = self.universes.entry(dmx.universe).or_insert(Universe {
            values: [0; UNIVERSE_SLOTS],
            len: 0,
            captured: now,
            packets: 0,
            sequence: 0,
        });

        // Sequence 0 means the sender does not implement ordering, so every
        // packet is current. Otherwise the difference is signed modulo 256:
        // anything not ahead of what we hold arrived late and is stale.
        if dmx.sequence != 0 && entry.sequence != 0 {
            let delta = dmx.sequence.wrapping_sub(entry.sequence) as i8;
            if delta <= 0 {
                self.out_of_order += 1;
                return false;
            }
        }

        entry.values[..dmx.values.len()].copy_from_slice(dmx.values);
        entry.len = entry.len.max(dmx.values.len());
        entry.captured = now;
        entry.sequence = dmx.sequence;
        entry.packets += 1;
        true
    }

    pub fn universe_count(&self) -> usize {
        self.universes.len()
    }

    pub fn universes(&self) -> impl Iterator<Item = (&u16, &Universe)> {
        self.universes.iter()
    }

    /// Blocks for every universe that fits in `budget` payload bytes.
    ///
    /// Whole universes are sent every frame rather than only what changed,
    /// because absolute values mean a client that joins or drops a frame is
    /// correct again immediately. When they do not all fit, the starting point
    /// advances each call so no universe starves at the far end of the patch.
    pub fn snapshot(&mut self, now: Instant, budget: usize) -> Vec<Block> {
        let n = self.universes.len();
        if n == 0 || budget < PAYLOAD_HEADER_LEN + BLOCK_HEADER_LEN {
            return Vec::new();
        }
        let mut used = PAYLOAD_HEADER_LEN;
        let mut blocks = Vec::new();
        let keys: Vec<u16> = self.universes.keys().copied().collect();
        let start = self.cursor % n;

        let mut taken = 0usize;
        for step in 0..n {
            let idx = (start + step) % n;
            let u = &self.universes[&keys[idx]];
            if u.len == 0 {
                continue;
            }
            let cost = BLOCK_HEADER_LEN + u.len;
            if used + cost > budget {
                break;
            }
            used += cost;
            taken += 1;
            blocks.push(Block {
                universe: keys[idx],
                start: 0,
                age_us: u32::try_from(now.duration_since(u.captured).as_micros())
                    .unwrap_or(u32::MAX),
                values: u.values[..u.len].to_vec(),
            });
        }
        self.cursor = if taken == 0 { 0 } else { (start + taken) % n };
        blocks
    }
}

/// Where to listen, from an address, an `address:port`, or a bracketed IPv6
/// address with or without a port. The port is 6454 unless given.
pub fn parse_listen(spec: &str) -> Result<SocketAddr> {
    let spec = spec.trim();
    if let Ok(addr) = spec.parse::<SocketAddr>() {
        return Ok(addr);
    }
    if let Ok(ip) = spec.trim_matches(['[', ']']).parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, DEFAULT_PORT));
    }
    bail!(
        "{spec:?} is not an address to listen on; give an IP address, with :port after it \
         when it is not {DEFAULT_PORT}"
    )
}

/// A background thread receiving Art-Net into a shared latch.
pub struct Receiver {
    latch: Arc<Mutex<Latch>>,
    running: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
    pub local_addr: SocketAddr,
    /// A second socket on 127.0.0.1, held when `local_addr` is every address.
    ///
    /// A datagram to 127.0.0.1 is delivered to a socket bound to that address
    /// ahead of any bound to every address, so a desk on this machine that
    /// sends there reaches this receiver and not whichever other Art-Net node
    /// shares the port. Polls from such a desk are answered with this address.
    pub loopback_addr: Option<SocketAddr>,
}

impl Receiver {
    pub fn bind(addr: SocketAddr) -> Result<Self> {
        let socket = open(addr)?;
        let local_addr = socket.local_addr()?;
        let loopback = match addr.ip() {
            IpAddr::V4(v4) if v4.is_unspecified() => open(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                local_addr.port(),
            ))
            .ok(),
            _ => None,
        };
        let loopback_addr = loopback.as_ref().and_then(|s| s.local_addr().ok());

        let latch = Arc::new(Mutex::new(Latch::default()));
        let running = Arc::new(AtomicBool::new(true));
        let mut threads = Vec::new();
        for (name, socket) in
            std::iter::once(("artnet", socket)).chain(loopback.map(|s| ("artnet-loopback", s)))
        {
            let latch = Arc::clone(&latch);
            let running = Arc::clone(&running);
            threads.push(
                std::thread::Builder::new()
                    .name(name.into())
                    .spawn(move || receive_loop(&socket, &latch, &running))
                    .context("spawning the Art-Net receive thread")?,
            );
        }

        Ok(Self {
            latch,
            running,
            threads,
            local_addr,
            loopback_addr,
        })
    }

    pub fn latch(&self) -> MutexGuard<'_, Latch> {
        self.latch.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Drop for Receiver {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

/// An Art-Net socket on `addr`, sharing the port with any other node here.
fn open(addr: SocketAddr) -> Result<UdpSocket> {
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))
        .context("creating the Art-Net socket")?;
    socket
        .set_reuse_address(true)
        .context("setting SO_REUSEADDR")?;
    // Replies to a poll go out on the controller's subnet broadcast too.
    socket.set_broadcast(true).context("setting SO_BROADCAST")?;
    socket
        .bind(&addr.into())
        .with_context(|| format!("binding {addr}"))?;
    let socket: UdpSocket = socket.into();
    // Bounded so the thread notices a shutdown rather than blocking on a
    // desk that has stopped sending.
    socket.set_read_timeout(Some(Duration::from_millis(200)))?;
    Ok(socket)
}

fn receive_loop(socket: &UdpSocket, latch: &Mutex<Latch>, running: &AtomicBool) {
    // One datagram at a time. An ArtDmx packet is 530 bytes; anything larger on
    // this port belongs to a protocol this does not speak.
    let mut buf = [0u8; 2048];
    let mut routes = Routes::default();
    while running.load(Ordering::Relaxed) {
        match socket.recv_from(&mut buf) {
            Ok((n, from)) => {
                let now = Instant::now();
                if let Some(poll) = parse_poll(&buf[..n]) {
                    answer_poll(socket, latch, &poll, from, &mut routes);
                } else if let Ok(mut l) = latch.lock() {
                    l.accept(&buf[..n], now);
                }
            }
            // Both are how a read timeout surfaces, and neither is a failure.
            Err(ref e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
            Err(ref e) if e.kind() == ErrorKind::Interrupted => {}
            // Windows reports an ICMP port-unreachable for an earlier send as a
            // reset on the next receive. A reply sent to a controller that was
            // not listening on 6454 is the usual cause, and the socket is fine.
            Err(ref e) if e.kind() == ErrorKind::ConnectionReset => {}
            Err(e) => {
                // Reporting beats carrying an empty lane that looks like a desk
                // sending nothing.
                if let Ok(mut l) = latch.lock() {
                    l.error = Some(format!("Art-Net receive failed: {e}"));
                }
                return;
            }
        }
    }
}

/// Where a reply to a controller goes, and the address it carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Route {
    /// The local address the controller is told to send to.
    pub ip: Ipv4Addr,
    /// The directed broadcast of the subnet the controller is on, when that
    /// is one of this machine's subnets.
    pub broadcast: Option<Ipv4Addr>,
}

/// Answer an `ArtPoll` from `from`, if it is one this node should answer.
///
/// The reply is unicast to the controller's address on the Art-Net port,
/// which is where a controller listens, to the exact endpoint the poll came
/// from when that differs, and broadcast on the controller's subnet. The
/// broadcast is what reaches a controller on this same machine: a unicast to
/// a port two sockets share is delivered to whichever of them the operating
/// system picks, a broadcast to both. All of it leaves from the receive
/// socket, so the reply carries the Art-Net port as its source, which some
/// controllers check.
///
/// A targeted poll is answered only when one of the ports the reply would
/// advertise is in its range, so a controller never receives an answer that
/// names no port it asked about.
fn answer_poll(
    socket: &UdpSocket,
    latch: &Mutex<Latch>,
    poll: &ArtPoll,
    from: SocketAddr,
    routes: &mut Routes,
) {
    let IpAddr::V4(controller) = from.ip() else {
        // Art-Net carries IPv4 addresses in its packets, so there is nothing
        // truthful to tell an IPv6 controller.
        return;
    };
    let Ok(local) = socket.local_addr() else {
        return;
    };
    let (latched, ports) = {
        let Ok(l) = latch.lock() else {
            return;
        };
        let ports = advertised_ports(l.universes.keys().copied());
        if !poll.wants(ports.iter().copied()) {
            return;
        }
        (l.universes.len(), ports)
    };

    let r = routes.route_to(local.ip(), controller, Instant::now());
    // Counted as answered only once there is an answer: a desk told 0.0.0.0
    // would send its DMX there, so a controller with no route yet gets no
    // reply, and the next poll is answered once a route is known.
    let Ok(mut l) = latch.lock() else {
        return;
    };
    if r.ip.is_unspecified() {
        l.polls_unanswered += 1;
        return;
    }
    l.polls += 1;
    l.last_controller = Some(from);
    let replies = l.polls;
    drop(l);
    let packets = poll_replies(r.ip, local.port(), replies, latched, &ports);

    let mut targets = vec![SocketAddr::new(IpAddr::V4(controller), DEFAULT_PORT)];
    if from.port() != DEFAULT_PORT {
        targets.push(from);
    }
    if let Some(b) = r.broadcast {
        targets.push(SocketAddr::new(IpAddr::V4(b), DEFAULT_PORT));
    }
    let mut failed = 0u64;
    for packet in &packets {
        for &target in &targets {
            if socket.send_to(packet, target).is_err() {
                failed += 1;
            }
        }
    }
    if failed > 0
        && let Ok(mut l) = latch.lock()
    {
        l.reply_errors += failed;
    }
}

/// How often the interface list is read again, and the least time between
/// two askings of the routing table.
const ROUTES_REFRESH: Duration = Duration::from_secs(1);
/// How long a routing-table answer is kept for the controller it was for.
/// Routes change rarely, and keeping an answer well past the probe budget is
/// what serves two routed controllers whose polls land inside each other's
/// second: once each has been asked about once, neither needs asking again.
const ROUTE_TTL: Duration = Duration::from_secs(60);
/// Routed controllers remembered at once; past this the oldest makes way.
const MAX_PROBED: usize = 8;

/// Where replies go, worked out from a snapshot of this machine's interfaces.
///
/// The interface whose subnet holds the controller decides the address to
/// advertise and the broadcast to answer on, so a machine with a VPN or a
/// virtual adapter advertises the address the desk can actually reach rather
/// than whichever is listed first. A controller at one of this machine's own
/// addresses is on this machine, and is told to use 127.0.0.1, where
/// [`Receiver`] holds the socket that wins that delivery. A socket bound to
/// one address advertises that address whatever interface the controller is
/// on. A controller on none of this machine's subnets is reached through a
/// router: the routing table then says which local address a packet to it
/// leaves from, and no broadcast reaches it.
///
/// The snapshot is read again at most once a second, and the routing table
/// asked at most once a second, so what a poll costs the receive thread does
/// not depend on who sent it. Art-Net is unauthenticated, and a source
/// address is anyone's to choose. A controller there is no answer for yet
/// gets an unspecified address, which the caller must treat as no reply at
/// all rather than advertise.
pub struct Routes {
    interfaces: Vec<(Ipv4Addr, Ipv4Addr)>,
    refreshed: Option<Instant>,
    /// Routing-table answers by controller, with when each was asked.
    probed: Vec<(Ipv4Addr, Option<Ipv4Addr>, Instant)>,
    /// When the routing table was last asked, for the budget.
    last_probe: Option<Instant>,
    probe: fn(Ipv4Addr) -> Option<Ipv4Addr>,
}

impl Default for Routes {
    fn default() -> Self {
        Self {
            interfaces: Vec::new(),
            refreshed: None,
            probed: Vec::new(),
            last_probe: None,
            probe: probe_route,
        }
    }
}

impl Routes {
    /// The route to a controller at `controller`, as of `now`.
    pub fn route_to(&mut self, bound: IpAddr, controller: Ipv4Addr, now: Instant) -> Route {
        if self
            .refreshed
            .is_none_or(|t| now.duration_since(t) >= ROUTES_REFRESH)
        {
            self.interfaces = local_interfaces();
            self.refreshed = Some(now);
        }
        let bound = match bound {
            IpAddr::V4(v4) if !v4.is_unspecified() => Some(v4),
            _ => None,
        };
        // Being on this machine and being on a subnet with a broadcast are
        // separate questions: a VPN gives this machine an address on a /32.
        let local =
            controller.is_loopback() || self.interfaces.iter().any(|(ip, _)| *ip == controller);
        let subnet = subnet_of(controller, self.interfaces.iter().copied());
        let ip = match (bound, local, subnet) {
            (Some(b), _, _) => b,
            (None, true, _) => Ipv4Addr::LOCALHOST,
            (None, false, Some((ip, _))) => ip,
            (None, false, None) => self
                .probe_for(controller, now)
                .unwrap_or(Ipv4Addr::UNSPECIFIED),
        };
        Route {
            ip,
            broadcast: subnet.map(|(_, broadcast)| broadcast),
        }
    }

    /// The routing table's answer for a controller on no local subnet.
    ///
    /// An answer already held for this controller is used while it lasts: a
    /// minute for an address, a second for a failure, so a route that could
    /// not be found is tried again soon. Otherwise the table is asked at most
    /// once a second across every controller, and a controller arriving
    /// inside that second gets nothing this time. Two desks reached through
    /// a router whose polls land in each other's second are both served after
    /// one round, since the first's answer is still held when the second's
    /// turn comes; a flood of invented sources costs one probe a second
    /// however fast it arrives.
    fn probe_for(&mut self, controller: Ipv4Addr, now: Instant) -> Option<Ipv4Addr> {
        if let Some((_, answer, when)) = self.probed.iter().find(|(who, _, _)| *who == controller) {
            let ttl = if answer.is_some() {
                ROUTE_TTL
            } else {
                ROUTES_REFRESH
            };
            if now.duration_since(*when) < ttl {
                return *answer;
            }
        }
        if self
            .last_probe
            .is_some_and(|t| now.duration_since(t) < ROUTES_REFRESH)
        {
            return None;
        }
        let answer = (self.probe)(controller);
        self.last_probe = Some(now);
        self.probed.retain(|(who, _, _)| *who != controller);
        if self.probed.len() >= MAX_PROBED {
            self.probed.remove(0);
        }
        self.probed.push((controller, answer, now));
        answer
    }
}

/// This machine's IPv4 interfaces as `(address, netmask)` pairs.
fn local_interfaces() -> Vec<(Ipv4Addr, Ipv4Addr)> {
    if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|i| match i.addr {
            if_addrs::IfAddr::V4(v4) => Some((v4.ip, v4.netmask)),
            if_addrs::IfAddr::V6(_) => None,
        })
        .collect()
}

/// The address and directed broadcast of the first of `interfaces`, given as
/// `(address, netmask)` pairs, whose subnet holds `controller`.
///
/// Loopback is left out: it has no broadcast worth sending to, and a
/// controller there is already sending to this machine by address.
fn subnet_of(
    controller: Ipv4Addr,
    interfaces: impl IntoIterator<Item = (Ipv4Addr, Ipv4Addr)>,
) -> Option<(Ipv4Addr, Ipv4Addr)> {
    interfaces.into_iter().find_map(|(ip, mask)| {
        let mask_bits = mask.to_bits();
        // A /32 holds only itself and a /0 holds everything; neither is a
        // subnet with a broadcast.
        if ip.is_loopback() || mask_bits == 0 || mask_bits == u32::MAX {
            return None;
        }
        if ip.to_bits() & mask_bits != controller.to_bits() & mask_bits {
            return None;
        }
        Some((ip, Ipv4Addr::from_bits(ip.to_bits() | !mask_bits)))
    })
}

/// The local address a packet to `controller` would leave from, from the
/// routing table, which needs a socket and nothing else.
fn probe_route(controller: Ipv4Addr) -> Option<Ipv4Addr> {
    let probe = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .and_then(|s| s.connect((controller, DEFAULT_PORT)).map(|()| s))
        .and_then(|s| s.local_addr());
    match probe {
        Ok(SocketAddr::V4(a)) => Some(*a.ip()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    fn art_dmx(universe: u16, sequence: u8, values: &[u8]) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(ID);
        p.extend_from_slice(&OP_DMX.to_le_bytes());
        p.extend_from_slice(&14u16.to_be_bytes());
        p.push(sequence);
        p.push(0); // physical
        p.push((universe & 0xFF) as u8);
        p.push((universe >> 8) as u8);
        p.extend_from_slice(&(values.len() as u16).to_be_bytes());
        p.extend_from_slice(values);
        p
    }

    #[test]
    fn a_packet_decodes_its_port_address_and_slots() {
        let packet = art_dmx(0x0103, 7, &[1, 2, 3, 4]);
        let dmx = parse_dmx(&packet).expect("parses");
        assert_eq!(dmx.universe, 0x0103);
        assert_eq!(dmx.sequence, 7);
        assert_eq!(dmx.values, &[1, 2, 3, 4]);
    }

    #[test]
    fn other_opcodes_and_junk_are_not_errors_they_are_just_not_dmx() {
        let mut poll = art_dmx(0, 0, &[1]);
        poll[8..10].copy_from_slice(&0x2000u16.to_le_bytes()); // OpPoll
        assert!(parse_dmx(&poll).is_none());
        assert!(parse_dmx(b"not art-net at all").is_none());
        assert!(parse_dmx(&[]).is_none());
    }

    #[test]
    fn a_truncated_packet_keeps_the_slots_that_arrived() {
        let mut packet = art_dmx(0, 1, &[9; 512]);
        packet.truncate(PACKET_HEADER_LEN + 16);
        let dmx = parse_dmx(&packet).expect("parses");
        assert_eq!(dmx.values.len(), 16);
    }

    #[test]
    fn the_latch_keeps_the_newest_value_per_universe() {
        let mut latch = Latch::default();
        let now = Instant::now();
        assert!(latch.accept(&art_dmx(0, 1, &[10, 20]), now));
        assert!(latch.accept(&art_dmx(0, 2, &[30, 40]), now));
        assert!(latch.accept(&art_dmx(5, 1, &[50]), now));

        let blocks = latch.snapshot(now, 4096);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].universe, 0);
        assert_eq!(blocks[0].values, vec![30, 40]);
        assert_eq!(blocks[1].universe, 5);
        assert_eq!(latch.packets, 3);
    }

    #[test]
    fn a_late_packet_does_not_overwrite_a_newer_one() {
        let mut latch = Latch::default();
        let now = Instant::now();
        latch.accept(&art_dmx(0, 10, &[1]), now);
        assert!(!latch.accept(&art_dmx(0, 9, &[2]), now));
        assert_eq!(latch.out_of_order, 1);
        assert_eq!(latch.snapshot(now, 4096)[0].values, vec![1]);
    }

    #[test]
    fn sequence_numbers_wrap_without_stalling_the_universe() {
        let mut latch = Latch::default();
        let now = Instant::now();
        latch.accept(&art_dmx(0, 255, &[1]), now);
        assert!(
            latch.accept(&art_dmx(0, 1, &[2]), now),
            "255 -> 1 is forward"
        );
        assert_eq!(latch.out_of_order, 0);
    }

    #[test]
    fn sequence_zero_means_ordering_is_not_implemented_so_nothing_is_dropped() {
        let mut latch = Latch::default();
        let now = Instant::now();
        latch.accept(&art_dmx(0, 0, &[1]), now);
        assert!(latch.accept(&art_dmx(0, 0, &[2]), now));
        assert_eq!(latch.out_of_order, 0);
    }

    #[test]
    fn a_budget_too_small_for_everything_rotates_rather_than_starving_a_universe() {
        let mut latch = Latch::default();
        let now = Instant::now();
        for u in 0..4u16 {
            latch.accept(&art_dmx(u, 1, &[u as u8; 512]), now);
        }
        // Room for two blocks per frame, four universes patched.
        let budget = PAYLOAD_HEADER_LEN + 2 * (BLOCK_HEADER_LEN + 512);

        let first: Vec<u16> = latch
            .snapshot(now, budget)
            .iter()
            .map(|b| b.universe)
            .collect();
        let second: Vec<u16> = latch
            .snapshot(now, budget)
            .iter()
            .map(|b| b.universe)
            .collect();
        let third: Vec<u16> = latch
            .snapshot(now, budget)
            .iter()
            .map(|b| b.universe)
            .collect();

        assert_eq!(first, vec![0, 1]);
        assert_eq!(second, vec![2, 3]);
        assert_eq!(third, vec![0, 1], "the rotation comes back round");
    }

    #[test]
    fn a_snapshot_fits_the_budget_it_was_given() {
        let mut latch = Latch::default();
        let now = Instant::now();
        for u in 0..20u16 {
            latch.accept(&art_dmx(u, 1, &[7; 512]), now);
        }
        let budget = 9216;
        let blocks = latch.snapshot(now, budget);
        assert!(crate::payload::encoded_len(&blocks) <= budget);
        assert_eq!(
            blocks.len(),
            (budget - PAYLOAD_HEADER_LEN) / (BLOCK_HEADER_LEN + 512)
        );
    }

    #[test]
    fn an_empty_latch_produces_nothing_to_send() {
        let mut latch = Latch::default();
        assert!(latch.snapshot(Instant::now(), 9216).is_empty());
    }

    #[test]
    fn the_receiver_binds_and_latches_from_a_real_socket() {
        let recv = Receiver::bind("127.0.0.1:0".parse().unwrap()).expect("binds");
        let to = recv.local_addr;
        let sender = UdpSocket::bind("127.0.0.1:0").expect("sender binds");
        sender
            .send_to(&art_dmx(2, 1, &[1, 2, 3]), to)
            .expect("sends");

        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if recv.latch().universe_count() == 1 {
                break;
            }
            assert!(Instant::now() < deadline, "no packet latched");
            std::thread::sleep(Duration::from_millis(10));
        }
        let blocks = recv.latch().snapshot(Instant::now(), 4096);
        assert_eq!(blocks[0].universe, 2);
        assert_eq!(blocks[0].values, vec![1, 2, 3]);
    }

    fn art_poll(flags: u8, range: Option<(u16, u16)>) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(ID);
        p.extend_from_slice(&OP_POLL.to_le_bytes());
        p.extend_from_slice(&14u16.to_be_bytes());
        p.push(flags);
        p.push(0); // diagnostic priority
        if let Some((top, bottom)) = range {
            p.extend_from_slice(&top.to_be_bytes());
            p.extend_from_slice(&bottom.to_be_bytes());
        }
        p
    }

    #[test]
    fn a_poll_parses_and_what_is_not_one_does_not() {
        let poll = parse_poll(&art_poll(0, None)).expect("parses");
        assert_eq!(poll.flags, 0);
        assert_eq!(poll.targeted, None);

        let mut old = art_poll(0, None);
        old[10..12].copy_from_slice(&13u16.to_be_bytes());
        assert!(
            parse_poll(&old).is_none(),
            "protocol 13 is before Art-Net 3"
        );
        assert!(parse_poll(&art_poll(0, None)[..13]).is_none(), "short");
        assert!(
            parse_poll(&art_dmx(0, 1, &[1])).is_none(),
            "DMX is not a poll"
        );
        assert!(parse_dmx(&art_poll(0, None)).is_none(), "a poll is not DMX");
    }

    #[test]
    fn targeted_mode_reads_its_range_and_decides_from_it() {
        let poll = parse_poll(&art_poll(POLL_FLAG_TARGETED, Some((20, 10)))).expect("parses");
        assert_eq!(
            poll.targeted,
            Some((10, 20)),
            "ordered low to high whichever way it came"
        );
        assert!(poll.wants([15]));
        assert!(poll.wants([0, 20]));
        assert!(!poll.wants([0, 21]));
        assert!(!poll.wants([]));

        let short = parse_poll(&art_poll(POLL_FLAG_TARGETED, None)).expect("parses");
        assert_eq!(
            short.targeted, None,
            "the flag without the range is a plain poll"
        );
        assert!(short.wants([]));

        let plain = parse_poll(&art_poll(0, Some((20, 10)))).expect("parses");
        assert_eq!(
            plain.targeted, None,
            "the range without the flag is ignored"
        );
    }

    #[test]
    fn the_reply_is_laid_out_as_the_specification_says() {
        let ip = Ipv4Addr::new(192, 168, 1, 20);
        // Net 1, sub-net 2, universes 3 and 5.
        let p = poll_reply(ip, DEFAULT_PORT, 7, 3, 1, &[0x0123, 0x0125]);
        assert_eq!(p.len(), POLL_REPLY_LEN);
        assert_eq!(&p[..8], ID);
        assert_eq!(&p[8..10], &[0x00, 0x21], "OpPollReply, little-endian");
        assert_eq!(&p[10..14], &ip.octets());
        assert_eq!(&p[14..16], &[0x36, 0x19], "6454, little-endian");
        assert_eq!(p[18], 1, "net");
        assert_eq!(p[19], 2, "sub-net");
        assert_eq!(&p[20..22], &OEM_UNKNOWN.to_be_bytes());
        assert_eq!(&p[24..26], &ESTA_EXPERIMENTAL.to_le_bytes());
        assert!(p[26..44].starts_with(b"Truss\0"));
        assert!(p[44..108].starts_with(LONG_NAME));
        assert_eq!(p[44 + LONG_NAME.len()], 0);
        assert!(p[108..172].starts_with(b"#0001 [0007] Truss relay, 3 universes latched\0"));
        assert_eq!(&p[172..174], &[0, 2], "two ports, big-endian");
        assert_eq!(
            &p[174..178],
            &[0x80, 0x80, 0, 0],
            "output ports carrying DMX512"
        );
        assert_eq!(
            &p[182..186],
            &[0x80, 0x80, 0, 0],
            "data flowing while universes are held"
        );
        assert_eq!(&p[190..194], &[3, 5, 0, 0], "universes within the sub-net");
        assert_eq!(p[200], 0, "a node");
        assert_eq!(&p[207..211], &ip.octets(), "bound to the same address");
        assert_eq!(p[211], 1, "the root device");
        assert_eq!(p[212], 0b0000_1000, "15-bit port addresses");

        let idle = poll_reply(ip, DEFAULT_PORT, 0, 0, 1, &[0]);
        assert_eq!(idle[182], 0, "no data flowing before the first universe");
        let wrapped = poll_reply(ip, DEFAULT_PORT, 123_456, 0, 1, &[0]);
        assert!(wrapped[108..172].starts_with(b"#0001 [3456]"));
    }

    #[test]
    fn ports_are_packed_four_to_a_packet_within_one_sub_net() {
        let ip = Ipv4Addr::new(10, 0, 0, 2);
        let ports = [0, 1, 2, 3, 4, 0x11, 0x0100];
        let packets = poll_replies(ip, DEFAULT_PORT, 1, 7, &ports);
        let shape: Vec<(u8, u8, u8, Vec<u8>)> = packets
            .iter()
            .map(|p| {
                let n = usize::from(p[173]);
                (p[211], p[18], p[19], p[190..190 + n].to_vec())
            })
            .collect();
        assert_eq!(
            shape,
            vec![
                (1, 0, 0, vec![0, 1, 2, 3]),
                (2, 0, 0, vec![4]),
                (3, 0, 1, vec![1]),
                (4, 1, 0, vec![0]),
            ],
            "(bind index, net, sub-net, universes)"
        );
        for p in &packets {
            assert!(
                p[174..174 + usize::from(p[173])].iter().all(|&t| t == 0x80),
                "every advertised port is an output"
            );
        }
    }

    #[test]
    fn a_node_with_nothing_latched_advertises_universe_zero_and_no_more_than_the_cap() {
        assert_eq!(advertised_ports([]), vec![0]);
        assert_eq!(advertised_ports([4, 9]), vec![4, 9]);
        let many = advertised_ports(0..100);
        assert_eq!(many.len(), MAX_ADVERTISED_PORTS);
        let packets = poll_replies(Ipv4Addr::LOCALHOST, DEFAULT_PORT, 1, 100, &many);
        assert_eq!(packets.len(), MAX_ADVERTISED_PORTS / PORTS_PER_REPLY);
        assert_eq!(
            packets.last().unwrap()[211],
            8,
            "bind indexes run to the last packet"
        );
    }

    #[test]
    fn text_that_does_not_fit_is_cut_and_still_terminated() {
        let mut field = [0xFFu8; 6];
        write_text(&mut field, b"too long for this");
        assert_eq!(&field, b"too l\0");
        let mut exact = [0xFFu8; 6];
        write_text(&mut exact, b"12345");
        assert_eq!(&exact, b"12345\0");
    }

    #[test]
    fn the_receiver_answers_a_poll_on_the_port_it_came_from() {
        let recv = Receiver::bind("127.0.0.1:0".parse().unwrap()).expect("binds");
        let to = recv.local_addr;
        let controller = UdpSocket::bind("127.0.0.1:0").expect("controller binds");
        controller
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        controller.send_to(&art_poll(0, None), to).expect("sends");

        let mut buf = [0u8; 512];
        let (n, from) = controller.recv_from(&mut buf).expect("a reply arrives");
        assert_eq!(
            from, to,
            "sent from the Art-Net socket, not a throwaway one"
        );
        assert_eq!(n, POLL_REPLY_LEN);
        assert_eq!(&buf[..8], ID);
        assert_eq!(&buf[8..10], &[0x00, 0x21]);
        assert_eq!(&buf[10..14], &[127, 0, 0, 1], "the address it is bound to");
        assert_eq!(
            u16::from_le_bytes([buf[14], buf[15]]),
            to.port(),
            "the port it is actually listening on"
        );

        assert_eq!(buf[173], 1, "one port before anything is latched");
        assert_eq!(buf[190], 0, "universe 0");
        {
            let latch = recv.latch();
            assert_eq!(latch.polls, 1);
            assert_eq!(
                latch.last_controller,
                Some(controller.local_addr().unwrap())
            );
            assert_eq!(latch.ignored, 0, "a poll is not junk");
        }

        // Once universes 7 and 8 have been heard, the next poll advertises
        // them, and a targeted poll for either finds the node while one for
        // universe 0 no longer does.
        controller.send_to(&art_dmx(7, 1, &[1]), to).unwrap();
        controller.send_to(&art_dmx(8, 1, &[1]), to).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while recv.latch().universe_count() < 2 {
            assert!(Instant::now() < deadline, "universes not latched");
            std::thread::sleep(Duration::from_millis(10));
        }
        controller.send_to(&art_poll(0, None), to).unwrap();
        let (n, _) = controller.recv_from(&mut buf).expect("a reply arrives");
        assert_eq!(n, POLL_REPLY_LEN);
        assert_eq!(buf[173], 2, "both universes advertised");
        assert_eq!(&buf[190..192], &[7, 8]);
        assert_eq!(buf[182], 0x80, "with data flowing");

        controller
            .send_to(&art_poll(POLL_FLAG_TARGETED, Some((8, 8))), to)
            .unwrap();
        let (n, _) = controller.recv_from(&mut buf).expect("universe 8 is ours");
        assert_eq!(n, POLL_REPLY_LEN);
        controller
            .send_to(&art_poll(POLL_FLAG_TARGETED, Some((0, 0))), to)
            .unwrap();
        assert!(
            controller.recv_from(&mut buf).is_err(),
            "universe 0 is no longer advertised, so no reply"
        );
        assert_eq!(recv.latch().polls, 3);
    }

    #[test]
    fn a_listen_address_takes_the_art_net_port_unless_told_otherwise() {
        assert_eq!(
            parse_listen("0.0.0.0").unwrap(),
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, DEFAULT_PORT))
        );
        assert_eq!(
            parse_listen("192.168.1.233:6455").unwrap(),
            "192.168.1.233:6455".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            parse_listen("::1").unwrap(),
            "[::1]:6454".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            parse_listen("[::1]").unwrap(),
            "[::1]:6454".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            parse_listen("[::1]:6455").unwrap(),
            "[::1]:6455".parse::<SocketAddr>().unwrap()
        );
        let e = parse_listen("desk").unwrap_err().to_string();
        assert!(e.contains("not an address"), "{e}");
        assert!(parse_listen("").is_err());
    }

    #[test]
    fn bound_to_every_address_the_receiver_also_holds_loopback() {
        let recv = Receiver::bind("0.0.0.0:0".parse().unwrap()).expect("binds");
        let port = recv.local_addr.port();
        let lo = recv.loopback_addr.expect("a loopback companion");
        assert_eq!(lo, SocketAddr::from((Ipv4Addr::LOCALHOST, port)));

        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.send_to(&art_dmx(3, 1, &[9]), lo).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while recv.latch().universe_count() == 0 {
            assert!(Instant::now() < deadline, "nothing latched via loopback");
            std::thread::sleep(Duration::from_millis(10));
        }

        let pinned = Receiver::bind("127.0.0.1:0".parse().unwrap()).expect("binds");
        assert_eq!(pinned.loopback_addr, None, "already on loopback");
    }

    #[test]
    fn a_desk_on_this_machine_is_told_to_use_loopback() {
        // Every IPv4 address this machine has, a VPN's /32 included.
        let own: Vec<(Ipv4Addr, u8)> = if_addrs::get_if_addrs()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|i| match i.addr {
                if_addrs::IfAddr::V4(v4) if !v4.ip.is_loopback() => Some((v4.ip, v4.prefixlen)),
                _ => None,
            })
            .collect();
        let mut routes = Routes::default();
        for (ip, prefixlen) in own {
            let r = routes.route_to(IpAddr::V4(Ipv4Addr::UNSPECIFIED), ip, Instant::now());
            assert_eq!(r.ip, Ipv4Addr::LOCALHOST, "{ip}/{prefixlen}");
            assert_eq!(
                r.broadcast.is_some(),
                prefixlen < 32,
                "{ip}/{prefixlen}: a subnet with room for a broadcast is answered on it"
            );

            let r = routes.route_to(IpAddr::V4(ip), ip, Instant::now());
            assert_eq!(r.ip, ip, "a pinned socket has no loopback companion");
        }
    }

    #[test]
    fn the_interface_whose_subnet_holds_the_controller_gives_the_broadcast() {
        let lan = (
            Ipv4Addr::new(192, 168, 1, 233),
            Ipv4Addr::new(255, 255, 255, 0),
        );
        let switch = (
            Ipv4Addr::new(172, 25, 160, 1),
            Ipv4Addr::new(255, 255, 240, 0),
        );
        let interfaces = [lan, switch];
        assert_eq!(
            subnet_of(Ipv4Addr::new(172, 25, 170, 9), interfaces),
            Some((switch.0, Ipv4Addr::new(172, 25, 175, 255)))
        );
        assert_eq!(
            subnet_of(Ipv4Addr::new(192, 168, 1, 5), interfaces),
            Some((lan.0, Ipv4Addr::new(192, 168, 1, 255)))
        );
        assert_eq!(
            subnet_of(Ipv4Addr::new(10, 9, 9, 9), interfaces),
            None,
            "routed"
        );

        let host_only = [(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::BROADCAST)];
        assert_eq!(
            subnet_of(Ipv4Addr::new(10, 0, 0, 1), host_only),
            None,
            "/32"
        );
        let everything = [(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::UNSPECIFIED)];
        assert_eq!(
            subnet_of(Ipv4Addr::new(10, 0, 0, 1), everything),
            None,
            "/0"
        );
        let loopback = [(Ipv4Addr::LOCALHOST, Ipv4Addr::new(255, 0, 0, 0))];
        assert_eq!(subnet_of(Ipv4Addr::LOCALHOST, loopback), None, "loopback");
    }

    #[test]
    fn a_bound_address_is_advertised_as_it_is() {
        let mut routes = Routes::default();
        let bound = Ipv4Addr::new(10, 1, 2, 3);
        let r = routes.route_to(
            IpAddr::V4(bound),
            Ipv4Addr::new(10, 1, 2, 9),
            Instant::now(),
        );
        assert_eq!(r.ip, bound);

        // Unspecified asks the interfaces; loopback is on this machine and is
        // reached by address, with no broadcast.
        let r = routes.route_to(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            Ipv4Addr::LOCALHOST,
            Instant::now(),
        );
        assert_eq!(
            r,
            Route {
                ip: Ipv4Addr::LOCALHOST,
                broadcast: None
            }
        );
    }

    static PROBES: AtomicUsize = AtomicUsize::new(0);

    fn counted_probe(_: Ipv4Addr) -> Option<Ipv4Addr> {
        PROBES.fetch_add(1, Ordering::Relaxed);
        Some(Ipv4Addr::new(203, 0, 113, 5))
    }

    fn fixed_probe(_: Ipv4Addr) -> Option<Ipv4Addr> {
        Some(Ipv4Addr::new(203, 0, 113, 5))
    }

    /// A snapshot holding one invented interface, taken at `now`, with
    /// `probe` in place of the routing table.
    fn invented_routes(now: Instant, probe: fn(Ipv4Addr) -> Option<Ipv4Addr>) -> Routes {
        Routes {
            interfaces: vec![(Ipv4Addr::new(10, 7, 7, 1), Ipv4Addr::new(255, 255, 255, 0))],
            refreshed: Some(now),
            probed: Vec::new(),
            last_probe: None,
            probe,
        }
    }

    #[test]
    fn the_snapshot_serves_a_second_of_polls_and_is_then_read_again() {
        let t0 = Instant::now();
        let mut routes = invented_routes(t0, fixed_probe);
        let desk = Ipv4Addr::new(10, 7, 7, 9);
        let any = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

        let r = routes.route_to(any, desk, t0);
        assert_eq!(
            r.ip,
            Ipv4Addr::new(10, 7, 7, 1),
            "from the snapshot, no walk"
        );
        assert_eq!(r.broadcast, Some(Ipv4Addr::new(10, 7, 7, 255)));
        let r = routes.route_to(
            any,
            Ipv4Addr::new(10, 7, 7, 10),
            t0 + Duration::from_millis(900),
        );
        assert_eq!(
            r.ip,
            Ipv4Addr::new(10, 7, 7, 1),
            "another controller, same snapshot"
        );

        // A second on, the real interfaces are read and the invented one is
        // gone, so the desk is now off every subnet and the probe answers.
        let r = routes.route_to(any, desk, t0 + Duration::from_secs(1));
        assert_eq!(r.broadcast, None);
        assert_eq!(r.ip, Ipv4Addr::new(203, 0, 113, 5));
    }

    static FAILED_PROBES: AtomicUsize = AtomicUsize::new(0);

    fn failing_probe(_: Ipv4Addr) -> Option<Ipv4Addr> {
        FAILED_PROBES.fetch_add(1, Ordering::Relaxed);
        None
    }

    #[test]
    fn the_routing_table_is_asked_at_most_once_a_second_and_every_controller_is_served() {
        let t0 = Instant::now();
        // The counter is this test's alone, so nothing else moves it.
        let mut routes = invented_routes(t0, counted_probe);
        let any = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let answer = Ipv4Addr::new(203, 0, 113, 5);
        // TEST-NET-2, on no subnet of any machine.
        let far = Ipv4Addr::new(198, 51, 100, 1);
        let other = Ipv4Addr::new(198, 51, 100, 2);
        let probes = || PROBES.load(Ordering::Relaxed);
        let before = probes();
        let at = |ms: u64| t0 + Duration::from_millis(ms);

        assert_eq!(routes.route_to(any, far, at(0)).ip, answer);
        assert_eq!(probes(), before + 1);

        let r = routes.route_to(any, other, at(100));
        assert_eq!(
            r.ip,
            Ipv4Addr::UNSPECIFIED,
            "no probe to spare for a second source inside the second"
        );
        assert_eq!(probes(), before + 1);

        assert_eq!(
            routes.route_to(any, far, at(200)).ip,
            answer,
            "the held answer, for who it was for"
        );
        assert_eq!(probes(), before + 1);

        assert_eq!(
            routes.route_to(any, other, at(1500)).ip,
            answer,
            "asked again once the second is up"
        );
        assert_eq!(probes(), before + 2);

        // From here both are held, so two controllers whose polls keep landing
        // inside each other's second are both answered without another probe.
        for (who, ms) in [(far, 3000), (other, 3500), (far, 6000), (other, 6500)] {
            assert_eq!(
                routes.route_to(any, who, at(ms)).ip,
                answer,
                "{who} at +{ms} ms"
            );
        }
        assert_eq!(probes(), before + 2);
    }

    #[test]
    fn a_route_that_could_not_be_found_is_tried_again_soon() {
        let t0 = Instant::now();
        let mut routes = invented_routes(t0, failing_probe);
        let any = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let far = Ipv4Addr::new(198, 51, 100, 3);
        let before = FAILED_PROBES.load(Ordering::Relaxed);

        assert_eq!(routes.route_to(any, far, t0).ip, Ipv4Addr::UNSPECIFIED);
        assert_eq!(FAILED_PROBES.load(Ordering::Relaxed), before + 1);
        routes.route_to(any, far, t0 + Duration::from_millis(500));
        assert_eq!(
            FAILED_PROBES.load(Ordering::Relaxed),
            before + 1,
            "a failure is held for the second, not asked again at once"
        );
        routes.route_to(any, far, t0 + Duration::from_millis(1500));
        assert_eq!(
            FAILED_PROBES.load(Ordering::Relaxed),
            before + 2,
            "and asked again after it"
        );
    }
}
