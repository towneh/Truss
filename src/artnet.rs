//! Art-Net ingest: the live desk data the SEI lane carries.
//!
//! A lighting desk broadcasts `ArtDmx` packets, one per universe, at up to
//! 44 Hz. The video frame grid runs slower than that, so this is a latch rather
//! than a queue: the newest value for each universe wins and intermediate ones
//! are dropped. That is the same thing every other Art-Net node does, and it is
//! safe because DMX values are absolute.
//!
//! The socket is bound with `SO_REUSEADDR` so another Art-Net consumer on the
//! same machine can keep running alongside this one. That only works for
//! broadcast traffic: if the desk is set to unicast to a single node's address,
//! exactly one process receives each packet and which one is undefined. Patch
//! both as separate nodes on the desk, or broadcast.

use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};

use crate::payload::{BLOCK_HEADER_LEN, Block, HEADER_LEN as PAYLOAD_HEADER_LEN};

pub const DEFAULT_PORT: u16 = 6454;
pub const UNIVERSE_SLOTS: usize = 512;

const ID: &[u8; 8] = b"Art-Net\0";
const OP_DMX: u16 = 0x5000;
const MIN_PROT_VER: u16 = 14;
const PACKET_HEADER_LEN: usize = 18;

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
    /// Datagrams on the port that were not `ArtDmx`.
    pub ignored: u64,
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

/// A background thread receiving Art-Net into a shared latch.
pub struct Receiver {
    latch: Arc<Mutex<Latch>>,
    running: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    pub local_addr: SocketAddr,
}

impl Receiver {
    pub fn bind(addr: SocketAddr) -> Result<Self> {
        let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))
            .context("creating the Art-Net socket")?;
        // Shares the port with any other Art-Net node on this machine.
        socket
            .set_reuse_address(true)
            .context("setting SO_REUSEADDR")?;
        socket
            .bind(&addr.into())
            .with_context(|| format!("binding {addr}"))?;
        let socket: UdpSocket = socket.into();
        // Bounded so the thread notices a shutdown rather than blocking on a
        // desk that has stopped sending.
        socket.set_read_timeout(Some(Duration::from_millis(200)))?;
        let local_addr = socket.local_addr()?;

        let latch = Arc::new(Mutex::new(Latch::default()));
        let running = Arc::new(AtomicBool::new(true));
        let thread = {
            let latch = Arc::clone(&latch);
            let running = Arc::clone(&running);
            std::thread::Builder::new()
                .name("artnet".into())
                .spawn(move || receive_loop(&socket, &latch, &running))
                .context("spawning the Art-Net receive thread")?
        };

        Ok(Self {
            latch,
            running,
            thread: Some(thread),
            local_addr,
        })
    }

    pub fn latch(&self) -> MutexGuard<'_, Latch> {
        self.latch.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Drop for Receiver {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn receive_loop(socket: &UdpSocket, latch: &Mutex<Latch>, running: &AtomicBool) {
    // One datagram at a time. An ArtDmx packet is 530 bytes; anything larger on
    // this port belongs to a protocol this does not speak.
    let mut buf = [0u8; 2048];
    while running.load(Ordering::Relaxed) {
        match socket.recv_from(&mut buf) {
            Ok((n, _from)) => {
                let now = Instant::now();
                if let Ok(mut l) = latch.lock() {
                    l.accept(&buf[..n], now);
                }
            }
            // Both are how a read timeout surfaces, and neither is a failure.
            Err(ref e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
            Err(ref e) if e.kind() == ErrorKind::Interrupted => {}
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
