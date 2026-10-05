//! A deliberately nosy MPEG-TS reader.
//!
//! A player's demuxer throws away everything it was not asked for: PIDs absent
//! from the PMT, stream types it cannot decode, sections it does not parse.
//! That is correct for playback and useless here, because the question is
//! precisely "did something we did not expect come through". So this reader
//! counts every PID it sees, names every stream type it finds, and flags any
//! PID carrying data that the PMT never declared.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::codec::VideoCodec;

pub const PACKET_LEN: usize = 188;
const SYNC_BYTE: u8 = 0x47;
const PID_PAT: u16 = 0x0000;
const PID_NULL: u16 = 0x1FFF;

/// Largest PES packet held while waiting for the next payload-unit-start. A
/// video access unit at the bitrates this carrier targets is a few hundred KB.
pub const MAX_PES_BYTES: usize = 4 * 1024 * 1024;
/// And across every PID at once. A 13-bit PID space is 8192 assemblers, so a
/// per-PID cap on its own still leaves room for tens of gigabytes.
pub const MAX_PES_TOTAL: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct PesUnit {
    pub pid: u16,
    pub stream_id: u8,
    pub pts: Option<u64>,
    pub dts: Option<u64>,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct StreamInfo {
    pub pid: u16,
    pub stream_type: u8,
    pub descriptor_tags: Vec<u8>,
}

impl StreamInfo {
    pub fn type_name(&self) -> &'static str {
        stream_type_name(self.stream_type)
    }

    /// `None` for anything that is not video the scanner can walk.
    pub fn video_codec(&self) -> Option<VideoCodec> {
        match self.stream_type {
            0x1B => Some(VideoCodec::H264),
            0x24 => Some(VideoCodec::Hevc),
            _ => None,
        }
    }
}

pub fn stream_type_name(t: u8) -> &'static str {
    match t {
        0x01 => "MPEG-1 video",
        0x02 => "MPEG-2 video",
        0x03 => "MPEG-1 audio",
        0x04 => "MPEG-2 audio",
        0x05 => "private sections",
        0x06 => "PES private data",
        0x0F => "AAC (ADTS)",
        0x11 => "AAC (LATM)",
        0x15 => "metadata in PES",
        0x1B => "H.264",
        0x24 => "HEVC",
        0x81 => "AC-3",
        0x86 => "SCTE-35",
        _ => "unknown",
    }
}

#[derive(Default)]
struct SectionAssembler {
    buf: Vec<u8>,
    want: usize,
}

#[derive(Default)]
struct PesAssembler {
    buf: Vec<u8>,
    started: bool,
}

#[derive(Debug, Default, Clone)]
pub struct TsStats {
    pub bytes: u64,
    pub packets: u64,
    /// Bytes discarded while hunting for a sync byte.
    pub resync_bytes: u64,
    pub continuity_errors: u64,
    pub packets_by_pid: BTreeMap<u16, u64>,
    pub scrambled_packets: u64,
    /// Reassemblies abandoned for running past the buffer limits. A sender that
    /// never closes a PES packet and one that carries none look identical
    /// without this.
    pub pes_overflow_drops: u64,
}

pub struct TsAnalyzer {
    buf: Vec<u8>,
    pub stats: TsStats,
    pub pmt_pids: BTreeSet<u16>,
    pub streams: BTreeMap<u16, StreamInfo>,
    pub pcr_pid: Option<u16>,
    pub service_name: Option<String>,
    sections: HashMap<u16, SectionAssembler>,
    pes: HashMap<u16, PesAssembler>,
    /// Bytes held across every PES assembler, kept alongside them so the total
    /// can be bounded without walking the map on each packet.
    pes_buffered: usize,
    last_cc: HashMap<u16, u8>,
}

impl Default for TsAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl TsAnalyzer {
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            stats: TsStats::default(),
            pmt_pids: BTreeSet::new(),
            streams: BTreeMap::new(),
            pcr_pid: None,
            service_name: None,
            sections: HashMap::new(),
            pes: HashMap::new(),
            pes_buffered: 0,
            last_cc: HashMap::new(),
        }
    }

    /// PIDs that carried packets but were never declared in a PMT, excluding
    /// the reserved ones. A non-empty list here is the headline result for any
    /// carrier that tries to smuggle a whole elementary stream through.
    pub fn undeclared_pids(&self) -> Vec<u16> {
        self.stats
            .packets_by_pid
            .keys()
            .copied()
            .filter(|pid| {
                *pid != PID_PAT
                    && *pid != PID_NULL
                    && *pid > 0x001F
                    && !self.pmt_pids.contains(pid)
                    && !self.streams.contains_key(pid)
            })
            .collect()
    }

    /// Bytes currently held across every PES assembler. Bounded by
    /// [`MAX_PES_TOTAL`], which is the property the fuzz targets assert.
    pub fn pes_buffered(&self) -> usize {
        self.pes_buffered
    }

    pub fn feed(&mut self, bytes: &[u8]) -> Vec<PesUnit> {
        self.stats.bytes += bytes.len() as u64;
        self.buf.extend_from_slice(bytes);
        let mut out = Vec::new();

        loop {
            if self.buf.len() < PACKET_LEN {
                break;
            }
            if self.buf[0] != SYNC_BYTE {
                // Drop one byte at a time until a plausible packet boundary
                // appears. Confirming against the *next* sync byte avoids
                // locking onto a 0x47 that happens to sit inside a payload.
                let skip = self
                    .buf
                    .iter()
                    .position(|&b| b == SYNC_BYTE)
                    .unwrap_or(self.buf.len());
                let skip = skip.max(1);
                self.stats.resync_bytes += skip as u64;
                self.buf.drain(..skip);
                continue;
            }
            let packet: [u8; PACKET_LEN] = match self.buf[..PACKET_LEN].try_into() {
                Ok(p) => p,
                Err(_) => break,
            };
            self.buf.drain(..PACKET_LEN);
            self.handle_packet(&packet, &mut out);
        }
        out
    }

    /// Emit whatever PES payloads are still buffered. A live stream ends
    /// mid-packet, and the last access unit is often the interesting one.
    pub fn flush(&mut self) -> Vec<PesUnit> {
        let mut out = Vec::new();
        let pids: Vec<u16> = self.pes.keys().copied().collect();
        for pid in pids {
            if let Some(asm) = self.pes.get_mut(&pid)
                && asm.started
                && !asm.buf.is_empty()
            {
                let data = std::mem::take(&mut asm.buf);
                asm.started = false;
                if let Some(unit) = parse_pes(pid, &data) {
                    out.push(unit);
                }
            }
        }
        self.pes_buffered = 0;
        out
    }

    fn handle_packet(&mut self, p: &[u8; PACKET_LEN], out: &mut Vec<PesUnit>) {
        self.stats.packets += 1;
        let pid = (((p[1] & 0x1F) as u16) << 8) | p[2] as u16;
        *self.stats.packets_by_pid.entry(pid).or_insert(0) += 1;

        if pid == PID_NULL {
            return;
        }
        let scrambling = (p[3] >> 6) & 0x03;
        if scrambling != 0 {
            self.stats.scrambled_packets += 1;
        }

        let pusi = p[1] & 0x40 != 0;
        let afc = (p[3] >> 4) & 0x03;
        let cc = p[3] & 0x0F;
        let has_payload = afc & 0x01 != 0;

        if has_payload {
            if let Some(&prev) = self.last_cc.get(&pid)
                && (prev + 1) & 0x0F != cc
            {
                self.stats.continuity_errors += 1;
            }
            self.last_cc.insert(pid, cc);
        }

        let mut off = 4usize;
        if afc & 0x02 != 0 {
            let af_len = p[4] as usize;
            off += 1 + af_len;
        }
        if !has_payload || off >= PACKET_LEN {
            return;
        }
        let payload = &p[off..];

        if pid == PID_PAT || self.pmt_pids.contains(&pid) {
            self.handle_section(pid, pusi, payload);
            return;
        }
        if self.streams.contains_key(&pid) || pid > 0x001F {
            self.handle_pes(pid, pusi, payload, out);
        }
    }

    fn handle_section(&mut self, pid: u16, pusi: bool, payload: &[u8]) {
        let asm = self.sections.entry(pid).or_default();
        let mut data = payload;
        if pusi {
            if data.is_empty() {
                return;
            }
            let pointer = data[0] as usize;
            if 1 + pointer > data.len() {
                return;
            }
            data = &data[1 + pointer..];
            asm.buf.clear();
            asm.want = 0;
        } else if asm.buf.is_empty() {
            return; // never saw the start of this section
        }

        asm.buf.extend_from_slice(data);
        if asm.want == 0 {
            if asm.buf.len() < 3 {
                return;
            }
            let section_len = (((asm.buf[1] & 0x0F) as usize) << 8) | asm.buf[2] as usize;
            asm.want = section_len + 3;
        }
        if asm.buf.len() < asm.want {
            return;
        }
        let section: Vec<u8> = asm.buf[..asm.want].to_vec();
        asm.buf.clear();
        asm.want = 0;

        if pid == PID_PAT {
            self.parse_pat(&section);
        } else {
            self.parse_pmt(&section);
        }
    }

    fn parse_pat(&mut self, section: &[u8]) {
        // table_id(1) len(2) tsid(2) ver(1) sec(1) last(1) = 8 header, 4 CRC
        if section.len() < 12 || section[0] != 0x00 {
            return;
        }
        let body = &section[8..section.len() - 4];
        for entry in body.chunks_exact(4) {
            let program = u16::from_be_bytes([entry[0], entry[1]]);
            let pid = (((entry[2] & 0x1F) as u16) << 8) | entry[3] as u16;
            if program != 0 {
                self.pmt_pids.insert(pid);
            }
        }
    }

    fn parse_pmt(&mut self, section: &[u8]) {
        if section.len() < 16 || section[0] != 0x02 {
            return;
        }
        let pcr = (((section[8] & 0x1F) as u16) << 8) | section[9] as u16;
        if pcr != 0x1FFF {
            self.pcr_pid = Some(pcr);
        }
        let program_info_len = (((section[10] & 0x0F) as usize) << 8) | section[11] as usize;
        let mut i = 12 + program_info_len;
        let end = section.len() - 4;

        while i + 5 <= end {
            let stream_type = section[i];
            let pid = (((section[i + 1] & 0x1F) as u16) << 8) | section[i + 2] as u16;
            let es_info_len = (((section[i + 3] & 0x0F) as usize) << 8) | section[i + 4] as usize;
            i += 5;
            let mut tags = Vec::new();
            let desc_end = (i + es_info_len).min(end);
            let mut d = i;
            while d + 2 <= desc_end {
                tags.push(section[d]);
                d += 2 + section[d + 1] as usize;
            }
            i = desc_end;
            self.streams.insert(
                pid,
                StreamInfo {
                    pid,
                    stream_type,
                    descriptor_tags: tags,
                },
            );
        }
    }

    fn handle_pes(&mut self, pid: u16, pusi: bool, payload: &[u8], out: &mut Vec<PesUnit>) {
        let asm = self.pes.entry(pid).or_default();
        if pusi {
            if asm.started && !asm.buf.is_empty() {
                let data = std::mem::take(&mut asm.buf);
                self.pes_buffered -= data.len();
                if let Some(unit) = parse_pes(pid, &data) {
                    out.push(unit);
                }
            }
            asm.started = true;
            self.pes_buffered -= asm.buf.len();
            asm.buf.clear();
        }
        if asm.started {
            // A PES packet is only closed by the next payload-unit-start on its
            // PID, so a sender that withholds one grows this for as long as the
            // tool runs. Abandon the reassembly rather than the process.
            if asm.buf.len() + payload.len() > MAX_PES_BYTES
                || self.pes_buffered + payload.len() > MAX_PES_TOTAL
            {
                self.pes_buffered -= asm.buf.len();
                asm.buf.clear();
                asm.started = false;
                self.stats.pes_overflow_drops += 1;
                return;
            }
            asm.buf.extend_from_slice(payload);
            self.pes_buffered += payload.len();
        }
    }
}

/// Split a reassembled PES packet into header metadata and elementary bytes.
fn parse_pes(pid: u16, data: &[u8]) -> Option<PesUnit> {
    if data.len() < 9 || data[0] != 0x00 || data[1] != 0x00 || data[2] != 0x01 {
        return None;
    }
    let stream_id = data[3];
    let header_len = data[8] as usize;
    let body_start = 9 + header_len;
    if body_start > data.len() {
        return None;
    }
    let flags = data[7];
    let mut pts = None;
    let mut dts = None;
    if flags & 0x80 != 0 && data.len() >= 14 {
        pts = read_timestamp(&data[9..14]);
        if flags & 0x40 != 0 && data.len() >= 19 {
            dts = read_timestamp(&data[14..19]);
        }
    }
    Some(PesUnit {
        pid,
        stream_id,
        pts,
        dts,
        data: data[body_start..].to_vec(),
    })
}

fn read_timestamp(b: &[u8]) -> Option<u64> {
    if b.len() < 5 {
        return None;
    }
    let v = ((b[0] as u64 & 0x0E) << 29)
        | ((b[1] as u64) << 22)
        | ((b[2] as u64 & 0xFE) << 14)
        | ((b[3] as u64) << 7)
        | ((b[4] as u64 & 0xFE) >> 1);
    Some(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build one TS packet.
    fn packet(pid: u16, pusi: bool, cc: u8, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![SYNC_BYTE, 0, 0, 0];
        p[1] = ((pid >> 8) as u8 & 0x1F) | if pusi { 0x40 } else { 0 };
        p[2] = (pid & 0xFF) as u8;
        assert!(payload.len() <= 184);
        let stuffing = 184 - payload.len();
        if stuffing > 0 {
            p[3] = 0x30 | (cc & 0x0F); // adaptation + payload
            p.push((stuffing - 1) as u8);
            if stuffing >= 2 {
                p.push(0x00);
                p.extend(std::iter::repeat_n(0xFF, stuffing - 2));
            }
        } else {
            p[3] = 0x10 | (cc & 0x0F);
        }
        p.extend_from_slice(payload);
        assert_eq!(p.len(), PACKET_LEN);
        p
    }

    fn section_packet(pid: u16, cc: u8, section: &[u8]) -> Vec<u8> {
        let mut payload = vec![0x00]; // pointer_field
        payload.extend_from_slice(section);
        packet(pid, true, cc, &payload)
    }

    fn crc_placeholder() -> [u8; 4] {
        [0, 0, 0, 0]
    }

    fn pat(pmt_pid: u16) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&1u16.to_be_bytes()); // program 1
        body.extend_from_slice(&(0xE000 | pmt_pid).to_be_bytes());
        let mut s = vec![0x00];
        let len = 5 + body.len() + 4;
        s.push(0xB0 | ((len >> 8) as u8 & 0x0F));
        s.push((len & 0xFF) as u8);
        s.extend_from_slice(&[0x00, 0x01, 0xC1, 0x00, 0x00]);
        s.extend_from_slice(&body);
        s.extend_from_slice(&crc_placeholder());
        s
    }

    fn pmt(streams: &[(u8, u16)]) -> Vec<u8> {
        let mut body = Vec::new();
        for &(st, pid) in streams {
            body.push(st);
            body.extend_from_slice(&(0xE000 | pid).to_be_bytes());
            body.extend_from_slice(&0xF000u16.to_be_bytes()); // no descriptors
        }
        let mut s = vec![0x02];
        let len = 9 + body.len() + 4;
        s.push(0xB0 | ((len >> 8) as u8 & 0x0F));
        s.push((len & 0xFF) as u8);
        s.extend_from_slice(&[0x00, 0x01, 0xC1, 0x00, 0x00]);
        s.extend_from_slice(&(0xE000 | streams[0].1).to_be_bytes()); // PCR pid
        s.extend_from_slice(&0xF000u16.to_be_bytes()); // program_info_len 0
        s.extend_from_slice(&body);
        s.extend_from_slice(&crc_placeholder());
        s
    }

    fn pes(stream_id: u8, pts: u64, body: &[u8]) -> Vec<u8> {
        let mut p = vec![0x00, 0x00, 0x01, stream_id];
        let mut hdr = vec![0x80u8, 0x80, 5];
        let t = |v: u64| -> [u8; 5] {
            [
                0x21 | (((v >> 29) as u8) & 0x0E),
                ((v >> 22) & 0xFF) as u8,
                (((v >> 14) as u8) & 0xFE) | 0x01,
                ((v >> 7) & 0xFF) as u8,
                (((v << 1) as u8) & 0xFE) | 0x01,
            ]
        };
        hdr.extend_from_slice(&t(pts));
        let total = hdr.len() + body.len();
        p.extend_from_slice(&(total as u16).to_be_bytes());
        p.extend_from_slice(&hdr);
        p.extend_from_slice(body);
        p
    }

    #[test]
    fn parses_pat_pmt_and_delivers_pes() {
        let mut a = TsAnalyzer::new();
        let mut stream = Vec::new();
        stream.extend_from_slice(&section_packet(PID_PAT, 0, &pat(0x100)));
        stream.extend_from_slice(&section_packet(
            0x100,
            0,
            &pmt(&[(0x1B, 0x101), (0x0F, 0x102)]),
        ));

        let body = b"\x00\x00\x00\x01\x09\x10payload".to_vec();
        stream.extend_from_slice(&packet(0x101, true, 0, &pes(0xE0, 90_000, &body)));
        // A second PUSI flushes the first access unit.
        stream.extend_from_slice(&packet(0x101, true, 1, &pes(0xE0, 93_000, &body)));

        let units = a.feed(&stream);
        assert_eq!(a.pmt_pids.iter().copied().collect::<Vec<_>>(), vec![0x100]);
        assert_eq!(a.streams[&0x101].stream_type, 0x1B);
        assert_eq!(a.streams[&0x101].type_name(), "H.264");
        assert_eq!(a.streams[&0x102].type_name(), "AAC (ADTS)");
        assert_eq!(a.pcr_pid, Some(0x101));

        assert_eq!(units.len(), 1);
        assert_eq!(units[0].pid, 0x101);
        assert_eq!(units[0].pts, Some(90_000));
        assert_eq!(units[0].data, body);
    }

    #[test]
    fn flags_a_pid_the_pmt_never_declared() {
        let mut a = TsAnalyzer::new();
        let mut stream = Vec::new();
        stream.extend_from_slice(&section_packet(PID_PAT, 0, &pat(0x100)));
        stream.extend_from_slice(&section_packet(0x100, 0, &pmt(&[(0x1B, 0x101)])));
        stream.extend_from_slice(&packet(0x1FF, true, 0, &pes(0xBD, 1000, b"smuggled")));

        a.feed(&stream);
        assert_eq!(a.undeclared_pids(), vec![0x1FF]);
    }

    #[test]
    fn recovers_from_a_torn_start() {
        let mut a = TsAnalyzer::new();
        let mut stream = vec![0xAA; 37]; // joined mid-packet, as a live pull does
        stream.extend_from_slice(&section_packet(PID_PAT, 0, &pat(0x100)));
        a.feed(&stream);
        assert!(a.stats.resync_bytes >= 37);
        assert_eq!(a.pmt_pids.iter().copied().collect::<Vec<_>>(), vec![0x100]);
    }

    #[test]
    fn a_pes_packet_that_is_never_closed_is_abandoned_rather_than_grown() {
        // A PES packet ends only when the next payload-unit-start arrives on
        // its PID. Withhold that and the reassembly buffer has nothing to stop
        // it, which is a remote out-of-memory on whatever the egress feels like
        // sending. Loopback never produces this because a real muxer closes its
        // packets.
        let mut a = TsAnalyzer::new();
        let body = [0xAAu8; 184];
        // Fed a packet at a time, the way the read loop does. One large feed
        // would spend its time in the resync drain rather than on the cap.
        a.feed(&packet(0x101, true, 0, &body));
        let needed = MAX_PES_BYTES / body.len() + 2;
        for i in 0..needed {
            a.feed(&packet(0x101, false, ((i + 1) & 0x0F) as u8, &body));
        }

        assert!(
            a.stats.pes_overflow_drops >= 1,
            "the reassembly should have been abandoned and counted"
        );
        assert!(
            a.pes_buffered <= MAX_PES_TOTAL,
            "buffered {} bytes, past the total cap",
            a.pes_buffered
        );
        assert_eq!(
            a.pes[&0x101].buf.len(),
            0,
            "the abandoned buffer should have been released, not merely capped"
        );
    }

    #[test]
    fn a_normal_pes_packet_still_reassembles_and_releases_its_bytes() {
        // The cap must not cost the ordinary case: a closed PES still comes out
        // whole, and the running total returns to zero once it does.
        let mut a = TsAnalyzer::new();
        let unit = pes(0xE0, 900_000, b"elementary bytes");
        let mut stream = Vec::new();
        stream.extend_from_slice(&packet(0x101, true, 0, &unit));
        stream.extend_from_slice(&packet(0x101, true, 1, &unit));
        let units = a.feed(&stream);

        assert_eq!(
            units.len(),
            1,
            "the first packet should have been delivered"
        );
        assert_eq!(a.stats.pes_overflow_drops, 0);
        a.flush();
        assert_eq!(a.pes_buffered, 0, "the running total should have unwound");
    }

    #[test]
    fn counts_continuity_errors() {
        let mut a = TsAnalyzer::new();
        let mut stream = Vec::new();
        stream.extend_from_slice(&packet(0x101, true, 0, b"a"));
        stream.extend_from_slice(&packet(0x101, false, 1, b"b"));
        stream.extend_from_slice(&packet(0x101, false, 5, b"c")); // jumped
        a.feed(&stream);
        assert_eq!(a.stats.continuity_errors, 1);
    }

    #[test]
    fn feed_is_resumable_across_arbitrary_chunk_boundaries() {
        let mut whole = Vec::new();
        whole.extend_from_slice(&section_packet(PID_PAT, 0, &pat(0x100)));
        whole.extend_from_slice(&section_packet(0x100, 0, &pmt(&[(0x1B, 0x101)])));

        let mut a = TsAnalyzer::new();
        for chunk in whole.chunks(7) {
            a.feed(chunk);
        }
        assert_eq!(a.streams[&0x101].stream_type, 0x1B);
    }

    #[test]
    fn flush_emits_the_trailing_access_unit() {
        let mut a = TsAnalyzer::new();
        let mut stream = Vec::new();
        stream.extend_from_slice(&section_packet(PID_PAT, 0, &pat(0x100)));
        stream.extend_from_slice(&section_packet(0x100, 0, &pmt(&[(0x1B, 0x101)])));
        stream.extend_from_slice(&packet(0x101, true, 0, &pes(0xE0, 1, b"only-one")));

        assert!(a.feed(&stream).is_empty(), "no second PUSI yet");
        let tail = a.flush();
        assert_eq!(tail.len(), 1);
        assert_eq!(tail[0].data, b"only-one");
    }
}
