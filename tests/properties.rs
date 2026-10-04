//! Generative cover for the parsers, on stable, in the CI that gates a merge.
//!
//! The properties themselves live in `truss::invariants`, shared with the
//! coverage-guided targets under `fuzz/`. This file only decides which bytes to
//! hand them.
//!
//! It is not a substitute for that layer and does not pretend to be. There is
//! no coverage feedback here, so this catches regressions in paths already
//! known to matter rather than discovering new ones. What it does buy is a
//! check that runs on Windows and Linux on every push, with no nightly
//! toolchain and no scheduled job.
//!
//! Generation is deterministic. Each case is numbered, the number seeds the
//! generator, and a failure prints the number and the input, so any case can be
//! reproduced exactly. There is no shrinking: the inputs are small by
//! construction, and `cargo fuzz tmin` covers minimisation on the other side.

use std::panic::{AssertUnwindSafe, catch_unwind};

use truss::flv::{self, TAG_AUDIO, TAG_SCRIPT, TAG_VIDEO, Tag};
use truss::invariants;
use truss::payload;
use truss::record::{DEFAULT_PAYLOAD_LEN, Record};

/// xorshift64*, so a case number reproduces its input without a dependency.
struct Rng(u64);

impl Rng {
    fn seeded(case: u64) -> Self {
        // Any odd constant does; this one just keeps case 0 from being all-zero.
        Self(case.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn byte(&mut self) -> u8 {
        (self.next() >> 33) as u8
    }

    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() >> 33) as usize % n
        }
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.byte()).collect()
    }

    /// Between 1 and `max` bytes. The length is drawn first so the call sites
    /// do not have to borrow the generator twice in one expression.
    fn some_bytes(&mut self, max: usize) -> Vec<u8> {
        let n = 1 + self.below(max);
        self.bytes(n)
    }
}

/// Damage a valid artefact without destroying its shape.
///
/// Uniform random bytes almost never reach past a magic check, so the useful
/// input is something the crate built itself with a few things wrong. Splices
/// and truncation matter as much as bit flips: a length field pointing past the
/// end is the shape most of these parsers have to survive.
fn mutate(rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    let mut out = seed.to_vec();
    if out.is_empty() {
        return out;
    }
    for _ in 0..1 + rng.below(4) {
        match rng.below(5) {
            0 => {
                let at = rng.below(out.len());
                out[at] ^= 1 << rng.below(8);
            }
            1 => {
                let at = rng.below(out.len());
                out[at] = rng.byte();
            }
            2 => {
                let at = rng.below(out.len());
                out.truncate(at);
            }
            3 => {
                let at = rng.below(out.len());
                let chunk = rng.some_bytes(8);
                out.splice(at..at, chunk);
            }
            _ => {
                let at = rng.below(out.len());
                let take = rng.below(out.len() - at).min(32);
                let dup: Vec<u8> = out[at..at + take].to_vec();
                out.extend_from_slice(&dup);
            }
        }
        if out.is_empty() {
            break;
        }
    }
    out
}

/// Run one property over many generated inputs, reporting the case that failed.
///
/// `build` gets the generator and returns the bytes for that case, so each
/// property can seed itself from whatever it needs.
fn each_case(name: &str, cases: u64, build: impl Fn(&mut Rng) -> Vec<u8>, check: fn(&[u8])) {
    for case in 0..cases {
        let mut rng = Rng::seeded(case);
        let input = build(&mut rng);
        let result = catch_unwind(AssertUnwindSafe(|| check(&input)));
        assert!(
            result.is_ok(),
            "{name} failed on case {case}\ninput ({} bytes): {}",
            input.len(),
            hex(&input)
        );
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    // Enough to reproduce by hand without burying the message in a huge dump.
    let shown = &bytes[..bytes.len().min(256)];
    let mut s = String::with_capacity(shown.len() * 2 + 16);
    for &b in shown {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0x0F) as usize] as char);
    }
    if shown.len() < bytes.len() {
        s.push_str("...(truncated)");
    }
    s
}

/// One TS packet, so the generated stream reaches past the sync hunt.
fn ts_packet(rng: &mut Rng, pid: u16, pusi: bool, cc: u8) -> Vec<u8> {
    let mut p = vec![0x47u8, 0, 0, 0];
    p[1] = ((pid >> 8) as u8 & 0x1F) | if pusi { 0x40 } else { 0 };
    p[2] = (pid & 0xFF) as u8;
    p[3] = 0x10 | (cc & 0x0F);
    p.extend(rng.bytes(184));
    p
}

fn ts_stream(rng: &mut Rng) -> Vec<u8> {
    // Leading byte drives the chunking inside the invariant.
    let mut out = vec![rng.byte()];
    for i in 0..1 + rng.below(12) {
        let pid = (rng.next() >> 33) as u16 & 0x1FFF;
        out.extend(ts_packet(rng, pid, i % 3 == 0, i as u8));
    }
    mutate(rng, &out.clone())
}

fn sample_flv(rng: &mut Rng) -> Vec<u8> {
    let mut tags = Vec::new();
    for i in 0..1 + rng.below(5) {
        let kind = match rng.below(3) {
            0 => TAG_VIDEO,
            1 => TAG_AUDIO,
            _ => TAG_SCRIPT,
        };
        let mut data = vec![0x17, 0x01, 0, 0, 0];
        data.extend(rng.some_bytes(64));
        tags.push(Tag {
            kind,
            timestamp: (i as u32) * 33,
            data,
        });
    }
    let bytes = flv::serialise(&flv::Flv {
        header: b"FLV\x01\x05\x00\x00\x00\x09".to_vec(),
        tags,
    })
    .expect("the generated tags are well inside the size limit");
    mutate(rng, &bytes)
}

#[test]
fn ts_feed_holds_its_bound_on_generated_streams() {
    each_case("ts_feed", 400, ts_stream, invariants::ts_feed);
}

#[test]
fn the_scanner_survives_arbitrary_access_units() {
    each_case(
        "scan_video_au",
        400,
        |rng| {
            let r = Record::new(1, rng.byte() as u32, 1, 0, DEFAULT_PAYLOAD_LEN);
            let seed = r.encode().expect("the default payload fits");
            mutate(rng, &seed)
        },
        invariants::scan_video_au,
    );
}

#[test]
fn a_record_always_reads_back_through_its_own_encoder() {
    // Unmutated, because the property is about a record that is valid by
    // construction: any body at all has to survive the escaping it goes
    // through on the way into the NAL.
    each_case(
        "scan_survives_its_own_encoder",
        400,
        |rng| {
            let mut v = rng.bytes(4);
            v.extend(rng.some_bytes(600));
            v
        },
        invariants::scan_survives_its_own_encoder,
    );
}

#[test]
fn record_decode_agrees_with_record_encode() {
    each_case(
        "record_decode",
        400,
        |rng| {
            let r = Record::new(1, rng.byte() as u32, 7, 3, rng.below(64));
            let seed = r.encode().expect("a small payload fits");
            mutate(rng, &seed)
        },
        invariants::record_decode,
    );
}

#[test]
fn serialising_a_parsed_flv_is_a_fixed_point() {
    each_case("flv_roundtrip", 400, sample_flv, invariants::flv_roundtrip);
}

#[test]
fn a_payload_round_trips_and_applies_idempotently() {
    each_case(
        "payload_decode",
        400,
        |rng| {
            let blocks: Vec<payload::Block> = (0..1 + rng.below(6))
                .map(|_| payload::Block {
                    universe: (rng.next() >> 33) as u16,
                    start: rng.below(512) as u16,
                    age_us: rng.next() as u32,
                    values: rng.some_bytes(64),
                })
                .collect();
            mutate(
                rng,
                &payload::encode(&blocks).expect("generated blocks are small"),
            )
        },
        invariants::payload_decode,
    );
}

#[test]
fn the_artnet_latch_honours_its_budget() {
    each_case(
        "artnet_packet",
        400,
        |rng| {
            let mut out = vec![rng.byte()];
            for _ in 0..1 + rng.below(6) {
                let mut d = b"Art-Net\0".to_vec();
                d.extend_from_slice(&[0x00, 0x50, 0x00, 0x0E]); // OpDmx, protocol 14
                d.push(rng.byte()); // sequence
                d.push(0); // physical
                d.extend_from_slice(&((rng.next() >> 33) as u16).to_be_bytes());
                let len = 1 + rng.below(512);
                d.extend_from_slice(&(len as u16).to_be_bytes());
                d.extend(rng.bytes(len));
                // u16, so a full 530-byte universe survives the framing. A
                // byte would truncate it while its own length field still said
                // 512, and the latch would refuse every one.
                out.extend_from_slice(&(d.len() as u16).to_be_bytes());
                out.extend_from_slice(&d);
            }
            mutate(rng, &out.clone())
        },
        invariants::artnet_packet,
    );
}

#[test]
fn the_osc_lane_frames_any_blob_and_reads_any_datagram() {
    each_case(
        "osc_message",
        400,
        |rng| {
            // Half the cases are raw bytes to frame; half are a message to
            // read, damaged in the usual ways.
            if rng.below(2) == 0 {
                let n = rng.below(600);
                return rng.bytes(n);
            }
            let address = ["/truss/dmx", "/x", "/a/b/c", "#bundle"][rng.below(4)];
            let mut m = address.as_bytes().to_vec();
            m.push(0);
            while !m.len().is_multiple_of(4) {
                m.push(0);
            }
            m.extend_from_slice(b",b\0\0");
            let n = rng.below(300);
            let blob = rng.bytes(n);
            m.extend_from_slice(&(blob.len() as u32).to_be_bytes());
            m.extend_from_slice(&blob);
            while !m.len().is_multiple_of(4) {
                m.push(0);
            }
            mutate(rng, &m.clone())
        },
        invariants::osc_message,
    );
}

#[test]
fn a_poll_is_answered_with_a_well_formed_reply() {
    each_case(
        "artnet_poll",
        400,
        |rng| {
            let mut d = b"Art-Net\0".to_vec();
            d.extend_from_slice(&[0x00, 0x20, 0x00, 0x0E]); // OpPoll, protocol 14
            d.push(rng.byte()); // flags, targeted mode among them
            d.push(rng.byte()); // diagnostic priority
            if rng.below(2) == 0 {
                d.extend(rng.bytes(4)); // a target range, either way round
            }
            if rng.below(4) == 0 {
                d.extend(rng.some_bytes(8)); // trailing bytes a newer controller might add
            }
            mutate(rng, &d.clone())
        },
        invariants::artnet_poll,
    );
}

#[test]
fn escaping_a_bitstream_round_trips() {
    each_case(
        "h264_nals",
        400,
        |rng| {
            let mut v = vec![rng.byte()];
            // Deliberately dense in 0x00, so emulation-prevention sequences turn
            // up far more often than uniform bytes would produce them.
            for _ in 0..1 + rng.below(200) {
                v.push(if rng.below(3) == 0 { 0 } else { rng.byte() });
            }
            v
        },
        invariants::h264_nals,
    );
}
