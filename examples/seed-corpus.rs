//! Write a starting corpus for the fuzz targets, built with the real encoders.
//!
//! A coverage-guided fuzzer starting from valid input is inside the interesting
//! code within a minute. Starting from random bytes it spends the first hours
//! working out what a sync byte is, and most targets here sit behind a magic
//! check it would never guess.
//!
//! ```sh
//! cargo run --example seed-corpus
//! cargo +nightly fuzz run ts_feed
//! ```
//!
//! Everything written is synthetic. Real captures make better seeds still,
//! since they carry a remuxer's actual output, and `--save` on `truss-detect`
//! will produce one; keep those out of the repository and check what is in
//! them before sharing.

use std::fs;
use std::path::Path;

use truss::carrier::Carrier;
use truss::record::{DEFAULT_PAYLOAD_LEN, Record};
use truss::{artnet, flv, h264, payload};

fn main() -> std::io::Result<()> {
    let root = Path::new("fuzz/corpus");

    use truss::invariants as inv;
    write(root, "ts_feed", &ts_seeds(), inv::ts_feed)?;
    write(root, "scan_video_au", &annexb_seeds(), inv::scan_video_au)?;
    write(
        root,
        "scan_survives_its_own_encoder",
        &live_body_seeds(),
        inv::scan_survives_its_own_encoder,
    )?;
    write(root, "record_decode", &record_seeds(), inv::record_decode)?;
    write(root, "flv_roundtrip", &flv_seeds(), inv::flv_roundtrip)?;
    write(
        root,
        "payload_decode",
        &payload_seeds(),
        inv::payload_decode,
    )?;
    write(root, "artnet_packet", &artnet_seeds(), inv::artnet_packet)?;
    write(root, "artnet_poll", &artnet_poll_seeds(), inv::artnet_poll)?;
    write(root, "h264_nals", &h264_seeds(), inv::h264_nals)?;

    Ok(())
}

/// Write one target's seeds, running each through its own invariant first.
///
/// A seed that trips the property it is meant to feed is worse than no seed:
/// every run would start by rediscovering it. Checking here means generating
/// the corpus doubles as a smoke test of both halves, on stable, without a
/// nightly toolchain anywhere near it.
fn write(root: &Path, target: &str, seeds: &[Vec<u8>], check: fn(&[u8])) -> std::io::Result<()> {
    let dir = root.join(target);
    fs::create_dir_all(&dir)?;
    for (i, seed) in seeds.iter().enumerate() {
        check(seed);
        fs::write(dir.join(format!("seed-{i:02}")), seed)?;
    }
    println!("{target}: {} seeds", seeds.len());
    Ok(())
}

fn ts_packet(pid: u16, pusi: bool, cc: u8, payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0x47u8, 0, 0, 0];
    p[1] = ((pid >> 8) as u8 & 0x1F) | if pusi { 0x40 } else { 0 };
    p[2] = (pid & 0xFF) as u8;
    p[3] = 0x10 | (cc & 0x0F);
    let mut body = payload.to_vec();
    body.resize(184, 0xFF);
    p.extend_from_slice(&body);
    p
}

fn ts_seeds() -> Vec<Vec<u8>> {
    // The leading byte is the chunk size the target reads, so both the
    // one-big-read and the many-small-reads shapes are seeded.
    let mut whole = vec![0u8];
    let mut chunked = vec![64u8];
    for (i, pid) in [0x0100u16, 0x0101, 0x1FFF, 0x0042].into_iter().enumerate() {
        let packet = ts_packet(pid, i % 2 == 0, i as u8, &[0x00, 0x00, 0x01, 0xE0]);
        whole.extend_from_slice(&packet);
        chunked.extend_from_slice(&packet);
    }
    // A PES that opens and never closes, which is the shape the cap exists for.
    let mut unclosed = vec![188u8];
    unclosed.extend_from_slice(&ts_packet(0x0100, true, 0, &[0x00, 0x00, 0x01, 0xE0]));
    for cc in 1..8u8 {
        unclosed.extend_from_slice(&ts_packet(0x0100, false, cc, &[0xAA]));
    }
    vec![whole, chunked, unclosed]
}

fn sei_annexb(record: &Record, carrier: Carrier) -> Vec<u8> {
    let nal = carrier.frame(record).expect("seed records are small");
    let mut out = vec![0, 0, 0, 1];
    out.extend_from_slice(&nal);
    out
}

fn annexb_seeds() -> Vec<Vec<u8>> {
    let r = Record::new(
        Carrier::SeiUnregistered.id(),
        1,
        1_700_000_000_000_000_000,
        1,
        DEFAULT_PAYLOAD_LEN,
    );
    let mut with_picture = sei_annexb(&r, Carrier::SeiUnregistered);
    with_picture.extend_from_slice(&[0, 0, 0, 1, 0x65, 0xAA, 0xBB]);
    vec![
        sei_annexb(&r, Carrier::SeiUnregistered),
        sei_annexb(&r, Carrier::SeiT35),
        sei_annexb(&r, Carrier::FillerNal),
        with_picture,
    ]
}

fn live_body_seeds() -> Vec<Vec<u8>> {
    // The target reads universe, start and then values. Byte patterns that
    // provoke emulation prevention are the point of seeding this one.
    vec![
        vec![0, 1, 0, 0, 0x00, 0x00, 0x01, 0xFF],
        vec![0, 2, 0, 0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        vec![0, 3, 0, 0, 0x00, 0x00, 0x03, 0x00, 0x00, 0x01],
        {
            let mut v = vec![0, 4, 0, 0];
            v.extend(std::iter::repeat_n(0u8, 512));
            v
        },
    ]
}

fn record_seeds() -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for len in [0usize, 1, DEFAULT_PAYLOAD_LEN, 1024] {
        let r = Record::new(1, 7, 1_700_000_000_000_000_000, 7, len);
        out.push(r.encode().expect("seed payloads are small"));
    }
    let live = payload::encode(&[payload::Block {
        universe: 1,
        start: 0,
        age_us: 1234,
        values: vec![0xFF; 512],
    }])
    .expect("one universe encodes");
    let r = Record::with_payload(1, 8, 1, 8, live);
    out.push(r.encode().expect("one universe fits a record"));
    out
}

fn flv_seeds() -> Vec<Vec<u8>> {
    let mut seq = vec![0x17u8, flv::AVC_SEQUENCE_HEADER, 0, 0, 0];
    seq.extend_from_slice(&[1, 0x42, 0xC0, 0x1F, 0xFF, 0xE1]);

    let mut nalu = vec![0x17u8, flv::AVC_NALU, 0, 0, 0];
    nalu.extend_from_slice(&h264::avcc_wrap(&[0x65, 0xAA, 0xBB], 4));

    let tags = vec![
        flv::Tag {
            kind: flv::TAG_VIDEO,
            timestamp: 0,
            data: seq,
        },
        flv::Tag {
            kind: flv::TAG_VIDEO,
            timestamp: 33,
            data: nalu,
        },
        flv::Tag {
            kind: flv::TAG_AUDIO,
            timestamp: 40,
            data: vec![0xAF, 0x01, 0x21, 0x10],
        },
        flv::Tag {
            kind: flv::TAG_SCRIPT,
            timestamp: 0,
            data: b"onMetaData-ish".to_vec(),
        },
    ];
    let whole = flv::serialise(&flv::Flv {
        header: b"FLV\x01\x05\x00\x00\x00\x09".to_vec(),
        tags: tags.clone(),
    })
    .expect("seed tags are small");

    let video_only = flv::serialise(&flv::Flv {
        header: b"FLV\x01\x01\x00\x00\x00\x09".to_vec(),
        tags: tags[..2].to_vec(),
    })
    .expect("seed tags are small");

    vec![whole, video_only]
}

fn payload_seeds() -> Vec<Vec<u8>> {
    let one = payload::encode(&[payload::Block {
        universe: 1,
        start: 0,
        age_us: 0,
        values: vec![0x7F; 512],
    }])
    .expect("one universe encodes");
    let many: Vec<payload::Block> = (0..8)
        .map(|u| payload::Block {
            universe: u,
            start: u * 16,
            age_us: u as u32 * 1000,
            values: vec![u as u8; 64],
        })
        .collect();
    vec![
        payload::encode(&[]).expect("an empty payload encodes"),
        one,
        payload::encode(&many).expect("seed blocks are small"),
    ]
}

fn art_dmx(universe: u16, sequence: u8, values: &[u8]) -> Vec<u8> {
    let mut d = b"Art-Net\0".to_vec();
    d.extend_from_slice(&[0x00, 0x50, 0x00, 0x0E]); // OpDmx, protocol 14
    d.push(sequence);
    d.push(0); // physical
    d.extend_from_slice(&universe.to_be_bytes());
    d.extend_from_slice(&(values.len() as u16).to_be_bytes());
    d.extend_from_slice(values);
    d
}

fn artnet_seeds() -> Vec<Vec<u8>> {
    // Leading byte is the budget in 256-byte units, then datagrams behind a
    // big-endian u16 length. A full universe is 530 bytes, so the prefix has to
    // be wide enough to express one.
    let mut generous = vec![40u8];
    let mut tight = vec![1u8];
    for u in 0..4u16 {
        let d = art_dmx(u, 1, &vec![0xAA; artnet::UNIVERSE_SLOTS]);
        for out in [&mut generous, &mut tight] {
            out.extend_from_slice(&(d.len() as u16).to_be_bytes());
            out.extend_from_slice(&d);
        }
    }
    vec![generous, tight]
}

fn artnet_poll_seeds() -> Vec<Vec<u8>> {
    let mut plain = b"Art-Net\0".to_vec();
    plain.extend_from_slice(&[0x00, 0x20, 0x00, 0x0E, 0x00, 0x00]); // OpPoll, protocol 14
    let mut targeted = b"Art-Net\0".to_vec();
    targeted.extend_from_slice(&[0x00, 0x20, 0x00, 0x0E, 0x20, 0x00]); // targeted mode
    targeted.extend_from_slice(&[0x00, 0x0F, 0x00, 0x00]); // port addresses 0 to 15
    vec![plain, targeted]
}

fn h264_seeds() -> Vec<Vec<u8>> {
    let mut avcc = vec![3u8]; // length_size 4 after the target's %4 + 1
    avcc.extend_from_slice(&h264::avcc_wrap(&[0x65, 0x00, 0x00, 0x01, 0xAA], 4));

    let mut annexb = vec![0u8]; // length_size 1
    annexb.extend_from_slice(&[0, 0, 0, 1, 0x06, 0x05, 0x02, 0xAA, 0xBB, 0x80]);

    let mut zeros = vec![1u8];
    zeros.extend(std::iter::repeat_n(0u8, 64));

    vec![avcc, annexb, zeros]
}
