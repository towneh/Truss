//! Properties that hold for any input, however hostile.
//!
//! Two things drive these: `tests/properties.rs` on stable, with generated and
//! mutated input, and the targets under `fuzz/`, with libFuzzer's. Writing them
//! once means the two layers cannot disagree about what the invariant is, and
//! it keeps each fuzz target down to a three-line shim, which matters because
//! that half needs a nightly toolchain and so is not compiled by the CI that
//! gates a merge.
//!
//! Every function here takes raw bytes and derives whatever else it needs from
//! them, so a caller never has to know what a given target wants.
//!
//! Each panics on a violation, which is the contract libFuzzer expects. Where a
//! function can only assert "did not panic", that is said in its own docs
//! rather than dressed up: a target without an oracle finds crashes and nothing
//! else, and this crate's worse failure is silent corruption.

use std::time::Instant;

use crate::carrier::Carrier;
use crate::codec::VideoCodec;
use crate::detect::scan::Scanner;
use crate::detect::ts::{MAX_PES_TOTAL, TsAnalyzer};
use crate::flv::Video;
use crate::inject::{InjectOptions, Injector};
use crate::monitor::DmxState;
use crate::record::{CRC_LEN, HEADER_LEN, MAX_PAYLOAD_LEN, Record};
use crate::{artnet, flv, h264, hevc, osc, payload};

/// Feed arbitrary bytes to the TS reader, in chunks the input chooses.
///
/// The chunking is the point rather than a detail. Resync and the packet drain
/// live at the boundary between one read and the next, so a single large feed
/// leaves the part most likely to be wrong untested.
///
/// Asserts the reassembly bound holds after every chunk. An abandoned
/// reassembly is correct behaviour under a hostile stream, so the drop counter
/// is deliberately not asserted to be zero.
pub fn ts_feed(data: &[u8]) {
    let mut a = TsAnalyzer::new();
    let mut rest = data;

    while let Some((&n, tail)) = rest.split_first() {
        // Zero means "the remainder in one go", so both the many-small-reads
        // and the one-big-read shapes are reachable.
        let take = if n == 0 {
            tail.len()
        } else {
            (n as usize).min(tail.len())
        };
        let (chunk, next) = tail.split_at(take);
        a.feed(chunk);
        assert!(
            a.pes_buffered() <= MAX_PES_TOTAL,
            "buffered {} bytes, past the {MAX_PES_TOTAL} byte cap",
            a.pes_buffered()
        );
        rest = next;
    }

    a.flush();
    assert_eq!(
        a.pes_buffered(),
        0,
        "flush left bytes behind in the assemblers"
    );
}

/// Push arbitrary bytes through the video and raw scan paths.
///
/// No oracle beyond surviving: the scanner reports counts rather than the
/// records behind them, so there is nothing here to check the result against.
/// [`scan_survives_its_own_encoder`] is where the real property lives.
pub fn scan_video_au(data: &[u8]) {
    let mut s = Scanner::new();
    s.feed_video_au(VideoCodec::H264, data, 0);
    s.feed_video_au(VideoCodec::Hevc, data, 0);
    s.feed_raw(data, 0);
}

/// A record this crate encoded must survive being read back by this crate.
///
/// This is the emulation-prevention trap as a property. A record is escaped on
/// its way into the NAL, so any `00 00 01` the payload happens to contain gains
/// a `0x03` splice, and a reader that scans the coded bytes for the magic finds
/// it and then fails the CRC on the body behind it. The payload comes from the
/// input, so the search is free to look for the byte patterns that trigger it.
pub fn scan_survives_its_own_encoder(data: &[u8]) {
    let Some(blocks) = blocks_from(data) else {
        return;
    };
    let body = payload::encode(&blocks).expect("one block of at most a universe encodes");
    if body.len() > MAX_PAYLOAD_LEN {
        return;
    }

    let c = Carrier::SeiUnregistered;
    let record = Record::with_payload(c.id(), 7, 1, 7, body);
    for codec in [VideoCodec::H264, VideoCodec::Hevc] {
        let nal = c
            .frame_for(codec, &record)
            .expect("a payload inside the limit encodes");
        let mut annexb = vec![0, 0, 0, 1];
        annexb.extend_from_slice(&nal);

        let mut s = Scanner::new();
        s.feed_video_au(codec, &annexb, 2);

        let t = &s.report().carriers[c.slug()];
        assert_eq!(
            t.ok, 1,
            "a {codec:?} record we built ourselves did not read back: {t:?}"
        );
        assert_eq!(
            t.corrupt, 0,
            "our own {codec:?} record was scored corrupt: {t:?}"
        );
        assert_eq!(t.rewritten, 0, "a live payload must not score rewritten");
    }
}

/// Anything that decodes as a record must re-encode to the bytes it came from.
///
/// Stronger than checking for a panic: it catches a decoder that accepts a
/// record while disagreeing with the encoder about what it says, which for this
/// crate is the worse failure of the two.
pub fn record_decode(data: &[u8]) {
    let Ok(r) = Record::decode(data) else {
        return;
    };
    let consumed = HEADER_LEN + r.payload.len() + CRC_LEN;
    let re = r.encode().expect("a record that decoded must re-encode");
    assert_eq!(
        &data[..consumed],
        re.as_slice(),
        "decode and encode disagree about the same record"
    );
}

/// Serialising a parsed FLV is a fixed point.
///
/// Deliberately not `serialise(parse(x)) == x`: parsing drops a truncated final
/// tag and normalises the leading `PreviousTagSize`, so that would fail on the
/// first malformed input for a reason that is not a bug. Going round twice is
/// the property that actually has to hold.
pub fn flv_roundtrip(data: &[u8]) {
    let Ok(once) = flv::parse(data) else {
        return;
    };
    let Ok(bytes) = flv::serialise(&once) else {
        return;
    };
    let twice = flv::parse(&bytes).expect("our own output parses");
    assert_eq!(
        twice.tags.len(),
        once.tags.len(),
        "a tag was lost or gained on the way round"
    );
    let again = flv::serialise(&twice).expect("and re-serialises");
    assert_eq!(bytes, again, "serialise is not a fixed point");
}

/// Rewrite an arbitrary video tag payload the way the relay does.
///
/// An error is fine: the encoder's bytes are not ours to trust. A panic is
/// not, and nor is a rewrite that no longer reads as the frame it came from,
/// because the relay forwards whatever comes back.
pub fn inject_video_tag(data: &[u8]) {
    let mut inj = Injector::new(&InjectOptions {
        carriers: vec![
            Carrier::SeiUnregistered,
            Carrier::SeiT35,
            Carrier::FillerNal,
        ],
        ..Default::default()
    })
    .expect("these options are valid");
    let _ = inj.note_sequence_header(data);
    let Ok(Some(out)) = inj.inject_tag(data, 0) else {
        return;
    };
    let Video::Frame { body, .. } = flv::video(data) else {
        panic!("a tag that is not a frame was rewritten");
    };
    assert_eq!(
        flv::video(&out),
        flv::video(data),
        "the parsed video changed"
    );
    assert_eq!(&out[..body], &data[..body], "the tag header changed");
}

/// A decoded payload re-encodes, and applying it twice changes nothing.
///
/// The second half is the one worth having. Values are absolute, so a client
/// that misses a frame is corrected by the next one, and the whole design rests
/// on that. If applying the same blocks twice ever reported a change, a
/// consumer could not tell a repeat from a cue.
pub fn payload_decode(data: &[u8]) {
    let Ok(blocks) = payload::decode(data) else {
        return;
    };
    let re = payload::encode(&blocks).expect("blocks that decoded must re-encode");
    let again = payload::decode(&re).expect("our own output decodes");
    assert_eq!(again, blocks, "payload encode and decode disagree");

    let mut state = DmxState::default();
    state.apply(&blocks);
    let second = state.apply(&blocks);
    assert_eq!(
        second.changed, 0,
        "absolute values applied twice reported a change"
    );
}

/// Any bytes survive the OSC lane's framing, and any datagram reads without
/// panicking.
///
/// The lane is a listener's only way to tell a record the relay sent from
/// anything else on the port, so a message that reads back different from
/// what went in, or a datagram that takes the reader down, would each be
/// worse than a lost one.
pub fn osc_message(data: &[u8]) {
    let encoded = osc::encode_blob(osc::ADDRESS, data).expect("a blob this size frames");
    assert!(
        encoded.len().is_multiple_of(4),
        "a message is padded to four"
    );
    let (address, blob) = osc::decode_blob(&encoded).expect("our own message reads back");
    assert_eq!(address, osc::ADDRESS);
    assert_eq!(blob, data, "the blob came back different");

    // The input as a datagram: whatever it reads as, encoding that again
    // must read the same, so the reader and the writer agree.
    if let Some((address, blob)) = osc::decode_blob(data) {
        let again = osc::encode_blob(address, blob).expect("a blob this size frames");
        assert_eq!(
            osc::decode_blob(&again),
            Some((address, blob)),
            "reader and writer disagree about the same message"
        );
    }
}

/// Anything that parses as an `ArtPoll` gets replies that are not mistakable
/// for anything else and that advertise exactly the ports asked for.
///
/// A reply goes back out on the same port it listens on, so a reply that read
/// as a poll would have two nodes answering each other for ever, and one that
/// read as DMX would latch its own bytes as a universe. The counters and the
/// universes come from the input, so the report text is exercised at every
/// width and the packing at every mix of net and sub-net.
pub fn artnet_poll(data: &[u8]) {
    let Some(poll) = artnet::parse_poll(data) else {
        return;
    };

    // The bytes after the header stand in for the latch: a run of universes in
    // whatever order and quantity the input chose, well past the cap.
    let universes = data
        .chunks(2)
        .map(|c| (u16::from(c[0]) << 8 | u16::from(*c.get(1).unwrap_or(&0))) & 0x7FFF);
    let ports = artnet::advertised_ports(universes);
    assert!(!ports.is_empty() && ports.len() <= artnet::MAX_ADVERTISED_PORTS);
    // Targeted mode is decided against the advertised ports and nothing else:
    // a range holding only universe 0 matches exactly when 0 is advertised, a
    // range holding every universe always matches, and the poll's own range
    // matches exactly when some advertised port falls inside it.
    let only_zero = artnet::ArtPoll {
        flags: poll.flags,
        targeted: Some((0, 0)),
    };
    assert_eq!(only_zero.wants(ports.iter().copied()), ports.contains(&0));
    let everything = artnet::ArtPoll {
        flags: poll.flags,
        targeted: Some((0, 0x7FFF)),
    };
    assert!(everything.wants(ports.iter().copied()));
    let expected = match poll.targeted {
        None => true,
        Some((lo, hi)) => ports.iter().any(|p| (lo..=hi).contains(p)),
    };
    assert_eq!(
        poll.wants(ports.iter().copied()),
        expected,
        "targeted mode decided against something other than the advertised ports"
    );

    let replies = u64::from(data.first().copied().unwrap_or(0)) * 97;
    let packets = artnet::poll_replies(
        std::net::Ipv4Addr::new(10, 0, 0, 2),
        artnet::DEFAULT_PORT,
        replies,
        data.len(),
        &ports,
    );
    assert!(packets.len() <= artnet::MAX_REPLY_PACKETS);

    let mut advertised = Vec::new();
    for (i, reply) in packets.iter().enumerate() {
        assert_eq!(reply.len(), artnet::POLL_REPLY_LEN);
        assert!(
            artnet::parse_poll(reply).is_none(),
            "a reply must not read as a poll"
        );
        assert!(
            artnet::parse_dmx(reply).is_none(),
            "a reply must not read as DMX"
        );
        for end in [43, 107, 171] {
            assert_eq!(
                reply[end], 0,
                "text field ending at {end} is not terminated"
            );
        }
        assert_eq!(
            usize::from(reply[211]),
            (i + 1).min(255),
            "bind indexes count from 1"
        );
        let n = usize::from(reply[173]);
        assert!((1..=4).contains(&n), "a packet holds one to four ports");
        for k in 0..n {
            let port =
                u16::from(reply[18]) << 8 | u16::from(reply[19]) << 4 | u16::from(reply[190 + k]);
            advertised.push(port);
        }
    }
    assert_eq!(
        advertised, ports,
        "the packets together advertise exactly the ports, in order"
    );
}

/// Take arbitrary datagrams into the latch, then check the budget is honoured.
///
/// Art-Net is unauthenticated by protocol design, so every byte here is
/// something any host on the network can send. The budget is the only thing
/// standing between that and a payload too large for a record.
pub fn artnet_packet(data: &[u8]) {
    let Some((&budget_hint, rest)) = data.split_first() else {
        return;
    };
    let mut latch = artnet::Latch::default();
    let now = Instant::now();

    // Each datagram carries a big-endian u16 length, so several universes can be
    // latched in one run rather than only the one.
    //
    // The width of that prefix matters. A full ArtDmx datagram is 530 bytes, 18
    // of header and 512 of values, so a one-byte length could not express one:
    // every full-universe datagram would arrive cut short with its own length
    // field still claiming 512, the latch would refuse it, and the budget check
    // below would never see a universe worth budgeting.
    let mut cursor = rest;
    while cursor.len() >= 2 {
        let n = u16::from_be_bytes([cursor[0], cursor[1]]) as usize;
        let tail = &cursor[2..];
        let take = n.min(tail.len());
        let (datagram, next) = tail.split_at(take);
        latch.accept(datagram, now);
        cursor = next;
    }

    let budget = (budget_hint as usize) * 256;
    let blocks = latch.snapshot(now, budget);
    if !blocks.is_empty() {
        let size = payload::encoded_len(&blocks);
        assert!(
            size <= budget,
            "snapshot returned {size} bytes against a {budget} byte budget"
        );
        assert!(
            size <= MAX_PAYLOAD_LEN,
            "snapshot returned {size} bytes, past what a record can carry"
        );
    }
}

/// Walk arbitrary bytes as NAL units, and check the escaping round-trips.
///
/// Only one direction of the round trip holds. `unescape(escape(x)) == x` is
/// always true; the reverse is not, because an escaped stream carrying a
/// redundant `0x03` unescapes and then re-escapes to something shorter.
pub fn h264_nals(data: &[u8]) {
    let Some((&ls, body)) = data.split_first() else {
        return;
    };
    let length_size = (ls % 4 + 1) as usize;

    let _ = h264::nal_units_avcc(body, length_size);
    let _ = h264::nal_units_annexb(body);
    h264::scan_sei_annexb(body, |_, _| {});
    hevc::scan_sei_annexb(body, |_, _| {});

    let escaped = h264::escape_rbsp(body);
    assert_eq!(
        h264::unescape_rbsp(&escaped),
        body,
        "escaping then unescaping changed the bytes"
    );
}

/// Carve the input into DMX blocks, so a fuzzer's bytes become a live payload.
///
/// `None` when there is not enough input to make one, which is a skip rather
/// than a failure.
fn blocks_from(data: &[u8]) -> Option<Vec<payload::Block>> {
    if data.len() < 5 {
        return None;
    }
    let universe = u16::from_be_bytes([data[0], data[1]]);
    let start = u16::from_be_bytes([data[2], data[3]]) % artnet::UNIVERSE_SLOTS as u16;
    let values = &data[4..data.len().min(4 + artnet::UNIVERSE_SLOTS)];
    Some(vec![payload::Block {
        universe,
        start,
        age_us: 0,
        values: values.to_vec(),
    }])
}

/// An hvcC from libx265 at 320x180 with three B-frames, so it states a
/// reorder depth of 2: a configuration record for [`pull_input`].
pub fn x265_hvcc() -> Vec<u8> {
    const SPS: &[u8] = &[
        0x42, 0x01, 0x01, 0x01, 0x60, 0x00, 0x00, 0x03, 0x00, 0x90, 0x00, 0x00, 0x03, 0x00, 0x00,
        0x03, 0x00, 0x3c, 0xa0, 0x0a, 0x08, 0x0b, 0x9f, 0x79, 0x65, 0x65, 0x92, 0x4c, 0xaf, 0x01,
        0x68, 0x08, 0x00, 0x00, 0x03, 0x00, 0x08, 0x00, 0x00, 0x03, 0x00, 0xf0, 0x40,
    ];
    let mut record = vec![
        1, 0x01, 0x60, 0, 0, 0, 0x90, 0, 0, 0, 0, 0, 60, 0xF0, 0, 0xFC,
    ];
    record.extend_from_slice(&[0xFD, 0xF8, 0xF8, 0, 0, 0x0F, 1, 0xA1, 0, 1]);
    record.extend_from_slice(&(SPS.len() as u16).to_be_bytes());
    record.extend_from_slice(SPS);
    record
}

/// One frame of [`pull_au_to_flv`]'s input.
#[derive(Debug, Clone)]
pub struct PullFrame {
    /// An audio frame, which the timeline places but the gate and the tag
    /// builder never see.
    pub audio: bool,
    pub key: bool,
    /// Packets went missing before this frame.
    pub lost: bool,
    /// The source's session ended before this frame, and it starts the next.
    pub reset: bool,
    /// Presentation time relative to the previous frame's.
    pub delta_us: i64,
    pub nals: Vec<u8>,
}

/// Encode input for [`pull_au_to_flv`]: byte 0 the codec (bit 0, set for
/// HEVC) and frame interval in ms (the other seven bits, 0 for 33 ms), then
/// the configuration record behind a length byte, then the frames. Each frame
/// is a flags byte (key, lost, reset, wide delta, audio), the presentation
/// time step from the previous frame of its stream (16 bits in 100 µs, or 32
/// bits in whole ms when wide, saturating at either end) and the NAL units
/// behind a length byte. Anything past what a frame can hold is cut short.
pub fn pull_input(hevc: bool, frame_ms: u8, config: &[u8], frames: &[PullFrame]) -> Vec<u8> {
    let mut out = vec![u8::from(hevc) | frame_ms.min(127) << 1];
    let config = &config[..config.len().min(255)];
    out.push(config.len() as u8);
    out.extend_from_slice(config);
    for f in frames {
        let narrow = i16::try_from(f.delta_us / 100)
            .ok()
            .filter(|_| f.delta_us % 100 == 0);
        let flags = u8::from(f.key)
            | u8::from(f.lost) << 1
            | u8::from(f.reset) << 2
            | u8::from(narrow.is_none()) << 3
            | u8::from(f.audio) << 4;
        out.push(flags);
        match narrow {
            Some(d) => out.extend_from_slice(&d.to_be_bytes()),
            None => {
                let ms = (f.delta_us / 1000).clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32;
                out.extend_from_slice(&ms.to_be_bytes());
            }
        }
        let nals = &f.nals[..f.nals.len().min(255)];
        out.push(nals.len() as u8);
        out.extend_from_slice(nals);
    }
    out
}

/// Run frames from an RTSP source through what the pull and the relay do with
/// them: the keyframe gate, the [`Timeline`](crate::pull::timing::Timeline)
/// (decode times, rebase, re-anchoring a stream whose timeline jumps) and the
/// tag build, then the injector, with the input deciding the codec, the
/// configuration record, the presentation times, keyframes, losses, session
/// ends and audio (see [`pull_input`]).
///
/// Asserts that what goes out opens on a keyframe; that neither stream's
/// timestamps ever go back, across jumps and session ends too; that the
/// composition time is never negative unless the window grew its reorder
/// depth for that frame or has reached the deepest any codec allows; that
/// `flv::video` reads back the codec, keyframe flag, composition time and NAL
/// units the tag was built from; and that the injector keeps any tag it
/// rewrites reading as the same frame. A tag refused for a composition time
/// that does not fit is the relay refusing a wild source, and passes.
pub fn pull_au_to_flv(data: &[u8]) {
    use crate::pull::timing::{self, AUDIO, Admit, KeyframeGate, MAX_DEPTH, Timeline, VIDEO};

    let Some((&head, rest)) = data.split_first() else {
        return;
    };
    let codec = if head & 1 == 0 {
        VideoCodec::H264
    } else {
        VideoCodec::Hevc
    };
    let frame_us = match i64::from(head >> 1) {
        0 => 33_333,
        ms => ms * 1000,
    };
    let Some((&config_len, rest)) = rest.split_first() else {
        return;
    };
    let Some((config, mut rest)) = rest.split_at_checked(usize::from(config_len)) else {
        return;
    };
    let depth = timing::reorder_depth(codec, config);
    assert!(depth.is_none_or(|d| d <= 16), "reorder depth {depth:?}");

    let mut inj = Injector::new(&InjectOptions {
        carriers: vec![Carrier::SeiUnregistered, Carrier::FillerNal],
        ..Default::default()
    })
    .expect("these options are valid")
    .strip_existing(true);
    let header = flv::video_sequence_header(codec, config);
    assert!(
        matches!(flv::video(&header), Video::Config { codec: c, .. } if c == codec)
            || config.is_empty(),
        "a sequence header does not read back"
    );
    let described = inj.note_sequence_header(&header).is_ok();

    let mut gate = KeyframeGate::default();
    let mut timeline = Timeline::default();
    timeline.video_parameters(depth, frame_us);
    let mut pts = [0i64; 2];
    let mut last_timestamp: [Option<u32>; 2] = [None; 2];
    // Frames arrive a millisecond apart on a clock of the input's own, so the
    // gaps the timeline measures, and with them every timestamp, are the same
    // however fast the harness runs.
    let t0 = Instant::now();
    let mut arrivals = 0u32;

    loop {
        let Some((&flags, tail)) = rest.split_first() else {
            return;
        };
        let wide = flags & 8 != 0;
        let (delta_us, tail) = if wide {
            let Some((d, tail)) = tail.split_first_chunk::<4>() else {
                return;
            };
            (i64::from(i32::from_be_bytes(*d)) * 1000, tail)
        } else {
            let Some((d, tail)) = tail.split_first_chunk::<2>() else {
                return;
            };
            (i64::from(i16::from_be_bytes(*d)) * 100, tail)
        };
        let Some((&len, tail)) = tail.split_first() else {
            return;
        };
        let Some((nals, tail)) = tail.split_at_checked(usize::from(len)) else {
            return;
        };
        rest = tail;
        let (key, lost, reset) = (flags & 1 != 0, flags & 2 != 0, flags & 4 != 0);
        let stream = if flags & 16 != 0 { AUDIO } else { VIDEO };
        arrivals += 1;
        let now = t0 + std::time::Duration::from_millis(u64::from(arrivals));
        pts[stream] = pts[stream].saturating_add(delta_us);
        let pts = pts[stream];

        if reset {
            gate = KeyframeGate::default();
            timeline.lost(now);
            timeline.video_parameters(depth, frame_us);
        }
        if stream == AUDIO {
            if !gate.admit_audio(pts) {
                continue;
            }
            let (timestamp, _) = timeline.audio(pts, now);
            if let Some(last) = last_timestamp[AUDIO] {
                assert!(
                    timestamp >= last,
                    "audio went back from {last} to {timestamp}"
                );
            }
            last_timestamp[AUDIO] = Some(timestamp);
            continue;
        }
        match gate.admit(pts, key, lost) {
            Admit::Open => {
                assert!(key, "the video opened on a frame that is not a keyframe");
                gate.open(pts);
            }
            Admit::Pass => {}
            Admit::Drop | Admit::Lost => continue,
        }

        let Ok(tag) = timeline.video_tag(codec, key, pts, nals, now) else {
            continue;
        };
        if let Some(last) = last_timestamp[VIDEO] {
            assert!(
                tag.timestamp >= last,
                "video went back from {last} to {}",
                tag.timestamp
            );
        }
        last_timestamp[VIDEO] = Some(tag.timestamp);
        assert!(
            tag.grew || tag.cts_ms >= 0 || timeline.depth() == MAX_DEPTH,
            "composition time {} ms with the window's depth unchanged at {}",
            tag.cts_ms,
            timeline.depth()
        );

        // A frame with no NAL units reads as nothing in particular, which is
        // as `flv::video` means it to; retina never hands one over.
        if nals.is_empty() {
            assert_eq!(flv::video(&tag.data), Video::Other);
            continue;
        }
        let Video::Frame {
            codec: read,
            keyframe,
            body,
        } = flv::video(&tag.data)
        else {
            panic!("a built tag does not read back as a frame");
        };
        assert_eq!(
            (read, keyframe),
            (codec, key),
            "the tag header reads back wrong"
        );
        let field = &tag.data[body - 3..body];
        let cts = i32::from_be_bytes([0, field[0], field[1], field[2]]) << 8 >> 8;
        assert_eq!(cts, tag.cts_ms, "the composition time reads back wrong");
        assert_eq!(&tag.data[body..], nals, "the NAL units read back wrong");

        if described && let Ok(Some(out)) = inj.inject_tag(&tag.data, 0) {
            assert_eq!(
                flv::video(&out),
                flv::video(&tag.data),
                "the injector changed what the tag reads as"
            );
        }
    }
}
