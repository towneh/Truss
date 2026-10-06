//! Plant carriers into an already-encoded FLV.
//!
//! The in-video carriers are NAL units, so they go into the length-prefixed
//! access unit alongside the slices. Placement follows the spec's ordering
//! rules: an access-unit delimiter stays first if one is present, SEI goes after
//! it and before the coded picture, and filler data goes after the last VCL NAL.
//! A carrier planted in the wrong position would be non-conformant on top of
//! whatever else it is doing, which muddies what a negative result means.

use std::collections::BTreeMap;

use anyhow::{Result, bail};

use crate::carrier::{Carrier, Class, Placement};
use crate::flv::{self, Flv, Video};
use crate::h264;
use crate::record::{DEFAULT_PAYLOAD_LEN, MAX_PAYLOAD_LEN, Record};

#[derive(Debug, Clone)]
pub struct InjectOptions {
    pub carriers: Vec<Carrier>,
    /// Inject on every Nth video frame. 1 means every frame.
    pub every_n_frames: u32,
    pub payload_len: usize,
    /// Only inject on keyframes. Useful for a low-rate run that still lands
    /// on every random-access point.
    pub keyframes_only: bool,
}

impl Default for InjectOptions {
    fn default() -> Self {
        Self {
            carriers: vec![Carrier::SeiUnregistered, Carrier::SeiT35],
            every_n_frames: 1,
            payload_len: DEFAULT_PAYLOAD_LEN,
            keyframes_only: false,
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct InjectStats {
    pub video_frames: u64,
    pub injected: BTreeMap<&'static str, u64>,
    pub added_bytes: u64,
    pub duration_ms: u32,
    /// Records left out because they would not fit the record's 16-bit length
    /// field or the stream's NAL length field.
    /// A frame without its lane beats a relay that stops mid-show, but it is
    /// still data the far end will not see, so it is counted rather than
    /// swallowed.
    pub oversize_skipped: u64,
    /// The video's codec, when records cannot ride in it. Its frames pass
    /// through untouched.
    pub unsupported_codec: Option<String>,
}

impl InjectStats {
    /// Extra bandwidth the carriers cost, in kb/s. This is the number that has
    /// to be added to the encoder's own bitrate before comparing against
    /// an ingest's limit, so it is reported rather than assumed negligible.
    pub fn added_kbps(&self) -> f64 {
        if self.duration_ms == 0 {
            return 0.0;
        }
        (self.added_bytes as f64 * 8.0) / (self.duration_ms as f64 / 1000.0) / 1000.0
    }
}

/// Injects into one video tag payload at a time, holding the per-carrier
/// sequence counters between calls.
///
/// The file rewriter and the live relay both drive this, so there is one
/// implementation of the placement rules rather than two that can drift. The
/// relay knows when a frame actually goes out and passes a real send time; the
/// file rewriter passes zero, because a timestamp baked in hours earlier would
/// measure the encoder rather than the network.
pub struct Injector {
    carriers: Vec<Carrier>,
    every_n_frames: u32,
    payload_len: usize,
    keyframes_only: bool,
    length_size: usize,
    seq: BTreeMap<&'static str, u32>,
    pub stats: InjectStats,
}

impl Injector {
    pub fn new(opts: &InjectOptions) -> Result<Self> {
        if opts.every_n_frames == 0 {
            bail!("injection interval must be at least 1");
        }
        // Caught here rather than at the first video tag, so a mistyped flag
        // fails while the operator is still watching.
        if opts.payload_len > MAX_PAYLOAD_LEN {
            bail!(
                "payload length {} exceeds the {MAX_PAYLOAD_LEN} bytes a record can carry",
                opts.payload_len
            );
        }
        for c in &opts.carriers {
            if c.class() == Class::Container {
                bail!(
                    "carrier {} rides in the RTMP container, not the video stream; \
                     it needs a publisher that can send AMF data messages",
                    c.slug()
                );
            }
        }
        Ok(Self {
            carriers: opts.carriers.clone(),
            every_n_frames: opts.every_n_frames,
            payload_len: opts.payload_len,
            keyframes_only: opts.keyframes_only,
            // Overwritten as soon as a sequence header goes past. Guessing
            // wrong here would corrupt every access unit, so the default only
            // stands for streams that never send one.
            length_size: 4,
            seq: BTreeMap::new(),
            stats: InjectStats::default(),
        })
    }

    /// Learn the NAL length size from a sequence header's configuration
    /// record. Any other tag is left alone.
    pub fn note_sequence_header(&mut self, tag_data: &[u8]) -> Result<()> {
        if let Video::Config { codec, body } = flv::video(tag_data) {
            self.length_size = flv::nal_length_size(codec, &tag_data[body..])?;
        }
        Ok(())
    }

    /// Rewrite one video tag payload. Returns `None` when this frame is not
    /// due for injection, so callers can forward the original bytes untouched.
    pub fn inject_tag(&mut self, tag_data: &[u8], now_unix_nanos: u64) -> Result<Option<Vec<u8>>> {
        self.inject_tag_with(tag_data, now_unix_nanos, None)
    }

    /// As [`Self::inject_tag`], with a payload supplied by the caller.
    ///
    /// Every carrier in the access unit ships the same bytes, so they are still
    /// scored against each other on equal terms. Passing `None` uses the
    /// sequence-derived body a measurement run needs.
    pub fn inject_tag_with(
        &mut self,
        tag_data: &[u8],
        now_unix_nanos: u64,
        payload: Option<&[u8]>,
    ) -> Result<Option<Vec<u8>>> {
        let (codec, keyframe, header_len) = match flv::video(tag_data) {
            Video::Frame {
                codec,
                keyframe,
                body,
            } => (codec, keyframe, body),
            Video::Unsupported(codec) => {
                self.stats.unsupported_codec = Some(codec);
                return Ok(None);
            }
            Video::Config { .. } | Video::Other => return Ok(None),
        };
        let frame_index = self.stats.video_frames as u32;
        self.stats.video_frames += 1;

        if (self.keyframes_only && !keyframe) || !frame_index.is_multiple_of(self.every_n_frames) {
            return Ok(None);
        }

        let body = &tag_data[header_len..];
        let Some(nals) = h264::nal_units_avcc(body, self.length_size) else {
            bail!("video tag is not consistently length-prefixed");
        };
        let owned: Vec<Vec<u8>> = nals.into_iter().map(<[u8]>::to_vec).collect();

        // An access-unit delimiter stays first when one is present.
        let insert_at = usize::from(
            owned
                .first()
                .is_some_and(|n| codec.is_aud(codec.nal_type(n[0]))),
        );

        let mut before = Vec::new();
        let mut after = Vec::new();
        for c in &self.carriers {
            let n = self.seq.entry(c.slug()).or_insert(0);
            let record = match payload {
                Some(p) => {
                    Record::with_payload(c.id(), *n, now_unix_nanos, frame_index, p.to_vec())
                }
                None => Record::new(c.id(), *n, now_unix_nanos, frame_index, self.payload_len),
            };
            // An Art-Net snapshot larger than the length field costs this frame
            // its lane, not the broadcast. The sequence number is left where it
            // is so a gap in the detector's count still means loss in transit
            // rather than a frame the injector declined to send.
            let framed = match c.frame_for(codec, &record) {
                Ok(f) if h264::fits_avcc(f.len(), self.length_size) => f,
                _ => {
                    self.stats.oversize_skipped += 1;
                    continue;
                }
            };
            *n += 1;
            match c.placement() {
                Placement::BeforePicture => before.push(framed),
                Placement::AfterPicture => after.push(framed),
            }
            *self.stats.injected.entry(c.slug()).or_insert(0) += 1;
        }

        let length_size = self.length_size;
        let mut rebuilt = Vec::with_capacity(body.len() + 128);
        let mut added = 0u64;
        let mut push = |dst: &mut Vec<u8>, nal: &[u8]| {
            dst.extend_from_slice(&h264::avcc_wrap(nal, length_size));
            added += (nal.len() + length_size) as u64;
        };
        for (i, nal) in owned.iter().enumerate() {
            if i == insert_at {
                for e in &before {
                    push(&mut rebuilt, e);
                }
            }
            rebuilt.extend_from_slice(&h264::avcc_wrap(nal, length_size));
        }
        if insert_at >= owned.len() {
            for e in &before {
                push(&mut rebuilt, e);
            }
        }
        // Filler data belongs after the last VCL NAL of the picture.
        for e in &after {
            push(&mut rebuilt, e);
        }
        self.stats.added_bytes += added;

        let mut out = Vec::with_capacity(header_len + rebuilt.len());
        out.extend_from_slice(&tag_data[..header_len]);
        out.extend_from_slice(&rebuilt);
        Ok(Some(out))
    }
}

pub fn inject(flv: &mut Flv, opts: &InjectOptions) -> Result<InjectStats> {
    let mut injector = Injector::new(opts)?;
    injector.stats.duration_ms = flv.tags.last().map(|t| t.timestamp).unwrap_or(0);

    for tag in flv.tags.iter_mut() {
        if tag.kind != flv::TAG_VIDEO {
            continue;
        }
        // Every sequence header, not just the first: a later one can change
        // the length size.
        injector.note_sequence_header(&tag.data)?;
        // Zero send time: see the note on `Injector`.
        if let Some(rewritten) = injector.inject_tag(&tag.data, 0)? {
            tag.data = rewritten;
        }
    }
    Ok(injector.stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::VideoCodec;
    use crate::detect::scan::Scanner;
    use crate::flv::{AVC_NALU, AVC_SEQUENCE_HEADER, TAG_VIDEO, Tag};

    fn avcc(nals: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for n in nals {
            out.extend_from_slice(&h264::avcc_wrap(n, 4));
        }
        out
    }

    fn video_tag(keyframe: bool, body: &[u8], ts: u32) -> Tag {
        let mut data = vec![if keyframe { 0x17 } else { 0x27 }, AVC_NALU, 0, 0, 0];
        data.extend_from_slice(body);
        Tag {
            kind: TAG_VIDEO,
            timestamp: ts,
            data,
        }
    }

    fn sample_flv() -> Flv {
        let mut seq_data = vec![0x17u8, AVC_SEQUENCE_HEADER, 0, 0, 0];
        seq_data.extend_from_slice(&[1, 0x42, 0xC0, 0x1F, 0xFF, 0xE1]); // lengthSize 4
        Flv {
            header: b"FLV\x01\x05\x00\x00\x00\x09".to_vec(),
            tags: vec![
                Tag {
                    kind: TAG_VIDEO,
                    timestamp: 0,
                    data: seq_data,
                },
                video_tag(true, &avcc(&[&[0x09, 0x10], &[0x65, 0xAA, 0xBB]]), 0),
                video_tag(false, &avcc(&[&[0x09, 0x30], &[0x41, 0xCC]]), 33),
                video_tag(false, &avcc(&[&[0x41, 0xDD]]), 66),
            ],
        }
    }

    /// Convert an injected AVCC tag body back to Annex-B so the detector's own
    /// scanner can read it. This is the same shape a TS remux produces.
    fn annexb_of(tag: &Tag) -> Vec<u8> {
        let mut out = Vec::new();
        for nal in h264::nal_units_avcc(tag.avc_body(), 4).expect("framed") {
            out.extend_from_slice(&[0, 0, 0, 1]);
            out.extend_from_slice(nal);
        }
        out
    }

    #[test]
    fn a_payload_length_past_the_record_limit_is_refused_up_front() {
        // The alternative is discovering it on the first video tag, which for
        // the relay means part way into a show.
        let opts = InjectOptions {
            payload_len: MAX_PAYLOAD_LEN + 1,
            ..Default::default()
        };
        let err = match Injector::new(&opts) {
            Ok(_) => panic!("a payload length past the record limit was accepted"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("exceeds"), "{err}");
    }

    #[test]
    fn an_oversize_live_payload_costs_its_frame_rather_than_the_relay() {
        // A desk on an unauthenticated network decides how many universes turn
        // up. One frame's worth that will not fit has to be dropped, counted,
        // and survived.
        let mut inj = Injector::new(&InjectOptions {
            carriers: vec![Carrier::SeiUnregistered],
            ..Default::default()
        })
        .expect("valid options");
        let tag = video_tag(true, &avcc(&[&[0x65, 0xAA]]), 0);
        let huge = vec![0u8; MAX_PAYLOAD_LEN + 1];

        let out = inj
            .inject_tag_with(&tag.data, 0, Some(&huge))
            .expect("an oversize payload is not a fatal error");

        assert_eq!(inj.stats.oversize_skipped, 1, "the skip must be counted");
        assert_eq!(
            inj.stats.injected.get("sei-unreg").copied().unwrap_or(0),
            0,
            "nothing should have been recorded as injected"
        );
        assert!(out.is_some(), "the frame itself still goes out");

        // And the lane recovers on the next frame, with no gap in the sequence.
        let ok = inj
            .inject_tag_with(&tag.data, 0, Some(b"small"))
            .expect("injects")
            .expect("rewritten");
        assert!(ok.len() > tag.data.len());
        assert_eq!(inj.stats.injected["sei-unreg"], 1);
        assert_eq!(inj.stats.oversize_skipped, 1);
    }

    #[test]
    fn a_record_too_long_for_a_one_byte_nal_length_is_skipped_not_cut() {
        let mut inj = Injector::new(&InjectOptions {
            carriers: vec![Carrier::SeiUnregistered],
            ..Default::default()
        })
        .expect("valid options");
        let mut config = vec![0x17u8, AVC_SEQUENCE_HEADER, 0, 0, 0];
        config.extend_from_slice(&[1, 0x42, 0xC0, 0x1F, 0xFC, 0xE1]); // lengthSize 1
        inj.note_sequence_header(&config).expect("config");
        let mut data = vec![0x17, AVC_NALU, 0, 0, 0];
        data.extend_from_slice(&h264::avcc_wrap(&[0x65, 0xAA], 1));

        let out = inj
            .inject_tag_with(&data, 0, Some(&[0u8; 300]))
            .expect("not fatal")
            .expect("the frame still goes out");
        assert_eq!(inj.stats.oversize_skipped, 1);
        let nals = h264::nal_units_avcc(&out[5..], 1).expect("still framed");
        assert_eq!(nals, vec![&[0x65, 0xAA][..]]);

        let out = inj
            .inject_tag_with(&data, 0, Some(b"small"))
            .expect("injects")
            .expect("rewritten");
        assert_eq!(inj.stats.injected["sei-unreg"], 1);
        assert_eq!(h264::nal_units_avcc(&out[5..], 1).expect("framed").len(), 2);
    }

    #[test]
    fn injects_into_every_video_frame_and_is_readable_downstream() {
        let mut flv = sample_flv();
        let opts = InjectOptions {
            carriers: vec![Carrier::SeiUnregistered, Carrier::SeiT35],
            ..Default::default()
        };
        let stats = inject(&mut flv, &opts).expect("injects");

        assert_eq!(stats.video_frames, 3);
        assert_eq!(stats.injected["sei-unreg"], 3);
        assert_eq!(stats.injected["sei-t35"], 3);
        assert!(stats.added_bytes > 0);

        let mut scanner = Scanner::new();
        for tag in flv.tags.iter().filter(|t| t.is_avc_nalu()) {
            scanner.feed_video_au(VideoCodec::H264, &annexb_of(tag), 0);
        }
        let r = scanner.report();
        assert_eq!(r.carriers["sei-unreg"].ok, 3);
        assert_eq!(r.carriers["sei-t35"].ok, 3);
        assert_eq!(r.carriers["sei-unreg"].gaps(), 0);
        assert_eq!(r.unattributed.ok, 0);
    }

    #[test]
    fn a_live_payload_survives_the_round_trip_and_is_not_scored_as_rewritten() {
        // A universe of dark fixtures is all zeros, which is both the common
        // case on a real desk and the case that forces emulation prevention.
        let blocks = vec![
            crate::payload::Block {
                universe: 3,
                start: 0,
                age_us: 4_200,
                values: vec![0; 512],
            },
            crate::payload::Block {
                universe: 4,
                start: 0,
                age_us: 11_000,
                values: (0..512).map(|i| (i % 256) as u8).collect(),
            },
        ];
        let payload = crate::payload::encode(&blocks).expect("test blocks are small");

        let mut flv = sample_flv();
        let mut injector = Injector::new(&InjectOptions::default()).expect("injector");
        let header = flv
            .tags
            .iter()
            .find(|t| t.is_avc_sequence_header())
            .expect("sequence header")
            .data
            .clone();
        injector.note_sequence_header(&header).expect("length size");
        for tag in flv.tags.iter_mut().filter(|t| t.is_avc_nalu()) {
            if let Some(rewritten) = injector
                .inject_tag_with(&tag.data, 0, Some(&payload))
                .expect("injects")
            {
                tag.data = rewritten;
            }
        }

        let mut scanner = Scanner::new();
        let mut recovered = Vec::new();
        for tag in flv.tags.iter().filter(|t| t.is_avc_nalu()) {
            let au = annexb_of(tag);
            scanner.feed_video_au(VideoCodec::H264, &au, 0);
            h264::scan_sei_annexb(&au, |ty, sei| {
                if ty == h264::SEI_UNREGISTERED
                    && let Some(body) = Carrier::SeiUnregistered.unframe_sei(sei)
                    && let Ok(r) = Record::decode(body)
                {
                    recovered.push(crate::payload::decode(&r.payload).expect("payload decodes"));
                }
            });
        }

        let report = scanner.report();
        assert_eq!(report.carriers["sei-unreg"].ok, 3);
        assert_eq!(report.carriers["sei-unreg"].corrupt, 0);
        assert_eq!(
            report.carriers["sei-unreg"].rewritten, 0,
            "a self-describing payload has no generator to disagree with"
        );
        assert_eq!(recovered.len(), 3);
        assert_eq!(recovered[0], blocks);
    }

    #[test]
    fn keeps_the_access_unit_delimiter_first() {
        let mut flv = sample_flv();
        inject(&mut flv, &InjectOptions::default()).unwrap();
        let tag = flv.tags.iter().find(|t| t.is_avc_nalu()).unwrap();
        let nals = h264::nal_units_avcc(tag.avc_body(), 4).unwrap();
        assert_eq!(h264::nal_type(nals[0][0]), 9, "AUD must stay first");
        assert_eq!(h264::nal_type(nals[1][0]), h264::NAL_SEI);
        assert_eq!(
            h264::nal_type(nals.last().unwrap()[0]),
            5,
            "slice stays last"
        );
    }

    #[test]
    fn inserts_at_the_front_when_there_is_no_delimiter() {
        let mut flv = Flv {
            header: b"FLV\x01\x05\x00\x00\x00\x09".to_vec(),
            tags: vec![video_tag(true, &avcc(&[&[0x65, 0x11]]), 0)],
        };
        inject(&mut flv, &InjectOptions::default()).unwrap();
        let nals = h264::nal_units_avcc(flv.tags[0].avc_body(), 4).unwrap();
        assert_eq!(h264::nal_type(nals[0][0]), h264::NAL_SEI);
        assert_eq!(h264::nal_type(nals.last().unwrap()[0]), 5);
    }

    #[test]
    fn sequence_numbers_are_per_carrier_and_gapless() {
        let mut flv = sample_flv();
        inject(&mut flv, &InjectOptions::default()).unwrap();

        let mut seqs = Vec::new();
        for tag in flv.tags.iter().filter(|t| t.is_avc_nalu()) {
            h264::scan_sei_annexb(&annexb_of(tag), |ty, payload| {
                if ty == h264::SEI_UNREGISTERED
                    && let Some(body) = Carrier::SeiUnregistered.unframe_sei(payload)
                    && let Ok(r) = Record::decode(body)
                {
                    seqs.push(r.seq);
                }
            });
        }
        assert_eq!(seqs, vec![0, 1, 2]);
    }

    #[test]
    fn every_n_thins_the_rate() {
        let mut flv = sample_flv();
        let opts = InjectOptions {
            carriers: vec![Carrier::SeiUnregistered],
            every_n_frames: 2,
            ..Default::default()
        };
        let stats = inject(&mut flv, &opts).unwrap();
        assert_eq!(stats.injected["sei-unreg"], 2, "frames 0 and 2 of 3");
    }

    #[test]
    fn filler_lands_after_the_picture_and_sei_before_it() {
        let mut flv = sample_flv();
        let opts = InjectOptions {
            carriers: vec![Carrier::SeiUnregistered, Carrier::FillerNal],
            ..Default::default()
        };
        inject(&mut flv, &opts).unwrap();

        let tag = flv.tags.iter().find(|t| t.is_avc_nalu()).unwrap();
        let types: Vec<u8> = h264::nal_units_avcc(tag.avc_body(), 4)
            .unwrap()
            .iter()
            .map(|n| h264::nal_type(n[0]))
            .collect();
        assert_eq!(
            types,
            vec![9, h264::NAL_SEI, 5, h264::NAL_FILLER],
            "AUD first, SEI before the picture, filler after it"
        );
    }

    #[test]
    fn keyframes_only_hits_just_the_idr() {
        let mut flv = sample_flv();
        let opts = InjectOptions {
            carriers: vec![Carrier::SeiUnregistered],
            keyframes_only: true,
            ..Default::default()
        };
        let stats = inject(&mut flv, &opts).unwrap();
        assert_eq!(stats.injected["sei-unreg"], 1);
    }

    #[test]
    fn container_carriers_are_refused_with_a_reason() {
        let mut flv = sample_flv();
        let opts = InjectOptions {
            carriers: vec![Carrier::AmfCustom],
            ..Default::default()
        };
        let err = inject(&mut flv, &opts).unwrap_err().to_string();
        assert!(err.contains("amf-custom"), "got: {err}");
        assert!(err.contains("AMF data messages"), "got: {err}");
    }

    #[test]
    fn added_bitrate_is_reported() {
        let mut flv = sample_flv();
        let stats = inject(&mut flv, &InjectOptions::default()).unwrap();
        assert!(stats.added_kbps() > 0.0);
        assert_eq!(stats.duration_ms, 66);
    }

    /// An Enhanced RTMP HEVC stream: hvcC with 4-byte lengths, a keyframe as
    /// CodedFrames (composition time present) and an inter frame as
    /// CodedFramesX (none).
    fn hevc_flv() -> Flv {
        let mut hvcc = vec![1u8; 23];
        hvcc[21] = 0x0F;
        let mut config = vec![0x90, b'h', b'v', b'c', b'1'];
        config.extend_from_slice(&hvcc);
        let mut key = vec![0x91, b'h', b'v', b'c', b'1', 0, 0, 0];
        key.extend_from_slice(&avcc(&[&[0x46, 0x01, 0x10], &[0x26, 0x01, 0xAA]]));
        let mut inter = vec![0xA3, b'h', b'v', b'c', b'1'];
        inter.extend_from_slice(&avcc(&[&[0x02, 0x01, 0xBB]]));
        let tag = |timestamp, data| Tag {
            kind: TAG_VIDEO,
            timestamp,
            data,
        };
        Flv {
            header: b"FLV\x01\x01\x00\x00\x00\x09".to_vec(),
            tags: vec![tag(0, config), tag(0, key), tag(33, inter)],
        }
    }

    fn hevc_nals(tag: &Tag) -> Vec<Vec<u8>> {
        let Video::Frame { body, .. } = flv::video(&tag.data) else {
            panic!("not a frame tag");
        };
        h264::nal_units_avcc(&tag.data[body..], 4)
            .expect("framed")
            .into_iter()
            .map(<[u8]>::to_vec)
            .collect()
    }

    #[test]
    fn hevc_carriers_land_in_place_and_read_back() {
        let mut flv = hevc_flv();
        let opts = InjectOptions {
            carriers: vec![
                Carrier::SeiUnregistered,
                Carrier::SeiT35,
                Carrier::FillerNal,
            ],
            ..Default::default()
        };
        let stats = inject(&mut flv, &opts).expect("injects");
        assert_eq!(stats.video_frames, 2);
        assert_eq!(stats.unsupported_codec, None);

        let key = &flv.tags[1];
        assert_eq!(&key.data[..8], &[0x91, b'h', b'v', b'c', b'1', 0, 0, 0]);
        let types: Vec<u8> = hevc_nals(key)
            .iter()
            .map(|n| VideoCodec::Hevc.nal_type(n[0]))
            .collect();
        assert_eq!(
            types,
            vec![35, 39, 39, 19, 38],
            "AUD first, prefix SEI before the picture, filler after it"
        );
        assert_eq!(&flv.tags[2].data[..5], &[0xA3, b'h', b'v', b'c', b'1']);

        let mut scanner = Scanner::new();
        for tag in &flv.tags[1..] {
            let mut au = Vec::new();
            for nal in hevc_nals(tag) {
                au.extend_from_slice(&[0, 0, 0, 1]);
                au.extend_from_slice(&nal);
            }
            scanner.feed_video_au(VideoCodec::Hevc, &au, 0);
        }
        let r = scanner.report();
        for c in ["sei-unreg", "sei-t35", "filler-nal"] {
            assert_eq!(r.carriers[c].ok, 2, "{c}");
        }
        assert_eq!(r.unattributed.ok, 0);
    }

    #[test]
    fn a_later_sequence_header_changes_the_length_size() {
        let mut flv = hevc_flv();
        let mut second = flv.tags[0].data.clone();
        second[5 + 21] = 0x0D; // 2-byte lengths from here on
        let mut inter = vec![0xA3, b'h', b'v', b'c', b'1'];
        inter.extend_from_slice(&h264::avcc_wrap(&[0x02, 0x01, 0xCC], 2));
        flv.tags.push(Tag {
            kind: TAG_VIDEO,
            timestamp: 66,
            data: second,
        });
        flv.tags.push(Tag {
            kind: TAG_VIDEO,
            timestamp: 66,
            data: inter,
        });

        let stats = inject(&mut flv, &InjectOptions::default()).expect("injects");
        assert_eq!(stats.video_frames, 3);
        let last = &flv.tags[4].data;
        let nals = h264::nal_units_avcc(&last[5..], 2).expect("framed with 2-byte lengths");
        assert_eq!(VideoCodec::Hevc.nal_type(nals[0][0]), 39);
    }

    #[test]
    fn hevc_under_the_legacy_codec_id_is_injected_too() {
        let mut data = vec![0x1C, AVC_NALU, 0, 0, 0];
        data.extend_from_slice(&avcc(&[&[0x26, 0x01, 0xAA]]));
        let mut inj = Injector::new(&InjectOptions::default()).expect("injector");
        let out = inj
            .inject_tag(&data, 0)
            .expect("injects")
            .expect("rewritten");
        let nals = h264::nal_units_avcc(&out[5..], 4).expect("framed");
        assert_eq!(VideoCodec::Hevc.nal_type(nals[0][0]), 39);
    }

    #[test]
    fn an_unsupported_codec_passes_through_and_is_named() {
        let data = vec![0x91, b'a', b'v', b'0', b'1', 0, 0, 0, 0x12, 0x00];
        let mut inj = Injector::new(&InjectOptions::default()).expect("injector");
        assert_eq!(inj.inject_tag(&data, 0).expect("not an error"), None);
        assert_eq!(inj.stats.unsupported_codec.as_deref(), Some("av01"));
        assert_eq!(inj.stats.video_frames, 0);
    }

    #[test]
    fn non_avcc_video_is_an_error_rather_than_silent_corruption() {
        let mut flv = Flv {
            header: b"FLV\x01\x05\x00\x00\x00\x09".to_vec(),
            tags: vec![video_tag(true, &[0, 0, 0, 99, 1, 2], 0)],
        };
        assert!(inject(&mut flv, &InjectOptions::default()).is_err());
    }
}
