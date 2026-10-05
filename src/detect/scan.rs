//! Scoring: turn a stream of received bytes into a per-carrier verdict.
//!
//! The scanner records three tiers of evidence, because "we found nothing" is
//! ambiguous on its own:
//!
//! 1. Our records, attributed to a carrier and checked for integrity.
//! 2. Foreign SEI — messages of a payload type we use, but not ours. If the
//!    encoder's own type-5 SEI arrives and the probe's does not, the injector
//!    is at fault, not the path. If neither arrives, the path strips SEI wholesale.
//! 3. The raw NAL histogram, which says whether the bitstream reached us
//!    intact enough for the other two tiers to mean anything.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::carrier::{self, Carrier};
use crate::codec::VideoCodec;
use crate::h264;
use crate::record::{self, DecodeError, Record};

/// A distribution, summarised. Reported instead of a single peak because a
/// maximum cannot tell one stall apart from a pattern of them: a 30 minute run
/// with one scheduling hiccup and a run that is late in every frame produce the
/// same number, and they mean opposite things.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Stats {
    pub count: usize,
    pub min: f64,
    pub p50: f64,
    pub p95: f64,
    pub max: f64,
}

impl Stats {
    /// Summarise already-scaled values. Returns `None` for an empty sample, so
    /// "nothing measured" cannot be mistaken for "measured zero".
    pub fn of(values: impl IntoIterator<Item = f64>) -> Option<Self> {
        let mut v: Vec<f64> = values.into_iter().collect();
        if v.is_empty() {
            return None;
        }
        v.sort_by(f64::total_cmp);
        let at = |f: f64| {
            let idx = ((v.len() as f64 - 1.0) * f).round() as usize;
            v[idx]
        };
        Some(Self {
            count: v.len(),
            min: v[0],
            p50: at(0.5),
            p95: at(0.95),
            max: v[v.len() - 1],
        })
    }
}

fn serialize_latency_ms<S: serde::Serializer>(v: &[i64], s: S) -> Result<S::Ok, S::Error> {
    Stats::of(v.iter().map(|ns| *ns as f64 / 1e6)).serialize(s)
}

fn serialize_age_ms<S: serde::Serializer>(v: &[u32], s: S) -> Result<S::Ok, S::Error> {
    Stats::of(v.iter().map(|us| f64::from(*us) / 1e3)).serialize(s)
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct CarrierTally {
    /// Records that decoded cleanly.
    pub ok: u64,
    /// Records whose magic arrived but whose body did not survive.
    pub corrupt: u64,
    /// Records that decoded but whose payload was rewritten in flight.
    pub rewritten: u64,
    /// This carrier's own framing arrived (our SEI UUID, our T.35 provider
    /// code) carrying something that is not a probe record. The ffmpeg-driven
    /// smoke test plants a fixed marker rather than a record, so this is the
    /// counter that proves the carrier crosses before the full injector runs.
    pub marker: u64,
    /// A record that ran off the end of the buffer holding it.
    ///
    /// Kept apart from `corrupt` because it is usually not damage: joining a
    /// live stream mid-flight and leaving it mid-flight both clip an access
    /// unit, and every carrier in that access unit reports one. Counting those
    /// as corruption puts a CDN-is-mangling-our-data number in the report for
    /// something the capture did to itself.
    pub truncated: u64,
    pub first_seq: Option<u32>,
    pub last_seq: Option<u32>,
    #[serde(skip)]
    pub seqs: BTreeSet<u32>,
    /// Kept raw so percentiles can be taken over the whole run, and reported as
    /// a summary rather than as tens of thousands of numbers.
    #[serde(rename = "latency_ms", serialize_with = "serialize_latency_ms")]
    pub latencies_ns: Vec<i64>,
}

impl CarrierTally {
    /// Sequence numbers missing between the first and last we saw. Distinct
    /// from `ok` because a carrier that arrives but drops one record in three
    /// is not usable for anything that needs ordering.
    pub fn gaps(&self) -> u64 {
        match (self.first_seq, self.last_seq) {
            (Some(a), Some(b)) if b >= a => (u64::from(b - a) + 1) - self.seqs.len() as u64,
            _ => 0,
        }
    }

    pub fn latency_percentiles_ms(&self) -> Option<(f64, f64, f64)> {
        if self.latencies_ns.is_empty() {
            return None;
        }
        let mut v = self.latencies_ns.clone();
        v.sort_unstable();
        let at = |f: f64| {
            let idx = ((v.len() as f64 - 1.0) * f).round() as usize;
            v[idx] as f64 / 1e6
        };
        Some((at(0.0), at(0.5), at(1.0)))
    }

    fn observe(&mut self, r: &Record, now_unix_nanos: u64) {
        self.ok += 1;
        // A record carrying real data has no sequence-derived body to compare
        // against, so the CRC is what stands behind it. Scoring those as
        // rewritten would report damage on every frame of a live run.
        if !r.payload_intact() && !crate::payload::looks_like(&r.payload) {
            self.rewritten += 1;
        }
        self.first_seq = Some(self.first_seq.map_or(r.seq, |f| f.min(r.seq)));
        self.last_seq = Some(self.last_seq.map_or(r.seq, |l| l.max(r.seq)));
        self.seqs.insert(r.seq);
        if r.send_unix_nanos > 0 {
            self.latencies_ns
                .push(now_unix_nanos as i64 - r.send_unix_nanos as i64);
        }
    }
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct Evidence {
    /// H.264 NAL type -> count, over every access unit seen.
    pub nal_types: BTreeMap<u8, u64>,
    /// The same for HEVC, which numbers its types differently.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub hevc_nal_types: BTreeMap<u8, u64>,
    /// SEI payload type -> count, ours and foreign alike.
    pub sei_payload_types: BTreeMap<u64, u64>,
    /// SEI messages of a type we also use, but carrying someone else's data.
    /// The first few are kept as hex so the report can name the culprit.
    pub foreign_sei_samples: Vec<ForeignSei>,
    pub access_units: u64,
    pub video_es_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ForeignSei {
    pub payload_type: u64,
    pub len: usize,
    pub head_hex: String,
    pub head_ascii: String,
}

/// What the records were carrying, when they were carrying live DMX.
///
/// The carrier tallies answer whether the lane survived. This answers what came
/// down it, which is the only way to tell a desk sending nothing apart from a
/// lane that lost its contents.
#[derive(Debug, Default, Clone, Serialize)]
pub struct DmxTally {
    /// Records whose payload was a DMX snapshot.
    pub records: u64,
    /// Payloads that claimed to be a snapshot and did not parse. The record's
    /// CRC passed, so this is a sender fault rather than damage in flight.
    pub malformed: u64,
    pub blocks: u64,
    /// Channel bytes carried, across every record.
    pub channels: u64,
    pub universes: BTreeSet<u16>,
    /// Per record, how stale the oldest universe in it was when it was sent.
    /// One entry per record, so the summary answers what a typical frame looked
    /// like rather than only what the worst one did.
    #[serde(rename = "age_ms", serialize_with = "serialize_age_ms")]
    pub oldest_age_us: Vec<u32>,
}

impl DmxTally {
    pub fn age_stats_ms(&self) -> Option<Stats> {
        Stats::of(self.oldest_age_us.iter().map(|us| f64::from(*us) / 1e3))
    }
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct ScanReport {
    pub evidence: Evidence,
    pub carriers: BTreeMap<String, CarrierTally>,
    /// Records found by a raw byte scan that no carrier framing explained.
    /// A non-zero count here means a carrier arrived reframed rather than
    /// intact, which is worth knowing before declaring it dead.
    pub unattributed: CarrierTally,
    pub dmx: DmxTally,
}

#[derive(Default)]
pub struct Scanner {
    report: ScanReport,
    foreign_sample_budget: usize,
    /// Offsets already credited to a carrier, so the raw fallback scan does
    /// not double-count a record the structured pass already found.
    claimed: BTreeSet<(u64, u32)>,
}

impl Scanner {
    pub fn new() -> Self {
        Self {
            report: ScanReport::default(),
            foreign_sample_budget: 8,
            claimed: BTreeSet::new(),
        }
    }

    pub fn report(&self) -> &ScanReport {
        &self.report
    }

    pub fn into_report(self) -> ScanReport {
        self.report
    }

    /// Feed one video access unit in Annex-B framing.
    ///
    /// The codec comes from the container, not the bytes: an HEVC NAL header
    /// also parses as an H.264 one, of the wrong type.
    pub fn feed_video_au(&mut self, codec: VideoCodec, annexb: &[u8], now_unix_nanos: u64) {
        self.report.evidence.access_units += 1;
        self.report.evidence.video_es_bytes += annexb.len() as u64;

        for nal in h264::nal_units_annexb(annexb) {
            let ty = codec.nal_type(nal[0]);
            let histogram = match codec {
                VideoCodec::H264 => &mut self.report.evidence.nal_types,
                VideoCodec::Hevc => &mut self.report.evidence.hevc_nal_types,
            };
            *histogram.entry(ty).or_insert(0) += 1;

            // A NAL cut short inside its own header has no body to read.
            let Some(body) = nal.get(codec.nal_header_len()..) else {
                continue;
            };
            if codec.is_sei(ty) {
                let rbsp = h264::unescape_rbsp(body);
                let mut messages = Vec::new();
                h264::sei_messages(&rbsp, |t, p| messages.push((t, p.to_vec())));
                for (payload_type, payload) in messages {
                    self.feed_sei(payload_type, &payload, now_unix_nanos);
                }
                self.sweep_nal(&rbsp, now_unix_nanos);
            } else if codec.is_filler(ty) {
                let rbsp = h264::unescape_rbsp(body);
                self.feed_speculative(Carrier::FillerNal, &rbsp, now_unix_nanos);
                self.sweep_nal(&rbsp, now_unix_nanos);
            } else if !body.is_empty() {
                // Fallback for a carrier that arrived in a framing the
                // structured passes do not recognise. The sweep must run
                // on the unescaped RBSP: emulation-prevention bytes land
                // inside the record body, so scanning the coded bytes
                // would find the magic, read a `0x03`-riddled body and
                // report a corruption that never happened.
                let rbsp = h264::unescape_rbsp(body);
                self.sweep_nal(&rbsp, now_unix_nanos);
            }
        }
    }

    /// Raw sweep of one unescaped NAL body, skipped entirely when the magic is
    /// absent so the common case costs a substring search rather than an
    /// allocation per NAL.
    fn sweep_nal(&mut self, rbsp: &[u8], now_unix_nanos: u64) {
        if rbsp.len() < record::MAGIC.len() {
            return;
        }
        if !rbsp
            .windows(record::MAGIC.len())
            .any(|w| w == record::MAGIC)
        {
            return;
        }
        self.feed_raw(rbsp, now_unix_nanos);
    }

    /// Feed one SEI message, ours or not.
    pub fn feed_sei(&mut self, payload_type: u64, payload: &[u8], now_unix_nanos: u64) {
        *self
            .report
            .evidence
            .sei_payload_types
            .entry(payload_type)
            .or_insert(0) += 1;

        let carrier = match payload_type {
            h264::SEI_UNREGISTERED => Some(Carrier::SeiUnregistered),
            h264::SEI_T35 => Some(Carrier::SeiT35),
            _ => None,
        };

        if let Some(c) = carrier
            && let Some(body) = c.unframe_sei(payload)
        {
            self.feed_framed(c, body, now_unix_nanos);
            return;
        }

        // A payload type we use, carrying someone else's data. Worth a sample:
        // it proves SEI of that type crosses the path even when ours does not.
        if carrier.is_some() && self.foreign_sample_budget > 0 {
            self.foreign_sample_budget -= 1;
            self.report.evidence.foreign_sei_samples.push(ForeignSei {
                payload_type,
                len: payload.len(),
                head_hex: carrier::hex_encode(&payload[..payload.len().min(24)]),
                head_ascii: payload[..payload.len().min(24)]
                    .iter()
                    .map(|&b| {
                        if (0x20..0x7F).contains(&b) {
                            b as char
                        } else {
                            '.'
                        }
                    })
                    .collect(),
            });
        }
    }

    /// Feed a blob whose framing identifies the carrier on its own — our SEI
    /// UUID, our T.35 provider code, our AMF message name. A body that is not
    /// a record still counts, as a marker.
    pub fn feed_framed(&mut self, c: Carrier, body: &[u8], now_unix_nanos: u64) {
        self.record_body(c, body, now_unix_nanos, true);
    }

    /// Feed a blob from a framing that does not identify us — a filler NAL,
    /// which every encoder emits, or a raw sweep. Only a real record counts;
    /// anything else is somebody else's data and must not inflate the tally.
    pub fn feed_speculative(&mut self, c: Carrier, body: &[u8], now_unix_nanos: u64) {
        self.record_body(c, body, now_unix_nanos, false);
    }

    fn record_body(&mut self, c: Carrier, body: &[u8], now_unix_nanos: u64, identifying: bool) {
        let has_magic = body.len() >= record::MAGIC.len() && body[..8] == record::MAGIC;
        match Record::decode(body) {
            Ok(r) => {
                let tally = self
                    .report
                    .carriers
                    .entry(c.slug().to_string())
                    .or_default();
                tally.observe(&r, now_unix_nanos);
                self.note_payload(&r);
                self.claimed.insert((r.send_unix_nanos, r.seq));
            }
            Err(DecodeError::Truncated { .. }) if has_magic => {
                self.report
                    .carriers
                    .entry(c.slug().to_string())
                    .or_default()
                    .truncated += 1;
            }
            Err(_) if has_magic => {
                self.report
                    .carriers
                    .entry(c.slug().to_string())
                    .or_default()
                    .corrupt += 1;
            }
            Err(_) if identifying => {
                self.report
                    .carriers
                    .entry(c.slug().to_string())
                    .or_default()
                    .marker += 1;
            }
            Err(_) => {}
        }
    }

    /// Record what a live payload was carrying. Silent for a measurement run,
    /// whose bodies are generated rather than meaningful.
    fn note_payload(&mut self, r: &Record) {
        if !crate::payload::looks_like(&r.payload) {
            return;
        }
        let Ok(blocks) = crate::payload::decode(&r.payload) else {
            self.report.dmx.malformed += 1;
            return;
        };
        let dmx = &mut self.report.dmx;
        dmx.records += 1;
        dmx.blocks += blocks.len() as u64;
        let mut oldest = 0u32;
        for b in &blocks {
            dmx.channels += b.values.len() as u64;
            dmx.universes.insert(b.universe);
            oldest = oldest.max(b.age_us);
        }
        dmx.oldest_age_us.push(oldest);
    }

    /// Feed text from a container-level carrier (hex, as the AMF carriers use).
    pub fn feed_hex_text(&mut self, c: Carrier, text: &[u8], now_unix_nanos: u64) {
        match carrier::hex_decode(text) {
            Some(bytes) => self.feed_framed(c, &bytes, now_unix_nanos),
            None => {
                let tally = self
                    .report
                    .carriers
                    .entry(c.slug().to_string())
                    .or_default();
                tally.corrupt += 1;
            }
        }
    }

    /// Raw byte scan for records nothing else claimed.
    pub fn feed_raw(&mut self, haystack: &[u8], now_unix_nanos: u64) {
        for hit in record::find_records(haystack) {
            match hit.result {
                Ok(r) => {
                    if self.claimed.contains(&(r.send_unix_nanos, r.seq)) {
                        continue;
                    }
                    self.claimed.insert((r.send_unix_nanos, r.seq));
                    self.report.unattributed.observe(&r, now_unix_nanos);
                    self.note_payload(&r);
                }
                Err(DecodeError::Truncated { .. }) => self.report.unattributed.truncated += 1,
                Err(_) => self.report.unattributed.corrupt += 1,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hevc;
    use crate::record::DEFAULT_PAYLOAD_LEN;

    fn au_with(nals: &[Vec<u8>]) -> Vec<u8> {
        let mut au = Vec::new();
        for n in nals {
            au.extend_from_slice(&[0, 0, 0, 1]);
            au.extend_from_slice(n);
        }
        au
    }

    fn probe(c: Carrier, seq: u32, sent: u64) -> Vec<u8> {
        probe_in(VideoCodec::H264, c, seq, sent)
    }

    fn probe_in(codec: VideoCodec, c: Carrier, seq: u32, sent: u64) -> Vec<u8> {
        let r = Record::new(c.id(), seq, sent, seq, DEFAULT_PAYLOAD_LEN);
        c.frame_for(codec, &r).unwrap()
    }

    fn live_record(payload: Vec<u8>) -> Vec<u8> {
        let c = Carrier::SeiUnregistered;
        c.frame(&Record::with_payload(c.id(), 0, 1, 0, payload))
            .unwrap()
    }

    #[test]
    fn a_distribution_is_summarised_rather_than_reduced_to_its_peak() {
        // The case this exists for: one stall in an otherwise clean run. The
        // maximum alone cannot tell it from a run that is late throughout.
        let mut v: Vec<f64> = (0..99).map(|_| 30.0).collect();
        v.push(900.0);
        let s = Stats::of(v).expect("non-empty");
        assert_eq!(s.count, 100);
        assert_eq!(s.min, 30.0);
        assert_eq!(s.p50, 30.0);
        assert_eq!(s.p95, 30.0, "one outlier must not move p95");
        assert_eq!(s.max, 900.0);

        let late = Stats::of(vec![800.0; 100]).expect("non-empty");
        assert_eq!(late.p95, 800.0, "a systematic problem does move it");
        assert!(
            Stats::of(Vec::<f64>::new()).is_none(),
            "nothing measured is not zero"
        );
    }

    #[test]
    fn an_age_is_recorded_for_every_record_not_just_the_worst() {
        let mut s = Scanner::new();
        for age in [4_000u32, 40_000, 9_000] {
            let blocks = vec![crate::payload::Block {
                universe: 0,
                start: 0,
                age_us: age,
                values: vec![1; 16],
            }];
            s.feed_video_au(
                VideoCodec::H264,
                &au_with(&[live_record(
                    crate::payload::encode(&blocks).expect("test blocks are small"),
                )]),
                2,
            );
        }
        let dmx = &s.report().dmx;
        assert_eq!(dmx.oldest_age_us, vec![4_000, 40_000, 9_000]);
        let stats = dmx.age_stats_ms().expect("ages recorded");
        assert_eq!(stats.count, 3);
        assert_eq!(stats.max, 40.0);
        assert_eq!(stats.p50, 9.0);
    }

    #[test]
    fn a_live_payload_is_summarised_rather_than_scored_as_a_rewrite() {
        let blocks = vec![crate::payload::Block {
            universe: 7,
            start: 0,
            age_us: 12_000,
            values: vec![3; 512],
        }];
        let mut s = Scanner::new();
        s.feed_video_au(
            VideoCodec::H264,
            &au_with(&[live_record(
                crate::payload::encode(&blocks).expect("test blocks are small"),
            )]),
            2,
        );

        let r = s.report();
        assert_eq!(r.carriers["sei-unreg"].ok, 1);
        assert_eq!(r.carriers["sei-unreg"].rewritten, 0);
        assert_eq!(r.dmx.records, 1);
        assert_eq!(r.dmx.blocks, 1);
        assert_eq!(r.dmx.channels, 512);
        assert!(r.dmx.universes.contains(&7));
        assert_eq!(r.dmx.oldest_age_us, vec![12_000]);
    }

    #[test]
    fn a_snapshot_that_does_not_parse_is_kept_apart_from_damage_in_flight() {
        // Declares a block that is not there. The record's CRC still passes, so
        // this is the sender's fault and must not read as corruption.
        let mut body = crate::payload::encode(&[]).expect("an empty payload encodes");
        body[7] = 1;
        let mut s = Scanner::new();
        s.feed_video_au(VideoCodec::H264, &au_with(&[live_record(body)]), 2);

        let r = s.report();
        assert_eq!(r.carriers["sei-unreg"].ok, 1);
        assert_eq!(r.carriers["sei-unreg"].corrupt, 0);
        assert_eq!(r.carriers["sei-unreg"].rewritten, 0);
        assert_eq!(r.dmx.records, 0);
        assert_eq!(r.dmx.malformed, 1);
    }

    #[test]
    fn attributes_each_sei_carrier_and_measures_latency() {
        let mut s = Scanner::new();
        let sent = 1_000_000_000u64;
        let now = sent + 250_000_000; // 250 ms later

        let au = au_with(&[
            vec![0x09, 0x10],
            probe(Carrier::SeiUnregistered, 1, sent),
            probe(Carrier::SeiT35, 1, sent),
            vec![0x65, 0xAA, 0xBB],
        ]);
        s.feed_video_au(VideoCodec::H264, &au, now);

        let r = s.report();
        assert_eq!(r.carriers["sei-unreg"].ok, 1);
        assert_eq!(r.carriers["sei-t35"].ok, 1);
        assert_eq!(r.unattributed.ok, 0, "structured pass claimed both");
        assert_eq!(r.evidence.nal_types[&h264::NAL_SEI], 2);
        assert_eq!(r.evidence.nal_types[&5], 1);

        let (_, med, _) = r.carriers["sei-unreg"].latency_percentiles_ms().unwrap();
        assert!((med - 250.0).abs() < 0.001, "median was {med}");
    }

    #[test]
    fn foreign_sei_is_recorded_as_evidence_not_as_a_hit() {
        let mut s = Scanner::new();
        // x264 stamps its version through the same payload type we use.
        let mut payload = vec![0u8; 16];
        payload.extend_from_slice(b"x264 - core 164");
        let au = au_with(&[h264::build_sei_nal(h264::SEI_UNREGISTERED, &payload)]);
        s.feed_video_au(VideoCodec::H264, &au, 0);

        let r = s.report();
        assert!(r.carriers.get("sei-unreg").is_none_or(|t| t.ok == 0));
        assert_eq!(r.evidence.sei_payload_types[&h264::SEI_UNREGISTERED], 1);
        assert_eq!(r.evidence.foreign_sei_samples.len(), 1);
        assert!(
            r.evidence.foreign_sei_samples[0]
                .head_ascii
                .contains("....")
        );
    }

    #[test]
    fn gaps_count_missing_sequence_numbers() {
        let mut s = Scanner::new();
        for seq in [1u32, 2, 5] {
            let au = au_with(&[probe(Carrier::SeiUnregistered, seq, 1)]);
            s.feed_video_au(VideoCodec::H264, &au, 1);
        }
        let t = &s.report().carriers["sei-unreg"];
        assert_eq!(t.ok, 3);
        assert_eq!(t.gaps(), 2, "3 and 4 never arrived");
    }

    #[test]
    fn a_rewritten_payload_is_flagged_even_though_the_crc_is_valid() {
        let mut s = Scanner::new();
        let mut r = Record::new(Carrier::SeiUnregistered.id(), 9, 1, 9, DEFAULT_PAYLOAD_LEN);
        r.payload[0] ^= 0xFF; // re-encoding recomputes the CRC over the new body
        let nal = {
            let mut payload = carrier::PROBE_UUID.to_vec();
            payload.extend_from_slice(&r.encode().unwrap());
            h264::build_sei_nal(h264::SEI_UNREGISTERED, &payload)
        };
        s.feed_video_au(VideoCodec::H264, &au_with(&[nal]), 1);

        let t = &s.report().carriers["sei-unreg"];
        assert_eq!(t.ok, 1);
        assert_eq!(t.rewritten, 1);
    }

    #[test]
    fn a_record_clipped_by_the_capture_boundary_is_not_called_corruption() {
        // Joining or leaving a live stream mid-flight clips an access unit,
        // and every carrier in it reports one of these. Filing them as
        // corruption would put a CDN-is-mangling-our-data number in the report
        // for something the capture did to itself.
        let mut s = Scanner::new();
        let full = {
            let mut payload = carrier::PROBE_UUID.to_vec();
            payload.extend_from_slice(
                &Record::new(1, 4, 1, 4, DEFAULT_PAYLOAD_LEN)
                    .encode()
                    .unwrap(),
            );
            payload
        };
        let clipped = &full[..full.len() - 6];
        s.feed_sei(h264::SEI_UNREGISTERED, clipped, 1);

        let t = &s.report().carriers["sei-unreg"];
        assert_eq!(t.truncated, 1);
        assert_eq!(t.corrupt, 0, "a clipped tail is not damage");
        assert_eq!(t.ok, 0);
    }

    #[test]
    fn corrupt_bodies_are_counted_separately_from_absence() {
        let mut s = Scanner::new();
        let mut payload = carrier::PROBE_UUID.to_vec();
        let mut body = Record::new(1, 4, 1, 4, DEFAULT_PAYLOAD_LEN)
            .encode()
            .unwrap();
        let n = body.len();
        body[n - 1] ^= 0xFF; // break the CRC
        payload.extend_from_slice(&body);
        let nal = h264::build_sei_nal(h264::SEI_UNREGISTERED, &payload);
        s.feed_video_au(VideoCodec::H264, &au_with(&[nal]), 1);

        let t = &s.report().carriers["sei-unreg"];
        assert_eq!(t.ok, 0);
        assert_eq!(
            t.corrupt, 1,
            "arrived but mangled is not the same as absent"
        );
    }

    #[test]
    fn our_uuid_with_a_non_record_body_counts_as_a_marker() {
        // This is the shape the ffmpeg smoke test produces: right UUID, fixed
        // text instead of a record.
        let mut s = Scanner::new();
        let mut payload = carrier::PROBE_UUID.to_vec();
        payload.extend_from_slice(b"VCP-SMOKE-v1");
        let au = au_with(&[h264::build_sei_nal(h264::SEI_UNREGISTERED, &payload)]);
        s.feed_video_au(VideoCodec::H264, &au, 1);

        let t = &s.report().carriers["sei-unreg"];
        assert_eq!(t.marker, 1);
        assert_eq!(t.ok, 0);
        assert_eq!(t.corrupt, 0);
        assert!(s.report().evidence.foreign_sei_samples.is_empty());
    }

    #[test]
    fn an_encoders_own_filler_nal_creates_no_carrier_row() {
        let mut s = Scanner::new();
        let mut filler = vec![h264::NAL_FILLER];
        filler.extend_from_slice(&[0xFF; 40]);
        s.feed_video_au(VideoCodec::H264, &au_with(&[filler]), 1);

        assert!(
            !s.report().carriers.contains_key("filler-nal"),
            "padding must not look like a surviving carrier"
        );
        assert_eq!(s.report().evidence.nal_types[&h264::NAL_FILLER], 1);
    }

    #[test]
    fn filler_carrier_is_picked_up_from_nal_12() {
        let mut s = Scanner::new();
        let au = au_with(&[probe(Carrier::FillerNal, 3, 1)]);
        s.feed_video_au(VideoCodec::H264, &au, 1);
        assert_eq!(s.report().carriers["filler-nal"].ok, 1);
        assert_eq!(s.report().unattributed.ok, 0);
    }

    #[test]
    fn raw_fallback_catches_a_reframed_record() {
        let mut s = Scanner::new();
        // A record sitting in a slice NAL, in no framing we know about. It is
        // escaped because that is how it would arrive in a real bitstream.
        let body = Record::new(Carrier::SeiUnregistered.id(), 77, 1, 77, 8)
            .encode()
            .unwrap();
        let mut slice = vec![0x65u8];
        slice.extend_from_slice(&h264::escape_rbsp(&body));
        s.feed_video_au(VideoCodec::H264, &au_with(&[slice]), 1);

        assert_eq!(s.report().unattributed.ok, 1);
        assert!(
            s.report()
                .carriers
                .get("sei-unreg")
                .is_none_or(|t| t.ok == 0)
        );
    }

    #[test]
    fn a_body_needing_emulation_prevention_is_not_reported_as_corrupt() {
        // A payload of zeros forces escape bytes into the middle of the
        // record. Sweeping the coded bytes instead of the RBSP would find the
        // magic, read a 0x03-riddled body and invent a corruption for every
        // single frame.
        let mut s = Scanner::new();
        let mut r = Record::new(Carrier::SeiUnregistered.id(), 1, 1, 1, 24);
        r.payload = vec![0u8; 24];
        let mut payload = carrier::PROBE_UUID.to_vec();
        payload.extend_from_slice(&r.encode().unwrap());
        let nal = h264::build_sei_nal(h264::SEI_UNREGISTERED, &payload);
        assert!(
            nal.windows(3).any(|w| w == [0, 0, 3]),
            "the fixture must actually contain escape bytes"
        );

        s.feed_video_au(VideoCodec::H264, &au_with(&[nal]), 1);

        let rep = s.report();
        assert_eq!(rep.carriers["sei-unreg"].ok, 1);
        assert_eq!(rep.carriers["sei-unreg"].corrupt, 0);
        assert_eq!(rep.unattributed.corrupt, 0, "no phantom corruption");
        assert_eq!(rep.unattributed.ok, 0, "no double count either");
    }

    #[test]
    fn hex_text_path_decodes_the_amf_carriers() {
        let mut s = Scanner::new();
        let text = Carrier::AmfCustom
            .frame(&Record::new(
                Carrier::AmfCustom.id(),
                12,
                5,
                12,
                DEFAULT_PAYLOAD_LEN,
            ))
            .unwrap();
        s.feed_hex_text(Carrier::AmfCustom, &text, 5);
        assert_eq!(s.report().carriers["amf-custom"].ok, 1);
    }

    #[test]
    fn attributes_each_sei_carrier_in_hevc() {
        let mut s = Scanner::new();
        let mut suffix = probe_in(VideoCodec::Hevc, Carrier::SeiT35, 1, 1);
        suffix[0] = hevc::NAL_SUFFIX_SEI << 1;
        let au = au_with(&[
            vec![hevc::NAL_AUD << 1, 0x01, 0x50],
            probe_in(VideoCodec::Hevc, Carrier::SeiUnregistered, 1, 1),
            suffix,
            vec![19 << 1, 0x01, 0xAA, 0xBB], // IDR_W_RADL
        ]);
        s.feed_video_au(VideoCodec::Hevc, &au, 2);

        let r = s.report();
        assert_eq!(r.carriers["sei-unreg"].ok, 1);
        assert_eq!(r.carriers["sei-t35"].ok, 1);
        assert_eq!(r.unattributed.ok, 0, "structured pass claimed both");
        assert_eq!(r.evidence.hevc_nal_types[&hevc::NAL_PREFIX_SEI], 1);
        assert_eq!(r.evidence.hevc_nal_types[&hevc::NAL_SUFFIX_SEI], 1);
        assert_eq!(r.evidence.hevc_nal_types[&19], 1);
        assert!(
            r.evidence.nal_types.is_empty(),
            "HEVC must not land in the H.264 histogram"
        );
    }

    #[test]
    fn hevc_filler_carrier_is_picked_up_from_nal_38() {
        let mut s = Scanner::new();
        let au = au_with(&[probe_in(VideoCodec::Hevc, Carrier::FillerNal, 3, 1)]);
        s.feed_video_au(VideoCodec::Hevc, &au, 1);
        assert_eq!(s.report().carriers["filler-nal"].ok, 1);
        assert_eq!(s.report().unattributed.ok, 0);
    }

    #[test]
    fn an_hevc_sei_needing_emulation_prevention_reads_back_clean() {
        let mut s = Scanner::new();
        let mut r = Record::new(Carrier::SeiUnregistered.id(), 1, 1, 1, 24);
        r.payload = vec![0u8; 24];
        let mut payload = carrier::PROBE_UUID.to_vec();
        payload.extend_from_slice(&r.encode().unwrap());
        let nal = hevc::build_sei_nal(h264::SEI_UNREGISTERED, &payload);
        assert!(
            nal.windows(3).any(|w| w == [0, 0, 3]),
            "the fixture must actually contain escape bytes"
        );

        s.feed_video_au(VideoCodec::Hevc, &au_with(&[nal]), 1);

        let rep = s.report();
        assert_eq!(rep.carriers["sei-unreg"].ok, 1);
        assert_eq!(rep.carriers["sei-unreg"].corrupt, 0);
        assert_eq!(rep.unattributed.corrupt, 0, "no phantom corruption");
    }

    #[test]
    fn an_hevc_nal_cut_inside_its_header_is_counted_not_read() {
        let mut s = Scanner::new();
        s.feed_video_au(
            VideoCodec::Hevc,
            &[0, 0, 0, 1, hevc::NAL_PREFIX_SEI << 1],
            1,
        );
        assert_eq!(s.report().evidence.hevc_nal_types[&hevc::NAL_PREFIX_SEI], 1);
        assert!(s.report().carriers.is_empty());
    }
}
