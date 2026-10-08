//! Turning a pulled stream's presentation times into the decode times and
//! millisecond timestamps an RTMP publish carries.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::time::Instant;

use h264_reader::avcc::AvcDecoderConfigurationRecord;
use h264_reader::nal::sps::SeqParameterSet;
use h264_reader::nal::{Nal, RefNal};
use retina::codec::h265::nal as hevc_nal;

use crate::codec::VideoCodec;

/// The deepest reorder the window will grow to: the most pictures either
/// codec's decoded picture buffer can hold.
const MAX_DEPTH: usize = 16;

/// H.264 Baseline, which has no B-slices and so never reorders.
const PROFILE_BASELINE: u8 = 66;

/// HEVC's SPS NAL unit type, as an hvcC array names it.
const HEVC_SPS: u8 = 33;

/// How many frames the stream reorders by, from its decoder configuration
/// record (avcC or hvcC), when the SPS in it says.
pub fn reorder_depth(codec: VideoCodec, config: &[u8]) -> Option<usize> {
    match codec {
        VideoCodec::H264 => avc_reorder_depth(config),
        VideoCodec::Hevc => hevc_reorder_depth(config),
    }
}

/// None for Baseline, else what the SPS's optional VUI states.
fn avc_reorder_depth(avcc: &[u8]) -> Option<usize> {
    if avcc.get(1) == Some(&PROFILE_BASELINE) {
        return Some(0);
    }
    let record = AvcDecoderConfigurationRecord::try_from(avcc).ok()?;
    let sps = record.sequence_parameter_sets().next()?.ok()?;
    let sps = SeqParameterSet::from_bits(RefNal::new(sps, &[], true).rbsp_bits()).ok()?;
    let frames = sps
        .vui_parameters?
        .bitstream_restrictions?
        .max_num_reorder_frames;
    Some((frames as usize).min(MAX_DEPTH))
}

/// `sps_max_num_reorder_pics`, which every HEVC SPS states, from the first
/// SPS in an hvcC: 22 bytes of fixed fields, then arrays of NAL units, each
/// a type byte and a count, the units each behind a 16-bit length.
fn hevc_reorder_depth(hvcc: &[u8]) -> Option<usize> {
    let mut at = 23;
    for _ in 0..*hvcc.get(22)? {
        let ty = hvcc.get(at)? & 0x3F;
        let count = u16::from_be_bytes(hvcc.get(at + 1..at + 3)?.try_into().ok()?);
        at += 3;
        for _ in 0..count {
            let len = usize::from(u16::from_be_bytes(hvcc.get(at..at + 2)?.try_into().ok()?));
            let nal = hvcc.get(at + 2..at + 2 + len)?;
            if ty == HEVC_SPS {
                let (_, bits) = hevc_nal::split(nal).ok()?;
                let sps = hevc_nal::Sps::from_bits(bits).ok()?;
                return Some((sps.max_num_reorder_pics() as usize).min(MAX_DEPTH));
            }
            at += 2 + len;
        }
    }
    None
}

/// Decode times for video from presentation times alone, which is all RTP
/// carries, as ffmpeg derives them. Frames arrive in decode order; once more
/// than `depth` presentation times are held, each frame's decode time is the
/// smallest of them. The first `depth` frames come before any can be taken,
/// and are placed a frame apart ahead of the first.
///
/// Without a depth from the stream it starts at 0 and grows by one whenever
/// a frame is due to be shown before the last decode time. That frame is
/// held at the last decode time, so decode times never go backwards; it
/// goes out with a negative composition time, which FLV allows.
#[derive(Debug)]
pub struct DtsWindow {
    depth: usize,
    held: BinaryHeap<Reverse<i64>>,
    frame_us: i64,
    first: Option<i64>,
    count: usize,
    last: Option<i64>,
}

impl DtsWindow {
    pub fn new(depth: usize, frame_us: i64) -> Self {
        Self {
            depth,
            held: BinaryHeap::new(),
            frame_us: frame_us.max(1),
            first: None,
            count: 0,
            last: None,
        }
    }

    /// The decode time for the next frame in decode order, and whether the
    /// window grew to produce it.
    pub fn next(&mut self, pts: i64) -> (i64, bool) {
        let first = *self.first.get_or_insert(pts);
        let index = self.count;
        self.count += 1;
        self.held.push(Reverse(pts));
        if let Some(last) = self.last
            && pts < last
            && self.depth < MAX_DEPTH
        {
            self.depth += 1;
            return (last, true);
        }
        let dts = if self.held.len() > self.depth {
            self.held.pop().map_or(pts, |Reverse(p)| p)
        } else {
            first - self.depth.saturating_sub(index) as i64 * self.frame_us
        };
        let dts = self.last.map_or(dts, |last| dts.max(last));
        self.last = Some(dts);
        (dts, false)
    }

    pub fn depth(&self) -> usize {
        self.depth
    }
}

pub const VIDEO: usize = 0;
pub const AUDIO: usize = 1;

/// Microseconds on the source's aligned timeline to the milliseconds an RTMP
/// publish counts from its first frame.
///
/// The origin is set by the first frame placed, which the caller makes the
/// first video frame's decode time. A frame that would land before the last
/// one on its stream is held at the last one instead, and counted: an ingest
/// expects each stream's timestamps never to go back.
#[derive(Debug, Default)]
pub struct Rebase {
    origin: Option<i64>,
    last: [Option<u32>; 2],
    pub held: u64,
    /// When the source's session ended, if a new one is yet to place a frame.
    paused: Option<Instant>,
}

impl Rebase {
    /// The output timestamp for a frame at `us` on `stream`.
    pub fn place(&mut self, stream: usize, us: i64) -> u32 {
        self.place_at(stream, us, Instant::now())
    }

    /// As [`Rebase::place`], at `now`. After a [`Rebase::pause`] the first
    /// frame is placed after the last by however long the gap lasted, and
    /// the rest of the new timeline follows from it.
    pub fn place_at(&mut self, stream: usize, us: i64, now: Instant) -> u32 {
        if let Some(at) = self.paused.take() {
            let gap = u32::try_from(now.saturating_duration_since(at).as_millis())
                .unwrap_or(u32::MAX)
                .max(1);
            let resume = self.last(0).max(self.last(1)).saturating_add(gap);
            self.origin = Some(us - i64::from(resume) * 1000);
        }
        let ms = self.ms(us);
        let ms = match self.last[stream] {
            Some(last) if ms < last => {
                self.held += 1;
                last
            }
            _ => ms,
        };
        self.last[stream] = Some(ms);
        ms
    }

    /// `us` in output milliseconds, without placing a frame. Times before
    /// the origin read as 0.
    pub fn ms(&mut self, us: i64) -> u32 {
        let origin = *self.origin.get_or_insert(us);
        u32::try_from(us.saturating_sub(origin).max(0) / 1000).unwrap_or(u32::MAX)
    }

    /// The last timestamp placed on `stream`, or 0 before any.
    pub fn last(&self, stream: usize) -> u32 {
        self.last[stream].unwrap_or(0)
    }

    /// The source's session ended at `at`, and the next will bring a
    /// timeline of its own. A pause before any frame was placed changes
    /// nothing: the first frame sets the origin anyway.
    pub fn pause(&mut self, at: Instant) {
        if self.origin.is_some() {
            self.paused = Some(at);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FRAME: i64 = 33_333;

    fn run(depth: usize, ptss: &[i64]) -> (Vec<i64>, DtsWindow) {
        let mut w = DtsWindow::new(depth, FRAME);
        let dts = ptss.iter().map(|&p| w.next(p).0).collect();
        (dts, w)
    }

    /// I P B B P B B ..., as x264 with two B-frames sends them, in decode
    /// order: each P is shown after the two Bs that follow it.
    fn two_b_frames() -> Vec<i64> {
        let mut ptss = vec![0];
        for gop in 0..20 {
            let p = (gop * 3 + 3) * FRAME;
            ptss.extend([p, p - 2 * FRAME, p - FRAME]);
        }
        ptss
    }

    fn assert_sound(dts: &[i64], ptss: &[i64], from: usize) {
        for i in from.max(1)..ptss.len() {
            assert!(
                dts[i] <= ptss[i],
                "frame {i}: dts {} pts {}",
                dts[i],
                ptss[i]
            );
            assert!(dts[i] > dts[i - 1], "frame {i} repeats {}", dts[i]);
        }
    }

    #[test]
    fn without_b_frames_decode_time_is_presentation_time() {
        let ptss: Vec<i64> = (0..30).map(|i| i * FRAME).collect();
        let (dts, w) = run(0, &ptss);
        assert_eq!(dts, ptss);
        assert_eq!(w.depth(), 0);
    }

    #[test]
    fn a_known_depth_spaces_decode_times_a_frame_apart_from_the_start() {
        let ptss = two_b_frames();
        let (dts, w) = run(2, &ptss);
        assert_eq!(w.depth(), 2);
        let expected: Vec<i64> = (0..ptss.len() as i64).map(|i| (i - 2) * FRAME).collect();
        assert_eq!(dts, expected);
        assert_sound(&dts, &ptss, 0);
    }

    #[test]
    fn an_unknown_depth_is_learnt_and_decode_time_never_goes_back() {
        let ptss = two_b_frames();
        let (dts, w) = run(0, &ptss);
        assert_eq!(w.depth(), 2);
        assert!(dts.windows(2).all(|d| d[0] <= d[1]), "{dts:?}");
        // The first GOP holds while the depth is learnt; after it, the same
        // as a depth known from the start.
        assert_sound(&dts, &ptss, 8);
    }

    #[test]
    fn baseline_never_reorders() {
        assert_eq!(
            reorder_depth(VideoCodec::H264, &[1, 66, 0xC0, 0x1F, 0xFF, 0xE1]),
            Some(0)
        );
        assert_eq!(reorder_depth(VideoCodec::H264, &[]), None);
    }

    /// An hvcC holding `sps` as its only parameter set, after a VPS array
    /// with nothing in it.
    fn hvcc(sps: &[u8]) -> Vec<u8> {
        let mut record = vec![
            1, 0x01, 0x60, 0, 0, 0, 0x90, 0, 0, 0, 0, 0, 60, 0xF0, 0, 0xFC,
        ];
        record.extend_from_slice(&[0xFD, 0xF8, 0xF8, 0, 0, 0x0F]);
        record.push(2);
        record.extend_from_slice(&[0xA0, 0, 0]);
        record.extend_from_slice(&[0xA1, 0, 1]);
        record.extend_from_slice(&u16::try_from(sps.len()).unwrap().to_be_bytes());
        record.extend_from_slice(sps);
        record
    }

    #[test]
    fn hevc_reorder_depth_is_read_from_the_sps() {
        // libx265 at 320x180, bframes=0 and bframes=3 (B-pyramid).
        let no_b = b"\x42\x01\x01\x01\x60\x00\x00\x03\x00\x90\x00\x00\x03\x00\x00\x03\x00\x3c\xa0\x0a\x08\x0b\x9f\x79\x64\xa9\x24\xca\xf0\x16\x80\x80\x00\x00\x03\x00\x80\x00\x00\x0f\x04";
        let three_b = b"\x42\x01\x01\x01\x60\x00\x00\x03\x00\x90\x00\x00\x03\x00\x00\x03\x00\x3c\xa0\x0a\x08\x0b\x9f\x79\x65\x65\x92\x4c\xaf\x01\x68\x08\x00\x00\x03\x00\x08\x00\x00\x03\x00\xf0\x40";
        assert_eq!(reorder_depth(VideoCodec::Hevc, &hvcc(no_b)), Some(0));
        assert_eq!(reorder_depth(VideoCodec::Hevc, &hvcc(three_b)), Some(2));
        let truncated = hvcc(three_b);
        assert_eq!(
            reorder_depth(VideoCodec::Hevc, &truncated[..truncated.len() - 10]),
            None
        );
        assert_eq!(reorder_depth(VideoCodec::Hevc, &[1, 2, 3]), None);
    }

    #[test]
    fn rebase_counts_from_the_first_frame_placed() {
        let mut r = Rebase::default();
        assert_eq!(r.place(VIDEO, 5_000_000), 0);
        assert_eq!(r.place(AUDIO, 5_021_333), 21);
        assert_eq!(r.place(VIDEO, 5_033_333), 33);
        assert_eq!(r.held, 0);
    }

    #[test]
    fn a_new_session_continues_after_the_last_frame_by_the_gap() {
        let t0 = Instant::now();
        let mut r = Rebase::default();
        r.place_at(VIDEO, 5_000_000, t0);
        r.place_at(AUDIO, 6_980_000, t0);
        assert_eq!(r.place_at(VIDEO, 7_000_000, t0), 2_000);
        r.pause(t0);
        // The new session's clock starts anywhere, here far behind the old.
        let resumed = t0 + std::time::Duration::from_millis(3_500);
        assert_eq!(r.place_at(VIDEO, 100_000, resumed), 5_500);
        assert_eq!(r.place_at(AUDIO, 120_000, resumed), 5_520);
        assert_eq!(r.place_at(VIDEO, 133_333, resumed), 5_533);
        assert_eq!(r.held, 0);
    }

    #[test]
    fn a_step_back_is_held_at_the_last_timestamp() {
        let mut r = Rebase::default();
        r.place(VIDEO, 0);
        r.place(VIDEO, 2_000_000);
        assert_eq!(r.place(VIDEO, 1_000_000), 2_000);
        assert_eq!(r.held, 1);
        // Each stream keeps its own floor.
        assert_eq!(r.place(AUDIO, 1_000_000), 1_000);
    }
}
