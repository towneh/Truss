//! Turning a pulled stream's presentation times into the decode times and
//! millisecond timestamps an RTMP publish carries.

use std::cmp::Reverse;
use std::collections::BinaryHeap;

use h264_reader::avcc::AvcDecoderConfigurationRecord;
use h264_reader::nal::sps::SeqParameterSet;
use h264_reader::nal::{Nal, RefNal};

/// The deepest reorder the window will grow to: H.264's own limit.
const MAX_DEPTH: usize = 16;

/// H.264 Baseline, which has no B-slices and so never reorders.
const PROFILE_BASELINE: u8 = 66;

/// How many frames the stream reorders by, from its configuration record:
/// none for Baseline, else what the SPS states, when it states it.
pub fn reorder_depth(avcc: &[u8]) -> Option<usize> {
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
}

impl Rebase {
    /// The output timestamp for a frame at `us` on `stream`.
    pub fn place(&mut self, stream: usize, us: i64) -> u32 {
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
        assert_eq!(reorder_depth(&[1, 66, 0xC0, 0x1F, 0xFF, 0xE1]), Some(0));
        assert_eq!(reorder_depth(&[]), None);
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
