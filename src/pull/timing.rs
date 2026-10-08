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
use crate::flv;

/// The deepest reorder the window will grow to: the most pictures either
/// codec's decoded picture buffer can hold.
pub const MAX_DEPTH: usize = 16;

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
/// and are placed a frame apart ahead of the first, or at the earliest
/// presentation time held when that is sooner.
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
            let spaced = first.saturating_sub(
                (self.depth.saturating_sub(index) as i64).saturating_mul(self.frame_us),
            );
            // Never after a presentation time already held: the frame rate a
            // source states can be wrong.
            self.held.peek().map_or(spaced, |Reverse(p)| spaced.min(*p))
        };
        let dts = self.last.map_or(dts, |last| dts.max(last));
        self.last = Some(dts);
        (dts, false)
    }

    pub fn depth(&self) -> usize {
        self.depth
    }
}

/// Which frames go out: no video before the first keyframe, none after a
/// loss until the next one, and none of the leading pictures of the keyframe
/// the video opened or resumed on: frames due to be shown before it, which in
/// HEVC after a CRA refer to pictures the publish never had, and which a
/// decoder starting there drops anyway. Audio waits for the video to open.
#[derive(Debug, Default)]
pub struct KeyframeGate {
    opened_at: Option<i64>,
    awaiting: bool,
    floor: Option<i64>,
    audio_started: bool,
}

/// What [`KeyframeGate::admit`] says to do with a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admit {
    /// The first frame through: describe the video, then call
    /// [`KeyframeGate::open`] and send it.
    Open,
    Pass,
    Drop,
    /// Dropped because the source lost video; the gate now waits for a
    /// keyframe. Returned once per loss, for a note to the operator.
    Lost,
}

impl KeyframeGate {
    /// The verdict on a frame at `pts`. `lost` is whether packets went
    /// missing before it.
    pub fn admit(&mut self, pts: i64, key: bool, lost: bool) -> Admit {
        let opening = self.opened_at.is_none();
        let mut noted = false;
        if lost && !key && !opening && !self.awaiting {
            self.awaiting = true;
            noted = true;
        }
        if (opening || self.awaiting) && !key {
            return if noted { Admit::Lost } else { Admit::Drop };
        }
        // A loss reported on the keyframe itself is a resume too: its leading
        // pictures refer to what was lost.
        if opening || self.awaiting || lost {
            self.floor = Some(pts);
        } else if let Some(floor) = self.floor {
            if pts < floor {
                return Admit::Drop;
            }
            // Leading pictures all come before the first trailing one in
            // decode order, so the floor has done its job. Kept, it would
            // drop the rest of the session after the source's timeline
            // jumped back.
            self.floor = None;
        }
        self.awaiting = false;
        if opening { Admit::Open } else { Admit::Pass }
    }

    /// The video opened on the keyframe at `pts`.
    pub fn open(&mut self, pts: i64) {
        self.opened_at = Some(pts);
    }

    /// Whether an audio frame at `pts` goes out: none until the video has
    /// opened, and none due before the keyframe it opened on until the first
    /// that is not. From there audio follows its own timeline.
    pub fn admit_audio(&mut self, pts: i64) -> bool {
        match self.opened_at {
            None => false,
            Some(_) if self.audio_started => true,
            Some(opened) => {
                self.audio_started = pts >= opened;
                self.audio_started
            }
        }
    }
}

/// One video frame as the publish carries it.
#[derive(Debug)]
pub struct VideoTag {
    /// The tag's timestamp: the frame's decode time, rebased.
    pub timestamp: u32,
    /// Presentation minus decode time.
    pub cts_ms: i32,
    /// The tag body.
    pub data: Vec<u8>,
    /// Whether the window grew its reorder depth for this frame.
    pub grew: bool,
    /// How far the video's timeline jumped before this frame, in µs, when
    /// it did and the frame was re-anchored.
    pub jump: Option<i64>,
}

/// A backward step in a stream's presentation times past this is a jump, not
/// reordering. Longer for video when the deepest reorder at its frame rate is.
const JUMP_BACK_US: i64 = 1_000_000;
/// A forward step this much longer than the wall-clock time since the
/// stream's previous frame is a jump.
const JUMP_AHEAD_US: i64 = 5_000_000;

/// The pull's timestamps for both streams: decode times for video from a
/// [`DtsWindow`], both streams placed on the publish's timeline by a
/// [`Rebase`], and a stream whose timeline jumps re-anchored to carry on from
/// where the publish is, rather than held there or sent on with it.
#[derive(Debug, Default)]
pub struct Timeline {
    window: Option<DtsWindow>,
    depth: usize,
    frame_us: i64,
    rebase: Rebase,
    /// Each stream's previous presentation time, and when it arrived.
    seen: [Option<(i64, Instant)>; 2],
}

impl Timeline {
    /// The video's parameters. The first set of a session starts the decode
    /// time window, at the reorder depth the stream states or else at 0 to
    /// learn it; returns whether it did.
    pub fn video_parameters(&mut self, depth: Option<usize>, frame_us: i64) -> bool {
        if self.window.is_some() {
            return false;
        }
        self.depth = depth.unwrap_or(0).min(MAX_DEPTH);
        self.frame_us = frame_us.max(1);
        self.window = Some(DtsWindow::new(self.depth, self.frame_us));
        true
    }

    /// The tag for a video frame at `pts_us`, arriving at `now`: its decode
    /// time from the window, placed on the publish's timeline, with the
    /// composition time the presentation time leaves. Fails before the
    /// video's parameters, and when the composition time does not fit the
    /// tag, which only a source sending wild timestamps produces.
    pub fn video_tag(
        &mut self,
        codec: VideoCodec,
        key: bool,
        pts_us: i64,
        nals: &[u8],
        now: Instant,
    ) -> anyhow::Result<VideoTag> {
        let jump = self.jumped(VIDEO, pts_us, now);
        let Some(window) = self.window.as_mut() else {
            anyhow::bail!("the source sent video before its parameters");
        };
        if jump.is_some() {
            // At the depth learnt so far, which is still the stream's.
            *window = DtsWindow::new(window.depth(), self.frame_us);
        }
        let (decode_us, grew) = window.next(pts_us);
        if jump.is_some() {
            self.rebase.jump(VIDEO, decode_us, now);
        }
        let timestamp = self.rebase.place_at(VIDEO, decode_us, now);
        let cts = i64::from(self.rebase.ms(VIDEO, pts_us)) - i64::from(timestamp);
        let cts_ms = i32::try_from(cts)
            .map_err(|_| anyhow::anyhow!("composition time {cts} ms does not fit the tag"))?;
        let data = flv::video_frame(codec, key, cts_ms, nals)?;
        Ok(VideoTag {
            timestamp,
            cts_ms,
            data,
            grew,
            jump,
        })
    }

    /// The timestamp for an audio frame at `pts_us`, arriving at `now`, and
    /// how far its timeline jumped first, in µs, when it did.
    pub fn audio(&mut self, pts_us: i64, now: Instant) -> (u32, Option<i64>) {
        let jump = self.jumped(AUDIO, pts_us, now);
        if jump.is_some() {
            self.rebase.jump(AUDIO, pts_us, now);
        }
        (self.rebase.place_at(AUDIO, pts_us, now), jump)
    }

    /// The source's session ended at `at`. The next brings a timeline of its
    /// own, and fresh parameters before its first frame.
    pub fn lost(&mut self, at: Instant) {
        self.window = None;
        self.seen = [None; 2];
        self.rebase.pause(at);
    }

    /// The last timestamp placed on `stream`, or 0 before any.
    pub fn last(&self, stream: usize) -> u32 {
        self.rebase.last(stream)
    }

    /// Frames held at their stream's last timestamp so far.
    pub fn held(&self) -> u64 {
        self.rebase.held
    }

    /// The window's reorder depth.
    pub fn depth(&self) -> usize {
        self.window.as_ref().map_or(self.depth, DtsWindow::depth)
    }

    /// The step from the stream's previous frame, when it is too large to be
    /// anything but a jump in the source's timeline.
    fn jumped(&mut self, stream: usize, pts_us: i64, now: Instant) -> Option<i64> {
        let (previous, at) = self.seen[stream].replace((pts_us, now))?;
        let wall = i64::try_from(now.saturating_duration_since(at).as_micros()).unwrap_or(i64::MAX);
        let step = pts_us.saturating_sub(previous);
        // Only video reorders, so only video gets the allowance for it.
        let back = if stream == VIDEO {
            JUMP_BACK_US.max((MAX_DEPTH as i64 + 1).saturating_mul(self.frame_us))
        } else {
            JUMP_BACK_US
        };
        (step < -back || step > wall.saturating_add(JUMP_AHEAD_US)).then_some(step)
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
    /// Added to a stream's times once its timeline has jumped, so it carries
    /// on from where the publish is.
    shift: [i64; 2],
    last: [Option<u32>; 2],
    /// When a frame was last placed.
    placed_at: Option<Instant>,
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
            self.origin = Some(us.saturating_sub(i64::from(resume) * 1000));
            self.shift = [0; 2];
        }
        self.placed_at = Some(now);
        let ms = self.ms(stream, us);
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

    /// `us` on `stream` in output milliseconds, without placing a frame.
    /// Times before the origin read as 0.
    pub fn ms(&mut self, stream: usize, us: i64) -> u32 {
        let us = us.saturating_add(self.shift[stream]);
        let origin = *self.origin.get_or_insert(us);
        u32::try_from(us.saturating_sub(origin).max(0) / 1000).unwrap_or(u32::MAX)
    }

    /// `stream`'s timeline jumped, and `us` is its first time on the new one.
    /// Re-anchor the stream so that time lands after the newest timestamp on
    /// either stream by the wall-clock time since it was placed, at least
    /// 1 ms. The other stream keeps its anchor until its own timeline jumps.
    pub fn jump(&mut self, stream: usize, us: i64, now: Instant) {
        let Some(origin) = self.origin else {
            return;
        };
        let gap = self
            .placed_at
            .map_or(0, |t| now.saturating_duration_since(t).as_millis())
            .max(1);
        let target = self
            .last(0)
            .max(self.last(1))
            .saturating_add(u32::try_from(gap).unwrap_or(u32::MAX));
        self.shift[stream] = origin
            .saturating_add(i64::from(target) * 1000)
            .saturating_sub(us);
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
    use std::time::Duration;

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

    #[test]
    fn the_window_never_decodes_after_a_frame_it_has_seen() {
        // Stated at 50 fps, sent at 30: the opening placement would put the
        // B-frame's decode time after its presentation time.
        let mut w = DtsWindow::new(2, 20_000);
        let (first, _) = w.next(100_000);
        let (second, grew) = w.next(66_667);
        assert!(!grew);
        assert!(first <= second && second <= 66_667, "{first} {second}");
    }

    fn tags(t: &mut Timeline, ptss: &[i64], at: Instant) -> Vec<VideoTag> {
        ptss.iter()
            .map(|&p| {
                t.video_tag(VideoCodec::H264, false, p, &[0, 0, 0, 1, 0x41], at)
                    .unwrap()
            })
            .collect()
    }

    #[test]
    fn a_video_timeline_that_jumps_back_carries_on_from_the_last_timestamp() {
        let t0 = Instant::now();
        let mut t = Timeline::default();
        t.video_parameters(Some(0), FRAME);
        let before = tags(&mut t, &[100_000_000, 100_033_333, 100_066_667], t0);
        assert_eq!(before.last().unwrap().timestamp, 66);
        // 65 s back, 40 ms of wall clock later.
        let after = tags(
            &mut t,
            &[35_000_000, 35_033_333],
            t0 + Duration::from_millis(40),
        );
        assert_eq!(after[0].jump, Some(35_000_000 - 100_066_667));
        assert_eq!(after[0].timestamp, 66 + 40);
        assert_eq!(after[1].timestamp, 66 + 40 + 33);
        assert!(after.iter().all(|f| !f.grew && f.cts_ms == 0));
        assert_eq!((t.depth(), t.held()), (0, 0));
    }

    #[test]
    fn each_stream_re_anchors_when_its_own_timeline_jumps() {
        let t0 = Instant::now();
        let mut t = Timeline::default();
        t.video_parameters(Some(0), FRAME);
        tags(&mut t, &[0], t0);
        assert_eq!(t.audio(0, t0), (0, None));
        assert_eq!(t.audio(21_333, t0).0, 21);
        // Video jumps first; audio carries on in its old timeline.
        let jumped = tags(&mut t, &[-60_000_000], t0 + Duration::from_millis(30));
        assert_eq!(jumped[0].timestamp, 21 + 30);
        assert_eq!(t.audio(42_667, t0 + Duration::from_millis(31)), (42, None));
        // Then audio jumps, and lands after the newest timestamp.
        let (ms, jump) = t.audio(-59_990_000, t0 + Duration::from_millis(50));
        assert!(jump.is_some());
        assert_eq!(ms, 51 + 19);
    }

    #[test]
    fn a_jump_keeps_the_reorder_depth_the_window_learnt() {
        let t0 = Instant::now();
        let mut t = Timeline::default();
        t.video_parameters(None, FRAME);
        let ptss = two_b_frames();
        tags(&mut t, &ptss, t0);
        let learnt = t.depth();
        assert!(learnt > 0);
        let after: Vec<i64> = ptss.iter().map(|p| p - 60_000_000).collect();
        let tags = tags(&mut t, &after, t0 + Duration::from_millis(40));
        assert!(tags[0].jump.is_some());
        assert!(tags.iter().all(|f| !f.grew && f.cts_ms >= 0));
        assert_eq!(t.depth(), learnt);
    }

    #[test]
    fn the_gate_drops_leading_pictures_and_nothing_after_a_jump() {
        let mut g = KeyframeGate::default();
        assert_eq!(g.admit(1_000_000, false, false), Admit::Drop);
        assert!(!g.admit_audio(1_000_000));
        assert_eq!(g.admit(1_100_000, true, false), Admit::Open);
        g.open(1_100_000);
        // A leading picture, then the first trailing one.
        assert_eq!(g.admit(1_000_000, false, false), Admit::Drop);
        assert_eq!(g.admit(1_200_000, false, false), Admit::Pass);
        assert!(!g.admit_audio(1_050_000));
        assert!(g.admit_audio(1_110_000));
        // The source's timeline jumps back, with no loss: everything passes.
        assert_eq!(g.admit(5_000, false, false), Admit::Pass);
        assert!(g.admit_audio(4_000));
        // A loss waits for a keyframe, and that keyframe's leading pictures
        // are dropped in turn.
        assert_eq!(g.admit(40_000, false, true), Admit::Lost);
        assert_eq!(g.admit(50_000, true, false), Admit::Pass);
        assert_eq!(g.admit(45_000, false, false), Admit::Drop);
        assert_eq!(g.admit(60_000, false, false), Admit::Pass);
        // A loss reported on the keyframe itself: its leading pictures go too.
        assert_eq!(g.admit(70_000, true, true), Admit::Pass);
        assert_eq!(g.admit(65_000, false, false), Admit::Drop);
        assert_eq!(g.admit(80_000, false, false), Admit::Pass);
    }

    #[test]
    fn a_composition_time_the_tag_cannot_carry_is_refused() {
        // An hour between frames, arriving an hour apart, so no step is a
        // jump; three frames of reordering then put presentation three hours
        // after decode, past the tag's 24-bit field of milliseconds.
        let t0 = Instant::now();
        let hour = Duration::from_secs(3600);
        let mut t = Timeline::default();
        t.video_parameters(Some(3), FRAME);
        let refused = (0..8u32).find_map(|i| {
            t.video_tag(
                VideoCodec::H264,
                i == 0,
                i64::from(i) * 3_600_000_000,
                &[0, 0, 0, 1, 0x41],
                t0 + hour * i,
            )
            .err()
        });
        let e = refused.expect("every frame was accepted").to_string();
        assert!(e.contains("24-bit"), "{e}");
    }

    #[test]
    fn audio_jumps_back_past_a_second_whatever_the_video_frame_rate() {
        // At 1 fps the video's reorder allowance is 17 s; audio's stays 1 s.
        let t0 = Instant::now();
        let mut t = Timeline::default();
        t.video_parameters(Some(0), 1_000_000);
        tags(&mut t, &[10_000_000], t0);
        t.audio(10_000_000, t0);
        let (ms, jump) = t.audio(8_000_000, t0 + Duration::from_millis(21));
        assert_eq!(jump, Some(-2_000_000));
        assert_eq!(ms, 21);
    }

    #[test]
    fn steps_that_reordering_or_the_wall_clock_explain_are_not_jumps() {
        let t0 = Instant::now();
        let mut t = Timeline::default();
        t.video_parameters(Some(2), FRAME);
        let ptss = two_b_frames();
        let tags = tags(&mut t, &ptss, t0);
        assert!(tags.iter().all(|f| f.jump.is_none()));
        // A 4 s step after 4 s of silence is the source pausing, not a jump.
        let later = t
            .video_tag(
                VideoCodec::H264,
                true,
                ptss.iter().max().unwrap() + 4_000_000,
                &[0, 0, 0, 1, 0x65],
                t0 + Duration::from_secs(4),
            )
            .unwrap();
        assert!(later.jump.is_none());
    }
}
