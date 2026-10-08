//! The source thread's side: the RTSP session, aligning the streams on their
//! sender reports, and the keyframe gate.
//!
//! The stream choice and the SETUP and PLAY options follow the Basis media
//! player's `media-rtsp` (MIT OR Apache-2.0, Copyright (c) 2026 basis-media
//! contributors).

use std::time::Duration;

use futures::StreamExt;
use retina::client::{
    Credentials, InitialTimestampPolicy, PlayOptions, Session, SessionOptions, SetupOptions,
    Transport,
};
use retina::codec::{CodecItem, FrameFormat, ParametersRef};
use tokio::sync::mpsc;
use tokio::time::{Instant, timeout};

use super::{SourceEvent, SourceState, Spec};
use crate::codec::VideoCodec;

/// DESCRIBE, SETUP and PLAY together.
const OPEN_DEADLINE: Duration = Duration::from_secs(15);
/// Nothing of any kind from the source for this long ends the session.
const FEED_STALL: Duration = Duration::from_secs(10);
/// How long to wait for sender reports to agree before aligning on what
/// there is. VRCDN sends one every 5 s, and a session that starts stale
/// needs its third.
const ALIGN_LIMIT: Duration = Duration::from_secs(15);
/// How far two reports' anchors may differ and still agree. VRCDN's
/// consecutive reports put a stream's anchor in the same place to the
/// microsecond; a stale one is seconds out.
const AGREEMENT_US: i64 = 50_000;

const VIDEO: usize = 0;
const AUDIO: usize = 1;

type Tx = mpsc::Sender<SourceEvent>;

async fn send(tx: &Tx, event: SourceEvent) -> Result<(), String> {
    tx.send(event)
        .await
        .map_err(|_| "the relay stopped listening".to_string())
}

fn us(units: i64, clock_rate: u32) -> i64 {
    (i128::from(units) * 1_000_000 / i128::from(clock_rate.max(1))) as i64
}

/// An NTP timestamp (seconds since 1900 in the top 32 bits) in microseconds.
fn ntp_us(ntp: u64) -> i64 {
    let secs = (ntp >> 32) as i64;
    let frac = (ntp & 0xffff_ffff) as i64;
    secs * 1_000_000 + ((frac * 1_000_000) >> 32)
}

#[derive(Default)]
struct Track {
    /// Retina's stream index, when the source has this stream.
    index: Option<usize>,
    /// Server NTP time, in µs, at this stream's elapsed zero, by its latest
    /// sender report.
    last_report: Option<i64>,
    /// Where this stream's elapsed zero sits on the aligned timeline, once
    /// aligned.
    anchor: Option<i64>,
}

enum Align {
    /// Frames are discarded until every stream's reports agree.
    Waiting,
    /// Anchored on sender reports.
    Reports,
    /// No reports to go on: each stream is anchored on its frames' arrival.
    Arrival,
}

/// Why a session ended.
pub(super) enum End {
    /// Worth connecting again.
    Lost(String),
    /// The source wants a login it was not given, or refused the one it was.
    Refused(String),
}

impl From<String> for End {
    fn from(why: String) -> Self {
        Self::Lost(why)
    }
}

/// One session, from DESCRIBE until it ends. `relayed` is set once frames
/// have gone to the relay.
pub(super) async fn run(spec: &Spec, tx: &Tx, relayed: &mut bool) -> Result<(), End> {
    send(tx, SourceEvent::State(SourceState::Connecting)).await?;
    let (session, mut tracks) = timeout(OPEN_DEADLINE, open(spec, tx)).await.map_err(|_| {
        format!("the source did not answer DESCRIBE, SETUP and PLAY within {OPEN_DEADLINE:?}")
    })??;
    send(tx, SourceEvent::State(SourceState::Aligning)).await?;

    let started = Instant::now();
    let align_by = started + ALIGN_LIMIT;
    let mut align = Align::Waiting;
    let mut demuxed = session
        .demuxed()
        .map_err(|e| format!("starting the demuxer: {e}"))?;
    // Presentation time of the keyframe the publish starts on.
    let mut gate: Option<i64> = None;
    let mut audio_described = false;
    let mut awaiting_key = false;
    // Presentation time of the keyframe the video last started or resumed
    // on. A frame due to be shown before it is a leading picture of that
    // keyframe: in HEVC after a CRA, one that refers to pictures the publish
    // never had, and a decoder starting there drops it anyway.
    let mut floor: Option<i64> = None;

    loop {
        let item = match timeout(FEED_STALL, demuxed.next()).await {
            Err(_) => return Err(format!("nothing from the source for {FEED_STALL:?}").into()),
            Ok(None) => return Ok(()),
            Ok(Some(Err(e))) => return Err(format!("the source: {e}").into()),
            Ok(Some(Ok(item))) => item,
        };
        let now_us = started.elapsed().as_micros() as i64;

        if let CodecItem::Rtcp(rtcp) = &item {
            let Some(which) = tracks
                .iter()
                .position(|t| t.index == Some(rtcp.stream_id()))
            else {
                continue;
            };
            let track = &mut tracks[which];
            let Some(rtp) = rtcp.rtp_timestamp() else {
                continue;
            };
            let Some(sr) = rtcp
                .pkts()
                .find_map(|p| p.as_sender_report().ok().flatten())
            else {
                continue;
            };
            let at_zero = ntp_us(sr.ntp_timestamp().0) - us(rtp.elapsed(), rtp.clock_rate().get());
            if matches!(align, Align::Waiting)
                && let Some(prev) = track.last_report
            {
                let moved = at_zero - prev;
                if moved.abs() <= AGREEMENT_US {
                    track.anchor = Some(at_zero);
                } else {
                    track.last_report = Some(at_zero);
                    send(
                        tx,
                        SourceEvent::Note(format!(
                            "the {} sender report moved its timeline by {:+.3} s; waiting \
                             for the next to agree",
                            ["video", "audio"][which],
                            moved as f64 / 1e6
                        )),
                    )
                    .await?;
                }
            }
            tracks[which].last_report = Some(at_zero);
            if matches!(align, Align::Waiting)
                && tracks
                    .iter()
                    .all(|t| t.index.is_none() || t.anchor.is_some())
            {
                rebase_anchors(&mut tracks);
                align = Align::Reports;
                send(tx, SourceEvent::State(SourceState::WaitingForKeyframe)).await?;
            }
            continue;
        }

        if matches!(align, Align::Waiting) && Instant::now() >= align_by {
            let risk = if tracks[AUDIO].index.is_some() {
                ", so audio and video may be out of step"
            } else {
                ""
            };
            if tracks
                .iter()
                .all(|t| t.index.is_none() || t.last_report.is_some())
            {
                for t in &mut tracks {
                    t.anchor = t.last_report;
                }
                rebase_anchors(&mut tracks);
                align = Align::Reports;
                send(
                    tx,
                    SourceEvent::Note(format!(
                        "the source's sender reports did not agree within {ALIGN_LIMIT:?}; \
                         aligned on the latest{risk}"
                    )),
                )
                .await?;
            } else {
                align = Align::Arrival;
                send(
                    tx,
                    SourceEvent::Note(format!(
                        "no sender reports from the source within {ALIGN_LIMIT:?}; aligned \
                         on arrival{risk}"
                    )),
                )
                .await?;
            }
            send(tx, SourceEvent::State(SourceState::WaitingForKeyframe)).await?;
        }

        match item {
            CodecItem::VideoFrame(frame) => {
                let ts = frame.timestamp();
                let elapsed = us(ts.elapsed(), ts.clock_rate().get());
                let Some(pts) = place(&align, &mut tracks[VIDEO], elapsed, now_us) else {
                    continue;
                };
                let key = frame.is_random_access_point();
                let opening = gate.is_none();
                if frame.loss() > 0 && !key && !opening && !awaiting_key {
                    awaiting_key = true;
                    send(
                        tx,
                        SourceEvent::Note(
                            "the source skipped video; holding the picture until the next \
                             keyframe"
                                .into(),
                        ),
                    )
                    .await?;
                }
                if (opening || awaiting_key) && !key {
                    continue;
                }
                if opening || awaiting_key {
                    floor = Some(pts);
                } else if floor.is_some_and(|f| pts < f) {
                    continue;
                }
                awaiting_key = false;
                if opening || frame.has_new_parameters() {
                    let Some(event) = video_parameters(&demuxed, tracks[VIDEO].index) else {
                        continue;
                    };
                    send(tx, event).await?;
                }
                if opening {
                    gate = Some(pts);
                    if let Some(event) = audio_parameters(&demuxed, tracks[AUDIO].index) {
                        send(tx, event).await?;
                        audio_described = true;
                    }
                    send(tx, SourceEvent::State(SourceState::Relaying)).await?;
                    *relayed = true;
                }
                send(
                    tx,
                    SourceEvent::VideoFrame {
                        data: frame.into_data(),
                        pts_us: pts,
                        key,
                    },
                )
                .await?;
            }
            CodecItem::AudioFrame(frame) => {
                let ts = frame.timestamp();
                let elapsed = us(ts.elapsed(), ts.clock_rate().get());
                let Some(pts) = place(&align, &mut tracks[AUDIO], elapsed, now_us) else {
                    continue;
                };
                if gate.is_none_or(|g| pts < g) {
                    continue;
                }
                if !audio_described {
                    let Some(event) = audio_parameters(&demuxed, tracks[AUDIO].index) else {
                        continue;
                    };
                    send(tx, event).await?;
                    audio_described = true;
                }
                send(
                    tx,
                    SourceEvent::AudioFrame {
                        data: frame.data().to_vec(),
                        pts_us: pts,
                    },
                )
                .await?;
            }
            _ => {}
        }
    }
}

/// DESCRIBE, then SETUP of the H.264 or HEVC video and any AAC audio over the RTSP
/// connection, then PLAY.
async fn open(spec: &Spec, tx: &Tx) -> Result<(Session<retina::client::Playing>, [Track; 2]), End> {
    let options = SessionOptions::default()
        .user_agent(format!("truss-relay/{}", env!("CARGO_PKG_VERSION")))
        .creds(spec.login.as_ref().map(|login| Credentials {
            username: login.user.clone(),
            password: login.password.expose().to_owned(),
        }));
    let mut session = Session::describe(spec.url.clone(), options)
        .await
        .map_err(|e| failed(spec, "DESCRIBE", &e))?;

    let mut tracks: [Track; 2] = Default::default();
    let streams: Vec<(&str, &str)> = session
        .streams()
        .iter()
        .map(|s| (s.media(), s.encoding_name()))
        .collect();
    let (chosen, others) = choose_streams(&streams, spec.audio);
    tracks[VIDEO].index = chosen[VIDEO];
    tracks[AUDIO].index = chosen[AUDIO];
    if tracks[VIDEO].index.is_none() {
        return Err(End::Lost(if others.is_empty() {
            "the source has no streams".into()
        } else {
            format!(
                "the source has no H.264 or HEVC video, which records ride in. It has: {}",
                others.join(", ")
            )
        }));
    }
    if !others.is_empty() {
        send(
            tx,
            SourceEvent::Note(format!(
                "not relayed from the source: {}{}",
                others.join(", "),
                if tracks[AUDIO].index.is_none() {
                    "; the publish is video only"
                } else {
                    ""
                }
            )),
        )
        .await?;
    }

    for index in tracks.iter().filter_map(|t| t.index) {
        session
            .setup(
                index,
                SetupOptions::default()
                    .transport(Transport::Tcp(Default::default()))
                    .frame_format(FrameFormat::MP4),
            )
            .await
            .map_err(|e| {
                if e.status_code() == Some(461) {
                    End::Lost(
                        "the source refuses RTP over the RTSP connection (461 Unsupported \
                         Transport), and that is the only transport the relay speaks"
                            .into(),
                    )
                } else {
                    failed(spec, "SETUP", &e)
                }
            })?;
    }
    // Permissive: servers may leave rtptime out of RTP-Info for a stream
    // that has not seen data yet.
    let session = session
        .play(PlayOptions::default().initial_timestamp(InitialTimestampPolicy::Permissive))
        .await
        .map_err(|e| failed(spec, "PLAY", &e))?;
    Ok((session, tracks))
}

/// A request that failed. 401 is told apart from the rest: the next attempt
/// would send the same login, and could only fail the same way.
fn failed(spec: &Spec, request: &str, e: &retina::Error) -> End {
    if e.status_code() != Some(401) {
        return End::Lost(format!("{request}: {e}"));
    }
    End::Refused(match &spec.login {
        None => "the source asks for a login. Give the user with --source-user and the \
                 password with --source-password-file or TRUSS_SOURCE_PASSWORD"
            .into(),
        Some(login) => format!(
            "the source refused the login for user {:?} at {request}. Not trying again, so \
             a camera that counts failed logins does not lock the account",
            login.user
        ),
    })
}

/// The first H.264 or HEVC video and, when `audio`, the first AAC audio, by index,
/// and the streams that will not be relayed. Audio left out by choice is not
/// listed with them.
fn choose_streams(streams: &[(&str, &str)], audio: bool) -> ([Option<usize>; 2], Vec<String>) {
    let mut chosen = [None; 2];
    let mut others = Vec::new();
    for (index, &(media, encoding)) in streams.iter().enumerate() {
        match (media, encoding) {
            ("video", "h264" | "h265") if chosen[VIDEO].is_none() => chosen[VIDEO] = Some(index),
            ("audio", _) if !audio => {}
            ("audio", "mpeg4-generic") if chosen[AUDIO].is_none() => chosen[AUDIO] = Some(index),
            _ => others.push(format!("{media} {encoding}")),
        }
    }
    (chosen, others)
}

/// Shift the anchors so the earliest sits at 0, keeping numbers small.
fn rebase_anchors(tracks: &mut [Track; 2]) {
    let Some(base) = tracks.iter().filter_map(|t| t.anchor).min() else {
        return;
    };
    for t in tracks.iter_mut() {
        if let Some(a) = t.anchor.as_mut() {
            *a -= base;
        }
    }
}

/// A frame's presentation time on the aligned timeline, or `None` while the
/// streams are not yet aligned.
fn place(align: &Align, track: &mut Track, elapsed: i64, now_us: i64) -> Option<i64> {
    match align {
        Align::Waiting => None,
        Align::Reports => track.anchor.map(|a| a + elapsed),
        Align::Arrival => Some(*track.anchor.get_or_insert(now_us - elapsed) + elapsed),
    }
}

fn video_parameters(
    demuxed: &retina::client::Demuxed,
    index: Option<usize>,
) -> Option<SourceEvent> {
    let stream = &demuxed.streams()[index?];
    let ParametersRef::Video(v) = stream.parameters()? else {
        return None;
    };
    let codec = match stream.encoding_name() {
        "h265" => VideoCodec::Hevc,
        _ => VideoCodec::H264,
    };
    let (width, height) = v.pixel_dimensions();
    let fps = v
        .frame_rate()
        .filter(|&(num, den)| num > 0 && den > 0)
        .map(|(num, den)| f64::from(den) / f64::from(num));
    Some(SourceEvent::Video {
        codec,
        config: v.extra_data().to_vec(),
        width,
        height,
        fps,
    })
}

fn audio_parameters(
    demuxed: &retina::client::Demuxed,
    index: Option<usize>,
) -> Option<SourceEvent> {
    let ParametersRef::Audio(a) = demuxed.streams()[index?].parameters()? else {
        return None;
    };
    Some(SourceEvent::Audio {
        asc: a.extra_data().to_vec(),
        sample_rate: a.clock_rate(),
        channels: a.channels().get(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_video_and_aac_are_chosen_and_the_rest_named() {
        let streams = [
            ("audio", "pcmu"),
            ("video", "h264"),
            ("audio", "mpeg4-generic"),
            ("video", "h265"),
            ("application", "onvif.metadata"),
        ];
        let (chosen, others) = choose_streams(&streams, true);
        assert_eq!(chosen, [Some(1), Some(2)]);
        assert_eq!(
            others,
            ["audio pcmu", "video h265", "application onvif.metadata"]
        );
        let (chosen, _) = choose_streams(&[("video", "h265"), ("video", "h264")], true);
        assert_eq!(chosen, [Some(0), None]);
    }

    #[test]
    fn dropped_audio_is_neither_chosen_nor_reported() {
        let streams = [
            ("video", "h264"),
            ("audio", "mpeg4-generic"),
            ("audio", "pcmu"),
        ];
        let (chosen, others) = choose_streams(&streams, false);
        assert_eq!(chosen, [Some(0), None]);
        assert!(others.is_empty(), "{others:?}");
    }

    #[test]
    fn an_ntp_timestamp_reads_as_microseconds() {
        assert_eq!(ntp_us(1 << 32), 1_000_000);
        assert_eq!(ntp_us((2 << 32) | (1 << 31)), 2_500_000);
    }

    #[test]
    fn anchors_are_shifted_so_the_earliest_is_zero() {
        let mut tracks: [Track; 2] = Default::default();
        tracks[VIDEO].anchor = Some(4_000_000_000_015_000);
        tracks[AUDIO].anchor = Some(4_000_000_000_000_000);
        rebase_anchors(&mut tracks);
        assert_eq!(tracks[VIDEO].anchor, Some(15_000));
        assert_eq!(tracks[AUDIO].anchor, Some(0));
    }

    #[test]
    fn nothing_is_placed_until_aligned() {
        let mut track = Track {
            anchor: Some(100),
            ..Default::default()
        };
        assert_eq!(place(&Align::Waiting, &mut track, 5, 0), None);
        assert_eq!(place(&Align::Reports, &mut track, 5, 0), Some(105));
        let mut fresh = Track::default();
        assert_eq!(place(&Align::Arrival, &mut fresh, 40, 1_000), Some(1_000));
        assert_eq!(place(&Align::Arrival, &mut fresh, 80, 9_999), Some(1_040));
    }
}
