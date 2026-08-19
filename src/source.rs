//! Opening an egress path, for whichever tool wants to read it.
//!
//! The three transports are not equally trustworthy at every layer. MPEG-TS is
//! read directly, so its PID table and continuity counters are the origin's own.
//! RTSP and RTMP go through ffmpeg, which re-muxes on the way in, so for those
//! only the bitstream says anything about the origin. A reader that does not know
//! which it has cannot report honestly, so that distinction travels with the
//! source rather than being remembered by the caller.

use std::io::Read;
use std::process::{Child, Command, Stdio};

use anyhow::{Context, Result, bail};

/// Whether bytes are arriving now or were captured earlier.
///
/// Latency is the difference between a record's send time and the moment it is
/// read, so it only means anything on a live source. A saved capture would
/// report the age of the file, which looks like a plausible latency figure and
/// is not one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Freshness {
    Live,
    Offline,
}

/// Where the transport statistics come from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Transport {
    /// the origin's own container, so its transport numbers mean something.
    Direct,
    /// ffmpeg re-muxed on the way in; only the bitstream is the origin's.
    ViaFfmpeg,
}

/// What to read.
#[derive(Clone, Debug)]
pub enum Input {
    /// A URL, a file, or "-" for stdin.
    Ts(String),
    Rtsp {
        url: String,
        transport: String,
    },
    Rtmp {
        url: String,
    },
}

/// An open egress, plus what is knowable about it.
///
/// Holds the ffmpeg child when there is one, so a caller cannot forget to reap
/// it and leave a process reading the stream. That matters more than tidiness
/// here: an ffmpeg left attached counts as a reader, and a reader that stays
/// attached takes RTSP video away from the next session on this address.
pub struct Source {
    pub reader: Box<dyn Read>,
    pub freshness: Freshness,
    pub transport: Transport,
    child: Option<Child>,
}

impl Drop for Source {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

pub fn open(input: &Input) -> Result<Source> {
    match input {
        Input::Ts(target) => Ok(Source {
            freshness: freshness_of(target),
            transport: Transport::Direct,
            reader: open_ts(target)?,
            child: None,
        }),
        Input::Rtsp { url, transport } => via_ffmpeg(&[
            "-rtsp_transport",
            transport,
            "-i",
            url,
            "-c",
            "copy",
            "-f",
            "mpegts",
            "-",
        ]),
        Input::Rtmp { url } => via_ffmpeg(&["-i", url, "-c", "copy", "-f", "mpegts", "-"]),
    }
}

fn freshness_of(target: &str) -> Freshness {
    if target == "-" || target.starts_with("http://") || target.starts_with("https://") {
        Freshness::Live
    } else {
        Freshness::Offline
    }
}

fn open_ts(target: &str) -> Result<Box<dyn Read>> {
    if target == "-" {
        return Ok(Box::new(std::io::stdin().lock()));
    }
    if target.starts_with("http://") || target.starts_with("https://") {
        // Fetched here rather than through a curl pipe so the receive
        // timestamps stay live, which is what makes latency mean anything.
        let resp = ureq::get(target)
            .call()
            .with_context(|| format!("GET {target}"))?;
        let status = resp.status();
        if status != 200 {
            bail!(
                "{target} returned HTTP {status} (some origins answer 401 while the stream is offline)"
            );
        }
        return Ok(Box::new(resp.into_body().into_reader()));
    }
    Ok(Box::new(
        std::fs::File::open(target).with_context(|| format!("opening {target}"))?,
    ))
}

fn via_ffmpeg(args: &[&str]) -> Result<Source> {
    let mut cmd = Command::new("ffmpeg");
    cmd.args(["-v", "error"])
        .args(args)
        .stdout(Stdio::piped())
        // Let ffmpeg's errors through. Discarding them turns "ffmpeg refused to
        // open the stream" into an empty report identical to "nothing survived",
        // which is the one confusion these tools exist to prevent.
        .stderr(Stdio::inherit());
    let mut child = cmd.spawn().context("spawning ffmpeg (is it on PATH?)")?;
    let reader = child.stdout.take().expect("stdout piped");
    Ok(Source {
        reader: Box::new(reader),
        freshness: Freshness::Live,
        transport: Transport::ViaFfmpeg,
        child: Some(child),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_is_offline_and_a_url_is_not() {
        assert_eq!(freshness_of("capture.ts"), Freshness::Offline);
        assert_eq!(freshness_of("-"), Freshness::Live);
        assert_eq!(
            freshness_of("https://stream.example/live.ts"),
            Freshness::Live
        );
    }
}
