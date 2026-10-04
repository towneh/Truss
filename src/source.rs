//! Opening an egress path, for whichever tool wants to read it.
//!
//! The three transports are not equally trustworthy at every layer. MPEG-TS is
//! read directly, so its PID table and continuity counters are the origin's own.
//! RTSP and RTMP go through ffmpeg, which re-muxes on the way in, so for those
//! only the bitstream says anything about the origin. A reader that does not know
//! which it has cannot report honestly, so that distinction travels with the
//! source rather than being remembered by the caller.

use std::io::Read;
use std::net::{IpAddr, SocketAddr};
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

/// Where a tool reads from, in one spelling: the scheme picks the reader.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    Stream(Input),
    /// The relay's OSC lane, as the address to listen on.
    Osc(SocketAddr),
}

impl Target {
    /// `rtsp://` and `rtmp://` go through ffmpeg; `http://`, `https://`, a
    /// file path or `-` for stdin are MPEG-TS read directly; and
    /// `osc://[address][:port]` listens for the lane, every adapter on port
    /// 12100 unless given. `transport` is the RTSP lower transport and means
    /// nothing to the others.
    pub fn parse(spec: &str, transport: &str) -> Result<Self> {
        // A path is taken exactly as given, spaces and all; only a URL is
        // trimmed, where a stray space can be nothing but a typing slip.
        let Some((scheme, rest)) = spec.trim().split_once("://") else {
            if spec.trim().eq_ignore_ascii_case("osc") {
                bail!(
                    "the lane is osc://[address][:port]; osc:// alone listens on every adapter, port {}",
                    crate::osc::DEFAULT_PORT
                );
            }
            return Ok(Self::Stream(Input::Ts(spec.to_string())));
        };
        // Schemes are case-insensitive, ffmpeg's protocol lookup is not.
        let scheme = scheme.to_ascii_lowercase();
        let spec = format!("{scheme}://{rest}");
        Ok(match scheme.as_str() {
            "rtsp" => Self::Stream(Input::Rtsp {
                url: spec,
                transport: transport.to_string(),
            }),
            "rtmp" | "rtmps" => Self::Stream(Input::Rtmp { url: spec }),
            "http" | "https" => Self::Stream(Input::Ts(spec)),
            "osc" => Self::Osc(listen_address(
                rest.trim_end_matches('/'),
                crate::osc::DEFAULT_PORT,
            )?),
            other => bail!(
                "{other}:// is not a source this reads. Give rtsp:// or rtmp:// for an egress, \
                 http:// or https:// for MPEG-TS, a file path or - for stdin, or \
                 osc://[address][:port] for the relay's lane"
            ),
        })
    }

    /// The URL or path as given, for a status line.
    pub fn describe(&self) -> String {
        match self {
            Self::Stream(input) => input.describe().to_string(),
            Self::Osc(addr) => format!("osc://{addr}"),
        }
    }
}

/// Where to listen, from an address, an `address:port`, a bare `:port`, or a
/// bracketed IPv6 address with or without a port. Every adapter and
/// `default_port` fill in whatever is left out.
pub fn listen_address(spec: &str, default_port: u16) -> Result<SocketAddr> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Ok(SocketAddr::from(([0, 0, 0, 0], default_port)));
    }
    // A bare `:port`; an IPv6 address such as `::1` also starts with a colon
    // and is not one.
    if let Some(port) = spec.strip_prefix(':')
        && !port.is_empty()
        && port.bytes().all(|b| b.is_ascii_digit())
    {
        let port: u16 = port
            .parse()
            .ok()
            .filter(|&p| p != 0)
            .ok_or_else(|| anyhow::anyhow!("{port:?} is not a port number"))?;
        return Ok(SocketAddr::from(([0, 0, 0, 0], port)));
    }
    if let Ok(addr) = spec.parse::<SocketAddr>() {
        if addr.port() == 0 {
            bail!("{spec:?} has port 0, which nothing could be sent to");
        }
        return Ok(addr);
    }
    if let Ok(ip) = spec.trim_matches(['[', ']']).parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, default_port));
    }
    bail!(
        "{spec:?} is not an address to listen on; give an IP address, with :port after it \
         when it is not {default_port}, or :port alone for every adapter"
    )
}

/// What to read.
#[derive(Clone, Debug, PartialEq, Eq)]
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

impl Input {
    /// The URL or path as given, for a status line.
    pub fn describe(&self) -> &str {
        match self {
            Self::Ts(t) => t,
            Self::Rtsp { url, .. } | Self::Rtmp { url } => url,
        }
    }
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
    fn the_scheme_picks_the_reader() {
        let stream = |i: Input| Target::Stream(i);
        assert_eq!(
            Target::parse("rtsp://egress/live/x", "udp").unwrap(),
            stream(Input::Rtsp {
                url: "rtsp://egress/live/x".into(),
                transport: "udp".into()
            })
        );
        assert_eq!(
            Target::parse("RTMP://egress/live/x", "tcp").unwrap(),
            stream(Input::Rtmp {
                url: "rtmp://egress/live/x".into()
            }),
            "the scheme is normalised for ffmpeg"
        );
        assert_eq!(
            Target::parse("https://host/live.ts", "tcp").unwrap(),
            stream(Input::Ts("https://host/live.ts".into()))
        );
        assert_eq!(
            Target::parse("capture.ts", "tcp").unwrap(),
            stream(Input::Ts("capture.ts".into()))
        );
        assert_eq!(
            Target::parse("-", "tcp").unwrap(),
            stream(Input::Ts("-".into()))
        );
        assert_eq!(
            Target::parse(" odd name.ts ", "tcp").unwrap(),
            stream(Input::Ts(" odd name.ts ".into())),
            "a path is taken as given"
        );
        assert_eq!(
            Target::parse("osc://", "tcp").unwrap(),
            Target::Osc("0.0.0.0:12100".parse().unwrap())
        );
        assert_eq!(
            Target::parse("osc://:12200", "tcp").unwrap(),
            Target::Osc("0.0.0.0:12200".parse().unwrap())
        );
        assert_eq!(
            Target::parse("osc://127.0.0.1", "tcp").unwrap(),
            Target::Osc("127.0.0.1:12100".parse().unwrap())
        );
        assert_eq!(
            Target::parse("osc://[::1]:12101/", "tcp").unwrap(),
            Target::Osc("[::1]:12101".parse().unwrap())
        );
        let e = Target::parse("ftp://host/x", "tcp")
            .unwrap_err()
            .to_string();
        assert!(e.contains("not a source this reads"), "{e}");
        let e = Target::parse("osc", "tcp").unwrap_err().to_string();
        assert!(e.contains("osc://"), "{e}");
        assert!(Target::parse("osc://desk", "tcp").is_err());
        assert!(Target::parse("osc://:0", "tcp").is_err());
        assert!(Target::parse("osc://127.0.0.1:0", "tcp").is_err());
    }

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
