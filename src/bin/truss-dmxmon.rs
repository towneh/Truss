//! Watch the DMX arriving in a live stream.
//!
//! `vcp-detect` answers whether the lane survived; this answers what is coming
//! down it right now. At a venue that is the question actually being asked when
//! someone says the lights look wrong, and the two answers are different: a
//! stream can deliver every record intact while the desk sends nothing.
//!
//! It is also the reference decode. A player consuming this lane does what the
//! `monitor` module does here — hold the newest value per channel, apply blocks
//! as they arrive, notice when a universe stops updating — so anything that
//! disagrees with this tool disagrees with something that has been measured.

use std::collections::BTreeMap;
use std::io::Read;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::Parser;
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use truss::carrier::Carrier;
use truss::detect::ts::TsAnalyzer;
use truss::h264;
use truss::monitor::DmxState;
use truss::record::Record;
use truss::source::{self, Freshness, Target};

#[derive(Parser)]
#[command(
    name = "truss-dmxmon",
    about = "Watch the DMX arriving in a live stream"
)]
struct Cli {
    /// What to read. rtsp:// and rtmp:// go through ffmpeg; http://, https://,
    /// a file path or - for stdin are MPEG-TS read directly; and
    /// osc://[address][:port] listens for the relay's lane, every adapter on
    /// port 12100 unless given.
    ///
    /// RTSP delivers video only when nothing else from this machine is already
    /// reading the stream, so close other readers first or this sees audio and
    /// no data.
    source: String,
    /// RTSP lower transport, for an rtsp:// source.
    #[arg(long, default_value = "tcp")]
    transport: String,
    #[command(flatten)]
    common: Common,
}

#[derive(clap::Args, Clone)]
struct Common {
    /// Stop after this many seconds.
    #[arg(long)]
    max_seconds: Option<u64>,
    /// Seconds between status lines.
    #[arg(long, default_value_t = 1.0)]
    interval: f64,
    /// Print these channels whenever they change, as universe.slot or
    /// universe.first-last, comma separated. Slots are 1-based, as on a desk.
    #[arg(long)]
    watch: Option<String>,
    /// Print this universe's values as a grid on every status line.
    #[arg(long)]
    universe: Option<u16>,
}

/// A channel range a desk operator would recognise: universe, first and last
/// slot, counting slots from 1.
#[derive(Clone, Copy, Debug)]
struct Watch {
    universe: u16,
    first: u16,
    last: u16,
}

/// Accepts `1.5`, `1.5-9` and `1.5-1.9`. The last is redundant but it is what
/// anyone writing a range naturally types, and rejecting it teaches nothing.
fn parse_watch(spec: &str) -> Result<Vec<Watch>> {
    const FORM: &str =
        "expected universe.slot, universe.first-last, or universe.first-universe.last";
    let mut out = Vec::new();
    for part in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let (head, tail) = part
            .split_once('-')
            .map_or((part, None), |(a, b)| (a, Some(b)));

        let (u, first) = split_addr(head, part, FORM)?;
        let last = match tail {
            None => first,
            Some(t) if t.contains('.') => {
                let (u2, last) = split_addr(t, part, FORM)?;
                if u2 != u {
                    anyhow::bail!("{part:?}: a range cannot span universes ({u} then {u2})");
                }
                last
            }
            Some(t) => t
                .trim()
                .parse()
                .with_context(|| format!("{part:?}: bad slot. {FORM}"))?,
        };

        if first == 0 || last < first {
            anyhow::bail!("{part:?}: slots count from 1 and must be in order");
        }
        out.push(Watch {
            universe: u,
            first,
            last,
        });
    }
    Ok(out)
}

fn split_addr(addr: &str, part: &str, form: &str) -> Result<(u16, u16)> {
    let (u, slot) = addr
        .trim()
        .split_once('.')
        .with_context(|| format!("{part:?}: {form}"))?;
    Ok((
        u.trim()
            .parse()
            .with_context(|| format!("{part:?}: bad universe. {form}"))?,
        slot.trim()
            .parse()
            .with_context(|| format!("{part:?}: bad slot. {form}"))?,
    ))
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let common = cli.common;
    let input = match Target::parse(&cli.source, &cli.transport)? {
        Target::Osc(listen) => return watch_osc(listen, &common),
        Target::Stream(input) => input,
    };
    let watches = common
        .watch
        .as_deref()
        .map(parse_watch)
        .transpose()?
        .unwrap_or_default();

    let mut src = source::open(&input)?;
    // A file is read as fast as the disk allows, so a per-second rate would
    // describe this machine rather than the stream. Totals are the honest
    // figure there, the same way latency is reported as offline rather than as
    // the age of the file.
    let live = src.freshness == Freshness::Live;
    let mut ts = TsAnalyzer::new();
    let mut tally = Tally::new(watches);
    let mut buf = vec![0u8; 64 * 1024];

    let started = Instant::now();
    let mut last_report = Instant::now();
    let interval = Duration::from_secs_f64(common.interval.max(0.1));

    println!("reading {}...", input.describe());

    loop {
        if let Some(secs) = common.max_seconds
            && started.elapsed().as_secs() >= secs
        {
            break;
        }
        let n = src.reader.read(&mut buf).context("reading input")?;
        if n == 0 {
            break;
        }
        for unit in ts.feed(&buf[..n]) {
            let is_video = ts
                .streams
                .get(&unit.pid)
                .is_some_and(|s| matches!(s.stream_type, 0x1B | 0x24));
            if !is_video {
                continue;
            }
            for payload in records_in(&unit.data) {
                tally.absorb(&payload);
            }
        }

        if live && last_report.elapsed() >= interval {
            tally.status(last_report.elapsed().as_secs_f64(), live, common.universe);
            last_report = Instant::now();
        }
    }

    println!(
        "\nstream ended after {:.1}s",
        started.elapsed().as_secs_f64()
    );
    tally.finish(started.elapsed().as_secs_f64(), live, common.universe);
    Ok(())
}

/// Watch the relay's OSC lane instead of a stream: the same records, sent
/// to a socket as they are built, so a desk can be watched with no encoder,
/// ingest or player running.
fn watch_osc(listen: SocketAddr, common: &Common) -> Result<()> {
    let watches = common
        .watch
        .as_deref()
        .map(parse_watch)
        .transpose()?
        .unwrap_or_default();
    let socket = UdpSocket::bind(listen).with_context(|| format!("binding {listen}"))?;
    socket.set_read_timeout(Some(Duration::from_millis(200)))?;
    let mut tally = Tally::new(watches);
    let mut buf = vec![0u8; 64 * 1024];
    let mut not_ours = 0u64;

    let started = Instant::now();
    let mut last_report = Instant::now();
    let interval = Duration::from_secs_f64(common.interval.max(0.1));

    println!(
        "listening on {} for {}...",
        socket.local_addr()?,
        truss::osc::ADDRESS
    );

    loop {
        if let Some(secs) = common.max_seconds
            && started.elapsed().as_secs() >= secs
        {
            break;
        }
        match socket.recv_from(&mut buf) {
            Ok((n, _)) => match truss::osc::decode_blob(&buf[..n]) {
                Some((address, blob)) if address == truss::osc::ADDRESS => {
                    match Record::decode(blob) {
                        Ok(record) => tally.absorb(&record.payload),
                        Err(_) => tally.malformed += 1,
                    }
                }
                _ => not_ours += 1,
            },
            Err(ref e)
                if matches!(
                    e.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::ConnectionReset
                ) => {}
            Err(e) => return Err(e).context("reading the OSC socket"),
        }

        if last_report.elapsed() >= interval {
            tally.status(last_report.elapsed().as_secs_f64(), true, common.universe);
            if not_ours > 0 {
                println!(
                    "  [{not_ours} datagrams that were not {}]",
                    truss::osc::ADDRESS
                );
            }
            last_report = Instant::now();
        }
    }

    println!("\nstopped after {:.1}s", started.elapsed().as_secs_f64());
    tally.finish(started.elapsed().as_secs_f64(), true, common.universe);
    Ok(())
}

/// The DMX state and the counts around it, fed one record payload at a time.
struct Tally {
    state: DmxState,
    /// Records and changes since the last status line, so the rates describe
    /// now rather than the average since the tool started.
    window: Window,
    totals: Window,
    watches: Vec<Watch>,
    watched: BTreeMap<(u16, u16), u8>,
    malformed: u64,
    out_of_range: u64,
}

impl Tally {
    fn new(watches: Vec<Watch>) -> Self {
        Self {
            state: DmxState::default(),
            window: Window::default(),
            totals: Window::default(),
            watches,
            watched: BTreeMap::new(),
            malformed: 0,
            out_of_range: 0,
        }
    }

    fn absorb(&mut self, payload: &[u8]) {
        match truss::payload::decode(payload) {
            Ok(blocks) => {
                let applied = self.state.apply(&blocks);
                self.window.records += 1;
                self.window.changed += applied.changed as u64;
                self.totals.records += 1;
                self.totals.changed += applied.changed as u64;
                self.out_of_range += applied.out_of_range as u64;
                report_watches(&self.state, &self.watches, &mut self.watched);
            }
            Err(_) => self.malformed += 1,
        }
    }

    fn status(&mut self, secs: f64, live: bool, universe: Option<u16>) {
        print_status(
            &self.state,
            &self.window,
            secs,
            live,
            self.malformed,
            self.out_of_range,
        );
        if let Some(u) = universe {
            print_universe(&self.state, u);
        }
        self.window = Window::default();
    }

    fn finish(&self, secs: f64, live: bool, universe: Option<u16>) {
        print_status(
            &self.state,
            &self.totals,
            secs,
            live,
            self.malformed,
            self.out_of_range,
        );
        if let Some(u) = universe {
            print_universe(&self.state, u);
        }
    }
}

#[derive(Default)]
struct Window {
    records: u64,
    changed: u64,
}

/// Every record body in one access unit, from whichever carrier framed it.
///
/// Only the SEI carriers are looked at: they are the ones a real stream uses,
/// and the filler carrier exists for measurement rather than for carrying a
/// show. A record arriving on more than one carrier is applied more than once,
/// which is harmless because the values are absolute.
fn records_in(annexb: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    h264::scan_sei_annexb(annexb, |ty, payload| {
        let carrier = match ty {
            h264::SEI_UNREGISTERED => Carrier::SeiUnregistered,
            h264::SEI_T35 => Carrier::SeiT35,
            _ => return,
        };
        if let Some(body) = carrier.unframe_sei(payload)
            && let Ok(record) = Record::decode(body)
        {
            out.push(record.payload);
        }
    });
    out
}

fn print_status(
    state: &DmxState,
    window: &Window,
    secs: f64,
    live: bool,
    malformed: u64,
    out_of_range: u64,
) {
    let ages: Vec<u32> = state.universes().map(|(_, u)| u.last_age_us).collect();
    let age = ages.iter().copied().max().unwrap_or(0) as f64 / 1000.0;

    let counts = if live && secs > 0.0 {
        format!(
            "{:>5.1} rec/s  {:>8.0} ch/s changed",
            window.records as f64 / secs,
            window.changed as f64 / secs
        )
    } else {
        format!(
            "{:>6} records  {:>9} changes",
            window.records, window.changed
        )
    };

    let mut line = format!(
        "{counts}  {:>3} universes  {:>5} channels  age {:>5.1} ms",
        state.universe_count(),
        state.channel_count(),
        age
    );
    if malformed > 0 {
        line.push_str(&format!("  [{malformed} malformed]"));
    }
    if out_of_range > 0 {
        line.push_str(&format!(
            "  [{out_of_range} slots past the end of a universe]"
        ));
    }
    // No records this window is worth saying out loud: the stream is arriving
    // and carrying nothing, which is a desk problem rather than a CDN one.
    if window.records == 0 {
        line.push_str("  <- no records this interval");
    }
    println!("{line}");
}

fn print_universe(state: &DmxState, universe: u16) {
    let Some(u) = state.universe(universe) else {
        println!("  universe {universe}: not seen");
        return;
    };
    println!(
        "  universe {universe}, {} channels, age {:.1} ms",
        u.len,
        f64::from(u.last_age_us) / 1000.0
    );
    for row in 0..u.len.div_ceil(16) {
        let start = row * 16;
        let end = (start + 16).min(u.len);
        let cells: Vec<String> = u.values[start..end]
            .iter()
            .map(|v| format!("{v:>3}"))
            .collect();
        println!("   {:>4}: {}", start + 1, cells.join(" "));
    }
}

fn report_watches(state: &DmxState, watches: &[Watch], last: &mut BTreeMap<(u16, u16), u8>) {
    for w in watches {
        for slot in w.first..=w.last {
            // Slots are 1-based on a desk and 0-based in the payload.
            let Some(v) = state.value(w.universe, slot - 1) else {
                continue;
            };
            let key = (w.universe, slot);
            if last.insert(key, v) != Some(v) {
                println!("  {}.{} = {}", w.universe, slot, v);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(spec: &str) -> Vec<(u16, u16, u16)> {
        parse_watch(spec)
            .expect("parses")
            .into_iter()
            .map(|w| (w.universe, w.first, w.last))
            .collect()
    }

    #[test]
    fn a_range_can_be_written_either_way() {
        assert_eq!(parsed("1.5"), vec![(1, 5, 5)]);
        assert_eq!(parsed("1.5-9"), vec![(1, 5, 9)]);
        assert_eq!(
            parsed("1.5-1.9"),
            vec![(1, 5, 9)],
            "the redundant form is the natural one"
        );
        assert_eq!(parsed("0.1-4, 3.1"), vec![(0, 1, 4), (3, 1, 1)]);
    }

    #[test]
    fn nonsense_is_refused_with_the_form_in_the_message() {
        for bad in ["1", "1.0", "1.9-5", "1.5-2.9", "x.1", "1.x"] {
            let err = parse_watch(bad).expect_err(bad).to_string();
            assert!(!err.is_empty(), "{bad} should explain itself");
        }
    }
}
