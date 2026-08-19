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
use clap::{Parser, Subcommand};
use truss::carrier::Carrier;
use truss::detect::ts::TsAnalyzer;
use truss::h264;
use truss::monitor::DmxState;
use truss::record::Record;
use truss::source::{self, Freshness, Input};

#[derive(Parser)]
#[command(
    name = "truss-dmxmon",
    about = "Watch the DMX arriving in a live stream"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Read an MPEG-TS stream: a URL, a file, or "-" for stdin.
    Ts {
        input: String,
        #[command(flatten)]
        common: Common,
    },
    /// Read the RTSP egress, using ffmpeg as the transport.
    ///
    /// Note that RTSP delivers video only when nothing else from this machine is
    /// already reading the stream, so close other readers first or this will see
    /// audio and no data.
    Rtsp {
        url: String,
        #[arg(long, default_value = "tcp")]
        transport: String,
        #[command(flatten)]
        common: Common,
    },
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
    let (input, common) = match cli.cmd {
        Cmd::Ts { input, common } => (Input::Ts(input), common),
        Cmd::Rtsp {
            url,
            transport,
            common,
        } => (Input::Rtsp { url, transport }, common),
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
    let mut state = DmxState::default();
    let mut buf = vec![0u8; 64 * 1024];

    let started = Instant::now();
    let mut last_report = Instant::now();
    let interval = Duration::from_secs_f64(common.interval.max(0.1));
    // Records and changes since the last status line, so the rates describe now
    // rather than the average since the tool started.
    let mut window = Window::default();
    let mut totals = Window::default();
    let mut watched: BTreeMap<(u16, u16), u8> = BTreeMap::new();
    let mut malformed = 0u64;
    let mut out_of_range = 0u64;

    println!("reading {}...", describe(&input));

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
                match truss::payload::decode(&payload) {
                    Ok(blocks) => {
                        let applied = state.apply(&blocks);
                        window.records += 1;
                        window.changed += applied.changed as u64;
                        totals.records += 1;
                        totals.changed += applied.changed as u64;
                        out_of_range += applied.out_of_range as u64;
                        report_watches(&state, &watches, &mut watched);
                    }
                    Err(_) => malformed += 1,
                }
            }
        }

        if live && last_report.elapsed() >= interval {
            let secs = last_report.elapsed().as_secs_f64();
            print_status(&state, &window, secs, live, malformed, out_of_range);
            if let Some(u) = common.universe {
                print_universe(&state, u);
            }
            window = Window::default();
            last_report = Instant::now();
        }
    }

    println!(
        "\nstream ended after {:.1}s",
        started.elapsed().as_secs_f64()
    );
    print_status(
        &state,
        &totals,
        started.elapsed().as_secs_f64(),
        live,
        malformed,
        out_of_range,
    );
    if let Some(u) = common.universe {
        print_universe(&state, u);
    }
    Ok(())
}

#[derive(Default)]
struct Window {
    records: u64,
    changed: u64,
}

fn describe(input: &Input) -> String {
    match input {
        Input::Ts(t) => t.clone(),
        Input::Rtsp { url, .. } => url.clone(),
        Input::Rtmp { url } => url.clone(),
    }
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
