//! Read one of your egress paths and report what crossed the network.
//!
//! Three transports, and they are not equally trustworthy at every layer.
//! The MPEG-TS egress is read directly, so its PID table, continuity counters
//! and stream types are the origin's own. RTSP and RTMP are read through ffmpeg,
//! which re-muxes into MPEG-TS on the way in — so for those the transport
//! numbers describe ffmpeg's muxer and only the bitstream analysis says
//! anything about the origin. The tool labels which it is rather than leaving the
//! reader to work it out.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use truss::detect::scan::{ScanReport, Scanner};
use truss::detect::ts::{PesUnit, TsAnalyzer};
use truss::source::{self, Freshness, Input, Source, Transport};

#[derive(Parser)]
#[command(
    name = "truss-detect",
    about = "Score what survived a round trip through your own CDN"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args, Clone)]
struct Common {
    /// Stop after this many seconds of reading.
    #[arg(long)]
    max_seconds: Option<u64>,
    /// Stop after this many megabytes.
    #[arg(long)]
    max_mb: Option<u64>,
    /// Write the full report as JSON here.
    #[arg(long)]
    json: Option<PathBuf>,
    /// Also write the bytes read to this file, for later re-analysis.
    #[arg(long)]
    save: Option<PathBuf>,
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
    Rtsp {
        url: String,
        /// RTSP lower transport.
        #[arg(long, default_value = "tcp")]
        transport: String,
        #[command(flatten)]
        common: Common,
    },
    /// Read the RTMP egress, using ffmpeg as the transport.
    ///
    /// This sees the video bitstream, so it covers the in-video carriers. It
    /// does not see custom AMF data messages: ffmpeg discards script data it
    /// does not recognise, so the `amf-custom` carrier needs a native RTMP
    /// client. `amf-onmeta` is checked separately via ffprobe's format tags.
    Rtmp {
        url: String,
        #[command(flatten)]
        common: Common,
    },
}

fn now_unix_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Ts { input, common } => {
            let mut src = source::open(&Input::Ts(input))?;
            let out = analyse(&mut src, &common)?;
            finish(&out, &common, None)
        }
        Cmd::Rtsp {
            url,
            transport,
            common,
        } => {
            let mut src = source::open(&Input::Rtsp { url, transport })?;
            let out = analyse(&mut src, &common)?;
            finish(&out, &common, None)
        }
        Cmd::Rtmp { url, common } => {
            let amf = probe_onmetadata(&url);
            let mut src = source::open(&Input::Rtmp { url })?;
            let out = analyse(&mut src, &common)?;
            finish(&out, &common, Some(amf))
        }
    }
}

struct Outcome {
    ts: TsAnalyzer,
    report: ScanReport,
    elapsed: f64,
    transport: Transport,
    freshness: Freshness,
}

/// Ask ffprobe for the container tags. The `amf-onmeta` carrier rides as an
/// extra key inside `onMetaData`, and ffmpeg surfaces those as format tags, so
/// this covers that carrier without a native RTMP client.
fn probe_onmetadata(url: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let Ok(res) = Command::new("ffprobe")
        .args([
            "-v",
            "error",
            "-show_format",
            "-of",
            "default=noprint_wrappers=1",
            url,
        ])
        .stderr(Stdio::null())
        .output()
    else {
        return out;
    };
    for line in String::from_utf8_lossy(&res.stdout).lines() {
        if let Some(rest) = line.strip_prefix("TAG:")
            && let Some((k, v)) = rest.split_once('=')
        {
            out.insert(k.to_string(), v.to_string());
        }
    }
    out
}

fn analyse(src: &mut Source, common: &Common) -> Result<Outcome> {
    let mut sink = common
        .save
        .as_ref()
        .map(|p| File::create(p).with_context(|| format!("creating {}", p.display())))
        .transpose()?
        .map(BufWriter::new);

    // The read loop is fallible and the sink is buffered, so the flush has to
    // happen on the way out of every path rather than after a loop that a `?`
    // can leave early. Dropping a BufWriter flushes and discards the error,
    // which would leave a short capture reading as a complete one.
    let outcome = read_into(src, common, sink.as_mut());
    let flushed = match sink {
        Some(mut s) => s
            .flush()
            .context("flushing capture; the saved file is short"),
        None => Ok(()),
    };
    match (outcome, flushed) {
        // The read error is the root cause and the failed flush follows from
        // it, so that is the one worth reporting.
        (Err(e), _) => Err(e),
        (Ok(_), Err(e)) => Err(e),
        (Ok(o), Ok(())) => Ok(o),
    }
}

fn read_into(
    src: &mut Source,
    common: &Common,
    mut sink: Option<&mut BufWriter<File>>,
) -> Result<Outcome> {
    let mut ts = TsAnalyzer::new();
    let mut scanner = Scanner::new();
    let mut buf = vec![0u8; 64 * 1024];
    let started = Instant::now();
    let byte_limit = common.max_mb.map(|m| m * 1024 * 1024);

    loop {
        if let Some(secs) = common.max_seconds
            && started.elapsed().as_secs() >= secs
        {
            break;
        }
        if let Some(limit) = byte_limit
            && ts.stats.bytes >= limit
        {
            break;
        }
        let n = src.reader.read(&mut buf).context("reading input")?;
        if n == 0 {
            break;
        }
        if let Some(s) = sink.as_mut() {
            s.write_all(&buf[..n]).context("writing capture")?;
        }
        let units = ts.feed(&buf[..n]);
        consume(&ts, &mut scanner, units);
    }
    let tail = ts.flush();
    consume(&ts, &mut scanner, tail);

    Ok(Outcome {
        elapsed: started.elapsed().as_secs_f64(),
        report: scanner.into_report(),
        ts,
        transport: src.transport,
        freshness: src.freshness,
    })
}

fn consume(ts: &TsAnalyzer, scanner: &mut Scanner, units: Vec<PesUnit>) {
    let now = now_unix_nanos();
    for unit in units {
        let is_video = ts
            .streams
            .get(&unit.pid)
            .is_some_and(|s| matches!(s.stream_type, 0x1B | 0x24));
        if is_video {
            scanner.feed_video_au(&unit.data, now);
        } else {
            // Anything else still gets a raw sweep: a carrier arriving on a
            // PID we did not expect is exactly the result worth catching.
            scanner.feed_raw(&unit.data, now);
        }
    }
}

fn finish(
    out: &Outcome,
    common: &Common,
    amf_tags: Option<BTreeMap<String, String>>,
) -> Result<()> {
    print_summary(out, amf_tags.as_ref());
    let Some(path) = &common.json else {
        return Ok(());
    };
    let ts = &out.ts;
    let doc = serde_json::json!({
        "seconds": out.elapsed,
        "transport_stats_are_origins": out.transport == Transport::Direct,
        "latency_meaningful": out.freshness == Freshness::Live,
        "ts": {
            "bytes": ts.stats.bytes,
            "packets": ts.stats.packets,
            "resync_bytes": ts.stats.resync_bytes,
            "continuity_errors": ts.stats.continuity_errors,
            "scrambled_packets": ts.stats.scrambled_packets,
            "pes_overflow_drops": ts.stats.pes_overflow_drops,
            "packets_by_pid": ts.stats.packets_by_pid.iter()
                .map(|(k, v)| (k.to_string(), *v)).collect::<BTreeMap<_, _>>(),
            "streams": ts.streams.values().map(|s| serde_json::json!({
                "pid": s.pid,
                "stream_type": s.stream_type,
                "type_name": s.type_name(),
                "descriptor_tags": s.descriptor_tags,
            })).collect::<Vec<_>>(),
            "undeclared_pids": ts.undeclared_pids(),
        },
        "amf_tags": amf_tags,
        "scan": out.report,
    });
    std::fs::write(path, serde_json::to_vec_pretty(&doc)?)
        .with_context(|| format!("writing {}", path.display()))?;
    println!("\nJSON report written to {}", path.display());
    Ok(())
}

fn print_summary(out: &Outcome, amf_tags: Option<&BTreeMap<String, String>>) {
    let ts = &out.ts;
    let report = &out.report;
    let mbits = if out.elapsed > 0.0 {
        (ts.stats.bytes as f64 * 8.0) / out.elapsed / 1e6
    } else {
        0.0
    };

    println!("== transport ==");
    if out.transport == Transport::ViaFfmpeg {
        println!("  (read through ffmpeg: these numbers describe ffmpeg's muxer,");
        println!("   not the CDN's. Only the bitstream section below is the CDN's.)");
    }
    println!(
        "  {:.1} s, {} packets, {:.2} MB, {:.2} Mb/s",
        out.elapsed,
        ts.stats.packets,
        ts.stats.bytes as f64 / 1e6,
        mbits
    );
    println!(
        "  resync {} B, continuity errors {}, scrambled {}, pes overflow drops {}",
        ts.stats.resync_bytes,
        ts.stats.continuity_errors,
        ts.stats.scrambled_packets,
        ts.stats.pes_overflow_drops
    );

    {
        println!("\n== PIDs ==");
        if out.transport == Transport::ViaFfmpeg {
            // Worth printing even though these are ffmpeg's PIDs: a track
            // missing from this table means ffmpeg never delivered it, which
            // is a different failure from the server never sending it. Hiding the
            // table makes those two look identical.
            println!("  (ffmpeg's muxer, not the CDN's, but a track absent here");
            println!("   means ffmpeg did not deliver it at all)");
        }
        for (pid, count) in &ts.stats.packets_by_pid {
            let label = match ts.streams.get(pid) {
                Some(s) => format!("{} (type 0x{:02x})", s.type_name(), s.stream_type),
                None if *pid == 0 => "PAT".into(),
                None if ts.pmt_pids.contains(pid) => "PMT".into(),
                None if *pid == 0x0011 => "SDT".into(),
                None if *pid == 0x1FFF => "null".into(),
                None => "UNDECLARED".into(),
            };
            println!("  0x{pid:04x}  {count:>8}  {label}");
        }
        let undeclared = ts.undeclared_pids();
        if !undeclared.is_empty() {
            println!(
                "  !! {} PID(s) carried data without a PMT entry: {}",
                undeclared.len(),
                undeclared
                    .iter()
                    .map(|p| format!("0x{p:04x}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }

    let ev = &report.evidence;
    println!("\n== bitstream ==");
    println!(
        "  {} access units, {:.2} MB of video ES",
        ev.access_units,
        ev.video_es_bytes as f64 / 1e6
    );
    print!("  NAL types:");
    for (ty, n) in &ev.nal_types {
        print!(" {}={}({})", ty, n, nal_name(*ty));
    }
    println!();
    if ev.sei_payload_types.is_empty() {
        println!("  SEI: none present");
    } else {
        print!("  SEI payload types:");
        for (t, n) in &ev.sei_payload_types {
            print!(" {t}={n}");
        }
        println!();
    }
    for f in &ev.foreign_sei_samples {
        println!(
            "  foreign SEI type {} len {} :: {} | {}",
            f.payload_type, f.len, f.head_hex, f.head_ascii
        );
    }

    if let Some(tags) = amf_tags {
        println!("\n== onMetaData ==");
        if tags.is_empty() {
            println!("  no container tags reported");
        }
        for (k, v) in tags {
            let ours = k.eq_ignore_ascii_case(truss::carrier::AMF_METADATA_KEY);
            let mark = if ours { " <- probe key" } else { "" };
            println!("  {k} = {}{mark}", truncate(v, 72));
        }
    }

    println!("\n== carriers ==");
    println!(
        "  {:<12} {:>6} {:>7} {:>8} {:>6} {:>9} {:>5} {:>15} {:>21}",
        "carrier",
        "ok",
        "marker",
        "corrupt",
        "clip",
        "rewritten",
        "gaps",
        "seq span",
        "latency min/med/max ms"
    );
    let mut any = false;
    for c in truss::carrier::ALL {
        let Some(t) = report.carriers.get(c.slug()) else {
            continue;
        };
        any = true;
        let lat = match (out.freshness, t.latency_percentiles_ms()) {
            (Freshness::Offline, _) => "n/a offline".into(),
            (Freshness::Live, Some((a, b, c))) => format!("{a:.0}/{b:.0}/{c:.0}"),
            (Freshness::Live, None) => "-".into(),
        };
        println!(
            "  {:<12} {:>6} {:>7} {:>8} {:>6} {:>9} {:>5} {:>15} {:>21}",
            c.slug(),
            t.ok,
            t.marker,
            t.corrupt,
            t.truncated,
            t.rewritten,
            t.gaps(),
            span(t),
            lat
        );
    }
    if !any {
        println!("  no probe records found on any carrier");
    }
    if report.unattributed.ok > 0
        || report.unattributed.corrupt > 0
        || report.unattributed.truncated > 0
    {
        println!(
            "  {:<12} {:>6} {:>7} {:>8} {:>6} {:>9} {:>5}   (raw scan; framing unrecognised)",
            "unattributed",
            report.unattributed.ok,
            report.unattributed.marker,
            report.unattributed.corrupt,
            report.unattributed.truncated,
            report.unattributed.rewritten,
            report.unattributed.gaps()
        );
    }
    print_dmx(&report.dmx);
}

/// What the lane was carrying, when it was carrying live DMX rather than a
/// generated test body. Silent otherwise, so a measurement run reads as before.
fn print_dmx(dmx: &truss::detect::scan::DmxTally) {
    if dmx.records == 0 && dmx.malformed == 0 {
        return;
    }
    println!("\n== dmx ==");
    let universes: Vec<String> = dmx.universes.iter().map(u16::to_string).collect();
    println!(
        "  {} records  {} blocks  {} channels ({:.0} per record)",
        dmx.records,
        dmx.blocks,
        dmx.channels,
        dmx.channels as f64 / dmx.records.max(1) as f64
    );
    println!(
        "  universes: {}",
        if universes.is_empty() {
            "none".into()
        } else {
            universes.join(", ")
        }
    );
    // How far behind the desk the frame grid ran, per record. A median near the
    // frame interval is the grid waiting its turn. A median that is fine with a
    // far larger maximum is one stall; a raised p95 is a pattern, and only the
    // second means universes are queueing behind the payload budget.
    match dmx.age_stats_ms() {
        Some(a) => println!(
            "  universe age at send: {:.1} / {:.1} / {:.1} ms  (median / p95 / max)",
            a.p50, a.p95, a.max
        ),
        None => println!("  universe age at send: -"),
    }
    if dmx.malformed > 0 {
        println!(
            "  WARNING: {} payloads claimed to be snapshots and did not parse. The record CRC \
             passed, so this is the sender's fault rather than damage in flight.",
            dmx.malformed
        );
    }
}

/// First and last sequence number seen. Printed because `gaps` alone is
/// ambiguous: joining a live stream mid-flight yields a buffered segment and
/// then a jump to the live edge, which shows up as a cluster of missing
/// sequences at the start and is not loss. Seeing the span makes the two cases
/// distinguishable at a glance.
fn span(t: &truss::detect::scan::CarrierTally) -> String {
    match (t.first_seq, t.last_seq) {
        (Some(a), Some(b)) => format!("{a}..{b}"),
        _ => "-".into(),
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        return s.to_string();
    }
    let head: String = s.chars().take(n).collect();
    format!("{head}...")
}

fn nal_name(ty: u8) -> &'static str {
    match ty {
        1 => "slice",
        5 => "IDR",
        6 => "SEI",
        7 => "SPS",
        8 => "PPS",
        9 => "AUD",
        12 => "filler",
        _ => "?",
    }
}
