//! Plant probe carriers into an encoded FLV, ready for ffmpeg to publish.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::Parser;
use truss::carrier::{self, Carrier};
use truss::inject::{InjectOptions, inject};
use truss::record::DEFAULT_PAYLOAD_LEN;

#[derive(Parser)]
#[command(
    name = "truss-inject",
    about = "Plant DMX carriers into an FLV, for publishing or for offline checking"
)]
struct Cli {
    /// Source FLV, as produced by ffmpeg.
    #[arg(long)]
    input: PathBuf,
    /// Where to write the carrier-bearing FLV.
    #[arg(long)]
    output: PathBuf,
    /// Comma-separated carrier slugs. Defaults to the two SEI carriers.
    #[arg(long, default_value = "sei-unreg,sei-t35")]
    carriers: String,
    /// Inject on every Nth video frame.
    #[arg(long, default_value_t = 1)]
    every: u32,
    /// Payload bytes per record, on top of the 32-byte frame.
    #[arg(long, default_value_t = DEFAULT_PAYLOAD_LEN)]
    payload_len: usize,
    /// Inject only on keyframes.
    #[arg(long)]
    keyframes_only: bool,
    /// Refuse to write if the carriers would add more than this many kb/s.
    #[arg(long, default_value_t = 250.0)]
    max_added_kbps: f64,
}

fn parse_carriers(spec: &str) -> Result<Vec<Carrier>> {
    let mut out = Vec::new();
    for name in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let Some(c) = carrier::ALL.into_iter().find(|c| c.slug() == name) else {
            let known: Vec<&str> = carrier::ALL.iter().map(|c| c.slug()).collect();
            bail!(
                "unknown carrier {name:?}; known carriers: {}",
                known.join(", ")
            );
        };
        out.push(c);
    }
    if out.is_empty() {
        bail!("no carriers selected");
    }
    Ok(out)
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let carriers = parse_carriers(&cli.carriers)?;

    let bytes =
        std::fs::read(&cli.input).with_context(|| format!("reading {}", cli.input.display()))?;
    let mut flv = truss::flv::parse(&bytes)?;

    let opts = InjectOptions {
        carriers: carriers.clone(),
        every_n_frames: cli.every,
        payload_len: cli.payload_len,
        keyframes_only: cli.keyframes_only,
    };
    let stats = inject(&mut flv, &opts)?;
    if let Some(codec) = &stats.unsupported_codec {
        bail!("the video is {codec}; records go into H.264 or HEVC only");
    }
    if stats.oversize_skipped > 0 {
        bail!(
            "{} records were too large for the video's NAL length field and were left out; \
             lower --payload-len",
            stats.oversize_skipped
        );
    }

    println!("carriers:");
    for c in &carriers {
        let n = stats.injected.get(c.slug()).copied().unwrap_or(0);
        println!("  {:<12} {:>6} records  ({})", c.slug(), n, c.description());
    }
    println!(
        "video frames: {}, duration {:.1} s",
        stats.video_frames,
        stats.duration_ms as f64 / 1000.0
    );
    println!(
        "added {:.1} kB, {:.1} kb/s",
        stats.added_bytes as f64 / 1000.0,
        stats.added_kbps()
    );

    // The carriers are small, but "small" is an assumption worth enforcing:
    // An ingest typically counts every byte against a combined limit, and a mistyped
    // --payload-len should not be what gets the account flagged.
    if stats.added_kbps() > cli.max_added_kbps {
        bail!(
            "carriers would add {:.1} kb/s, over the {:.1} kb/s ceiling; \
             lower --payload-len or raise --every",
            stats.added_kbps(),
            cli.max_added_kbps
        );
    }

    std::fs::write(&cli.output, truss::flv::serialise(&flv)?)
        .with_context(|| format!("writing {}", cli.output.display()))?;
    println!("wrote {}", cli.output.display());
    Ok(())
}
