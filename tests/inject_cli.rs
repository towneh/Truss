//! truss-inject run as a user runs it, for the checks that live in its `main`.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use truss::flv::{self, Flv, TAG_VIDEO, Tag};

/// Three frames of H.264 whose configuration record declares 1-byte NAL
/// lengths, so a record NAL over 255 bytes cannot be framed in it.
fn one_byte_nal_lengths() -> Vec<u8> {
    let video = |timestamp, data: Vec<u8>| Tag {
        kind: TAG_VIDEO,
        timestamp,
        data,
    };
    // avcC with lengthSizeMinusOne = 0 in the low bits of its fifth byte.
    let mut tags = vec![video(
        0,
        vec![0x17, 0, 0, 0, 0, 1, 0x42, 0xC0, 0x1F, 0xFC, 0xE1],
    )];
    for i in 0..3u8 {
        // A keyframe and its IDR slice first, then two inter frames.
        let (frame, slice) = if i == 0 { (0x17, 0x65) } else { (0x27, 0x41) };
        let nal = [slice, 0xAA, 0xBB];
        let mut data = vec![frame, 1, 0, 0, 0, nal.len() as u8];
        data.extend_from_slice(&nal);
        tags.push(video(u32::from(i) * 33, data));
    }
    flv::serialise(&Flv {
        header: b"FLV\x01\x01\x00\x00\x00\x09".to_vec(),
        tags,
    })
    .unwrap()
}

fn scratch(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn inject(dir: &Path, extra: &[&str]) -> (Output, PathBuf) {
    let input = dir.join("in.flv");
    let output = dir.join("out.flv");
    std::fs::write(&input, one_byte_nal_lengths()).unwrap();
    // An earlier run's output would otherwise pass for this one's.
    if output.exists() {
        std::fs::remove_file(&output).unwrap();
    }
    let run = Command::new(env!("CARGO_BIN_EXE_truss-inject"))
        .arg("--input")
        .arg(&input)
        .arg("--output")
        .arg(&output)
        .args(extra)
        .output()
        .unwrap();
    (run, output)
}

#[test]
fn a_file_missing_records_is_not_written() {
    let dir = scratch("a_file_missing_records_is_not_written");
    let (run, output) = inject(&dir, &["--payload-len", "300"]);
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(!run.status.success(), "succeeded: {stderr}");
    // Three frames, each with both default carriers.
    assert!(stderr.contains("6 records were too large"), "{stderr}");
    assert!(stderr.contains("--payload-len"), "{stderr}");
    assert!(!output.exists(), "wrote {}", output.display());
}

#[test]
fn records_that_fit_the_nal_length_are_written() {
    let dir = scratch("records_that_fit_the_nal_length_are_written");
    let (run, output) = inject(&dir, &[]);
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let before = flv::parse(&one_byte_nal_lengths()).unwrap();
    let after = flv::parse(&std::fs::read(&output).unwrap()).unwrap();
    assert_eq!(after.tags.len(), before.tags.len());
    for (b, a) in before.tags.iter().zip(&after.tags).skip(1) {
        assert!(
            a.data.len() > b.data.len(),
            "frame at {} has no records",
            b.timestamp
        );
    }
}
