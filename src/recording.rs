//! Recording the relayed stream to a local FLV file, records and all.
//!
//! The file holds the tags the relay publishes, byte for byte, written as they
//! go out. A write error stops the recording and cuts the file back to its last
//! whole tag; what to do about the session is the caller's choice.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use rml_amf0::Amf0Value;
use rml_rtmp::sessions::StreamMetadata;

use crate::codec::VideoCodec;
use crate::flv::{self, TAG_AUDIO, TAG_SCRIPT, TAG_VIDEO};

/// Shortening a file back to a length, which a full disk still allows.
///
/// The writer must be unbuffered. [`flv::Writer::complete`] counts bytes the
/// writer accepted, which are on disk only when nothing sits between it and
/// the file; behind a `BufWriter`, cutting the file to that length would cut
/// in the wrong place.
pub trait Truncate {
    fn truncate(&mut self, len: u64) -> std::io::Result<()>;
}

impl Truncate for File {
    fn truncate(&mut self, len: u64) -> std::io::Result<()> {
        self.set_len(len)
    }
}

/// One session's recording.
pub struct Recording<W: Write + Truncate = File> {
    path: PathBuf,
    writer: flv::Writer<W>,
    stopped: Option<String>,
    codec: Option<VideoCodec>,
    last_timestamp: u32,
}

impl Recording<File> {
    /// A new file in `dir`, named for the local time:
    /// `truss-YYYYMMDD-HHMMSS.flv`, with `-2`, `-3` and so on after it when
    /// a session in the same second already took the name.
    pub fn create(dir: &Path) -> Result<Self> {
        let stamp = jiff::Zoned::now().strftime("%Y%m%d-%H%M%S").to_string();
        for n in 1u32.. {
            let name = match n {
                1 => format!("truss-{stamp}.flv"),
                n => format!("truss-{stamp}-{n}.flv"),
            };
            let path = dir.join(name);
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(file) => return Self::new(path, file),
                Err(e) if e.kind() == ErrorKind::AlreadyExists && n < 1000 => continue,
                Err(e) => {
                    return Err(e).with_context(|| format!("creating {}", path.display()));
                }
            }
        }
        unreachable!("the loop returns or fails by its thousandth name")
    }
}

impl<W: Write + Truncate> Recording<W> {
    pub fn new(path: PathBuf, out: W) -> Result<Self> {
        let writer = flv::Writer::new(out)
            .with_context(|| format!("writing the FLV header to {}", path.display()))?;
        Ok(Self {
            path,
            writer,
            stopped: None,
            codec: None,
            last_timestamp: 0,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Bytes written, up to the last whole tag.
    pub fn bytes(&self) -> u64 {
        self.writer.complete()
    }

    /// Why the recording stopped, once it has.
    pub fn stopped(&self) -> Option<&str> {
        self.stopped.as_deref()
    }

    /// The video codec, once a sequence header has been written.
    pub fn codec(&self) -> Option<VideoCodec> {
        self.codec
    }

    /// One video tag body. Errs once, on the write that stops the recording;
    /// after that every call does nothing.
    pub fn video(&mut self, timestamp: u32, data: &[u8]) -> Result<()> {
        if let flv::Video::Config { codec, .. } = flv::video(data) {
            self.codec = Some(codec);
        }
        self.tag(TAG_VIDEO, timestamp, data)
    }

    pub fn audio(&mut self, timestamp: u32, data: &[u8]) -> Result<()> {
        self.tag(TAG_AUDIO, timestamp, data)
    }

    /// `onMetaData` as a script tag, at the latest timestamp written so the
    /// file's timeline never steps back.
    pub fn metadata(&mut self, metadata: &StreamMetadata) -> Result<()> {
        let body = rml_amf0::serialize(&vec![
            Amf0Value::Utf8String("onMetaData".into()),
            Amf0Value::Object(metadata_properties(metadata)),
        ])
        .map_err(|e| anyhow!("encoding onMetaData: {e:?}"))?;
        self.tag(TAG_SCRIPT, self.last_timestamp, &body)
    }

    fn tag(&mut self, kind: u8, timestamp: u32, data: &[u8]) -> Result<()> {
        if self.stopped.is_some() {
            return Ok(());
        }
        let writer = &mut self.writer;
        let Err(e) = writer.tag(kind, timestamp, data) else {
            self.last_timestamp = self.last_timestamp.max(timestamp);
            return Ok(());
        };
        let complete = writer.complete();
        let mut why = e.to_string();
        if let Err(cut) = writer.get_mut().truncate(complete) {
            why.push_str(&format!(
                "; cutting the file back to its last whole tag failed too: {cut}"
            ));
        }
        self.stopped = Some(why.clone());
        Err(anyhow!("{why}")).with_context(|| format!("writing {}", self.path.display()))
    }
}

/// The properties an RTMP publish's `onMetaData` carries, as rml_rtmp builds
/// them for `ClientSession::publish_metadata`.
fn metadata_properties(m: &StreamMetadata) -> HashMap<String, Amf0Value> {
    let numbers = [
        ("width", m.video_width.map(f64::from)),
        ("height", m.video_height.map(f64::from)),
        ("videocodecid", m.video_codec_id.map(f64::from)),
        ("framerate", m.video_frame_rate.map(f64::from)),
        ("videodatarate", m.video_bitrate_kbps.map(f64::from)),
        ("audiocodecid", m.audio_codec_id.map(f64::from)),
        ("audiodatarate", m.audio_bitrate_kbps.map(f64::from)),
        ("audiosamplerate", m.audio_sample_rate.map(f64::from)),
        ("audiochannels", m.audio_channels.map(f64::from)),
    ];
    let mut properties: HashMap<String, Amf0Value> = numbers
        .into_iter()
        .filter_map(|(name, value)| Some((name.to_string(), Amf0Value::Number(value?))))
        .collect();
    if let Some(stereo) = m.audio_is_stereo {
        properties.insert("stereo".into(), Amf0Value::Boolean(stereo));
    }
    if let Some(encoder) = &m.encoder {
        properties.insert("encoder".into(), Amf0Value::Utf8String(encoder.clone()));
    }
    properties
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Takes `room` bytes, then refuses everything, as a full disk does.
    /// Truncating shortens what it kept.
    struct Disk {
        room: usize,
        kept: Vec<u8>,
    }

    impl Write for Disk {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let n = buf.len().min(self.room.saturating_sub(self.kept.len()));
            if n == 0 {
                return Err(std::io::Error::other("no space left on device"));
            }
            self.kept.extend_from_slice(&buf[..n]);
            Ok(n)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Truncate for Disk {
        fn truncate(&mut self, len: u64) -> std::io::Result<()> {
            self.kept.truncate(len as usize);
            Ok(())
        }
    }

    fn recording(room: usize) -> Recording<Disk> {
        Recording::new(
            PathBuf::from("test.flv"),
            Disk {
                room,
                kept: Vec::new(),
            },
        )
        .unwrap()
    }

    fn kept(r: &mut Recording<Disk>) -> Vec<u8> {
        r.writer.get_mut().kept.clone()
    }

    #[test]
    fn a_full_disk_stops_the_recording_on_a_whole_tag() {
        let mut r = recording(13 + 20 + 20 + 7);
        r.audio(0, &[0xAF, 1, 1, 2, 3]).unwrap();
        r.audio(23, &[0xAF, 1, 4, 5, 6]).unwrap();
        let e = r.audio(46, &[0xAF, 1, 7, 8, 9]).unwrap_err();
        assert!(format!("{e:#}").contains("no space left"), "{e:#}");
        assert!(r.stopped().is_some());
        // Said once: later writes do nothing.
        r.audio(69, &[0xAF, 1, 1]).unwrap();
        let kept = kept(&mut r);
        assert_eq!(kept.len(), 13 + 2 * 20);
        assert_eq!(flv::parse(&kept).unwrap().tags.len(), 2);
    }

    #[test]
    fn metadata_and_the_codec_are_recorded() {
        let mut r = recording(usize::MAX);
        let mut m = StreamMetadata::new();
        m.video_width = Some(1280);
        m.video_codec_id = Some(u32::from_be_bytes(*b"hvc1"));
        m.encoder = Some("truss-relay".into());
        r.video(
            40,
            &flv::video_sequence_header(VideoCodec::Hevc, &[1, 2, 3]),
        )
        .unwrap();
        r.metadata(&m).unwrap();
        assert_eq!(r.codec(), Some(VideoCodec::Hevc));

        let flv = flv::parse(&kept(&mut r)).unwrap();
        let script = &flv.tags[1];
        assert_eq!((script.kind, script.timestamp), (TAG_SCRIPT, 40));
        let values = rml_amf0::deserialize(&mut &script.data[..]).unwrap();
        assert_eq!(values[0], Amf0Value::Utf8String("onMetaData".into()));
        let Amf0Value::Object(properties) = &values[1] else {
            panic!("{values:?}");
        };
        assert_eq!(properties["width"], Amf0Value::Number(1280.0));
        assert_eq!(properties["videocodecid"], Amf0Value::Number(1752589105.0));
        assert_eq!(
            properties["encoder"],
            Amf0Value::Utf8String("truss-relay".into())
        );
        assert!(!properties.contains_key("height"));
    }

    #[test]
    fn sessions_in_the_same_second_get_files_of_their_own() {
        let dir = std::env::temp_dir().join(format!("truss-recording-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = Recording::create(&dir).unwrap();
        let b = Recording::create(&dir).unwrap();
        let (pa, pb) = (a.path().to_owned(), b.path().to_owned());
        drop((a, b));
        let names = [&pa, &pb].map(|p| p.file_name().unwrap().to_string_lossy().into_owned());
        for p in [&pa, &pb] {
            std::fs::remove_file(p).unwrap();
        }
        std::fs::remove_dir(&dir).unwrap();
        assert_ne!(pa, pb);
        assert!(
            names[0].starts_with("truss-") && names[0].ends_with(".flv"),
            "{names:?}"
        );
        assert_eq!(
            names[0].len(),
            "truss-20261008-120000.flv".len(),
            "{names:?}"
        );
    }
}
