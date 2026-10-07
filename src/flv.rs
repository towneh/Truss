//! Minimal FLV read/write, enough to plant carriers in a file that ffmpeg
//! then publishes over RTMP.
//!
//! Rewriting a file offline and handing it to ffmpeg avoids writing an RTMP
//! client, at one real cost: we no longer know when each frame actually goes
//! out on the wire, so a send timestamp baked in here would measure the
//! encoder's schedule rather than the network. The injector therefore leaves
//! `send_unix_nanos` at zero on this path and the detector skips latency for
//! it. Sequence numbers, loss, ordering and integrity all still work, which is
//! most of what the question needs.

use anyhow::{Result, bail};

use crate::codec::VideoCodec;

/// Largest tag body an FLV can declare, fixed by the 24-bit DataSize field.
pub const MAX_TAG_SIZE: usize = 0x00FF_FFFF;
/// Signature, version, flags and DataOffset. Nothing valid points inside it.
pub const FLV_HEADER_LEN: usize = 9;

pub const TAG_AUDIO: u8 = 8;
pub const TAG_VIDEO: u8 = 9;
pub const TAG_SCRIPT: u8 = 18;

/// AVC packet type inside a video tag payload.
pub const AVC_SEQUENCE_HEADER: u8 = 0;
pub const AVC_NALU: u8 = 1;

/// Legacy CodecID for HEVC. Outside the FLV spec, but some encoders send it.
const CODEC_ID_HEVC: u8 = 12;
/// Enhanced RTMP: the top bit of a video tag's first byte marks the extended
/// header, a packet type and a FourCC in place of a CodecID.
const EX_HEADER: u8 = 0x80;
const EX_SEQUENCE_START: u8 = 0;
const EX_CODED_FRAMES: u8 = 1;
const EX_CODED_FRAMES_X: u8 = 3;
/// A frame type that carries a command rather than a picture.
const FRAME_TYPE_COMMAND: u8 = 5;

/// What a video tag payload holds, read from its header. `body` is where the
/// config record or the length-prefixed NAL units start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Video {
    /// A decoder configuration record (avcC or hvcC).
    Config { codec: VideoCodec, body: usize },
    /// The NAL units of one access unit.
    Frame {
        codec: VideoCodec,
        keyframe: bool,
        body: usize,
    },
    /// A codec records cannot ride in, named for a log line.
    Unsupported(String),
    /// Anything else of a known codec: end of sequence, metadata, multitrack,
    /// or a tag too short to hold what its header says.
    Other,
}

/// Read a video tag payload's header, in the legacy layout (AVC, or HEVC as
/// CodecID 12) or the Enhanced RTMP one (`avc1` and `hvc1`).
///
/// Takes the payload rather than a `Tag` because the relay receives exactly
/// these bytes from an RTMP session, with no surrounding tag header.
pub fn video(data: &[u8]) -> Video {
    let Some(&first) = data.first() else {
        return Video::Other;
    };
    enum Packet {
        Config,
        Frame,
    }
    let (codec, packet, keyframe, body) = if first & EX_HEADER != 0 {
        // Checked before the FourCC: a multitrack packet has its own byte at
        // offset 1, so bytes 1..5 are not a FourCC there.
        let packet_type = first & 0x0F;
        if !matches!(
            packet_type,
            EX_SEQUENCE_START | EX_CODED_FRAMES | EX_CODED_FRAMES_X
        ) {
            return Video::Other;
        }
        let Some(fourcc) = data.get(1..5) else {
            return Video::Other;
        };
        let codec = match fourcc {
            b"avc1" => VideoCodec::H264,
            b"hvc1" => VideoCodec::Hevc,
            other => return Video::Unsupported(String::from_utf8_lossy(other).into_owned()),
        };
        let frame_type = (first >> 4) & 0x07;
        if frame_type == FRAME_TYPE_COMMAND {
            return Video::Other;
        }
        match packet_type {
            EX_SEQUENCE_START => (codec, Packet::Config, false, 5),
            // CodedFrames has a composition time ahead of the NAL units.
            EX_CODED_FRAMES => (codec, Packet::Frame, frame_type == 1, 8),
            EX_CODED_FRAMES_X => (codec, Packet::Frame, frame_type == 1, 5),
            _ => return Video::Other,
        }
    } else {
        let codec = match first & 0x0F {
            7 => VideoCodec::H264,
            CODEC_ID_HEVC => VideoCodec::Hevc,
            id => return Video::Unsupported(format!("FLV codec id {id}")),
        };
        let packet = match data.get(1) {
            Some(&AVC_SEQUENCE_HEADER) => Packet::Config,
            Some(&AVC_NALU) => Packet::Frame,
            _ => return Video::Other,
        };
        (codec, packet, first >> 4 == 1, 5)
    };
    if data.len() <= body {
        return Video::Other;
    }
    match packet {
        Packet::Config => Video::Config { codec, body },
        Packet::Frame => Video::Frame {
            codec,
            keyframe,
            body,
        },
    }
}

#[derive(Debug, Clone)]
pub struct Tag {
    pub kind: u8,
    /// Milliseconds, already merged with the extended byte.
    pub timestamp: u32,
    pub data: Vec<u8>,
}

/// True for a video tag payload carrying coded NAL units (not a config record).
///
/// Takes the payload rather than a `Tag` because the relay receives exactly
/// these bytes from an RTMP session, with no surrounding tag header.
pub fn is_avc_nalu_data(data: &[u8]) -> bool {
    data.len() > 5 && data[0] & 0x0F == 7 && data[1] == AVC_NALU // CodecID 7 == AVC
}

pub fn is_avc_sequence_header_data(data: &[u8]) -> bool {
    data.len() > 5 && data[0] & 0x0F == 7 && data[1] == AVC_SEQUENCE_HEADER
}

impl Tag {
    /// True for a video tag carrying coded NAL units (not a config record).
    pub fn is_avc_nalu(&self) -> bool {
        self.kind == TAG_VIDEO && is_avc_nalu_data(&self.data)
    }

    pub fn is_avc_sequence_header(&self) -> bool {
        self.kind == TAG_VIDEO && is_avc_sequence_header_data(&self.data)
    }

    pub fn is_keyframe(&self) -> bool {
        self.kind == TAG_VIDEO && self.data.first().is_some_and(|b| b >> 4 == 1)
    }

    /// The AVCC body of a NALU tag: everything past the 5-byte AVC header.
    pub fn avc_body(&self) -> &[u8] {
        &self.data[5..]
    }

    pub fn set_avc_body(&mut self, body: &[u8]) {
        self.data.truncate(5);
        self.data.extend_from_slice(body);
    }
}

pub struct Flv {
    /// The 9-byte header plus whatever the DataOffset skipped.
    pub header: Vec<u8>,
    pub tags: Vec<Tag>,
}

pub fn parse(bytes: &[u8]) -> Result<Flv> {
    if bytes.len() < 13 || &bytes[..3] != b"FLV" {
        bail!("not an FLV file");
    }
    let data_offset = u32::from_be_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]) as usize;
    if data_offset > bytes.len() {
        bail!("FLV DataOffset {data_offset} runs past the file");
    }
    // The header this points past is 9 bytes at minimum. A smaller offset would
    // leave `header` holding a truncated one, and rewriting the file would then
    // emit something no reader accepts, this crate's own parser included.
    if data_offset < FLV_HEADER_LEN {
        bail!("FLV DataOffset {data_offset} is inside the {FLV_HEADER_LEN} byte header");
    }
    let header = bytes[..data_offset].to_vec();

    let mut tags = Vec::new();
    let mut i = data_offset + 4; // skip PreviousTagSize0
    while i + 11 <= bytes.len() {
        let kind = bytes[i] & 0x1F;
        let size = u32::from_be_bytes([0, bytes[i + 1], bytes[i + 2], bytes[i + 3]]) as usize;
        let ts = u32::from_be_bytes([bytes[i + 7], bytes[i + 4], bytes[i + 5], bytes[i + 6]]);
        let start = i + 11;
        let end = start + size;
        if end + 4 > bytes.len() {
            break; // truncated final tag
        }
        tags.push(Tag {
            kind,
            timestamp: ts,
            data: bytes[start..end].to_vec(),
        });
        i = end + 4;
    }
    Ok(Flv { header, tags })
}

pub fn serialise(flv: &Flv) -> Result<Vec<u8>> {
    // `header` is public and written out verbatim, so a caller can hand over
    // something that is not an FLV header at all and get bytes back that no
    // reader accepts. Anything `parse` produced satisfies all three of these by
    // construction: it slices the header at DataOffset, having already checked
    // the signature and that the offset clears the header.
    if flv.header.len() < FLV_HEADER_LEN || flv.header[..3] != *b"FLV" {
        bail!("FLV header of {} bytes is not one", flv.header.len());
    }
    let declared =
        u32::from_be_bytes([flv.header[5], flv.header[6], flv.header[7], flv.header[8]]) as usize;
    if declared != flv.header.len() {
        bail!(
            "FLV DataOffset {declared} disagrees with the {} byte header it sits in",
            flv.header.len()
        );
    }

    let mut out = Vec::with_capacity(flv.header.len() + 4);
    out.extend_from_slice(&flv.header);
    out.extend_from_slice(&0u32.to_be_bytes()); // PreviousTagSize0

    for tag in &flv.tags {
        let size = tag.data.len();
        // DataSize is three bytes, and the body is written whole regardless.
        // Declaring size & 0xFFFFFF would leave the file disagreeing with
        // itself, and this crate's own parser reads that field to find the next
        // tag, so it would desync from here to the end.
        if size > MAX_TAG_SIZE {
            bail!("FLV tag of {size} bytes exceeds the {MAX_TAG_SIZE} byte DataSize field");
        }
        out.push(tag.kind);
        out.extend_from_slice(&(size as u32).to_be_bytes()[1..]);
        // Timestamp is a 24-bit little-endian-ish split with the top byte last.
        out.push(((tag.timestamp >> 16) & 0xFF) as u8);
        out.push(((tag.timestamp >> 8) & 0xFF) as u8);
        out.push((tag.timestamp & 0xFF) as u8);
        out.push(((tag.timestamp >> 24) & 0xFF) as u8);
        out.extend_from_slice(&[0, 0, 0]); // StreamID
        out.extend_from_slice(&tag.data);
        out.extend_from_slice(&((size + 11) as u32).to_be_bytes());
    }
    Ok(out)
}

/// NAL length size from the decoder configuration record in the sequence
/// header: byte 4 of an avcC, byte 21 of an hvcC. Every access unit is framed
/// with it, so guessing 4 and being wrong would corrupt all of them.
pub fn nal_length_size(codec: VideoCodec, config: &[u8]) -> Result<usize> {
    let (at, name) = match codec {
        VideoCodec::H264 => (4, "AVCDecoderConfigurationRecord"),
        VideoCodec::Hevc => (21, "HEVCDecoderConfigurationRecord"),
    };
    let Some(&byte) = config.get(at) else {
        bail!("{name} too short");
    };
    Ok(((byte & 0x03) + 1) as usize)
}

/// FLV's SoundFormat for AAC with the rate, size and channel bits set as the
/// spec says to for AAC, whatever the stream: decoders read the
/// AudioSpecificConfig instead.
const AAC_SOUND_FLAGS: u8 = 0xAF;

/// An H.264 sequence header as a video tag payload, wrapping an
/// AVCDecoderConfigurationRecord.
pub fn avc_sequence_header(avcc: &[u8]) -> Vec<u8> {
    let mut out = vec![0x17, AVC_SEQUENCE_HEADER, 0, 0, 0];
    out.extend_from_slice(avcc);
    out
}

/// One H.264 access unit as a video tag payload. `nals` are length-prefixed
/// as the stream's sequence header declares, and `cts_ms` is presentation
/// minus decode time, which the tag carries as a signed 24-bit field.
pub fn avc_frame(keyframe: bool, cts_ms: i32, nals: &[u8]) -> Result<Vec<u8>> {
    if !(-0x80_0000..0x80_0000).contains(&cts_ms) {
        bail!("composition time {cts_ms} ms does not fit the tag's 24-bit field");
    }
    let mut out = vec![if keyframe { 0x17 } else { 0x27 }, AVC_NALU];
    out.extend_from_slice(&cts_ms.to_be_bytes()[1..]);
    out.extend_from_slice(nals);
    Ok(out)
}

/// An AAC sequence header as an audio tag payload, wrapping an
/// AudioSpecificConfig.
pub fn aac_sequence_header(asc: &[u8]) -> Vec<u8> {
    let mut out = vec![AAC_SOUND_FLAGS, 0];
    out.extend_from_slice(asc);
    out
}

/// One raw AAC frame as an audio tag payload.
pub fn aac_frame(raw: &[u8]) -> Vec<u8> {
    let mut out = vec![AAC_SOUND_FLAGS, 1];
    out.extend_from_slice(raw);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_video_tags_read_back_as_what_they_were_built_from() {
        let avcc = [1, 0x42, 0xC0, 0x1F, 0xFF, 0xE1];
        let header = avc_sequence_header(&avcc);
        assert_eq!(
            video(&header),
            Video::Config {
                codec: VideoCodec::H264,
                body: 5
            }
        );
        assert_eq!(&header[5..], &avcc);

        let nals = [0, 0, 0, 2, 0x65, 0xAA];
        for (key, cts) in [(true, 0), (false, 67), (false, -33)] {
            let frame = avc_frame(key, cts, &nals).unwrap();
            assert_eq!(
                video(&frame),
                Video::Frame {
                    codec: VideoCodec::H264,
                    keyframe: key,
                    body: 5
                }
            );
            let field = i32::from_be_bytes([0, frame[2], frame[3], frame[4]]);
            let read = (field << 8) >> 8;
            assert_eq!(read, cts);
            assert_eq!(&frame[5..], &nals);
        }
    }

    #[test]
    fn a_composition_time_past_24_bits_is_refused() {
        assert!(avc_frame(false, 0x7F_FFFF, &[]).is_ok());
        assert!(avc_frame(false, -0x80_0000, &[]).is_ok());
        assert!(avc_frame(false, 0x80_0000, &[]).is_err());
        assert!(avc_frame(false, -0x80_0001, &[]).is_err());
    }

    #[test]
    fn audio_tags_carry_aac_and_their_packet_type() {
        assert_eq!(aac_sequence_header(&[0x11, 0x90]), [0xAF, 0, 0x11, 0x90]);
        assert_eq!(aac_frame(&[1, 2, 3]), [0xAF, 1, 1, 2, 3]);
    }

    fn build(tags: &[Tag]) -> Vec<u8> {
        let mut header = b"FLV".to_vec();
        header.push(1);
        header.push(0x05); // audio + video
        header.extend_from_slice(&9u32.to_be_bytes());
        serialise(&Flv {
            header,
            tags: tags.to_vec(),
        })
        .expect("the test tags are well within the size limit")
    }

    fn video_tag(keyframe: bool, packet_type: u8, body: &[u8], ts: u32) -> Tag {
        let mut data = vec![if keyframe { 0x17 } else { 0x27 }, packet_type, 0, 0, 0];
        data.extend_from_slice(body);
        Tag {
            kind: TAG_VIDEO,
            timestamp: ts,
            data,
        }
    }

    #[test]
    fn a_data_offset_pointing_inside_the_header_is_refused() {
        // Accepting one leaves `header` holding a truncated FLV header, and
        // rewriting the file then produces something no reader takes, this
        // crate's own parser included. Found by the generative cover.
        let mut bytes = b"FLV\x01\x05\x00\x00\x00\x09".to_vec();
        bytes.extend_from_slice(&[0u8; 16]);
        bytes[8] = 3; // DataOffset inside the header
        let err = match parse(&bytes) {
            Ok(_) => panic!("a DataOffset pointing inside the header was accepted"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("inside the"), "{err}");
    }

    #[test]
    fn a_tag_too_large_for_the_size_field_is_refused_rather_than_truncated() {
        // Writing the low three bytes and the whole body leaves the file
        // disagreeing with itself, and parse() reads that same field to find
        // the next tag, so it would read frame bytes as headers from here on.
        let err = serialise(&Flv {
            header: b"FLV\x01\x05\x00\x00\x00\x09".to_vec(),
            tags: vec![Tag {
                kind: TAG_SCRIPT,
                timestamp: 0,
                data: vec![0u8; MAX_TAG_SIZE + 1],
            }],
        })
        .expect_err("an oversize tag has no valid encoding")
        .to_string();
        assert!(err.contains("exceeds"), "{err}");
    }

    #[test]
    fn round_trips_tags() {
        let tags = vec![
            Tag {
                kind: TAG_SCRIPT,
                timestamp: 0,
                data: b"onMetaData-ish".to_vec(),
            },
            video_tag(true, AVC_NALU, &[0, 0, 0, 2, 0x65, 0xAA], 33),
            Tag {
                kind: TAG_AUDIO,
                timestamp: 40,
                data: vec![0xAF, 0x01, 0x21, 0x10],
            },
        ];
        let bytes = build(&tags);
        let back = parse(&bytes).expect("parses");
        assert_eq!(back.tags.len(), 3);
        assert_eq!(back.tags[0].kind, TAG_SCRIPT);
        assert_eq!(back.tags[1].timestamp, 33);
        assert_eq!(back.tags[2].data, vec![0xAF, 0x01, 0x21, 0x10]);
        assert_eq!(
            serialise(&back).expect("round-trips"),
            bytes,
            "re-serialising is byte-identical"
        );
    }

    #[test]
    fn large_timestamps_survive_the_extended_byte() {
        // Anything past ~4.6 hours needs the extended byte; getting the split
        // wrong shows up as a stream that plays fine then jumps.
        let tags = vec![video_tag(
            false,
            AVC_NALU,
            &[0, 0, 0, 1, 0x41],
            0x01_A2_B3_C4,
        )];
        let back = parse(&build(&tags)).expect("parses");
        assert_eq!(back.tags[0].timestamp, 0x01_A2_B3_C4);
    }

    #[test]
    fn classifies_tag_shapes() {
        let nalu = video_tag(true, AVC_NALU, &[0, 0, 0, 1, 0x65], 0);
        assert!(nalu.is_avc_nalu());
        assert!(nalu.is_keyframe());
        assert!(!nalu.is_avc_sequence_header());

        let seq = video_tag(true, AVC_SEQUENCE_HEADER, &[1, 0x42, 0, 0x1F, 0xFF], 0);
        assert!(seq.is_avc_sequence_header());
        assert!(!seq.is_avc_nalu());

        let inter = video_tag(false, AVC_NALU, &[0, 0, 0, 1, 0x41], 0);
        assert!(!inter.is_keyframe());
    }

    #[test]
    fn reads_nal_length_size_from_the_config_record() {
        // lengthSizeMinusOne lives in the low two bits of byte 4.
        let h264 = VideoCodec::H264;
        assert_eq!(
            nal_length_size(h264, &[1, 0x42, 0xC0, 0x1F, 0xFF]).unwrap(),
            4
        );
        assert_eq!(
            nal_length_size(h264, &[1, 0x42, 0xC0, 0x1F, 0xFC]).unwrap(),
            1
        );
        assert!(nal_length_size(h264, &[1, 2]).is_err());
    }

    #[test]
    fn reads_hevc_nal_length_size_from_byte_21() {
        let mut hvcc = vec![0u8; 23];
        hvcc[21] = 0x0F; // constantFrameRate 0, 1 temporal layer, nested, lengthSizeMinusOne 3
        assert_eq!(nal_length_size(VideoCodec::Hevc, &hvcc).unwrap(), 4);
        hvcc[21] = 0x0D;
        assert_eq!(nal_length_size(VideoCodec::Hevc, &hvcc).unwrap(), 2);
        assert!(nal_length_size(VideoCodec::Hevc, &hvcc[..21]).is_err());
    }

    #[test]
    fn reads_every_video_header_layout() {
        use VideoCodec::{H264, Hevc};
        let frame = |codec, keyframe, body| Video::Frame {
            codec,
            keyframe,
            body,
        };

        assert_eq!(video(&[0x17, 1, 0, 0, 0, 0xAA]), frame(H264, true, 5));
        assert_eq!(
            video(&[0x17, 0, 0, 0, 0, 0xAA]),
            Video::Config {
                codec: H264,
                body: 5
            }
        );
        assert_eq!(video(&[0x2C, 1, 0, 0, 0, 0xAA]), frame(Hevc, false, 5));

        // Enhanced RTMP: CodedFrames keeps a composition time, CodedFramesX does not.
        assert_eq!(
            video(&[0x91, b'h', b'v', b'c', b'1', 0, 0, 0, 0xAA]),
            frame(Hevc, true, 8)
        );
        assert_eq!(
            video(&[0xA3, b'h', b'v', b'c', b'1', 0xAA]),
            frame(Hevc, false, 5)
        );
        assert_eq!(
            video(&[0x90, b'h', b'v', b'c', b'1', 0xAA]),
            Video::Config {
                codec: Hevc,
                body: 5
            }
        );
        assert_eq!(
            video(&[0x91, b'a', b'v', b'c', b'1', 0, 0, 0, 0xAA]),
            frame(H264, true, 8)
        );
    }

    #[test]
    fn names_a_codec_records_cannot_ride_in() {
        assert_eq!(
            video(&[0x91, b'a', b'v', b'0', b'1', 0, 0, 0, 0xAA]),
            Video::Unsupported("av01".into())
        );
        assert_eq!(
            video(&[0x14, 1, 0, 0, 0, 0xAA]),
            Video::Unsupported("FLV codec id 4".into())
        );
    }

    #[test]
    fn leaves_non_picture_tags_alone() {
        // End of sequence, a command frame, and a CodedFrames tag with no body.
        assert_eq!(video(&[0x17, 2, 0, 0, 0, 0]), Video::Other);
        // Multitrack, one track of CodedFrames: the FourCC sits at byte 2.
        assert_eq!(
            video(&[0x96, 0x01, b'h', b'v', b'c', b'1', 0, 0, 0, 0xAA]),
            Video::Other
        );
        assert_eq!(
            video(&[0xD1, b'h', b'v', b'c', b'1', 0, 0, 0, 0]),
            Video::Other
        );
        assert_eq!(
            video(&[0x91, b'h', b'v', b'c', b'1', 0, 0, 0]),
            Video::Other
        );
        assert_eq!(video(&[]), Video::Other);
    }

    #[test]
    fn body_replacement_keeps_the_avc_header() {
        let mut t = video_tag(true, AVC_NALU, &[0, 0, 0, 1, 0x65], 0);
        t.set_avc_body(&[0, 0, 0, 2, 0x06, 0x80]);
        assert_eq!(&t.data[..5], &[0x17, 1, 0, 0, 0]);
        assert_eq!(t.avc_body(), &[0, 0, 0, 2, 0x06, 0x80]);
    }

    #[test]
    fn a_truncated_final_tag_is_dropped_not_fatal() {
        let mut bytes = build(&[video_tag(true, AVC_NALU, &[0, 0, 0, 1, 0x65], 0)]);
        bytes.truncate(bytes.len() - 3);
        let back = parse(&bytes).expect("still parses what it can");
        assert_eq!(back.tags.len(), 0);
    }

    #[test]
    fn rejects_non_flv_input() {
        assert!(parse(b"not an flv file at all").is_err());
    }
}
