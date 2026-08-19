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

/// The AVCC body of a video tag payload: everything past the 5-byte AVC header.
pub fn avc_body_of(data: &[u8]) -> &[u8] {
    &data[5..]
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

/// NAL length size from an AVCDecoderConfigurationRecord, which sits in the
/// AVC sequence-header tag. Everything in the file is framed this way, so
/// guessing 4 and being wrong would corrupt every access unit.
pub fn nal_length_size(sequence_header_body: &[u8]) -> Result<usize> {
    if sequence_header_body.len() < 5 {
        bail!("AVCDecoderConfigurationRecord too short");
    }
    Ok(((sequence_header_body[4] & 0x03) + 1) as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(nal_length_size(&[1, 0x42, 0xC0, 0x1F, 0xFF]).unwrap(), 4);
        assert_eq!(nal_length_size(&[1, 0x42, 0xC0, 0x1F, 0xFC]).unwrap(), 1);
        assert!(nal_length_size(&[1, 2]).is_err());
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
