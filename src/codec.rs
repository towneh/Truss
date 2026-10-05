//! The video codecs a record can ride in. Both carry it in SEI or filler NAL
//! units and share the SEI syntax; the NAL header and type numbers differ.

use crate::{h264, hevc};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoCodec {
    H264,
    Hevc,
}

impl VideoCodec {
    pub fn name(self) -> &'static str {
        match self {
            Self::H264 => "H.264",
            Self::Hevc => "HEVC",
        }
    }

    /// Bytes of NAL header before the RBSP.
    pub fn nal_header_len(self) -> usize {
        match self {
            Self::H264 => 1,
            Self::Hevc => hevc::NAL_HEADER_LEN,
        }
    }

    pub fn nal_type(self, header_byte: u8) -> u8 {
        match self {
            Self::H264 => h264::nal_type(header_byte),
            Self::Hevc => hevc::nal_type(header_byte),
        }
    }

    pub fn is_aud(self, ty: u8) -> bool {
        match self {
            Self::H264 => ty == h264::NAL_AUD,
            Self::Hevc => ty == hevc::NAL_AUD,
        }
    }

    pub fn is_sei(self, ty: u8) -> bool {
        match self {
            Self::H264 => ty == h264::NAL_SEI,
            Self::Hevc => hevc::is_sei(ty),
        }
    }

    pub fn is_filler(self, ty: u8) -> bool {
        match self {
            Self::H264 => ty == h264::NAL_FILLER,
            Self::Hevc => ty == hevc::NAL_FILLER,
        }
    }

    pub fn sei_nal(self, payload_type: u64, payload: &[u8]) -> Vec<u8> {
        match self {
            Self::H264 => h264::build_sei_nal(payload_type, payload),
            Self::Hevc => hevc::build_sei_nal(payload_type, payload),
        }
    }

    pub fn filler_nal(self, payload: &[u8]) -> Vec<u8> {
        match self {
            Self::H264 => h264::build_filler_nal(payload),
            Self::Hevc => hevc::build_filler_nal(payload),
        }
    }

    /// Deliver every SEI message in an Annex-B buffer as `(payload_type, payload)`.
    pub fn scan_sei_annexb(self, annexb: &[u8], f: impl FnMut(u64, &[u8])) {
        match self {
            Self::H264 => h264::scan_sei_annexb(annexb, f),
            Self::Hevc => hevc::scan_sei_annexb(annexb, f),
        }
    }
}
