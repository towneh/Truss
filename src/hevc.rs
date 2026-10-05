//! Where HEVC differs from H.264 for carrying a record: a two-byte NAL header
//! and different type numbers. SEI message syntax, Annex-B framing and
//! emulation prevention are the same, and live in [`crate::h264`].

use crate::h264;

/// Bytes of NAL header before the RBSP.
pub const NAL_HEADER_LEN: usize = 2;

pub const NAL_AUD: u8 = 35;
pub const NAL_FILLER: u8 = 38;
/// Prefix SEI, which sits before the first slice of the access unit.
pub const NAL_PREFIX_SEI: u8 = 39;
/// Suffix SEI, which follows the first slice. User data is allowed in either.
pub const NAL_SUFFIX_SEI: u8 = 40;

pub fn nal_type(header_byte: u8) -> u8 {
    (header_byte >> 1) & 0x3F
}

pub fn is_sei(ty: u8) -> bool {
    ty == NAL_PREFIX_SEI || ty == NAL_SUFFIX_SEI
}

/// Build a complete prefix SEI NAL (header included, emulation-prevented)
/// carrying one message, on layer 0 and temporal sub-layer 0.
pub fn build_sei_nal(payload_type: u64, payload: &[u8]) -> Vec<u8> {
    let rbsp = h264::sei_rbsp(payload_type, payload);
    let mut nal = Vec::with_capacity(rbsp.len() + NAL_HEADER_LEN + 2);
    // nuh_temporal_id_plus1 must be at least 1, hence the 0x01.
    nal.extend_from_slice(&[NAL_PREFIX_SEI << 1, 0x01]);
    nal.extend_from_slice(&h264::escape_rbsp(&rbsp));
    nal
}

/// As [`h264::build_filler_nal`], with an HEVC header: a record in place of
/// the `0xFF` run, so non-conformant in the same way.
pub fn build_filler_nal(payload: &[u8]) -> Vec<u8> {
    let mut rbsp = Vec::with_capacity(payload.len() + 1);
    rbsp.extend_from_slice(payload);
    rbsp.push(0x80);
    let mut nal = Vec::with_capacity(rbsp.len() + NAL_HEADER_LEN + 2);
    nal.extend_from_slice(&[NAL_FILLER << 1, 0x01]);
    nal.extend_from_slice(&h264::escape_rbsp(&rbsp));
    nal
}

/// Deliver every SEI message in an Annex-B buffer as `(payload_type, payload)`,
/// prefix and suffix alike.
pub fn scan_sei_annexb(annexb: &[u8], mut f: impl FnMut(u64, &[u8])) {
    for nal in h264::nal_units_annexb(annexb) {
        if nal.len() <= NAL_HEADER_LEN || !is_sei(nal_type(nal[0])) {
            continue;
        }
        let rbsp = h264::unescape_rbsp(&nal[NAL_HEADER_LEN..]);
        h264::sei_messages(&rbsp, &mut f);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_sei_header_is_the_one_encoders_write() {
        let nal = build_sei_nal(h264::SEI_UNREGISTERED, b"x");
        assert_eq!(&nal[..2], &[0x4E, 0x01]);
        assert_eq!(nal_type(nal[0]), NAL_PREFIX_SEI);
    }

    #[test]
    fn an_h264_reading_of_the_header_misses_it() {
        // Read with H.264 rules, an HEVC prefix SEI header is type 14.
        assert_eq!(h264::nal_type(NAL_PREFIX_SEI << 1), 14);
    }

    #[test]
    fn scan_finds_prefix_and_suffix_sei() {
        let mut suffix = build_sei_nal(h264::SEI_T35, b"after");
        suffix[0] = NAL_SUFFIX_SEI << 1;
        let mut data = vec![0, 0, 0, 1, NAL_AUD << 1, 0x01, 0x50];
        for nal in [build_sei_nal(h264::SEI_UNREGISTERED, b"before"), suffix] {
            data.extend_from_slice(&[0, 0, 0, 1]);
            data.extend_from_slice(&nal);
        }
        let mut seen = Vec::new();
        scan_sei_annexb(&data, |t, p| seen.push((t, p.to_vec())));
        assert_eq!(
            seen,
            vec![
                (h264::SEI_UNREGISTERED, b"before".to_vec()),
                (h264::SEI_T35, b"after".to_vec()),
            ]
        );
    }

    #[test]
    fn a_bare_header_is_skipped_rather_than_read_past() {
        let data = [0, 0, 0, 1, NAL_PREFIX_SEI << 1, 0x01];
        let mut seen = 0;
        scan_sei_annexb(&data, |_, _| seen += 1);
        assert_eq!(seen, 0);
    }
}
