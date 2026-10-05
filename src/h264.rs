//! Just enough H.264 to plant a record in the video elementary stream and find
//! it again on the other side.
//!
//! Two NAL framings matter here. An MPEG-TS or RTSP egress hands us
//! Annex-B (start-code separated); the FLV/RTMP ingest side is AVCC
//! (length-prefixed). The injector writes AVCC because that is what an RTMP
//! video tag holds, and the detector reads Annex-B. Keeping both in one module
//! keeps the escape/unescape rules in a single place, which is where the
//! subtle bugs live.

/// H.264 NAL type for SEI.
pub const NAL_SEI: u8 = 6;
/// H.264 NAL type for an access-unit delimiter.
pub const NAL_AUD: u8 = 9;
/// H.264 NAL type for filler data.
pub const NAL_FILLER: u8 = 12;
/// SEI payload type: user_data_registered_itu_t_t35.
pub const SEI_T35: u64 = 4;
/// SEI payload type: user_data_unregistered.
pub const SEI_UNREGISTERED: u64 = 5;

pub fn nal_type(header_byte: u8) -> u8 {
    header_byte & 0x1F
}

/// Iterate Annex-B NAL units, returning slices that include the header byte
/// but not the start code. Trailing zero bytes before the next start code are
/// trimmed, since encoders pad and those bytes are not part of the NAL.
pub fn nal_units_annexb(data: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let starts = start_code_offsets(data);
    for (i, &(sc_start, sc_len)) in starts.iter().enumerate() {
        let begin = sc_start + sc_len;
        let end = starts.get(i + 1).map_or(data.len(), |&(next, _)| next);
        if begin >= end {
            continue;
        }
        let mut nal = &data[begin..end];
        while let Some((&0, rest)) = nal.split_last() {
            nal = rest;
        }
        if !nal.is_empty() {
            out.push(nal);
        }
    }
    out
}

/// Offsets and lengths of every `00 00 01` / `00 00 00 01` start code.
fn start_code_offsets(data: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 3 <= data.len() {
        if data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 1 {
            if i > 0 && data[i - 1] == 0 {
                out.push((i - 1, 4));
            } else {
                out.push((i, 3));
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    out
}

/// Iterate length-prefixed (AVCC) NAL units. Returns `None` if the buffer is
/// not consistently framed, which is the signal to stop trusting it rather
/// than to guess.
pub fn nal_units_avcc(data: &[u8], length_size: usize) -> Option<Vec<&[u8]>> {
    if !(1..=4).contains(&length_size) {
        return None;
    }
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < data.len() {
        if i + length_size > data.len() {
            return None;
        }
        let mut len = 0usize;
        for k in 0..length_size {
            len = (len << 8) | data[i + k] as usize;
        }
        i += length_size;
        if len == 0 || i + len > data.len() {
            return None;
        }
        out.push(&data[i..i + len]);
        i += len;
    }
    Some(out)
}

/// Prefix a NAL with its AVCC length field.
pub fn avcc_wrap(nal: &[u8], length_size: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(length_size + nal.len());
    let len = nal.len();
    for k in (0..length_size).rev() {
        out.push(((len >> (8 * k)) & 0xFF) as u8);
    }
    out.extend_from_slice(nal);
    out
}

/// Insert emulation-prevention bytes: any `00 00 00`, `00 00 01`, `00 00 02`
/// or `00 00 03` in the RBSP gains a `03` before the third byte.
///
/// Skipping this is the classic way to plant a payload that decodes fine in
/// your own test and corrupts the slice that follows it on someone else's
/// decoder, because a payload byte pair of zeros followed by `01` fabricates a
/// start code in the middle of the NAL.
pub fn escape_rbsp(rbsp: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(rbsp.len() + rbsp.len() / 64 + 4);
    let mut zeros = 0usize;
    for &b in rbsp {
        if zeros >= 2 && b <= 0x03 {
            out.push(0x03);
            zeros = 0;
        }
        out.push(b);
        zeros = if b == 0 { zeros + 1 } else { 0 };
    }
    out
}

/// Remove emulation-prevention bytes (`00 00 03` -> `00 00`).
pub fn unescape_rbsp(ebsp: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ebsp.len());
    let mut zeros = 0usize;
    for &b in ebsp {
        if zeros >= 2 && b == 0x03 {
            zeros = 0;
            continue;
        }
        out.push(b);
        zeros = if b == 0 { zeros + 1 } else { 0 };
    }
    out
}

/// Encode an SEI type or size as the spec's run of `0xFF` plus a terminator.
fn push_varlen(out: &mut Vec<u8>, mut value: u64) {
    while value >= 255 {
        out.push(0xFF);
        value -= 255;
    }
    out.push(value as u8);
}

/// Build a complete SEI NAL (header byte included, emulation-prevented)
/// carrying one message.
pub fn build_sei_nal(payload_type: u64, payload: &[u8]) -> Vec<u8> {
    let rbsp = sei_rbsp(payload_type, payload);
    let mut nal = Vec::with_capacity(rbsp.len() + 2);
    nal.push(NAL_SEI); // nal_ref_idc = 0, type = 6
    nal.extend_from_slice(&escape_rbsp(&rbsp));
    nal
}

/// One SEI message plus trailing bits, unescaped. HEVC uses the same syntax
/// under a different NAL header.
pub(crate) fn sei_rbsp(payload_type: u64, payload: &[u8]) -> Vec<u8> {
    let mut rbsp = Vec::with_capacity(payload.len() + 8);
    push_varlen(&mut rbsp, payload_type);
    push_varlen(&mut rbsp, payload.len() as u64);
    rbsp.extend_from_slice(payload);
    rbsp.push(0x80); // rbsp_trailing_bits
    rbsp
}

/// Build a filler-data NAL whose RBSP holds `payload` instead of the `0xFF`
/// run the spec mandates.
///
/// Non-conformant by construction. It earns its place because filler NALs are
/// observably passes a remux today, so it is the control that
/// tells us whether an SEI loss is "SEI specifically" or "anything we add".
/// A payload byte of `0x00` would end the RBSP early on a strict reader, so
/// the caller's bytes are escaped the same way an SEI would be.
pub fn build_filler_nal(payload: &[u8]) -> Vec<u8> {
    let mut rbsp = Vec::with_capacity(payload.len() + 2);
    rbsp.extend_from_slice(payload);
    rbsp.push(0x80);

    let mut nal = Vec::with_capacity(rbsp.len() + 2);
    nal.push(NAL_FILLER);
    nal.extend_from_slice(&escape_rbsp(&rbsp));
    nal
}

/// Walk the SEI messages in an already-unescaped RBSP.
///
/// Both accumulators are `u64`: a run of `0xFF` is bounded only by the NAL
/// length, so a narrower accumulator overflows on a hostile stream.
pub fn sei_messages(rbsp: &[u8], mut f: impl FnMut(u64, &[u8])) {
    let mut p = 0usize;
    while p + 2 <= rbsp.len() {
        let mut payload_type = 0u64;
        while p < rbsp.len() && rbsp[p] == 0xFF {
            payload_type += 255;
            p += 1;
        }
        if p >= rbsp.len() {
            break;
        }
        payload_type += u64::from(rbsp[p]);
        p += 1;

        let mut size = 0u64;
        while p < rbsp.len() && rbsp[p] == 0xFF {
            size += 255;
            p += 1;
        }
        if p >= rbsp.len() {
            break;
        }
        size += u64::from(rbsp[p]);
        p += 1;

        if size > (rbsp.len() - p) as u64 {
            break;
        }
        let size = size as usize;
        f(payload_type, &rbsp[p..p + size]);
        p += size;
        if p < rbsp.len() && rbsp[p] == 0x80 {
            break;
        }
    }
}

/// Deliver every SEI message in an Annex-B buffer as `(payload_type, payload)`.
pub fn scan_sei_annexb(annexb: &[u8], mut f: impl FnMut(u64, &[u8])) {
    for nal in nal_units_annexb(annexb) {
        if nal.len() <= 1 || nal_type(nal[0]) != NAL_SEI {
            continue;
        }
        let rbsp = unescape_rbsp(&nal[1..]);
        sei_messages(&rbsp, &mut f);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_round_trips_and_kills_fake_start_codes() {
        let raw = [0x00, 0x00, 0x01, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x03];
        let esc = escape_rbsp(&raw);
        assert!(
            !esc.windows(3).any(|w| w == [0, 0, 1]),
            "escaped bytes must not contain a start code"
        );
        assert_eq!(unescape_rbsp(&esc), raw);
    }

    #[test]
    fn escape_leaves_clean_payloads_alone() {
        let raw = [0xDE, 0xAD, 0xBE, 0xEF];
        assert_eq!(escape_rbsp(&raw), raw);
    }

    #[test]
    fn sei_nal_round_trips_through_the_walker() {
        let payload = b"probe-body-goes-here".to_vec();
        let nal = build_sei_nal(SEI_UNREGISTERED, &payload);
        assert_eq!(nal_type(nal[0]), NAL_SEI);

        let mut seen = Vec::new();
        let rbsp = unescape_rbsp(&nal[1..]);
        sei_messages(&rbsp, |t, p| seen.push((t, p.to_vec())));
        assert_eq!(seen, vec![(SEI_UNREGISTERED, payload)]);
    }

    #[test]
    fn sei_nal_survives_a_payload_full_of_zeros() {
        // The escaping path is what makes this case work; without it the
        // walker would see a truncated message.
        let payload = vec![0u8; 64];
        let nal = build_sei_nal(SEI_T35, &payload);
        let rbsp = unescape_rbsp(&nal[1..]);
        let mut seen = Vec::new();
        sei_messages(&rbsp, |t, p| seen.push((t, p.to_vec())));
        assert_eq!(seen, vec![(SEI_T35, payload)]);
    }

    #[test]
    fn long_payloads_use_ff_run_length_coding() {
        let payload = vec![0xAB; 600];
        let nal = build_sei_nal(SEI_UNREGISTERED, &payload);
        let rbsp = unescape_rbsp(&nal[1..]);
        // type 5, then 0xFF 0xFF 0x5A == 255+255+90 == 600
        assert_eq!(&rbsp[..5], &[5, 0xFF, 0xFF, 90, 0xAB]);
        let mut seen_len = 0;
        sei_messages(&rbsp, |_, p| seen_len = p.len());
        assert_eq!(seen_len, 600);
    }

    #[test]
    fn annexb_walk_handles_both_start_code_widths() {
        let data = [
            0, 0, 0, 1, 0x09, 0x10, // 4-byte start code, AUD
            0, 0, 1, 0x06, 0x04, 0x01, 0xAB, 0x80, // 3-byte, SEI
            0, 0, 0, 1, 0x41, 0x9A, 0x00, // trailing zero is padding
        ];
        let nals = nal_units_annexb(&data);
        assert_eq!(nals.len(), 3);
        assert_eq!(nal_type(nals[0][0]), 9);
        assert_eq!(nal_type(nals[1][0]), 6);
        assert_eq!(nals[2], &[0x41, 0x9A]);
    }

    #[test]
    fn scan_sei_annexb_finds_the_message() {
        let sei = build_sei_nal(SEI_UNREGISTERED, b"hello");
        let mut data = vec![0, 0, 0, 1, 0x09, 0x10];
        data.extend_from_slice(&[0, 0, 0, 1]);
        data.extend_from_slice(&sei);
        let mut seen = Vec::new();
        scan_sei_annexb(&data, |t, p| seen.push((t, p.to_vec())));
        assert_eq!(seen, vec![(SEI_UNREGISTERED, b"hello".to_vec())]);
    }

    #[test]
    fn avcc_round_trips() {
        let a = build_sei_nal(SEI_UNREGISTERED, b"one");
        let b = vec![0x41u8, 0x9A, 0xBC];
        let mut buf = avcc_wrap(&a, 4);
        buf.extend_from_slice(&avcc_wrap(&b, 4));
        let nals = nal_units_avcc(&buf, 4).expect("well framed");
        assert_eq!(nals, vec![a.as_slice(), b.as_slice()]);
    }

    #[test]
    fn avcc_rejects_inconsistent_framing() {
        // Declares 99 bytes but only 3 follow.
        assert!(nal_units_avcc(&[0, 0, 0, 99, 1, 2, 3], 4).is_none());
    }

    #[test]
    fn hostile_ff_run_does_not_hang_or_overread() {
        sei_messages(&vec![0xFF; 4096], |_, _| panic!("no complete message"));
        sei_messages(&[4, 200, 0, 0], |_, _| panic!("payload is truncated"));
    }
}
