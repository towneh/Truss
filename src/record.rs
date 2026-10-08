//! The carrier-agnostic probe record.
//!
//! Every carrier ships the same bytes so the detector can score them on equal
//! terms. The record is self-delimiting and self-verifying: it carries its own
//! magic, length and CRC, so the detector can scan a haystack it does not
//! understand (an unfamiliar SEI payload, a private PID, an AMF blob) and still
//! recognise a survivor.
//!
//! Layout, all integers big-endian:
//!
//! ```text
//! off  len  field
//!   0    8  magic "TRUSSDMX"
//!   8    1  version
//!   9    1  carrier id
//!  10    4  seq
//!  14    8  send_unix_nanos
//!  22    4  frame_index
//!  26    2  payload_len
//!  28    N  payload
//! 28+N    4  crc32 over bytes[0 .. 28+N]
//! ```
//!
//! For measurement runs `payload` is a deterministic function of `seq`, so a
//! record that arrives with a valid CRC but the wrong body means something
//! rewrote it rather than dropped it. That distinction is the whole point of
//! the exercise: a carrier that silently mangles data is worse than one that
//! drops it, because the player would happily decode the garbage.
//!
//! A record carrying real data cannot be checked that way, so those payloads
//! identify themselves (see [`crate::payload`]) and the CRC is what stands
//! behind them.

use std::fmt;

pub const MAGIC: [u8; 8] = *b"TRUSSDMX";
pub const VERSION: u8 = 1;
/// Bytes before the variable-length payload.
pub const HEADER_LEN: usize = 28;
/// Trailing CRC width.
pub const CRC_LEN: usize = 4;
/// Payload size used by the injector unless overridden.
pub const DEFAULT_PAYLOAD_LEN: usize = 24;
/// Largest payload one record can carry, fixed by the 16-bit length field.
pub const MAX_PAYLOAD_LEN: usize = u16::MAX as usize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub carrier: u8,
    pub seq: u32,
    pub send_unix_nanos: u64,
    pub frame_index: u32,
    pub payload: Vec<u8>,
}

/// Why a candidate at a given offset was not a usable record.
///
/// `BadCrc` and `PayloadMismatch` are deliberately distinct from the "not a
/// record at all" cases: both mean the magic survived the trip but the bytes
/// after it did not, which is evidence about the carrier rather than noise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    TooShort,
    BadMagic,
    BadVersion(u8),
    /// The declared payload length runs off the end of the buffer.
    Truncated {
        declared: usize,
        available: usize,
    },
    BadCrc {
        declared: u32,
        computed: u32,
    },
    /// Not checked: [`find_records`] had spent its CRC budget for the
    /// haystack before reaching this candidate.
    OverBudget,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort => write!(f, "buffer shorter than a record header"),
            Self::BadMagic => write!(f, "magic mismatch"),
            Self::BadVersion(v) => write!(f, "unsupported record version {v}"),
            Self::Truncated {
                declared,
                available,
            } => write!(
                f,
                "declared payload {declared} exceeds {available} available"
            ),
            Self::BadCrc { declared, computed } => {
                write!(
                    f,
                    "crc mismatch: declared {declared:#010x}, computed {computed:#010x}"
                )
            }
            Self::OverBudget => write!(f, "not checked: the scan's crc budget was spent"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Why a record could not be encoded.
///
/// The length field is 16 bits, so a larger payload has no representation.
/// Reported rather than asserted: the sizes reaching here come from a flag and
/// from however many universes a desk happens to be sending, neither of which
/// this module gets to decide.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    PayloadTooLong { len: usize, max: usize },
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PayloadTooLong { len, max } => {
                write!(f, "payload of {len} bytes exceeds the {max} byte limit")
            }
        }
    }
}

impl std::error::Error for EncodeError {}

impl Record {
    pub fn new(
        carrier: u8,
        seq: u32,
        send_unix_nanos: u64,
        frame_index: u32,
        payload_len: usize,
    ) -> Self {
        Self {
            carrier,
            seq,
            send_unix_nanos,
            frame_index,
            payload: expected_payload(seq, payload_len),
        }
    }

    /// A record carrying supplied bytes rather than the self-check body.
    ///
    /// The sequence number, send time and CRC still apply, so loss, ordering
    /// and corruption are scored exactly as they are for a measurement run.
    /// What no longer applies is [`Self::payload_intact`], since there is
    /// nothing to compare a live payload against.
    pub fn with_payload(
        carrier: u8,
        seq: u32,
        send_unix_nanos: u64,
        frame_index: u32,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            carrier,
            seq,
            send_unix_nanos,
            frame_index,
            payload,
        }
    }

    pub fn encoded_len(payload_len: usize) -> usize {
        HEADER_LEN + payload_len + CRC_LEN
    }

    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let len = u16::try_from(self.payload.len()).map_err(|_| EncodeError::PayloadTooLong {
            len: self.payload.len(),
            max: MAX_PAYLOAD_LEN,
        })?;
        let mut out = Vec::with_capacity(Self::encoded_len(self.payload.len()));
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.push(self.carrier);
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.send_unix_nanos.to_be_bytes());
        out.extend_from_slice(&self.frame_index.to_be_bytes());
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.payload);
        debug_assert_eq!(out.len(), HEADER_LEN + self.payload.len());
        let crc = crc32fast::hash(&out);
        out.extend_from_slice(&crc.to_be_bytes());
        Ok(out)
    }

    /// Decode a record anchored at the start of `buf`.
    pub fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        let end = crc_end(buf)?;
        let carrier = buf[9];
        let seq = u32::from_be_bytes(buf[10..14].try_into().unwrap());
        let send_unix_nanos = u64::from_be_bytes(buf[14..22].try_into().unwrap());
        let frame_index = u32::from_be_bytes(buf[22..26].try_into().unwrap());

        let declared = u32::from_be_bytes(buf[end..end + CRC_LEN].try_into().unwrap());
        let computed = crc32fast::hash(&buf[..end]);
        if declared != computed {
            return Err(DecodeError::BadCrc { declared, computed });
        }

        Ok(Self {
            carrier,
            seq,
            send_unix_nanos,
            frame_index,
            payload: buf[HEADER_LEN..end].to_vec(),
        })
    }

    /// True when the payload still matches what `seq` says it should be.
    /// A record can pass CRC and fail this only if the injector and detector
    /// disagree about the generator, so it doubles as a harness self-check.
    pub fn payload_intact(&self) -> bool {
        self.payload == expected_payload(self.seq, self.payload.len())
    }
}

/// One hit from scanning a haystack, keeping the offset so callers can report
/// where in an opaque blob the record was sitting.
#[derive(Debug, Clone)]
pub struct Hit {
    pub offset: usize,
    pub result: Result<Record, DecodeError>,
}

/// Find every record-shaped thing in `haystack`, including damaged ones.
///
/// Scanning for the magic rather than parsing a known container is what lets a
/// single detector score carriers whose framing we do not control. A hit that
/// fails to decode is still reported: "the magic arrived but the body did not"
/// is a different verdict from "nothing arrived".
///
/// A candidate that fails is stepped past by its magic alone, because its
/// length may be the damaged field and the next real record could sit inside
/// the span it claims. That lets candidates overlap, each claiming up to 64 KB
/// of CRC, so the total CRC work is capped at [`CRC_BUDGET_PER_BYTE`] times
/// the haystack. Records that decode never overlap, so an undamaged haystack
/// spends at most its own length. Candidates past the cap are reported as
/// [`DecodeError::OverBudget`].
///
/// Hits come one at a time, so a caller holds one however many there are: a
/// haystack of back-to-back magics has one for every 8 bytes.
pub fn find_records(haystack: &[u8]) -> Records<'_> {
    Records {
        haystack,
        at: 0,
        budget: haystack.len().saturating_mul(CRC_BUDGET_PER_BYTE),
    }
}

/// The hits in a haystack, as [`find_records`] finds them.
#[derive(Debug, Clone)]
pub struct Records<'a> {
    haystack: &'a [u8],
    /// Where the scan resumes.
    at: usize,
    /// CRC work left to spend.
    budget: usize,
}

impl Iterator for Records<'_> {
    type Item = Hit;

    fn next(&mut self) -> Option<Hit> {
        let haystack = self.haystack;
        while self.at + MAGIC.len() <= haystack.len() {
            let i = self.at;
            if haystack[i..i + MAGIC.len()] != MAGIC {
                self.at += 1;
                continue;
            }
            let cost = crc_span(&haystack[i..]);
            let result = if cost > self.budget {
                Err(DecodeError::OverBudget)
            } else {
                self.budget -= cost;
                Record::decode(&haystack[i..])
            };
            self.at += match &result {
                Ok(r) => Record::encoded_len(r.payload.len()),
                Err(_) => MAGIC.len(),
            };
            return Some(Hit { offset: i, result });
        }
        None
    }
}

/// CRC work [`find_records`] may spend per byte of haystack.
pub const CRC_BUDGET_PER_BYTE: usize = 4;

/// How many bytes [`Record::decode`] would run through the CRC for a candidate
/// at the start of `buf`: none when it would stop at the header first.
fn crc_span(buf: &[u8]) -> usize {
    crc_end(buf).unwrap_or(0)
}

/// The checks [`Record::decode`] makes before the CRC, in its order, and on
/// success the end of the range the CRC covers, read from the length field.
/// [`crc_span`] uses the same checks, so the budget charges what decoding
/// will actually cost.
fn crc_end(buf: &[u8]) -> Result<usize, DecodeError> {
    if buf.len() < HEADER_LEN {
        return Err(DecodeError::TooShort);
    }
    if buf[..8] != MAGIC {
        return Err(DecodeError::BadMagic);
    }
    if buf[8] != VERSION {
        return Err(DecodeError::BadVersion(buf[8]));
    }
    let payload_len = usize::from(u16::from_be_bytes([buf[26], buf[27]]));
    let end = HEADER_LEN + payload_len;
    if buf.len() < end + CRC_LEN {
        return Err(DecodeError::Truncated {
            declared: payload_len,
            available: buf.len().saturating_sub(HEADER_LEN),
        });
    }
    Ok(end)
}

/// Deterministic payload bytes for a sequence number (xorshift32).
pub fn expected_payload(seq: u32, len: usize) -> Vec<u8> {
    let mut s = seq.wrapping_mul(0x9E37_79B1) ^ 0xDEAD_BEEF;
    if s == 0 {
        s = 1;
    }
    (0..len)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 17;
            s ^= s << 5;
            (s & 0xFF) as u8
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Record {
        Record::new(3, 12345, 1_700_000_000_123_456_789, 42, DEFAULT_PAYLOAD_LEN)
    }

    #[test]
    fn a_payload_too_large_for_the_length_field_is_reported_not_asserted() {
        // The length field is 16 bits and the payload sizes reaching here come
        // from a flag and from a desk on an unauthenticated network, so this is
        // a condition to report rather than an invariant to assert.
        let r = Record::with_payload(1, 0, 0, 0, vec![0u8; MAX_PAYLOAD_LEN + 1]);
        assert_eq!(
            r.encode(),
            Err(EncodeError::PayloadTooLong {
                len: MAX_PAYLOAD_LEN + 1,
                max: MAX_PAYLOAD_LEN,
            })
        );
        // And the largest that does fit still encodes.
        let r = Record::with_payload(1, 0, 0, 0, vec![0u8; MAX_PAYLOAD_LEN]);
        assert_eq!(
            r.encode().expect("the limit itself is allowed").len(),
            Record::encoded_len(MAX_PAYLOAD_LEN)
        );
    }

    #[test]
    fn round_trips() {
        let r = sample();
        let bytes = r.encode().unwrap();
        assert_eq!(bytes.len(), Record::encoded_len(DEFAULT_PAYLOAD_LEN));
        let back = Record::decode(&bytes).expect("decodes");
        assert_eq!(back, r);
        assert!(back.payload_intact());
    }

    #[test]
    fn detects_a_flipped_body_byte() {
        let mut bytes = sample().encode().unwrap();
        bytes[HEADER_LEN] ^= 0x01;
        assert!(matches!(
            Record::decode(&bytes),
            Err(DecodeError::BadCrc { .. })
        ));
    }

    #[test]
    fn truncation_is_distinct_from_corruption() {
        let bytes = sample().encode().unwrap();
        let cut = &bytes[..bytes.len() - 2];
        assert!(matches!(
            Record::decode(cut),
            Err(DecodeError::Truncated { .. })
        ));
    }

    #[test]
    fn scan_finds_records_embedded_in_noise() {
        let a = Record::new(1, 7, 1, 7, 8);
        let b = Record::new(2, 9, 2, 9, 8);
        let mut hay = vec![0xAB; 13];
        hay.extend_from_slice(&a.encode().unwrap());
        hay.extend_from_slice(&[0x00; 5]);
        hay.extend_from_slice(&b.encode().unwrap());
        hay.extend_from_slice(&[0xFF; 3]);

        let hits: Vec<Hit> = find_records(&hay).collect();
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].result.as_ref().unwrap().seq, 7);
        assert_eq!(hits[1].result.as_ref().unwrap().seq, 9);
        assert_eq!(hits[0].offset, 13);
    }

    #[test]
    fn scan_reports_damaged_hits_rather_than_skipping_them() {
        let mut bytes = sample().encode().unwrap();
        let good_seq = sample().seq;
        bytes[HEADER_LEN + 3] ^= 0xFF;
        let hits: Vec<Hit> = find_records(&bytes).collect();
        assert_eq!(hits.len(), 1, "the magic survived, so it is still a hit");
        assert!(hits[0].result.is_err());
        // The header is readable even though the body is not, which is how the
        // report attributes a corrupt record to the right carrier and seq.
        let hdr = &bytes[..HEADER_LEN];
        assert_eq!(
            u32::from_be_bytes(hdr[10..14].try_into().unwrap()),
            good_seq
        );
    }

    #[test]
    fn overlapping_decoys_cannot_run_the_crc_past_its_budget() {
        // Every 14 bytes a magic and version, with a length that reads 0xFFFF,
        // so each candidate would claim a 64 KB CRC.
        let mut period = MAGIC.to_vec();
        period.extend_from_slice(&[VERSION, 0, 0, 0, 0xFF, 0xFF]);
        let mut hay = sample().encode().unwrap();
        hay.extend(period.iter().copied().cycle().take(512 * 1024));

        let hits: Vec<Hit> = find_records(&hay).collect();
        assert_eq!(hits[0].result.as_ref().unwrap(), &sample());
        let spent: usize = hits
            .iter()
            .filter(|h| !matches!(h.result, Err(DecodeError::OverBudget)))
            .map(|h| crc_span(&hay[h.offset..]))
            .sum();
        assert!(spent <= hay.len() * CRC_BUDGET_PER_BYTE);
        assert!(
            hits.iter()
                .any(|h| matches!(h.result, Err(DecodeError::OverBudget)))
        );
    }

    #[test]
    fn the_budget_charges_what_decode_hashes() {
        let good = sample().encode().unwrap();
        let hashed = HEADER_LEN + DEFAULT_PAYLOAD_LEN;
        assert_eq!(crc_span(&good), hashed);
        let mut bad_crc = good.clone();
        *bad_crc.last_mut().unwrap() ^= 0xFF;
        assert_eq!(crc_span(&bad_crc), hashed);
        assert_eq!(crc_span(&good[..good.len() - 1]), 0, "truncated");
        let mut bad_version = good.clone();
        bad_version[8] = VERSION + 1;
        assert_eq!(crc_span(&bad_version), 0);
    }

    #[test]
    fn a_haystack_of_records_stays_inside_the_budget() {
        let mut hay = Vec::new();
        for seq in 0..50 {
            hay.extend_from_slice(
                &Record::new(1, seq, 1, seq, MAX_PAYLOAD_LEN / 64)
                    .encode()
                    .unwrap(),
            );
        }
        let hits: Vec<Hit> = find_records(&hay).collect();
        assert_eq!(hits.len(), 50);
        assert!(hits.iter().all(|h| h.result.is_ok()));
    }

    #[test]
    fn payloads_differ_per_seq() {
        assert_ne!(expected_payload(1, 16), expected_payload(2, 16));
        assert_eq!(expected_payload(99, 16), expected_payload(99, 16));
    }
}
