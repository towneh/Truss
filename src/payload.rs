//! The payload a record carries when it is carrying real data.
//!
//! A probe record's body is normally a deterministic function of its sequence
//! number, which is what lets the detector tell "arrived intact" apart from
//! "arrived and was rewritten". Live DMX cannot be checked that way, so the
//! payload identifies itself instead: the detector recognises the magic and
//! falls back to the record's CRC for integrity.
//!
//! Layout, all integers big-endian:
//!
//! ```text
//! off  len  field
//!   0    4  magic "DMXS"
//!   4    1  version
//!   5    1  flags
//!   6    2  block count
//!   8   ..  blocks
//!
//! block:
//!   0    2  universe (15-bit Art-Net port address)
//!   2    2  start slot, 0-based
//!   4    2  length
//!   6    4  age_us: how long before the record's send time this universe was
//!           captured
//!  10    N  values, one byte per slot
//! ```
//!
//! Values are absolute rather than deltas, so a dropped or late snapshot is
//! corrected by the next one and a client joining mid-show is correct within
//! one frame. `age_us` is per block rather than per payload because each
//! universe is latched when its own packet arrives: DMX at 44 Hz does not
//! divide into a 30 fps frame grid, so the consumer needs to know how stale
//! each universe is rather than assuming they were all sampled together.
//!
//! A block is a run rather than a whole universe, so sending only the channels
//! that changed needs no format change.

use std::fmt;

pub const MAGIC: [u8; 4] = *b"DMXS";
pub const VERSION: u8 = 1;
/// Bytes before the first block.
pub const HEADER_LEN: usize = 8;
/// Bytes a block costs on top of its values.
pub const BLOCK_HEADER_LEN: usize = 10;

/// Values are absolute. Cleared would mean deltas against a previous snapshot,
/// which nothing emits yet.
pub const FLAG_ABSOLUTE: u8 = 0x01;

/// Most blocks one payload can list, fixed by the 16-bit count field.
pub const MAX_BLOCKS: usize = u16::MAX as usize;
/// Most values one block can carry, fixed by its own 16-bit length field.
pub const MAX_BLOCK_VALUES: usize = u16::MAX as usize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub universe: u16,
    pub start: u16,
    /// Microseconds between this universe being latched and the record being
    /// sent. Saturates rather than wrapping, so a stale universe reads as very
    /// old instead of very fresh.
    pub age_us: u32,
    pub values: Vec<u8>,
}

impl Block {
    pub fn encoded_len(&self) -> usize {
        BLOCK_HEADER_LEN + self.values.len()
    }
}

/// Why a set of blocks could not be encoded.
///
/// Both are the format's own 16-bit fields rather than anything this module
/// chose. [`Block`] carries public fields, so a caller can build one past
/// either limit and there is no type that says otherwise; reporting beats
/// asserting for the same reason it does in [`crate::record`], since what
/// arrives here is shaped by however many universes a desk is sending.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    TooManyBlocks {
        count: usize,
        max: usize,
    },
    BlockTooLong {
        block: usize,
        len: usize,
        max: usize,
    },
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyBlocks { count, max } => {
                write!(f, "{count} blocks exceeds the {max} a payload can list")
            }
            Self::BlockTooLong { block, len, max } => {
                write!(
                    f,
                    "block {block} carries {len} values, past the {max} byte limit"
                )
            }
        }
    }
}

impl std::error::Error for EncodeError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    TooShort,
    BadMagic,
    BadVersion(u8),
    /// A block's declared length runs off the end of the payload.
    Truncated {
        block: usize,
    },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort => write!(f, "buffer shorter than a payload header"),
            Self::BadMagic => write!(f, "magic mismatch"),
            Self::BadVersion(v) => write!(f, "unsupported payload version {v}"),
            Self::Truncated { block } => write!(f, "block {block} runs off the end"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Total size of a payload carrying these blocks.
pub fn encoded_len(blocks: &[Block]) -> usize {
    HEADER_LEN + blocks.iter().map(Block::encoded_len).sum::<usize>()
}

pub fn encode(blocks: &[Block]) -> Result<Vec<u8>, EncodeError> {
    // Everything is checked before anything is reserved or written. Ordering the
    // other way round sizes the buffer from block lengths that have not been
    // validated yet, so a set that is going to be refused anyway is paid for
    // first.
    let count = u16::try_from(blocks.len()).map_err(|_| EncodeError::TooManyBlocks {
        count: blocks.len(),
        max: MAX_BLOCKS,
    })?;
    for (i, b) in blocks.iter().enumerate() {
        if b.values.len() > MAX_BLOCK_VALUES {
            return Err(EncodeError::BlockTooLong {
                block: i,
                len: b.values.len(),
                max: MAX_BLOCK_VALUES,
            });
        }
    }

    let mut out = Vec::with_capacity(encoded_len(blocks));
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);
    out.push(FLAG_ABSOLUTE);
    out.extend_from_slice(&count.to_be_bytes());
    for b in blocks {
        out.extend_from_slice(&b.universe.to_be_bytes());
        out.extend_from_slice(&b.start.to_be_bytes());
        out.extend_from_slice(&(b.values.len() as u16).to_be_bytes());
        out.extend_from_slice(&b.age_us.to_be_bytes());
        out.extend_from_slice(&b.values);
    }
    Ok(out)
}

pub fn decode(buf: &[u8]) -> Result<Vec<Block>, DecodeError> {
    if buf.len() < HEADER_LEN {
        return Err(DecodeError::TooShort);
    }
    if buf[..4] != MAGIC {
        return Err(DecodeError::BadMagic);
    }
    if buf[4] != VERSION {
        return Err(DecodeError::BadVersion(buf[4]));
    }
    let count = u16::from_be_bytes(buf[6..8].try_into().unwrap()) as usize;

    let mut blocks = Vec::with_capacity(count);
    let mut at = HEADER_LEN;
    for i in 0..count {
        if at + BLOCK_HEADER_LEN > buf.len() {
            return Err(DecodeError::Truncated { block: i });
        }
        let universe = u16::from_be_bytes(buf[at..at + 2].try_into().unwrap());
        let start = u16::from_be_bytes(buf[at + 2..at + 4].try_into().unwrap());
        let len = u16::from_be_bytes(buf[at + 4..at + 6].try_into().unwrap()) as usize;
        let age_us = u32::from_be_bytes(buf[at + 6..at + 10].try_into().unwrap());
        let from = at + BLOCK_HEADER_LEN;
        let to = from + len;
        if to > buf.len() {
            return Err(DecodeError::Truncated { block: i });
        }
        blocks.push(Block {
            universe,
            start,
            age_us,
            values: buf[from..to].to_vec(),
        });
        at = to;
    }
    Ok(blocks)
}

/// True when these bytes claim to be a payload of this format.
///
/// The detector uses this to decide whether the record's body can be checked
/// against the sequence-number generator. A record carrying real data cannot
/// be, so scoring it as rewritten would report a fault that is not there.
pub fn looks_like(buf: &[u8]) -> bool {
    buf.len() >= HEADER_LEN && buf[..4] == MAGIC && buf[4] == VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(universe: u16, len: usize) -> Block {
        Block {
            universe,
            start: 0,
            age_us: 1234,
            values: (0..len).map(|i| (i % 251) as u8).collect(),
        }
    }

    #[test]
    fn a_block_running_past_its_universe_is_not_an_encoding_concern() {
        // The format bounds a block's length, not where it lands. A sender that
        // addresses past slot 512 produces a perfectly well-formed payload, and
        // the disagreement is the receiver's to report: DmxState counts those
        // slots as out_of_range rather than clamping them away. Encoding is
        // deliberately not the place that decides, so the two ends can disagree
        // visibly instead of one of them silently winning.
        let overrun = Block {
            universe: 1,
            start: 511,
            age_us: 0,
            values: vec![0xFF; 512],
        };
        let blocks = vec![overrun];
        let bytes = encode(&blocks).expect("an overrunning block still encodes");
        assert_eq!(decode(&bytes).expect("and decodes"), blocks);
    }

    #[test]
    fn a_block_set_past_the_format_limits_is_reported_not_asserted() {
        // `Block` has public fields, so nothing stops a caller building either
        // of these. Neither is reachable from the relay, where the budget bounds
        // both, but a panic in an encoder is the wrong answer to input the
        // module does not choose.
        let too_many: Vec<Block> = (0..=MAX_BLOCKS).map(|_| block(1, 0)).collect();
        assert_eq!(
            encode(&too_many),
            Err(EncodeError::TooManyBlocks {
                count: MAX_BLOCKS + 1,
                max: MAX_BLOCKS,
            })
        );

        let too_long = vec![block(1, 4), block(2, MAX_BLOCK_VALUES + 1)];
        assert_eq!(
            encode(&too_long),
            Err(EncodeError::BlockTooLong {
                block: 1,
                len: MAX_BLOCK_VALUES + 1,
                max: MAX_BLOCK_VALUES,
            }),
            "the failing block should be named by its index"
        );

        // And the largest set that does fit still encodes.
        assert!(encode(&[block(1, MAX_BLOCK_VALUES)]).is_ok());
    }

    #[test]
    fn round_trips() {
        let blocks = vec![block(0, 512), block(3, 512)];
        let bytes = encode(&blocks).expect("test blocks are small");
        assert_eq!(bytes.len(), encoded_len(&blocks));
        assert_eq!(decode(&bytes).expect("decodes"), blocks);
    }

    #[test]
    fn an_empty_snapshot_is_still_a_valid_payload() {
        let bytes = encode(&[]).expect("an empty payload encodes");
        assert_eq!(bytes.len(), HEADER_LEN);
        assert!(decode(&bytes).expect("decodes").is_empty());
    }

    #[test]
    fn a_partial_run_round_trips() {
        // What a changed-channels-only sender would emit.
        let blocks = vec![Block {
            universe: 12,
            start: 100,
            age_us: 0,
            values: vec![1, 2, 3],
        }];
        let bytes = encode(&blocks).expect("test blocks are small");
        assert_eq!(decode(&bytes).expect("decodes"), blocks);
    }

    #[test]
    fn a_clipped_payload_is_reported_rather_than_read_past_the_end() {
        let bytes = encode(&[block(1, 512)]).expect("one universe encodes");
        let cut = &bytes[..bytes.len() - 4];
        assert_eq!(decode(cut), Err(DecodeError::Truncated { block: 0 }));
    }

    #[test]
    fn the_synthetic_probe_body_is_not_mistaken_for_a_payload() {
        for seq in 0..64 {
            let body = crate::record::expected_payload(seq, 64);
            assert!(!looks_like(&body), "seq {seq} looked like a payload");
        }
    }

    #[test]
    fn block_sizes_match_the_documented_overhead() {
        let b = block(0, 512);
        assert_eq!(b.encoded_len(), BLOCK_HEADER_LEN + 512);
        // Twelve full universes, the figure the capacity planning is built on.
        let dozen: Vec<Block> = (0..12).map(|u| block(u, 512)).collect();
        assert_eq!(encoded_len(&dozen), 8 + 12 * 522);
    }
}
