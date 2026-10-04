//! The OSC lane: records sent beside the stream, for a listener on the
//! network rather than a viewer of the stream.
//!
//! A VJ checking what they are sending should not need an encoder, an
//! ingest and a player running. The relay can send every record it would
//! put in the video to an OSC listener as well, as one message carrying the
//! record as a blob, and the listener decodes it with the same code that
//! decodes the stream. One message shape is all that takes, so this encodes
//! and reads that shape and nothing else: no bundles, no other argument
//! types. A datagram that is anything else is not ours and reads as `None`.
//!
//! OSC is big-endian throughout, strings are NUL-terminated and every field
//! is padded to a multiple of four bytes.

use std::net::{SocketAddr, UdpSocket};

use crate::carrier::Carrier;
use crate::record::{EncodeError, Record};

/// The address every record goes out under.
pub const ADDRESS: &str = "/truss/dmx";
/// Clear of Art-Net on 6454, the VRSL Grid Node on 12000 and 12001, and
/// QLC+ from 9000.
pub const DEFAULT_PORT: u16 = 12100;

/// One message with a single blob argument.
///
/// The specification writes the length as a signed 32-bit integer, so a
/// blob past that is refused rather than written with a length that does
/// not match its bytes. A record is at most a few tens of kilobytes, so the
/// refusal is a statement of the limit rather than a path anything takes.
pub fn encode_blob(address: &str, blob: &[u8]) -> Result<Vec<u8>, EncodeError> {
    let len = i32::try_from(blob.len()).map_err(|_| EncodeError::PayloadTooLong {
        len: blob.len(),
        max: i32::MAX as usize,
    })?;
    let mut out = Vec::with_capacity(address.len() + 8 + blob.len() + 8);
    push_string(&mut out, address.as_bytes());
    push_string(&mut out, b",b");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(blob);
    pad(&mut out);
    Ok(out)
}

/// The address and blob of a message with exactly one blob argument, or
/// `None` for anything else: a bundle, another type, a cut-short datagram.
pub fn decode_blob(datagram: &[u8]) -> Option<(&str, &[u8])> {
    let (address, rest) = read_string(datagram)?;
    // A bundle starts with "#bundle"; an address starts with a slash.
    if !address.starts_with('/') {
        return None;
    }
    let (tags, rest) = read_string(rest)?;
    if tags != ",b" {
        return None;
    }
    let (len, rest) = rest.split_first_chunk::<4>()?;
    let len = usize::try_from(i32::from_be_bytes(*len)).ok()?;
    let blob = rest.get(..len)?;
    Some((address, blob))
}

fn push_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(s);
    out.push(0);
    pad(out);
}

fn pad(out: &mut Vec<u8>) {
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

/// A NUL-terminated string and what follows its padding.
fn read_string(buf: &[u8]) -> Option<(&str, &[u8])> {
    let nul = buf.iter().position(|&b| b == 0)?;
    let s = std::str::from_utf8(&buf[..nul]).ok()?;
    // The string occupies its bytes, the NUL, and padding to the next
    // multiple of four. A datagram cut inside that padding is malformed.
    let end = (nul + 4) & !3;
    let rest = buf.get(end..)?;
    Some((s, rest))
}

/// Sends records to one listener.
///
/// Sequence and frame index are the lane's own, counted from the first
/// record this sender built, so a listener scores loss and order on the
/// lane rather than on whatever the stream was doing.
pub struct Sender {
    socket: UdpSocket,
    target: SocketAddr,
    seq: u32,
    frame: u32,
    pub sent: u64,
    pub failed: u64,
}

impl Sender {
    pub fn to(target: SocketAddr) -> std::io::Result<Self> {
        let bind: SocketAddr = if target.is_ipv4() {
            "0.0.0.0:0".parse().expect("a literal address")
        } else {
            "[::]:0".parse().expect("a literal address")
        };
        Ok(Self {
            socket: UdpSocket::bind(bind)?,
            target,
            seq: 0,
            frame: 0,
            sent: 0,
            failed: 0,
        })
    }

    pub fn target(&self) -> SocketAddr {
        self.target
    }

    /// Send one record carrying `payload`.
    ///
    /// Nothing here stops the lane: a payload too long for a record, or a
    /// datagram the network would not take, is counted as failed and the
    /// next one is tried. The sequence number still advances, so a listener
    /// sees the gap.
    pub fn send(&mut self, payload: &[u8], now_unix_nanos: u64) {
        let record = Record::with_payload(
            Carrier::Osc.id(),
            self.seq,
            now_unix_nanos,
            self.frame,
            payload.to_vec(),
        );
        self.seq = self.seq.wrapping_add(1);
        self.frame = self.frame.wrapping_add(1);
        let delivered = Carrier::Osc
            .frame(&record)
            .is_ok_and(|framed| self.socket.send_to(&framed, self.target).is_ok());
        if delivered {
            self.sent += 1;
        } else {
            self.failed += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rosc::{OscMessage, OscPacket, OscType};

    #[test]
    fn a_message_is_laid_out_as_the_specification_says() {
        let m = encode_blob("/truss/dmx", b"abcde").unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(b"/truss/dmx\0\0"); // 10 bytes, NUL, one pad
        expected.extend_from_slice(b",b\0\0");
        expected.extend_from_slice(&[0, 0, 0, 5]);
        expected.extend_from_slice(b"abcde\0\0\0");
        assert_eq!(m, expected);

        let aligned = encode_blob("/abc", b"").unwrap();
        assert_eq!(
            aligned, b"/abc\0\0\0\0,b\0\0\0\0\0\0",
            "a string of 4 still ends in a NUL"
        );
    }

    #[test]
    fn a_message_reads_back_and_everything_else_reads_as_nothing() {
        let m = encode_blob(ADDRESS, b"\x00\x01\x02\x03").unwrap();
        assert_eq!(decode_blob(&m), Some((ADDRESS, &b"\x00\x01\x02\x03"[..])));

        let mut bundle = b"#bundle\0".to_vec();
        bundle.extend_from_slice(&[0; 8]);
        bundle.extend_from_slice(&(m.len() as u32).to_be_bytes());
        bundle.extend_from_slice(&m);
        assert_eq!(decode_blob(&bundle), None, "a bundle is not a message");

        let int = b"/truss/dmx\0\0,i\0\0\0\0\0\x07";
        assert_eq!(decode_blob(int), None, "an int is not a blob");
        let two = b"/truss/dmx\0\0,bb\0\0\0\0\0";
        assert_eq!(decode_blob(two), None, "two blobs are not one");

        assert_eq!(decode_blob(&m[..m.len() - 1]), None, "cut inside the blob");
        assert_eq!(decode_blob(&m[..13]), None, "cut inside the tags");
        assert_eq!(decode_blob(b"/no-terminator"), None);
        assert_eq!(
            decode_blob(b"/\xff\xfe\0\0,b\0\0\0\0\0\0"),
            None,
            "not UTF-8"
        );
        assert_eq!(decode_blob(b""), None);

        let mut negative = encode_blob(ADDRESS, b"x").unwrap();
        negative[16..20].copy_from_slice(&(-1i32).to_be_bytes());
        assert_eq!(decode_blob(&negative), None, "a negative length");
    }

    #[test]
    fn rosc_reads_ours_and_we_read_rosc() {
        let blob = (0u8..200).collect::<Vec<_>>();
        let ours = encode_blob(ADDRESS, &blob).unwrap();
        let (rest, packet) = rosc::decoder::decode_udp(&ours).expect("rosc decodes it");
        assert!(rest.is_empty());
        match packet {
            OscPacket::Message(m) => {
                assert_eq!(m.addr, ADDRESS);
                assert_eq!(m.args, vec![OscType::Blob(blob.clone())]);
            }
            OscPacket::Bundle(_) => panic!("not a bundle"),
        }

        let theirs = rosc::encoder::encode(&OscPacket::Message(OscMessage {
            addr: ADDRESS.into(),
            args: vec![OscType::Blob(blob.clone())],
        }))
        .expect("rosc encodes it");
        assert_eq!(decode_blob(&theirs), Some((ADDRESS, blob.as_slice())));
    }

    #[test]
    fn a_sender_delivers_records_the_lane_can_score() {
        let listener = UdpSocket::bind("127.0.0.1:0").unwrap();
        listener
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let mut sender = Sender::to(listener.local_addr().unwrap()).expect("binds");

        let body = crate::payload::encode(&[crate::payload::Block {
            universe: 3,
            start: 0,
            age_us: 5,
            values: vec![1, 2, 3],
        }])
        .unwrap();
        sender.send(&body, 1_000);
        sender.send(&body, 2_000);
        assert_eq!(sender.sent, 2);

        let mut buf = [0u8; 2048];
        for expected_seq in 0..2u32 {
            let (n, _) = listener.recv_from(&mut buf).expect("a datagram arrives");
            let (address, blob) = decode_blob(&buf[..n]).expect("it is our message");
            assert_eq!(address, ADDRESS);
            let record = Record::decode(blob).expect("carrying a record");
            assert_eq!(record.carrier, Carrier::Osc.id());
            assert_eq!(record.seq, expected_seq);
            assert_eq!(record.frame_index, expected_seq);
            assert_eq!(record.payload, body);
            let blocks = crate::payload::decode(&record.payload).unwrap();
            assert_eq!(blocks[0].universe, 3);
            assert_eq!(blocks[0].values, vec![1, 2, 3]);
        }
    }

    #[test]
    fn a_payload_too_long_for_a_record_is_counted_not_sent() {
        let listener = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut sender = Sender::to(listener.local_addr().unwrap()).unwrap();
        let too_long = vec![0u8; crate::record::MAX_PAYLOAD_LEN + 1];
        sender.send(&too_long, 0);
        assert_eq!((sender.sent, sender.failed), (0, 1));
    }
}
