//! The carriers under test, and the framing each one wraps a record in.
//!
//! RTMP ingest is the constraint that shapes this list. FLV can carry exactly
//! one video elementary stream, one audio elementary stream, and AMF script
//! messages — so a side-band payload has only two places to hide: inside the
//! video bitstream, or in the container's script channel. A separate MPEG-TS
//! private-data PID would be a third place, but it is not reachable without
//! SRT ingest, so it is absent here by necessity rather than by choice.

use crate::h264;
use crate::osc;
use crate::record::{EncodeError, Record};
use serde::Serialize;

/// UUID stamped on every `user_data_unregistered` message we emit, so the
/// detector can tell our SEI from an encoder's own (x264 stamps its build
/// string through the same payload type).
pub const PROBE_UUID: [u8; 16] = [
    0xb1, 0xf0, 0xa7, 0xd4, 0x9c, 0x3e, 0x4a, 0x52, 0x8f, 0x61, 0x2d, 0x7c, 0x5e, 0x0b, 0x93, 0xa8,
];

/// ITU-T T.35 country code for the United States, the value in practice use
/// for privately-scoped payloads.
pub const T35_COUNTRY_CODE: u8 = 0xB5;
/// Terminal provider code. Deliberately not ATSC's `0x0031`, so a caption
/// parser upstream does not mistake the probe for CEA-608 data.
pub const T35_PROVIDER_CODE: u16 = 0x5342;

/// AMF data message name for the custom-message carrier.
pub const AMF_MESSAGE_NAME: &str = "onBasisProbe";
/// Key added to the standard `onMetaData` object for the metadata-key carrier.
pub const AMF_METADATA_KEY: &str = "basisProbe";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Class {
    /// Rides inside the H.264 elementary stream. Survives any pure remux that
    /// treats the video payload as opaque.
    InVideoEs,
    /// Rides in the RTMP container alongside the media. Has no defined mapping
    /// into MPEG-TS or RTP, so egress-dependent by construction.
    Container,
    /// Sent on its own socket beside the stream, never inside it. Reaches a
    /// listener on the network, not a viewer of the stream, so no CDN is
    /// involved and nothing about its survival says anything about one.
    Network,
}

/// Where an in-video carrier's NAL belongs within the access unit.
///
/// H.264 puts SEI ahead of the primary coded picture and filler data after the
/// last VCL NAL of it. Getting this wrong does not stop a tolerant decoder, but
/// it makes a carrier non-conformant in a second way on top of whatever else it
/// is doing, which muddies what a negative result means.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Placement {
    BeforePicture,
    AfterPicture,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Carrier {
    /// SEI `user_data_unregistered` (payload type 5), UUID-tagged.
    SeiUnregistered,
    /// SEI `user_data_registered_itu_t_t35` (payload type 4).
    SeiT35,
    /// A custom AMF0 data message.
    AmfCustom,
    /// An extra key inside the standard `onMetaData` object.
    AmfMetadataKey,
    /// Filler-data NAL (type 12) with a non-conformant body.
    FillerNal,
    /// An OSC message, `/truss/dmx`, with the record as its one blob argument.
    Osc,
}

/// The carriers that go into a stream, which is what the relay and the
/// injector choose between.
pub const ALL: [Carrier; 5] = [
    Carrier::SeiUnregistered,
    Carrier::SeiT35,
    Carrier::AmfCustom,
    Carrier::AmfMetadataKey,
    Carrier::FillerNal,
];

/// Every carrier a record can arrive by, which is what a detector reports on.
pub const EVERY: [Carrier; 6] = [
    Carrier::SeiUnregistered,
    Carrier::SeiT35,
    Carrier::AmfCustom,
    Carrier::AmfMetadataKey,
    Carrier::FillerNal,
    Carrier::Osc,
];

impl Carrier {
    pub fn id(self) -> u8 {
        match self {
            Self::SeiUnregistered => 1,
            Self::SeiT35 => 2,
            Self::AmfCustom => 3,
            Self::AmfMetadataKey => 4,
            Self::FillerNal => 5,
            Self::Osc => 6,
        }
    }

    pub fn from_id(id: u8) -> Option<Self> {
        EVERY.into_iter().find(|c| c.id() == id)
    }

    pub fn slug(self) -> &'static str {
        match self {
            Self::SeiUnregistered => "sei-unreg",
            Self::SeiT35 => "sei-t35",
            Self::AmfCustom => "amf-custom",
            Self::AmfMetadataKey => "amf-onmeta",
            Self::FillerNal => "filler-nal",
            Self::Osc => "osc",
        }
    }

    pub fn class(self) -> Class {
        match self {
            Self::SeiUnregistered | Self::SeiT35 | Self::FillerNal => Class::InVideoEs,
            Self::AmfCustom | Self::AmfMetadataKey => Class::Container,
            Self::Osc => Class::Network,
        }
    }

    /// Only meaningful for the in-video carriers; the container carriers never
    /// touch the access unit.
    pub fn placement(self) -> Placement {
        match self {
            Self::FillerNal => Placement::AfterPicture,
            _ => Placement::BeforePicture,
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::SeiUnregistered => "SEI user_data_unregistered (type 5), UUID-tagged",
            Self::SeiT35 => "SEI user_data_registered_itu_t_t35 (type 4)",
            Self::AmfCustom => "custom AMF0 data message",
            Self::AmfMetadataKey => "extra key inside onMetaData",
            Self::FillerNal => "filler-data NAL (type 12), non-conformant body",
            Self::Osc => "OSC message /truss/dmx, record as a blob",
        }
    }

    /// Enabled unless the user opts in explicitly. The filler-NAL carrier is
    /// off by default: its body violates the filler RBSP rule, so a strict
    /// decoder downstream is entitled to reject the stream. OSC is not a
    /// stream carrier at all and is switched on by naming a listener.
    pub fn default_enabled(self) -> bool {
        !matches!(self, Self::FillerNal | Self::Osc)
    }

    /// Wrap an encoded record in this carrier's framing.
    ///
    /// For the in-video carriers this returns the complete NAL, ready to be
    /// length-prefixed into an AVCC access unit. For the container carriers it
    /// returns the hex text that goes into the AMF value.
    pub fn frame(self, record: &Record) -> Result<Vec<u8>, EncodeError> {
        let body = record.encode()?;
        Ok(match self {
            Self::SeiUnregistered => {
                let mut payload = Vec::with_capacity(16 + body.len());
                payload.extend_from_slice(&PROBE_UUID);
                payload.extend_from_slice(&body);
                h264::build_sei_nal(h264::SEI_UNREGISTERED, &payload)
            }
            Self::SeiT35 => {
                let mut payload = Vec::with_capacity(3 + body.len());
                payload.push(T35_COUNTRY_CODE);
                payload.extend_from_slice(&T35_PROVIDER_CODE.to_be_bytes());
                payload.extend_from_slice(&body);
                h264::build_sei_nal(h264::SEI_T35, &payload)
            }
            Self::FillerNal => h264::build_filler_nal(&body),
            Self::AmfCustom | Self::AmfMetadataKey => hex_encode(&body).into_bytes(),
            Self::Osc => osc::encode_blob(osc::ADDRESS, &body)?,
        })
    }

    /// Strip this carrier's framing from an SEI payload, returning the record
    /// bytes. `None` when the payload is not ours.
    pub fn unframe_sei(self, payload: &[u8]) -> Option<&[u8]> {
        match self {
            Self::SeiUnregistered => {
                let rest = payload.strip_prefix(&PROBE_UUID[..])?;
                Some(rest)
            }
            Self::SeiT35 => {
                let rest = payload.strip_prefix(&[T35_COUNTRY_CODE])?;
                let rest = rest.strip_prefix(&T35_PROVIDER_CODE.to_be_bytes()[..])?;
                Some(rest)
            }
            _ => None,
        }
    }
}

/// Uppercase hex. Chosen over base64 for the AMF carriers so the record magic
/// stays greppable in a raw capture: "TRUSSDMX" is `5452555353444D58`, which a
/// byte scan finds without knowing anything about AMF.
pub fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0x0F) as usize] as char);
    }
    s
}

pub fn hex_decode(text: &[u8]) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    fn nibble(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    text.chunks_exact(2)
        .map(|p| Some((nibble(p[0])? << 4) | nibble(p[1])?))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{DEFAULT_PAYLOAD_LEN, find_records};

    fn rec(c: Carrier) -> Record {
        Record::new(c.id(), 1234, 99, 7, DEFAULT_PAYLOAD_LEN)
    }

    #[test]
    fn ids_are_unique_and_round_trip() {
        for c in ALL {
            assert_eq!(Carrier::from_id(c.id()), Some(c));
        }
        let mut ids: Vec<u8> = ALL.iter().map(|c| c.id()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), ALL.len());
    }

    #[test]
    fn sei_carriers_round_trip_through_a_real_nal() {
        for c in [Carrier::SeiUnregistered, Carrier::SeiT35] {
            let record = rec(c);
            let nal = c.frame(&record).unwrap();

            let mut annexb = vec![0, 0, 0, 1];
            annexb.extend_from_slice(&nal);

            let mut found = None;
            h264::scan_sei_annexb(&annexb, |ty, payload| {
                if let Some(body) = c.unframe_sei(payload) {
                    found = Some((ty, Record::decode(body).expect("decodes")));
                }
            });

            let (ty, back) = found.expect("carrier payload located");
            let want_ty = match c {
                Carrier::SeiUnregistered => h264::SEI_UNREGISTERED,
                _ => h264::SEI_T35,
            };
            assert_eq!(ty, want_ty);
            assert_eq!(back, record);
            assert!(back.payload_intact());
        }
    }

    #[test]
    fn unframe_rejects_a_foreign_uuid() {
        // An encoder's own type-5 SEI must not be attributed to the probe.
        let foreign = [0u8; 16];
        let mut payload = foreign.to_vec();
        payload.extend_from_slice(b"x264 - core 164");
        assert!(Carrier::SeiUnregistered.unframe_sei(&payload).is_none());
    }

    #[test]
    fn filler_carrier_round_trips() {
        let record = rec(Carrier::FillerNal);
        let nal = Carrier::FillerNal.frame(&record).unwrap();
        assert_eq!(h264::nal_type(nal[0]), h264::NAL_FILLER);
        let rbsp = h264::unescape_rbsp(&nal[1..]);
        let back = Record::decode(&rbsp).expect("decodes");
        assert_eq!(back, record);
    }

    #[test]
    fn hex_round_trips_and_keeps_the_magic_greppable() {
        let record = rec(Carrier::AmfCustom);
        let text = Carrier::AmfCustom.frame(&record).unwrap();
        // Derived from the constant rather than written out again: a second
        // copy of the magic is a second thing to forget when it changes, and
        // the point of this row is that the magic survives the encoding.
        let magic_hex = hex_encode(&crate::record::MAGIC);
        assert!(
            text.windows(magic_hex.len())
                .any(|w| w == magic_hex.as_bytes()),
            "hex of the magic must appear verbatim, looked for {magic_hex}"
        );
        let back = hex_decode(&text).expect("decodes");
        assert_eq!(Record::decode(&back).unwrap(), record);
        // And the decoded bytes are findable by the generic scanner.
        assert_eq!(find_records(&back).len(), 1);
    }

    #[test]
    fn hex_decode_rejects_rubbish() {
        assert!(hex_decode(b"ABC").is_none(), "odd length");
        assert!(hex_decode(b"ZZ").is_none(), "not hex");
    }

    #[test]
    fn only_filler_is_off_by_default() {
        let off: Vec<_> = ALL.iter().filter(|c| !c.default_enabled()).collect();
        assert_eq!(off, vec![&Carrier::FillerNal]);
    }
}
