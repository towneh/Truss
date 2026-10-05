//! Carries DMX lighting control inside a live video stream.
//!
//! A lighting desk speaks Art-Net over the local network, and that does not
//! leave the building. Video does. Truss takes the desk's output, packs it into
//! H.264 or HEVC SEI user data on its way through an RTMP relay, and it arrives
//! wherever the video does, frame-locked to the picture because it rides inside
//! the access unit rather than beside it.
//!
//! This works because SEI survives a remux. It does **not** survive a transcode,
//! so whether a given path carries it is a property of that path rather than of
//! this crate — which is what `truss-detect` is for: point it at your own egress
//! and it reports what actually arrived, before you build a show on the answer.
//!
//! The record framing is self-delimiting and self-verifying, so a reader can
//! recognise a survivor in a stream it does not otherwise understand, and can
//! tell "arrived damaged" from "did not arrive".

pub mod artnet;
pub mod carrier;
pub mod codec;
pub mod console;
pub mod creds;
pub mod detect;
pub mod flv;
pub mod h264;
pub mod hevc;
pub mod inject;
pub mod invariants;
pub mod monitor;
pub mod osc;
pub mod payload;
pub mod record;
pub mod relay;
pub mod source;
