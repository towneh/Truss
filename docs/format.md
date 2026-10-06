# Record format

What Truss writes into a stream, byte by byte, and the standards each part
rests on. A player that implements this can read Truss records; the Basis Media
Player and VRSL were built to it. The source of truth is `src/record.rs`,
`src/payload.rs` and `src/carrier.rs`.

All integers are big-endian.

## The record

Every carrier ships the same record. It carries its own magic, length and CRC,
so a reader can find one in bytes it otherwise knows nothing about, and can
tell a damaged record from a missing one.

| Offset | Length | Field |
| --- | --- | --- |
| 0 | 8 | Magic, `TRUSSDMX` |
| 8 | 1 | Version, currently 1 |
| 9 | 1 | Carrier id (below) |
| 10 | 4 | Sequence number |
| 14 | 8 | Send time, Unix nanoseconds |
| 22 | 4 | Frame index |
| 26 | 2 | Payload length, N |
| 28 | N | Payload |
| 28+N | 4 | CRC-32 over bytes 0 to 28+N |

The CRC is the common CRC-32 used by zlib and Ethernet (polynomial
`0x04C11DB7`, reflected).

## The DMX payload

A record carrying live DMX holds this payload. A test record from
`truss-inject`, or the relay without `--artnet`, holds bytes derived from the
sequence number instead, which is how `truss-detect` tells a rewritten record
from an intact one.

| Offset | Length | Field |
| --- | --- | --- |
| 0 | 4 | Magic, `DMXS` |
| 4 | 1 | Version, currently 1 |
| 5 | 1 | Flags. `0x01`: values are absolute |
| 6 | 2 | Block count |
| 8 | | Blocks |

Each block:

| Offset | Length | Field |
| --- | --- | --- |
| 0 | 2 | Universe, the 15-bit Art-Net port address |
| 2 | 2 | Start slot, from 0 |
| 4 | 2 | Length, N |
| 6 | 4 | Age: microseconds between the universe being captured and the record's send time |
| 10 | N | Values, one byte per slot |

A universe may appear in more than one block. Where two blocks cover the same
slot, the later one wins, as a later Art-Net packet would. The relay currently
sends each universe as one block from slot 0.

## Carriers

The carrier id in the record says how it travelled.

| Id | Name | Where it sits |
| --- | --- | --- |
| 1 | `sei-unreg` | SEI `user_data_unregistered` (payload type 5), after a 16-byte UUID, ahead of the picture |
| 2 | `sei-t35` | SEI `user_data_registered_itu_t_t35` (payload type 4), after country code `0xB5` and provider code `0x5342`, ahead of the picture |
| 3 | `amf-custom` | An AMF0 data message, `onBasisProbe`, as uppercase hex |
| 4 | `amf-onmeta` | A `basisProbe` key in `onMetaData`, as uppercase hex |
| 5 | `filler-nal` | A filler-data NAL (type 12 in H.264, 38 in HEVC) after the picture. Its body breaks the filler rules, and a strict decoder may reject the stream |
| 6 | `osc` | An OSC message, `/truss/dmx`, with the record as its one blob argument. Sent beside the stream, not in it |

The relay sends `sei-unreg` unless `--carriers` names others, and
`truss-inject` sends `sei-unreg` and `sei-t35`. The Basis Media Player reads
`sei-unreg` only.

The UUID for `sei-unreg` is `b1f0a7d4-9c3e-4a52-8f61-2d7c5e0b93a8`. It lets a
reader tell Truss's SEI from an encoder's own, since x264 writes its build
string through the same payload type. The provider code for `sei-t35` is
chosen to avoid ATSC's `0x0031`, so a caption parser does not mistake a record
for CEA-608 data.

SEI goes through the codec's usual emulation prevention. A reader removes the
`0x03` bytes before looking for the magic.

## Standards

| Area | Standard | Used for |
| --- | --- | --- |
| H.264 | [ITU-T H.264](https://www.itu.int/rec/T-REC-H.264) (ISO/IEC 14496-10), Annex D | SEI payload types 4 and 5, filler NAL type 12, emulation prevention |
| HEVC | [ITU-T H.265](https://www.itu.int/rec/T-REC-H.265) (ISO/IEC 23008-2), Annex D | Prefix and suffix SEI (NAL types 39 and 40), filler NAL type 38, the two-byte NAL header |
| T.35 | [ITU-T T.35](https://www.itu.int/rec/T-REC-T.35) | Country code in the `sei-t35` carrier |
| UUID | [RFC 9562](https://www.rfc-editor.org/rfc/rfc9562) | The 16-byte tag on `sei-unreg` |
| RTMP and FLV | Adobe RTMP 1.0 and FLV 10.1 specifications; [Enhanced RTMP](https://github.com/veovera/enhanced-rtmp) | Ingest and relay; HEVC under the legacy CodecID 12 and the `avc1` and `hvc1` FourCC headers |
| MPEG-TS | [ITU-T H.222.0](https://www.itu.int/rec/T-REC-H.222.0) (ISO/IEC 13818-1) | Reading egress; PMT stream types `0x1B` (H.264) and `0x24` (HEVC) |
| Art-Net | [Art-Net 4](https://art-net.org.uk/), Artistic Licence | ArtDmx, ArtPoll and ArtPollReply |
| OSC | [OSC 1.0](https://opensoundcontrol.stanford.edu/spec-1_0.html) | The `osc` carrier |
| DMX | [ANSI E1.11](https://tsp.esta.org/) (DMX512-A) | 512 slots to a universe |
