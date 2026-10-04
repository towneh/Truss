# Truss

DMX lighting control carried inside a live video stream, as H.264 SEI user data.

A lighting desk speaks Art-Net across the local network, and that traffic does
not leave the building. Video does. Truss takes what the desk is sending, packs
it into the video as that passes through an RTMP relay, and it arrives wherever
the video arrives. The data rides inside the access unit rather than alongside
it, so it stays locked to the picture.

The picture itself is unaltered. What Truss adds sits in a part of the bitstream
a decoder is required to skip over.

## Will it work on your path

SEI survives a remux. It does not survive a transcode. A CDN that repackages the
stream will carry it; one that re-encodes will strip the lane out entirely. No
warning is given in either case, because the video continues to work and the
lighting data simply never arrives.

That is worth establishing before anything else:

```sh
truss-detect rtmp rtmp://your-egress/live/stream --max-seconds 30
```

This reads your own egress and reports what arrived. It distinguishes the three
outcomes that matter: nothing arrived, something arrived but was damaged,
something arrived intact. Only the last is a basis for running a show.

The reader is a subcommand. `rtmp` and `rtsp` go through ffmpeg, which needs to
be on your PATH; `ts` takes an MPEG-TS URL, a local file, or `-` for stdin, and
is read directly. `--max-seconds` and `--max-mb` bound the run, `--json` writes
the full report for something else to read, and `--save` keeps the bytes, so a
disagreement about what arrived can be settled against the capture rather than
against anyone's recollection of it.

## A dry run

`truss-detect` needs a stream that already carries records, and before the first
show there is not one. `truss-inject` writes them into a file, which is enough
to put the path under test with no desk and no encoder present:

```sh
ffmpeg -i source.mp4 -c:v libx264 -f flv plain.flv
truss-inject --input plain.flv --output carried.flv
ffmpeg -re -i carried.flv -c copy -f flv rtmp://ingest.example.net/live/<key>
```

`-c copy` publishes the file as it stands, so what reaches the egress is what
`truss-inject` wrote, and `truss-detect` against the egress then scores the path
itself.

The same file can also be read back without leaving the machine, which separates
a fault in the carrier from a fault in the network:

```sh
ffmpeg -i carried.flv -c copy -f mpegts carried.ts
truss-detect ts carried.ts
```

The body written here is derived from the sequence number rather than from a
desk, so what this establishes is that the path carries bytes intact, not that
the lighting is right. `--payload-len` sets how much each record carries,
`--every N` and `--keyframes-only` reduce how often records are written, and
`--max-added-kbps` refuses to write the file at all if the result would cost
more than was budgeted for. That is a better place to find out than a show.

## Running a show

```sh
truss-relay \
  --listen 127.0.0.1:1935 \
  --ingest ingest.example.net:1935 \
  --stream-key-file /run/credentials/truss/key \
  --artnet
```

Point your encoder at `rtmp://127.0.0.1/live` with any stream key. Truss holds
the real one, so it need never be entered into OBS.

Point the lighting desk at the machine's Art-Net port, 6454 by default. Truss
retains the newest value for each universe and packs as much as will fit into
each video frame. Where the payload budget is exceeded it rotates through the
universes, so one at the far end of the patch cannot starve.

A desk that lists nodes rather than broadcasting will find one named Truss.
The relay answers `ArtPoll` with the address the desk can reach it on, which on
a machine with several adapters is the one on the desk's own subnet, and sends
the answer to the desk directly and as a broadcast on that subnet. Pick it and
assign it the universes to carry. Until DMX arrives the status line names the
controller that found the node, so a show that is lit on the desk and dark in
the stream is a patch problem and not a network one. The node advertises the universes it has heard, up to 32, and
universe 0 before it has heard any, so a desk that searches by universe finds
it from the first poll after that universe starts arriving.

A desk on this same machine shares UDP port 6454 with the relay, and a packet
sent to a shared port by address reaches whichever socket the operating system
picks. The relay therefore also listens on 127.0.0.1, which a packet addressed
there reaches ahead of any socket bound to every address, and tells a desk on
this machine to send there. A desk set to send to localhost needs no discovery
at all; set it to send to this node or to localhost, not both, or every
universe arrives twice.

`truss-dmxmon` reports what a receiver would decode. It shows values rather than
counts, which is the more useful measure: a stream can deliver every record
intact and still carry a snapshot that never changes, and that is a dead show
which scores correctly on every other test.

```sh
truss-dmxmon rtsp rtsp://your-egress/live/stream --universe 0
```

`--universe` prints that universe as a grid on every status line. `--watch
0.1-16` prints only the channels named, and only as they change, which is the
shorter way to answer whether one fixture is moving; slots are numbered from 1,
as on a desk. The readers here are `ts` and `rtsp`, so an RTMP egress is remuxed
on the way in:

```sh
ffmpeg -i rtmp://your-egress/live/stream -c copy -f mpegts - | truss-dmxmon ts -
```

## With no ingest to point at

The relay can be exercised without a real one. ffmpeg will accept a publish on a
port, which is enough to stand in for an ingest and put the whole path on a
single machine. Three terminals, started in this order:

```sh
ffmpeg -listen 1 -f flv -i rtmp://127.0.0.1:1936/live -c copy -f mpegts egress.ts
truss-relay --listen 127.0.0.1:1935 --ingest 127.0.0.1:1936 --stream-key-file key.txt
ffmpeg -re -i source.mp4 -c:v libx264 -f flv rtmp://127.0.0.1:1935/live/anykey
```

The order matters, as each waits for the one before it. OBS can take the place
of the third terminal, pointed at the same URL. The key in `key.txt` can be
anything, since the stand-in accepts whatever it is given.

`truss-detect ts egress.ts` then scores what left the far end, and adding
`--artnet` to the relay puts a desk in the same loop. None of it leaves the
machine.

## The stream key

No flag accepts the key. An argument is visible to anything that can list
processes, including other users on the same machine, so the option does not
exist.

Truss resolves the key in this order:

| Source | Intended for |
| --- | --- |
| `--stream-key-file <path>`, or `-` for stdin | Services. systemd `LoadCredential=` places the secret on a tmpfs readable only by the unit, and container secrets are presented as files in the same way |
| `TRUSS_STREAM_KEY` | Convenience, and weaker for it. A process environment is readable through `/proc` on Linux and is retained in crash dumps |
| A prompt | When stdin is a terminal and no earlier source resolved |

An RTMP publish URL is `rtmp://host/app/<key>`, so the key is the URL. Truss
holds the host, the application and the key separately, composes the URL only at
the point of connecting, and passes anything it prints through a redactor first,
including child process output.

The redactor exists because the leak is not something a caller can avoid by
being careful. ffmpeg writes the publish URL to its own stderr, and that output
is shown deliberately: suppressing it makes "the server refused the stream"
indistinguishable from "nothing arrived". Both can hold only if the text is
scrubbed as it passes.

A systemd unit:

```ini
[Service]
LoadCredential=key:/etc/truss/stream.key
ExecStart=/usr/local/bin/truss-relay --ingest ingest.example.net:1935 \
          --stream-key-file %d/key --artnet
```

## What arrives

Values are absolute rather than deltas, so a late or dropped frame is corrected
by the next, and a client joining part way through a show is correct within one
frame.

Each block carries its own age. Universes are latched as their packets arrive,
and DMX at 44 Hz does not divide evenly into a frame grid, so a consumer needs
to know how stale each universe is rather than assume they were sampled
together.

Blocks are runs rather than whole universes, so transmitting only the channels
that have changed requires no separate format.

The framing carries a magic, a version, a sequence number, a send time, a length
and a CRC. A reader can therefore identify a record in a stream it otherwise
knows nothing about, and can distinguish one that arrived damaged from one that
never arrived. Those are separate faults with separate causes.

## Bitrate cost

The lane shares a bitrate ceiling with the picture, so the cost of a given patch
is worth establishing before committing to it.

A full snapshot is 8 bytes of header plus 522 for each universe, that being 512
channels and a 10 byte block header. At 30 frames per second, transmitting every
universe on every frame:

| Universes | Per frame | Bitrate | Share of a 6,320 kb/s ceiling |
| --- | --- | --- | --- |
| 1 | 530 B | 127 kb/s | 2% |
| 4 | 2,096 B | 503 kb/s | 8% |
| 8 | 4,184 B | 1,004 kb/s | 16% |
| 12 | 6,272 B | 1,505 kb/s | 24% |
| 16 | 8,360 B | 2,006 kb/s | 32% |
| 20 | 10,448 B | 2,508 kb/s | 40% |

The ceiling in the final column is an example, being 6,000 kb/s of video and 320
of audio counted together. Substituting your own figure moves the shares without
changing the shape: at twenty universes on every frame the lane accounts for
roughly two fifths of the ceiling, and the encoder must be configured for the
remainder.

Framing and NAL overhead are additional to the payload figures, and vary with
content. Long runs of zero channels expand more than active ones, because a
coded bitstream has to break up runs of zero bytes, and an unpatched universe is
largely zeros.

Two options reduce the cost. Blocks are runs rather than whole universes, so
transmitting only the channels that have changed is a fraction of a full
snapshot for a typical cue. And `--every N` injects on every Nth frame, dividing
the rate by N at the cost of that much delay before a change is carried.

The relay measures what actually leaves rather than relying on the arithmetic
above. `--warn-kbps` reports when the outgoing average exceeds a figure you set,
and `--abort-kbps` stops the relay rather than allowing it to exceed one.

## Building

```sh
cargo build --release
cargo test
```

Rust 1.87 or newer. Windows and Linux are both supported, and both are built and
tested in CI. None of the code is platform specific.

Every parser here reads bytes it did not choose, so there is generative cover
alongside the unit tests. `cargo test` runs it on stable, on both platforms,
with no extra toolchain: the properties live in `truss::invariants` and
`tests/properties.rs` drives them with mutated input, deterministically, so a
failure names the case that caused it.

The same properties are driven by libFuzzer for the deeper search, which needs
nightly and is happiest on Linux:

```sh
cargo run --example seed-corpus
cargo +nightly fuzz run ts_feed
```

The seed corpus is built with the crate's own encoders, so a run starts inside
the interesting code rather than working out what a sync byte is. A weekly job
runs each target and keeps what it finds.

## Status

The carrier is measured rather than assumed. Across RTSP, MPEG-TS and RTMP
egress on a remuxing CDN: no loss in steady state, no corruption, payloads to
10,448 bytes per frame, a median end to end latency of around 112 ms, and 47,038
consecutive frames across half an hour without a gap. Live desk data has run the
full path at twenty universes.

Nothing longer than a thirty minute publish has been measured, and nothing on a
degraded uplink.

## Licence

MIT or Apache-2.0, at your option.
