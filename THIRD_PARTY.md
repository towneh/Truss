# Third-party code

## retina

`third_party/retina` is [retina](https://github.com/scottlamb/retina) 0.4.19,
the RTSP client `truss-relay --source` uses.

Copyright (c) 2021 Scott Lamb. MIT or Apache-2.0, at your option; the licence
texts are `third_party/retina/LICENSE-MIT.txt` and `LICENSE-APACHE.txt`.

## Basis media player

The copy of retina carries the Basis media player's patches, listed in
`third_party/retina/PATCHES.md`, which says what each is for; VRCDN's RTSP edge
needs the first. They come from the player's native engine
(`Basis/Packages/com.basis.mediaplayer/Native~` in the
[Basis](https://github.com/BasisVR/Basis) repository), as does the shape of
the RTSP set-up in `src/pull/session.rs`.

Copyright (c) 2026 basis-media contributors. MIT or Apache-2.0, at your option,
under the same licence texts as Truss (`LICENSE-MIT`, `LICENSE-APACHE`).
