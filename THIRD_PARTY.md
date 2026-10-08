# Third-party code

## retina

`third_party/retina` is [retina](https://github.com/scottlamb/retina) 0.4.19,
the RTSP client `truss-relay --source` uses.

Copyright (c) 2021 Scott Lamb. MIT or Apache-2.0, at your option; the licence
texts are `third_party/retina/LICENSE-MIT.txt` and `LICENSE-APACHE.txt`.

## Basis media player

The copy of retina carries patches, listed in `third_party/retina/PATCHES.md`
with what each is for. Most come from the Basis media player's native engine
(`Basis/Packages/com.basis.mediaplayer/Native~` in the
[Basis](https://github.com/BasisVR/Basis) repository); VRCDN's RTSP edge needs
the first. The RTSP set-up in `src/pull/session.rs` is based on the player's.

Copyright (c) 2026 basis-media contributors. MIT or Apache-2.0, at your option,
under the same licence texts as Truss (`LICENSE-MIT`, `LICENSE-APACHE`).

Three of the patches are Truss's own, marked "Added in Truss" in `PATCHES.md`:
the access unit ceilings for H.265, CRA and BLA pictures as keyframes, and the
SPS reorder count. They are under Truss's licence.
