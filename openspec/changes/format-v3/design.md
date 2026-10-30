# Design

## Context

Format 2.1 was built for replay. Mogsafe now makes it an archive format: every uploaded capture is kept for good in R2, and many people will upload. A review on 2026-10-30 read the C++ library, every binding, Mogsafe's ingest, and the captain converter against `FORMAT.md`. Its findings, and the owner's answers the same day, drive this change:

- Compatibility may break until the owner declares production. Nothing is archived yet; the one 1.x Memoria file on the owner's PC does not need to stay readable.
- Recorders start a new file when the character changes, not at every logout. Twenty relogs on one character in an hour would otherwise make twenty files, each carrying a 64 KiB dictionary.
- The header says whether a capture is retail or private-server traffic. Both go in the same archive eventually.
- Packets injected or blocked by addons are recorded, with flags.
- Recorders sign captures, so every capture traces to one key and a bad actor's uploads can be found and dropped by key.
- Chat is excluded first-class: stubbed by default, with byte-range redaction available. The archive's required policy lives in Mogsafe; xicap carries the mechanism.

## Goals / Non-Goals

**Goals:**
- A file plus `FORMAT.md`, RFC 8878, RFC 8032, and FIPS 180-4 is enough to decode and check a capture.
- A recording file only grows; a crash loses at most the frame being built.
- Damage costs the damaged frame, not the rest of the file.
- Every capture names the key that recorded it, and any change after recording shows.
- Private chat never reaches disk.

**Non-Goals:**
- Proving packets are genuine. A recorder controls its own key and can sign invented traffic; cross-checking captures against each other is Analytics and Auth work.
- Hiding identity inside the file. Packets carry character names and ids; privacy beyond chat exclusion comes from access control, to be designed when it matters.
- Reading 1.x or 2.x files.
- Recording the 28-byte datagram header and its sequence numbers. Ashita does not expose them as far as the review could tell; the FFXI packet header's own sequence is kept.

## Decisions

### Header written once, end fields in the footer
The writer writes the header when the first frame is flushed, so `startTimestamp` is known by then; nothing needs rewriting. `endTimestamp`, `totalPacketCount`, and `endZoneId` move to the footer trailer.
- Mogsafe's close drops `xicap_same_except_patched` and the header rewrite: the uploader sends only the file's hash.
- The header can carry its own CRC.
- Rejected: keep the rewrites. They are the only thing standing between the format and an append-only file, and they make Mogsafe compare two headers on every close.

### Feature mask, frame kinds, two flag groups
- Header: a u64 `requiredFeatures`; a reader refuses any bit it does not know. Format 3.0 defines bits for exclusion and signing.
- Frames: a kind byte. Kinds below 0x80 may be skipped by readers that do not know them; kinds from 0x80 must be understood. 3.0 defines packets (0x80) and checkpoint (0x01).
- `PacketEntry.flags`: the low byte holds flags a reader may ignore (injected, blocked, modified, first in datagram); the high byte holds flags it must understand (excluded, redacted). Direction stays bit 0 and every 3.x reader knows it.
- Rejected: one version number for everything. A reader cannot tell which part of a newer file it can still read.

### Frame magic and recovery
Each frame starts with `XCFR`, then the kind, then the 2.1 fields. The CRC covers the magic through the payload. Without a footer, a reader scans frame by frame; in recovery mode it searches for the next magic whose frame passes its CRC. Cost: 5 bytes per frame, about 30 KB for an 8-hour capture of about 9 MB.

### Magic
`\x89XCAP\r\n\x1a\n` (8 bytes), in the PNG pattern: the high byte catches 7-bit transfers, and the `\r\n`, `\x1a`, and `\n` catch line-ending rewrites and DOS `type`.

### Checksums
CRC-32/IEEE everywhere, as 2.1 uses for frames. The signature chain (below) is what defends against deliberate change; CRCs find accidental damage and keep recovery cheap.

### Dictionary
The dictionary is required as the first extension block whenever `dictionaryId` is not zero, and the reader's built-in fallback goes. 64 KiB per file is the price of a file that decodes on its own; at 1.1 MB per hour it is a few percent of a session.

### Timestamps
Live recorders read the wall clock once at the start and add a monotonic clock after, so timestamps never go backwards. The writer clamps an earlier time to the last one instead of letting the delta wrap. A header byte names the clock source: live, converted with an inferred offset, or unknown. Memoria's habit of adding 1 ms per tied packet goes: equal timestamps are allowed.

### Identity, rotation, and links
`captureId` is 16 random bytes; `previousCaptureId` is the capture this one continues, or zeros. A same-character relog continues the file with a marker, so the header's character is right for the whole file. The 24-hour cap keeps any one file bounded. Mogsafe groups linked captures into runs for search.

### Signing
- Ed25519 (RFC 8032) over a SHA-256 chain. `h0 = SHA-256(header)`, then `h = SHA-256(h || block)` for every extension block and frame in file order.
- A checkpoint is a frame of kind 0x01 holding the chain value it signs and the signature. The writer writes one at the first frame boundary after 60 seconds without one. Cost: about 100 bytes a minute, about 50 KB for 8 hours.
- The footer signs the final chain value together with the end fields.
- The header carries the 32-byte public key. Mogsafe registers keys per uploader; the format only names the key.
- Captain imports are signed by Mogsafe's converter key, so "converted by Mogsafe" is itself provable.
- Rejected: signing every frame. That costs 64 bytes per frame (about 370 KB per 8 hours) for no more than a one-minute checkpoint gives.
- Rejected: signing only at close. A cut-off capture, the common case after a crash, would carry no proof at all.

### Exclusion
- A policy is an extension block: a name, a version, and rules `(direction, opcode, action)`, where the action is a stub or a list of byte ranges to zero. The writer applies it before compressing, so excluded bytes never exist on disk.
- Byte ranges keep the library free of packet meanings; the policy carries the knowledge.
- A stub keeps the 4-byte FFXI header, which holds the original size and the sequence counter, so nothing about timing or order is lost.
- The library ships a default policy that stubs chat in both directions. The exact chat opcodes are checked against the client's resources during implementation.
- Rejected: dropping packets with no trace. A reader could not tell "the server never sent it" from "it was left out".

### Signing library
Monocypher, vendored as one C file, gives Ed25519 under RFC 8032 and builds on MSVC x86 and x64, Linux, and Emscripten with no system package. SHA-256 is about 200 lines under `src/internal/` beside the CRC, or Monocypher's SHA-512 if the chain switches to it. Implementation checks this choice against libsodium first: libsodium is the more widely used library, but it needs a package on every platform and a Wasm build.

### Test-only reader
`tests/spec_reader.py` reads format 3 from `FORMAT.md` alone, with `zstandard` and `cryptography`. It is not a binding and is never shipped; it exists to prove the spec is complete. `AGENTS.md`'s rule that bindings wrap the C++ library stays.

### Durability
- The writer flushes the file stream after each frame, so a frame reaches the operating system when written. It does not `fsync`: losing the last seconds on power loss is acceptable, and syncing every 5 seconds wears consumer disks for little.
- `flush()` closes the frame being built. Recorders call it on a timer, so a quiet session still reaches disk.
- Write errors throw.

## Risks / Trade-offs

- [Per-file overhead: dictionary, key, and checkpoints, about 65 KB plus 6 KB an hour] → Rotation only on character change keeps the file count low.
- [A stolen or shared recorder key signs anything] → The signature proves which key, not which person. Mogsafe can revoke a key and find everything it signed.
- [Vendored crypto] → Monocypher is small, audited, and maintained. Implementation tests it against RFC 8032 vectors in CI.
- [Chat opcodes missed by the default policy] → The conformance set includes every chat opcode found in the resources, and the policy's version is in each file, so a later fix shows which captures predate it.

## Migration Plan

None for data: nothing is archived. Mogsafe's change in `ffxi-dev/vault` lands after this one is tagged, and uploads stay closed until both are done.

## Open Questions

- Checkpoint interval: 60 seconds is a guess. Shorter costs a little more space and loses less proof after a crash.
- Whether the chain should use SHA-512, which Ed25519 already needs, to save one hash implementation.

## Implementation Notes

None yet.
