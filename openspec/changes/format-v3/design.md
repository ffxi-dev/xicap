# Design

## Context

Format 2.1 was built for replay. Mogsafe now makes it an archive format: every uploaded capture is kept for good in R2, and many people will upload. A review on 2026-10-30 read the C++ library, every binding, Mogsafe's ingest, and the captain converter against `FORMAT.md`. Its findings, and the owner's answers the same day, drive this change:

- Compatibility may break until the owner declares production. Nothing is archived yet; the one 1.x Memoria file on the owner's PC does not need to stay readable.
- Recorders start a new file when the character changes, not at every logout. Twenty relogs on one character in an hour would otherwise make twenty files, each carrying a 64 KiB dictionary.
- Two hard constraints: a capture is pinned to one character, for linking to Vault accounts later; and a custom client must be able to replay it, so the file holds all the context it needs as packets. Client memory snapshots go.
- The format records more than the game connection: the shipped plugin hooks the search server, which serves `/search` and the auction house, and IRC and profile traffic come later.
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
- Replaying a capture that starts mid-session on its own. Replay walks back through `previousCaptureId` to the capture that starts at the login.
- Defining the IRC, profile, and lobby channels' contents. Each gets its registry entry when its hooks exist.

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

### Packets are the whole context
The 2.1 extensions 0x0001 to 0x0007 copied client memory (player, inventory, entities, missions, spells, abilities) and the lobby's character blob. They are tied to one client build, cannot be checked against anything, and a custom client decades from now cannot load them. The server resends a character's whole state on the zone-in after a login, so a capture that starts at a login has it all as packets. The ids go; extensions remain for format-level data (dictionary, exclusion policy, import source) and metadata, never for state.

### Channels
Each packet entry gains a channel byte, numbered from a registry in `FORMAT.md`: 0 game server and 1 search server in 3.0. Search traffic (`/search`, the auction house) runs over its own connection, so it cannot share the game channel's opcode space or its 4-byte header; lobby, IRC, and profile traffic will be the same. One clock orders all channels.
- A new channel is a minor version: a reader passes on packets of an unknown channel with their number, so a viewer still shows the game channel of a file that also carries one it does not know.
- Each registry entry defines the channel's packet header, what the opcode field holds, and what a stub keeps.
- The packet length grows to 32 bits. FFXI packets fit in 16, but nothing says profile or IRC payloads will, and the cost after compression is close to nothing.
- Rejected: one frame per channel. Search traffic is sparse and interleaves with game traffic, so frames would split at every search.

### Identity, rotation, and links
`captureId` is 16 random bytes; `previousCaptureId` is the capture this one continues, or zeros. Files start only at a login, so each one replays on its own:
- A login of another character starts a new file; the same character relogging continues the file with a marker, so the header's character is right for the whole file.
- No timer cuts a session. A week-long session is one file of about 180 MB, which the uploader and Mogsafe handle like any other.
- A recorder that starts after a crash or a late load marks its capture as starting mid-session and links it to the one before. Replay walks back to the capture that starts at the login.
- The header's character is the recorder's claim. Readers report a capture whose zone-in packets name another character, and Mogsafe refuses it.
- Rejected: a 24-hour cap. It would cut a session mid-way and make files a replay cannot use alone.

Mogsafe groups linked captures into runs for search.

### Signing
- Ed25519 (RFC 8032) over a SHA-512 chain. `h0 = SHA-512(header)`, then `h = SHA-512(h || block)` for every extension block and frame in file order. SHA-512 because Ed25519 already needs it, so one implementation serves both (owner, 2026-10-30).
- A checkpoint is a frame of kind 0x01 holding the chain value it signs and the signature. Checkpoints follow activity, not the clock:
  - at the first frame boundary after 60 seconds of unsigned frames, so a busy session never has more than a minute unsigned;
  - when the host's timed flush finds the capture idle with unsigned frames, so a burst followed by quiet is signed at once;
  - before a login or logout marker, so each session's end is signed even if the client dies at character select;
  - never when nothing was written since the last one, so an idle client writes nothing.
- Cost: at most about 100 bytes a minute of activity, about 50 KB for 8 busy hours.
- The footer signs the final chain value together with the end fields.
- The header carries the 32-byte public key. Mogsafe registers keys per uploader; the format only names the key.
- Captain imports are signed by Mogsafe's converter key, so "converted by Mogsafe" is itself provable.
- Rejected: signing every frame. That costs 64 bytes per frame (about 370 KB per 8 hours) for little more than a one-minute checkpoint gives.
- Rejected: a fixed 60-second timer. It signs nothing new while idle and leaves a burst before a quiet spell unsigned for up to a minute.
- Rejected: signing only at close. A cut-off capture, the common case after a crash, would carry no proof at all.

### Exclusion
- A policy is an extension block: a name, a version, and rules `(channel, direction, opcode, action)`, where the action is a stub or a list of byte ranges to zero. The writer applies it before compressing, so excluded bytes never exist on disk.
- Byte ranges keep the library free of packet meanings; the policy carries the knowledge.
- A stub keeps its channel's packet header (on the game channel, the 4-byte FFXI header, which holds the original size and the sequence counter), so nothing about timing or order is lost.
- The library ships a default policy that stubs chat in both directions. The exact chat opcodes are checked against the client's resources during implementation.
- Rejected: dropping packets with no trace. A reader could not tell "the server never sent it" from "it was left out".

### Signing library
Monocypher (owner, 2026-10-30): `monocypher.c` plus `optional/monocypher-ed25519.c`, vendored, give RFC 8032 Ed25519 and SHA-512, and build on MSVC x86 and x64, Linux, and Emscripten with no system package. It is maintained (4.0.3 in June 2026, commits in October 2026) and was audited by Cure53. Rejected: libsodium, which needs a package on every platform and its own Wasm build for the same two functions.

### Test-only reader
`tests/spec_reader.py` reads format 3 from `FORMAT.md` alone, with `zstandard` and `cryptography`. It is not a binding and is never shipped; it exists to prove the spec is complete. `AGENTS.md`'s rule that bindings wrap the C++ library stays.

### Durability
- The writer flushes the file stream after each frame, so a frame reaches the operating system when written. It does not `fsync`: losing the last seconds on power loss is acceptable, and syncing every 5 seconds wears consumer disks for little.
- `flush()` closes the frame being built. Recorders call it on a timer, so a quiet session still reaches disk.
- Write errors throw.

## Risks / Trade-offs

- [Per-file overhead: dictionary, key, and checkpoints, about 65 KB plus 6 KB an hour] → Rotation only on character change keeps the file count low.
- [A stolen or shared recorder key signs anything] → The signature proves which key, not which person. Mogsafe can revoke a key and find everything it signed.
- [Vendored crypto] → Monocypher is small, audited, and maintained. Implementation tests it against RFC 8032 vectors in CI, and Renovate cannot bump a vendored file, so the vendored version is named in `FORMAT.md`'s dependencies and checked by hand on each release.
- [Chat opcodes missed by the default policy] → The conformance set includes every chat opcode found in the resources, and the policy's version is in each file, so a later fix shows which captures predate it.

## Migration Plan

None for data: nothing is archived. Mogsafe's change in `ffxi-dev/vault` lands after this one is tagged, and uploads stay closed until both are done.

## Open Questions

- The idle threshold for the timed-flush checkpoint: the recorder's flush timer decides it. The plugin's change picks the timer.

## Implementation Notes

None yet.
