# Proposal

## Why

Mogsafe will keep every uploaded capture in R2 for good, so the format has to be right before the first real upload. A review of format 2.1 (2026-10-30) found flaws that cannot be fixed later without breaking files:
- the writer goes back to rewrite the header, so no checksum can cover it, and Mogsafe needs special code to accept the rewrite;
- old readers silently misread files that use features they do not know;
- one damaged frame size loses the rest of a file that has no footer;
- a file can fall back to a dictionary it does not carry;
- packets an addon injected look like real server traffic;
- timestamps have no stated meaning;
- a capture cannot prove who recorded it or that nobody changed it;
- chat goes into the archive in full.

No capture has been uploaded yet and the format is not in production, so a clean break costs nothing now.

## What Changes

- **BREAKING:** format 3, with a new file magic. Readers do not read 1.x or 2.x files; nothing archived uses them.
- The header is written once and never rewritten. The end-of-capture fields move to the footer, so the file only ever grows at the end.
- Readers refuse files that need a feature they do not know: a header feature mask, frame kinds, and packet flags split into ones a reader may ignore and ones it must understand.
- Each frame starts with a magic number, so a reader resyncs after damage. The header, each extension, each frame, and the footer index carry a checksum.
- Each capture carries the zstd dictionary it was written with, and the spec pins the zstd details, so the file plus the spec is enough to decode it.
- Timestamps are UTC milliseconds that never go backwards in file order. The header says whether the times are live or were converted with a guessed offset.
- Packets carry provenance flags: injected, blocked, or modified by an addon, and first packet of its datagram.
- Packets name their channel from a registry: the game server and the search server first, which the shipped plugin hooks for `/search` and the auction house; lobby, IRC, and profile traffic later. Readers pass on channels they do not know.
- Packets are the whole context: the client memory snapshot extensions (player, inventory, entities, missions, spells, abilities, lobby) go. A capture that starts at a login holds every packet a replay needs.
- The header says where a capture came from: live or converted, retail or private server, and the server's name. Converted captures carry their source manifest.
- Each capture holds one character, named in the header and checked against its zone-in packets. Each has a random id and names the capture it continues. A recorder starts a new file only at a login of another character; the same character logging back in continues the same file, and no timer cuts a session. A capture that starts after a crash or a late start is marked mid-session and continues the one before it.
- Recorders sign captures. Each recorder has its own key; the writer chains a hash over the file, signs checkpoints as it goes, and signs the end in the footer.
- Packet exclusion: the writer applies an exclusion policy before anything reaches disk. A covered packet is kept as a stub (its 4-byte FFXI header, time, and direction) or has byte ranges zeroed. The policy is recorded in the file and covered by the signature. Chat packets are stubbed by the default policy.
- Writer durability: each frame reaches the operating system when it is written, the host can force a frame out on a timer, write errors are raised, and an empty capture still gets a footer.
- A conformance set of test files with expected readings, run by every binding, and a test-only reader written from `FORMAT.md` alone.

## Capabilities

### New Capabilities
- `capture-format`: the on-disk layout: magic and version, header, extensions, frames, footer, checksums, the embedded dictionary, and how readers handle unknown features, cut-off files, and damage.
- `capture-provenance`: what a capture records about where it came from and what a replay needs: packets as the whole context, channels, timestamp meaning, packet provenance flags, live or converted, retail or private, one character per capture, capture ids and links, and when a recorder starts a new file.
- `capture-signing`: recorder keys, the hash chain, checkpoint and final signatures, and how a reader checks them.
- `packet-exclusion`: exclusion policies, stubbed and redacted packets, and how a reader reports them.

### Modified Capabilities
None: this repository has no specs yet.

## Impact

- `FORMAT.md` is rewritten for format 3, and its worked example is fixed.
- The C++ reader and writer, and the Python, JavaScript, and Go bindings. The Go binding's C API gains extensions, the exclusion policy, and signing keys.
- A signing library joins zstd as a dependency of the C++ library and its Wasm build.
- `AGENTS.md`: readers keep reading every released version only from production on, and the test-only reader is allowed alongside the bindings.
- Mogsafe, in `ffxi-dev/vault` as its own change: close no longer rewrites the header, signatures are checked and recorder keys registered, uploads below the archive's required exclusion policy are refused, and captain imports are signed by Mogsafe's converter key.
- The client recorder plugin follows the rotation rule, passes host events (login, logout) to the writer, and records the search channel through its own hooks.
- Mogsafe refuses a capture whose header names a character its zone-in packets do not.
