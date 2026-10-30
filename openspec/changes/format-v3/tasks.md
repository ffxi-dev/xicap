# Tasks

## 1. Specification

- [ ] 1.1 Rewrite `FORMAT.md` for format 3: magic, header (feature mask, clock source, origin, retail or private, server name, capture ids, public key, header CRC), extension blocks with CRCs, frames with magic and kind, packet flags in two groups, checkpoints, footer with end fields and final signature, the zstd rules, and the exact chain and signature inputs; verify every structure's size and offsets against `static_assert`s in `types.h`
- [ ] 1.2 Replace the worked example with a hex dump of a real conformance file, annotated byte by byte; verify the test-only reader (6.1) reads the dumped bytes
- [ ] 1.3 Update `AGENTS.md`: readers keep reading every released version from production on, and `tests/spec_reader.py` is a test-only reader, not a binding

## 2. Layout and recovery

- [ ] 2.1 Write the header once at the first frame and move the end fields to the footer; verify a test that copies a recording file at every frame boundary and finds each copy a prefix of the next
- [ ] 2.2 Add the feature mask, frame kinds, and the two flag groups; verify tests that refuse an unknown required bit, an unknown must-understand frame kind, and an unknown must-understand flag, and skip an unknown skippable frame kind
- [ ] 2.3 Add frame magic, CRCs on the header, extension blocks, and footer index, and stop iteration at the index; verify tests for each checksum failure and for a footer index whose first entry would fit as a frame
- [ ] 2.4 Add recovery mode: resync on frame magic plus a passing CRC, count damaged frames, and end a cut-off capture at its last intact frame; verify tests for a damaged size field with and without a footer and for a torn tail
- [ ] 2.5 Require the embedded dictionary and remove the built-in fallback; verify a test that refuses a file naming a dictionary it does not carry
- [ ] 2.6 Write a footer on an empty capture, flush the stream after each frame, throw on write errors, clamp the writer's frame size to the reader's limit, and cut UTF-8 text only on character boundaries; verify a test for each

## 3. Provenance

- [ ] 3.1 Clamp backwards timestamps, add the clock-source, origin, retail or private, and server-name fields, and start a new frame on a zone change; verify tests for a clock step back, equal timestamps, and a frame spanning a zone change
- [ ] 3.2 Add the channel, the 32-bit length, and the provenance flags (injected, blocked, modified, first in datagram) to the writer's packet call, and remove the client memory snapshot extensions; verify a round-trip test with game and search packets interleaved and a packet over 64 KiB on a non-game channel
- [ ] 3.3 Add `captureId`, `previousCaptureId`, the start-context field, and a login marker call; verify a test that two writers get different ids and a continued capture names its predecessor
- [ ] 3.5 Report a capture whose zone-in packets name a character other than the header's, with the identifying zone-in fields checked against the client's resources; verify tests for a match and a mismatch
- [ ] 3.6 Define the search channel in `FORMAT.md` (its packet header, opcode field, and stub) from the plugin's hooks and real search traffic; verify a round-trip test on recorded search packets
- [ ] 3.4 Add the source extension for converted captures; verify a round-trip test with a captain manifest

## 4. Signing

- [ ] 4.1 Vendor Monocypher 4.0.3 (`monocypher.c` and `optional/monocypher-ed25519.c`) for Ed25519 and SHA-512; verify RFC 8032 and FIPS 180-4 SHA-512 test vectors pass on MSVC x86 and x64, Linux, and Emscripten
- [ ] 4.2 Keep the hash chain in the writer, write checkpoints by the rules in the design (60 seconds of unsigned frames, idle flush, before login and logout markers, never with nothing new), and sign the end in the footer; verify tests for a busy session, an idle session, a clean capture, a cut-off capture verified up to its last checkpoint, swapped frames, and an edited packet with a recomputed CRC
- [ ] 4.3 Report the key, the verification result, and the verified packet count from the reader, without stopping on a failure; verify against the tests in 4.2

## 5. Exclusion

- [ ] 5.1 Add exclusion policies (stub, zero byte ranges), apply them in the writer before compression, and record the policy as an extension block; verify a test that scans the raw file for a chat message's text and does not find it
- [ ] 5.2 Ship a default policy that stubs chat in both directions, with the opcodes checked against the client's resources (res.sruon.dev) and listed in `FORMAT.md`; verify a test with one packet of each chat opcode

## 6. Conformance

- [ ] 6.1 Write `tests/spec_reader.py` from `FORMAT.md` alone, using only `zstandard` and `cryptography`; verify it reads the conformance set
- [ ] 6.2 Commit the conformance set under `tests/vectors/` (each file with its expected reading as JSON), made by a generator in `tools/`: clean, empty, cut off, torn tail, damaged middle frame with and without footer, unknown required feature, unknown skippable frame kind, missing dictionary, excluded and redacted packets, bad signature; verify the C++ tests read every file as expected
- [ ] 6.3 Run the conformance set in the Python, JavaScript, and Go bindings' CI; verify every binding matches every expected reading

## 7. Bindings and release

- [ ] 7.1 Expose the new writer options and reader results in the C API and the Go, Python, and JavaScript bindings: extensions, provenance flags, origin fields, capture ids, signing key, exclusion policy, recovery mode, verification result; verify each binding's tests
- [ ] 7.2 Tag `v3.0.0`, the version Mogsafe pins; verify a clean module fetch of the tag builds the Go binding

## Follow-up outside this repository

- Mogsafe (`ffxi-dev/vault` change): close without the header rewrite, signature checks and recorder key registration, the archive's required exclusion policy, and a converter key for captain imports. Uploads stay closed until it lands.
- The client recorder plugin: rotation on character change, login markers, provenance flags from Ashita, and a flush timer.
