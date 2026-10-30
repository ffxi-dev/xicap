# Spec Delta

## Purpose

Defines how a capture is laid out on disk so any reader, now or decades from now, can decode it from the file and `FORMAT.md` alone, and can tell a complete, cut-off, or damaged file apart.

## ADDED Requirements

### Requirement: Little-endian layout with a version-3 magic
Every multi-byte integer SHALL be little-endian, and structures SHALL have no padding. A format 3 file SHALL start with an 8-byte magic that a text-mode transfer would alter, followed by the major and minor version. Readers SHALL refuse files with another magic or a major version they do not support.

#### Scenario: Format 2 file
- **WHEN** a reader opens a file that starts with the 2.x magic `XCAP`
- **THEN** it refuses the file with an unsupported-version error

#### Scenario: Line endings rewritten
- **WHEN** a file passed through a transfer that rewrote `\r\n` or `\n`
- **THEN** the magic no longer matches and the reader refuses the file

### Requirement: The header is written once
A writer SHALL write the header once, with every field final, before the first frame, and SHALL never write to it again. Every field known only at the end of a capture SHALL live in the footer.

#### Scenario: Growing file
- **WHEN** a capture is recording and its file is read twice, minutes apart
- **THEN** the first read's bytes are a prefix of the second read's

### Requirement: Features a reader must understand
The header SHALL carry a feature mask in which every set bit names a feature a reader must understand to read the file. Readers SHALL refuse a file with a bit they do not know. Frame kinds and packet flags SHALL each be split into values a reader may skip or ignore and values it must understand.

#### Scenario: Unknown required feature
- **WHEN** a reader opens a file whose feature mask has a bit it does not know
- **THEN** it refuses the file and names the bit

#### Scenario: Unknown optional frame kind
- **WHEN** a reader meets a frame of an unknown kind in the skippable range
- **THEN** it skips the frame after checking its checksum and reads on

### Requirement: Everything is checksummed
The header, each extension block, each frame, and the footer SHALL each carry a CRC-32 (IEEE 802.3) over their own bytes. Readers SHALL refuse a header, extension block, or footer whose checksum fails.

#### Scenario: Flipped bit in an extension
- **WHEN** one bit of an extension block's payload is flipped
- **THEN** the reader reports a checksum failure for that block

### Requirement: The dictionary travels with the capture
A capture compressed with a dictionary SHALL carry that dictionary as its first extension block. Readers SHALL decode only with the dictionary in the file. Each frame's payload SHALL be exactly one zstd frame (RFC 8878) that records its content size and carries the zstd checksum, and the dictionary SHALL be in the RFC 8878 dictionary format.

#### Scenario: Dictionary block missing
- **WHEN** a file names a dictionary in its header but carries no dictionary block
- **THEN** the reader refuses the file rather than use a dictionary of its own

### Requirement: Frames can be found without the footer
Each frame SHALL start with a frame magic and a kind, and its checksum SHALL cover everything from the magic to the end of the payload. A frame SHALL hold at most 16 MiB once decompressed, and writers SHALL not produce larger frames.

#### Scenario: Damaged frame size in a cut-off file
- **WHEN** a file without a footer has one frame whose size field is damaged
- **THEN** a reader in recovery mode skips to the next frame magic whose frame passes its checksum, reads every later intact frame, and reports one damaged frame

### Requirement: The footer closes a capture
A cleanly closed capture SHALL end with a footer holding the frame index, the end timestamp, the packet count, the end zone, and a trailer at a fixed distance from the end of the file. A file without a valid footer SHALL read as a cut-off capture, and an empty capture SHALL still get a footer.

#### Scenario: Closed with no packets
- **WHEN** a writer is closed before any packet is written
- **THEN** the file has a header, its extensions, and a footer with zero frames, and reads as complete with zero packets

#### Scenario: Reading stops at the index
- **WHEN** a reader iterates every packet of a closed capture
- **THEN** it stops at the footer index and never reads index bytes as a frame

### Requirement: Cut-off captures read up to the last intact frame
A reader SHALL read a file without a footer up to its last complete frame that passes its checksum, and SHALL report the capture as cut off. A torn final frame SHALL end the capture, not fail the read.

#### Scenario: Power lost mid-frame
- **WHEN** a file ends partway through a frame
- **THEN** the reader yields every packet of the earlier frames and reports the capture as cut off

### Requirement: A conformance set defines correct reading
The repository SHALL hold a set of test files, each with its expected reading, covering at least: a clean capture, an empty capture, a cut-off capture, a torn tail, a damaged middle frame with and without a footer, an unknown required feature, an unknown skippable frame kind, a missing dictionary, excluded and redacted packets, and a capture with a bad signature. Every binding SHALL read the whole set in CI, and a test-only reader written from `FORMAT.md` alone SHALL read it too.

#### Scenario: Spec alone is enough
- **WHEN** the test-only reader, which uses only `FORMAT.md`, zstd, and a signature library, reads the conformance set
- **THEN** its readings match the expected ones byte for byte
