# XICAP Binary Format

Version 3.0. This document is normative: a reader built from it alone, with the
references below, must read every capture the library writes.

**Status: draft.** Format 3 is not in production. Until the owner declares it
is, a later draft may change any part of it without keeping compatibility.

## Conventions

- Every integer is little-endian. Structures are byte-packed, with no padding.
- Offsets and sizes are in bytes. `u8`, `u16`, `u32`, `u64` are unsigned; `i32`
  is two's complement.
- `reserved` fields and bytes are written as zero, and readers ignore their
  value. A later minor version may give them a meaning only where an old reader
  can safely ignore it.
- A text field of N bytes holds UTF-8, padded with zero bytes. It holds at most
  N - 1 bytes of text, cut only between characters, so it always ends with at
  least one zero byte.
- Timestamps are milliseconds since the Unix epoch, in UTC.

### References

| Name | Used for |
|------|----------|
| CRC-32 | Polynomial `0x04C11DB7` reflected (`0xEDB88320`), initial value `0xFFFFFFFF`, final XOR `0xFFFFFFFF` (CRC-32/ISO-HDLC, as zlib). Check value: CRC of ASCII `123456789` is `0xCBF43926`. |
| SHA-512 | FIPS 180-4. |
| Ed25519 | RFC 8032, pure Ed25519 (not Ed25519ph or Ed25519ctx). |
| zstd | RFC 8878. |

## File layout

```
+--------------------+
| Header             |  headerSize bytes (384 in 3.0)
+--------------------+
| Extension blocks   |  Header.extensionCount blocks
+--------------------+
| Frames             |  0..N frames: packet frames and checkpoint frames
+--------------------+
| Footer index       |  only after a clean close
+--------------------+
| Footer trailer     |  112 bytes, only after a clean close
+--------------------+
```

A writer writes each byte once and only ever appends. Nothing already written is
changed, so every copy of a file being recorded is a prefix of the finished
file.

A file with a valid footer is **complete**. A file without one is **cut off**:
the recorder crashed, or is still recording.

## Header

The writer writes the header when the first frame is written, or at close if
there is none, with every field final.

| Off | Size | Field | Notes |
|----:|-----:|-------|-------|
| 0 | 8 | `magic` | `89 58 43 50 0D 0A 1A 0A`, see below |
| 8 | 1 | `versionMajor` | `3` |
| 9 | 1 | `versionMinor` | `0` |
| 10 | 2 | `headerSize` | `384` in 3.0. Readers accept any value from 384 to 4096 and skip to it |
| 12 | 4 | `extensionCount` | number of extension blocks after the header |
| 16 | 8 | `reserved` | |
| 24 | 16 | `captureId` | 16 random bytes, never all zero |
| 40 | 16 | `previousCaptureId` | the capture this one continues, or all zero |
| 56 | 8 | `startTimestamp` | the first packet's timestamp; `0` if the capture holds no packet |
| 64 | 3 | `reserved` | |
| 67 | 1 | `clockSource` | `0` unknown, `1` live, `2` converted with an inferred offset |
| 68 | 1 | `origin` | `0` unknown, `1` recorded live, `2` converted from another format |
| 69 | 1 | `network` | `0` unknown, `1` retail, `2` private server |
| 70 | 1 | `startContext` | `0` unknown, `1` starts at a login, `2` starts mid-session |
| 71 | 1 | `reserved` | |
| 72 | 4 | `dictionaryId` | id of the zstd dictionary the frames use; `0` for none. See [Dictionary](#dictionary) |
| 76 | 4 | `reserved` | |
| 80 | 32 | `signingKey` | the recorder's Ed25519 public key |
| 112 | 32 | `captureAgent` | text: the program that recorded the capture, with its version |
| 144 | 32 | `clientVersion` | text: the game client's build |
| 176 | 44 | `character` | `CharacterIdentity`: the capture's character |
| 220 | 160 | `reserved` | |
| 380 | 4 | `headerCrc` | CRC-32 of bytes `0` to `headerSize - 4` |

The magic follows PNG's pattern:

```
89 58 43 50 0D 0A 1A 0A
    X  C  P \r \n ^Z \n
```

The high first byte fails 7-bit transfers. `\r\n` fails transfers that turn
`\r\n` into `\n`, the last `\n` fails those that turn `\n` into `\r\n`, and `^Z`
stops DOS `type`. 2.x files start with `XCAP`, so a 3.x reader refuses them as a
bad magic.

`headerCrc` is always the last 4 bytes of the header. A later minor version may
grow the header: it adds fields in the reserved bytes or after them, moves the CRC to the new end,
and raises `headerSize`.

A reader refuses the file if the magic differs, `versionMajor` is not 3,
`headerSize` is out of range, or `headerCrc` fails.

### `CharacterIdentity` (44 bytes)

| Off | Size | Field | Notes |
|----:|-----:|-------|-------|
| 0 | 4 | `contentId` | POL character id (`ffxi_id`), unique to the character |
| 4 | 4 | `worldContentId` | the character's id on its world (`ffxi_id_world`) |
| 8 | 2 | `worldId` | |
| 10 | 2 | `reserved` | |
| 12 | 16 | `characterName` | text |
| 28 | 16 | `worldName` | text |

A capture holds one character's session. The character in `character` must be
the one the capture's zone-in packets name; a reader reports a capture where
they differ.

## Extension blocks

| Off | Size | Field |
|----:|-----:|-------|
| 0 | 4 | `type` |
| 4 | 4 | `length`: payload size, at most 16 MiB |
| 8 | `length` | payload |
| 8 + `length` | 4 | `crc`: CRC-32 of the type, length, and payload |

A reader refuses a block whose CRC fails or whose length is over 16 MiB.

| Type | Name | Required | Payload |
|-----:|------|----------|---------|
| `0x0008` | `ZSTD_DICT` | when `dictionaryId` is not 0; first block | [Dictionary](#dictionary) |
| `0x0009` | `EXCLUSION_POLICY` | always, exactly once | [Exclusion](#exclusion) |
| `0x000A` | `SOURCE` | when `origin` is 2 | [Source](#source) |

Ids `0x0001` to `0x0007` held client memory copies in 2.x and are retired:
never reuse them. A capture's context is its packets, never a copy of client
state.

| Range | Use |
|-------|-----|
| `0x0000_0001` to `0x0000_7FFF` | this document |
| `0x0000_8000` to `0xFFFF_FFFE` | other programs' metadata |
| `0x0000_0000`, `0xFFFF_FFFF` | never used |

Readers skip blocks of types they do not know and return them to the caller
unchanged.

### Source

Carried by converted captures (`origin` 2).

| Off | Size | Field | Notes |
|----:|-----:|-------|-------|
| 0 | 16 | `format` | text: the source format, such as `captain` |
| 16 | 16 | `formatVersion` | text: the source program's version |
| 32 | 4 | `skippedRecords` | source records not converted |
| 36 | 4 | `utcOffsetSeconds` | `i32`: offset added to the source's times to get UTC |
| 40 | 64 | `sourceHash` | SHA-512 of the source file as uploaded |
| 104 | 4 | `metadataLength` | |
| 108 | `metadataLength` | `metadata` | the source's metadata as found, such as captain's `manifest.txt` |

## Dictionary

Packet frames may be compressed with a zstd dictionary. When `dictionaryId` is
not 0, the first extension block must be `ZSTD_DICT`, holding the dictionary in
RFC 8878 section 5 format, whose `Dictionary_ID` equals `dictionaryId`. A reader
refuses the file otherwise. A reader decodes only with the dictionary in the
file, never with one of its own.

Writers train dictionaries with zstd's trainer:

```
zstd --train samples/* -o ffxi.dict --maxdict=65536
```

## Frames

Every frame starts with the same 28-byte header and ends with a CRC.

| Off | Size | Field | Notes |
|----:|-----:|-------|-------|
| 0 | 4 | `magic` | ASCII `XCFR` |
| 4 | 1 | `kind` | see below |
| 5 | 1 | `reserved` | |
| 6 | 2 | `markerCount` | markers in the payload; `0` for other kinds |
| 8 | 4 | `payloadSize` | bytes between this header and the CRC |
| 12 | 4 | `packetCount` | packets in the payload, at most 65535; `0` for other kinds |
| 16 | 8 | `baseTimestamp` | first packet's timestamp; for other kinds, the last packet's timestamp before the frame |
| 24 | 2 | `zoneId` | zone at the frame's first packet, from the last zone-in before it; `0` before the first zone-in. For other kinds, the zone in effect |
| 26 | 2 | `reserved` | |
| 28 | `payloadSize` | payload | |
| 28 + `payloadSize` | 4 | `crc` | CRC-32 of bytes `0` to `28 + payloadSize` of the frame |

| Kind | Name | Readers that do not know it |
|-----:|------|-----------------------------|
| `0x01` | checkpoint | skip it |
| `0x80` | packets | refuse the file |

Kinds below `0x80` may be skipped, after checking the CRC, by a reader that does
not know them. Kinds from `0x80` must be understood: a reader refuses a file
holding one it does not know.

### Packet frames

The payload is exactly one zstd frame (RFC 8878) with `Frame_Content_Size`
present and `Content_Checksum_flag` set, compressed with the capture's
dictionary if it has one. No skippable zstd frames.

The content size must not exceed 16 MiB, nor
`packetCount * (12 + 65535) + markerCount * (6 + 65535)` when every packet is
on the game channel. A reader checks the content size against 16 MiB before
allocating.

Decompressed, the payload is:

```
PacketEntry, packet bytes      x packetCount
FrameMarker, marker text       x markerCount
```

#### `PacketEntry` (12 bytes)

| Off | Size | Field | Notes |
|----:|-----:|-------|-------|
| 0 | 2 | `deltaMs` | milliseconds since the previous packet in this frame; `0` for the first |
| 2 | 2 | `flags` | see below |
| 4 | 1 | `channel` | see [Channels](#channels) |
| 5 | 1 | `reserved` | |
| 6 | 2 | `opcode` | meaning set by the channel |
| 8 | 4 | `length` | bytes of packet data that follow |

A packet's timestamp is the frame's `baseTimestamp` plus the `deltaMs` of every
entry up to and including its own.

| Bit | Flag | Group |
|----:|------|-------|
| 0 | direction: `0` to the client, `1` from the client | core |
| 1 | injected by an addon | may ignore |
| 2 | blocked by an addon | may ignore |
| 3 | modified by an addon | may ignore |
| 4 | first packet of its datagram | may ignore |
| 5 to 7 | reserved | may ignore |
| 8 | excluded: a stub, see [Exclusion](#exclusion) | must understand |
| 9 | redacted: byte ranges zeroed | must understand |
| 10 to 15 | reserved | must understand |

A reader refuses a file holding a set bit from 10 to 15. Packet bytes are the
packet as the client's hook delivered it, decrypted and decompressed, before any
addon changed it.

#### `FrameMarker` (6 bytes)

| Off | Size | Field | Notes |
|----:|-----:|-------|-------|
| 0 | 2 | `packetIndex` | the packet in this frame the marker attaches to, from 0 |
| 2 | 1 | `kind` | `0` note, `1` login, `2` logout; readers treat unknown kinds as notes |
| 3 | 1 | `reserved` | |
| 4 | 2 | `textLength` | |
| 6 | `textLength` | text | UTF-8, no terminator |

### Checkpoint frames

The payload is 128 bytes, not compressed:

| Off | Size | Field |
|----:|-----:|-------|
| 0 | 64 | `chain`: the chain value before this frame |
| 64 | 64 | `signature` |

See [Signatures](#signatures).

## Channels

| Channel | Name | Packet bytes | `opcode` | A stub keeps |
|--------:|------|--------------|----------|--------------|
| 0 | game | the FFXI packet, from its 4-byte header | the header's 9-bit id | the 4-byte header |
| 1 | search | defined when the plugin's hooks are (task 3.6) | | |
| 2 to 255 | reserved: lobby, IRC, and profile traffic come later | | | |

A reader passes on packets of a channel it does not know, with the channel's
number, and does not refuse the file. A new channel is a minor version.

### Game channel

The first 4 bytes of a game packet are its FFXI header:

```
byte 0     byte 1             byte 2     byte 3
[id_lo:8]  [size:7 | id_hi:1] [sync_lo:8] [sync_hi:8]
```

- `id` = `u16(bytes 0..2) & 0x01FF`, 9 bits
- `size` = `(u16(bytes 0..2) >> 9) & 0x7F`, in 4-byte words
- `sync` = `u16(bytes 2..4)`, a sequence counter per direction

A writer refuses a game packet shorter than 4 bytes and sets `opcode` to its
`id`. A reader treats a game packet whose `opcode` differs from its `id` as a
corrupt frame.

## Footer

A clean close writes the footer index, then the trailer.

### `FooterIndexEntry` (24 bytes)

One per packet frame, in file order. Checkpoint frames have no entry.

| Off | Size | Field |
|----:|-----:|-------|
| 0 | 8 | `timestamp`: the frame's `baseTimestamp` |
| 8 | 8 | `fileOffset`: the frame's first byte |
| 16 | 2 | `zoneId` |
| 18 | 6 | `reserved` |

### `FooterTrailer` (112 bytes, the last bytes of the file)

| Off | Size | Field | Notes |
|----:|-----:|-------|-------|
| 0 | 8 | `endTimestamp` | the last packet's timestamp; `0` if none |
| 8 | 8 | `totalPacketCount` | |
| 16 | 4 | `reserved` | |
| 20 | 4 | `entryCount` | footer index entries |
| 24 | 8 | `indexOffset` | file offset of the first index entry |
| 32 | 4 | `indexCrc` | CRC-32 of the whole index |
| 36 | 4 | `frameCount` | frames of every kind |
| 40 | 64 | `signature` | see [Signatures](#signatures) |
| 104 | 4 | `trailerCrc` | CRC-32 of trailer bytes `0` to `104` |
| 108 | 4 | `magic` | ASCII `XCPF` |

The footer is valid when all of these hold:

- the file is at least `dataStart + 112` bytes long, where `dataStart` is the
  end of the extension blocks;
- the last 4 bytes are `XCPF` and `trailerCrc` is correct;
- `indexOffset >= dataStart` and `indexOffset + 24 * entryCount + 112` equals
  the file size;
- `indexCrc` is correct.

A file whose footer is not valid is read as cut off. If its last 4 bytes are
`XCPF` anyway, the reader also reports a damaged footer.

## Signatures

Every capture is signed with the key in `signingKey`. Signatures sign a SHA-512
hash chain over the file:

1. `h = SHA-512(header)`, over all `headerSize` bytes.
2. For each extension block, in order: `h = SHA-512(h || block)`, over the
   block from `type` to `crc`.
3. For each frame, of every kind, in order: `h = SHA-512(h || frame)`, over the
   frame from `magic` to `crc`.
4. At close: `h = SHA-512(h || index || trailer[0..40])`, over every index
   entry and the first 40 bytes of the trailer.

A checkpoint frame stores the chain value `h` from before the frame, and
`signature = Ed25519(key, "xicap/3 checkpoint" || h)`. The footer's
`signature = Ed25519(key, "xicap/3 footer" || h)`, with `h` from step 4. The
prefixes are ASCII, with no terminator.

A reader recomputes the chain and reports:

- the signing key;
- **complete** if the footer's signature verifies;
- otherwise the last checkpoint whose stored chain value matches and whose
  signature verifies, and how many packets come before it;
- the file offset of the first frame where a stored chain value or signature
  fails, if any.

A failed signature never stops a reader from reading packets.

## Exclusion

Every capture carries the exclusion policy its writer applied, in an
`EXCLUSION_POLICY` block. The writer applies it to each packet before the packet
is compressed, so excluded bytes never reach the file.

| Off | Size | Field |
|----:|-----:|-------|
| 0 | 32 | `name`: text |
| 32 | 4 | `version` |
| 36 | 2 | `ruleCount` |
| 38 | 2 | `reserved` |
| 40 | | `ruleCount` rules |

Each rule:

| Off | Size | Field | Notes |
|----:|-----:|-------|-------|
| 0 | 1 | `channel` | |
| 1 | 1 | `direction` | `0` to the client, `1` from the client, `2` both |
| 2 | 1 | `action` | `1` stub, `2` zero byte ranges |
| 3 | 1 | `reserved` | |
| 4 | 2 | `opcode` | |
| 6 | 2 | `rangeCount` | `0` for a stub |
| 8 | | `rangeCount` ranges of `u32 offset, u32 length` | a length of `0xFFFFFFFF` runs to the packet's end |

The first rule that matches a packet's channel, direction, and opcode applies.

- **Stub:** the entry keeps its timestamp, channel, direction, provenance flags,
  and opcode, sets the excluded flag, and keeps only what its channel's row in
  [Channels](#channels) says a stub keeps. On the game channel that is the
  4-byte header, whose `size` still gives the original length.
- **Zero byte ranges:** the entry keeps its length, sets the redacted flag, and
  has each range zeroed. Ranges past the packet's end are cut at the end.

The library's default policy, `xicap-default`, stubs every chat packet on the
game channel in both directions. Its opcodes are checked against the client's
resources and listed here by task 5.2.

## Reading

A reader:

1. checks the header and its CRC, and every extension block's
   CRC and length, and the dictionary and policy rules above, and refuses the
   file if any fails;
2. checks the footer;
3. reads frames from the end of the extension blocks.

In a complete file, frames run up to `indexOffset`. A frame that is cut short,
lacks the `XCFR` magic, or fails its CRC there is an error.

In a cut-off file, frames run up to the first frame that is cut short, lacks the
magic, or fails its CRC. The capture ends there, and the reader reports how many
bytes it did not read.

In **recovery mode**, a reader that meets a bad frame searches forward, byte by
byte, for the next `XCFR` whose frame passes its CRC, and carries on from there.
It reports each skipped region. Recovery mode is for salvage; Mogsafe and other
archive checks read in the normal mode.

## Writer rules

These rules are part of the format: a capture that breaks them is wrong even if
it parses.

- **Timestamps never go backwards** in file order, across every channel. Equal
  timestamps are allowed. Given an earlier time than the last, a writer records
  the last again. Live recorders read the wall clock once and add a monotonic
  clock after.
- **Frame boundaries.** A writer ends the packet frame being built before adding
  a packet that would push its `deltaMs` past 65535, its `packetCount` past
  65535, or its decompressed size past 16 MiB, and when the server sends a
  zone-in, so a frame never spans two zones. It also ends frames by its own
  size and time settings (by default 1000 packets, 64 KiB, or 5 seconds) and
  when the host asks for a flush.
- **Checkpoints.** A writer writes a checkpoint, covering every frame so far, at
  the first frame boundary after 60 seconds of frames without one, when a flush
  finds the capture idle with frames since the last checkpoint, and before a
  login or logout marker. It never writes one when no frame was written since
  the last.
- **Captures start at a login.** A recorder starts a new capture when a
  character logs in and the current capture holds another character or none.
  When the same character logs out and back in, the capture continues, with a
  logout and a login marker. A recorder that starts after a login, or after a
  crash, sets `startContext` to mid-session and `previousCaptureId` to the
  capture it continues. No timer ends a capture.
- **Durability.** A writer hands each frame to the operating system as soon as
  it is written, and reports any write error.
- **Empty captures** still get a header, extension blocks, and a footer with no
  index entries.

## Conformance

`tests/vectors/` holds test files, each with a JSON file of its expected
reading. Every binding reads all of them in CI, and `tests/spec_reader.py`, a
reader written from this document alone, reads them too.

## Worked example

Replaced in task 1.2 by an annotated dump of a conformance file.

## Versioning

| Change | Version |
|--------|---------|
| Layout of an existing structure changes | major |
| A new frame kind, packet flag, channel, extension type, marker kind, or a field in reserved bytes that old readers can ignore | minor |
| Anything an old reader would misread without a must-understand frame kind or flag to stop it | major |
| A new check readers make | none |

A reader refuses a different major version. It reads a newer minor version,
skipping what it does not know, unless a must-understand frame kind or flag
tells it to refuse.

Before production, a draft may change anything. From production on, readers
keep reading every released version.

## Dependencies

The C++ library vendors Monocypher 4.0.3 (`monocypher.c` and
`optional/monocypher-ed25519.c`) for Ed25519 and SHA-512. Renovate cannot update
a vendored file; check Monocypher's releases when making a release of xicap.
