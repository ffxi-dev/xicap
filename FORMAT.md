# XICAP Binary Format

Version 3.0. This document is normative: a reader built from it alone, with the
references below, must read every capture the library writes.

**Status: draft.** Format 3 is not in production. Until the owner declares it
is, a later draft may change any part of it and break compatibility.

## Conventions

- Every integer is little-endian. Structures are byte-packed, with no padding.
- Offsets and sizes are in bytes. `u8`, `u16`, `u32`, `u64` are unsigned; `i32`
  is two's complement.
- Writers write `reserved` fields and bytes as zero, and readers ignore their
  value. A later minor version may give them a meaning only where an old reader
  can safely ignore it.
- A text field of N bytes holds UTF-8, padded with zero bytes. It holds at most
  N - 1 bytes of text, cut only between characters, so it always ends with at
  least one zero byte.
- Timestamps are milliseconds since the Unix epoch, in UTC.
- A byte range `a..b` includes byte `a` and stops before byte `b`.

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

A writer only appends, and writes each byte once. It never changes what it has
written, so every copy of a file being recorded is a prefix of the finished
file.

A file with a valid footer is **complete**. A file without one is **cut off**:
the recorder crashed, or is still recording.

## Header

The writer writes the header, with every field final, when it writes the first
frame, or at close if there is none.

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
| 380 | 4 | `headerCrc` | CRC-32 of header bytes `0..headerSize-4` |

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
grow the header: it adds fields in the reserved bytes or after them, moves the
CRC to the new end, and raises `headerSize`.

A reader refuses the file if the magic differs, `versionMajor` is not 3,
`headerSize` is out of range, or `headerCrc` fails.

### `CharacterIdentity` (44 bytes)

| Off | Size | Field | Notes |
|----:|-----:|-------|-------|
| 0 | 4 | `contentId` | POL character id (`ffxi_id`), unique to the character |
| 4 | 4 | `characterId` | the character's id on its world, as the zone-in's `UniqueNo` carries it; the lobby splits it into `ffxi_id_world` (bits 0 to 15) and `ffxi_id_world_tbl` (bits 16 to 23) |
| 8 | 2 | `worldId` | |
| 10 | 2 | `reserved` | |
| 12 | 16 | `characterName` | text |
| 28 | 16 | `worldName` | text |

A capture holds one character's session. The character in `character` must be
the one the capture's zone-in packets name. A reader that finds they differ
reports it and goes on reading; refusing such a capture is up to the archive.

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

Converted captures (`origin` 2) carry this block.

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

A writer may compress packet frames with a zstd dictionary. When
`dictionaryId` is not 0, the first extension block must be `ZSTD_DICT`, holding
the dictionary in RFC 8878 section 5 format, whose `Dictionary_ID` equals
`dictionaryId`. A reader refuses the file otherwise. A reader decodes only with
the dictionary in the file, never with one of its own.

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
| 24 | 2 | `zoneId` | zone named by the last zone-in at or before the frame's first packet; `0` if none. For other kinds, the zone in effect |
| 26 | 2 | `reserved` | |
| 28 | `payloadSize` | payload | |
| 28 + `payloadSize` | 4 | `crc` | CRC-32 of frame bytes `0..28+payloadSize` |

| Kind | Name | Readers that do not know it |
|-----:|------|-----------------------------|
| `0x01` | checkpoint | skip it |
| `0x80` | packets | refuse the file |

A reader that does not know a kind below `0x80` may skip it after checking its
CRC. Kinds from `0x80` must be understood: a reader refuses a file holding one
it does not know.

### Packet frames

The payload is exactly one zstd frame (RFC 8878) with `Frame_Content_Size`
present and `Content_Checksum_flag` set, compressed with the capture's
dictionary if it has one. The payload never holds skippable zstd frames.

The content size must not exceed 16 MiB; a reader checks it before allocating.
So no packet is longer than 16 MiB minus its 12-byte entry, and a writer refuses
a longer one.

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

Bits 1 to 7 are the **provenance flags**. A reader refuses a file holding a set
bit from 10 to 15.

Packet bytes are the packet as the client's hook delivered it, decrypted and
decompressed, before any addon changed it. For an injected packet, they are the
bytes the addon injected.

#### `FrameMarker` (6 bytes)

| Off | Size | Field | Notes |
|----:|-----:|-------|-------|
| 0 | 2 | `packetIndex` | the packet in this frame the marker sits just before, from 0 |
| 2 | 1 | `kind` | `0` note, `1` login, `2` logout; readers treat unknown kinds as notes |
| 3 | 1 | `reserved` | |
| 4 | 2 | `textLength` | |
| 6 | `textLength` | text | UTF-8, no terminator |

A marker marks a moment between two packets, so it sits just before the next
packet written after it. A logout marker therefore sits before the first packet
of the next login, and a marker with no packet after it when the capture closes
is dropped. A frame's markers follow the order they were written in.

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
number, and does not refuse the file. Adding a channel is a minor version.

### Game channel

The first 4 bytes of a game packet are its FFXI header:

```
byte 0     byte 1             byte 2     byte 3
[id_lo:8]  [size:7 | id_hi:1] [sync_lo:8] [sync_hi:8]
```

- `id` = `u16(bytes 0..2) & 0x01FF`, 9 bits
- `size` = `(u16(bytes 0..2) >> 9) & 0x7F`, in 4-byte words
- `sync` = `u16(bytes 2..4)`, a sequence counter per direction

A zone-in (`0x00A`, to the client) names the character: a u32 `UniqueNo` at
byte 4 and a 16-byte name at byte 132, counting the 4-byte header; its zone is
the u32 at byte 48. A reader compares every zone-in it reads that is neither
stubbed nor redacted with the header's `characterId` and `characterName`, and
reports a capture where any differs. Field offsets follow atom0s's XiPackets.

A writer refuses a game packet shorter than 4 bytes and sets `opcode` to its
`id`. A frame holding a game packet whose `opcode` differs from its `id` is a
bad frame (see [Reading](#reading)).

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
| 104 | 4 | `trailerCrc` | CRC-32 of trailer bytes `0..104` |
| 108 | 4 | `magic` | ASCII `XCPF` |

The footer is valid when all of these hold:

- the file is at least `dataStart + 112` bytes long, where `dataStart` is the
  end of the extension blocks;
- the last 4 bytes are `XCPF` and `trailerCrc` is correct;
- `indexOffset >= dataStart` and `indexOffset + 24 * entryCount + 112` equals
  the file size;
- `indexCrc` is correct.

A reader reads a file whose footer is not valid as cut off. If its last 4 bytes
are `XCPF` anyway, the reader also reports a damaged footer.

## Signatures

A writer signs every capture with the key in `signingKey`. The signatures cover
a SHA-512 hash chain over the file:

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
- **signed to the end** if the footer's signature verifies;
- otherwise the last checkpoint whose stored chain value matches and whose
  signature verifies, and how many packets come before it;
- the file offset of the first frame where a stored chain value or signature
  fails, if any.

A failed signature never stops a reader from reading packets.

## Exclusion

Every capture carries the exclusion policy its writer applied, in an
`EXCLUSION_POLICY` block. The writer applies it to each packet before
compressing the packet, so excluded bytes never reach the file.

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
A writer refuses a policy that stubs packets on a channel whose row in
[Channels](#channels) does not say what a stub keeps.

- **Stub:** the entry keeps its timestamp, channel, direction, provenance flags,
  and opcode, sets the excluded flag, and keeps only what its channel's row in
  [Channels](#channels) says a stub keeps. On the game channel that is the
  4-byte header, whose `size` still gives the original length.
- **Zero byte ranges:** the entry keeps its length and sets the redacted flag,
  and the writer zeroes each range. A range that runs past the packet's end
  stops at the end.

The library's default policy, `xicap-default` version 1, stubs the game
channel's packets that carry text players write to each other:

| Opcode | Direction | Packet |
|-------:|-----------|--------|
| `0x017` | to the client | chat, in every channel (say, shout, party, linkshell, tell, yell, unity, assist) |
| `0x0B5` | from the client | chat |
| `0x0B6` | from the client | tell |
| `0x0CC` | to the client | linkshell message board |
| `0x0E2` | from the client | linkshell message board post |

Opcodes and meanings follow atom0s's XiPackets. Public text, such as search and
bazaar comments, is kept.

## Reading

A reader:

1. checks the header and its CRC, each extension block's CRC and length, and
   the dictionary and policy rules above, and refuses the file if any check
   fails;
2. checks the footer;
3. reads frames, starting at the end of the extension blocks.

A **bad frame** is one that is cut short, lacks the `XCFR` magic, fails its CRC,
or breaks a rule of this document once read, such as a zstd error or a game
packet whose `opcode` differs from its `id`.

In a complete file, frames run up to `indexOffset`, and a bad frame makes the
reader refuse the file.

In a cut-off file, frames run up to the first bad frame. The capture ends there,
and the reader reports how many bytes it did not read.

In **recovery mode**, a reader that meets a bad frame searches forward, byte by
byte, for the next `XCFR` whose frame passes its CRC, and goes on from there.
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
  finds the capture idle with frames since the last checkpoint, and when the
  host marks a login or logout: it ends the frame being built and writes the
  checkpoint then, so the marker lands in the next frame. It never writes one
  when it has written no frame since the last, so a capture's opening login
  has none.
- **When captures start.** A recorder starts a new capture when a
  character logs in and the current capture holds another character or none.
  When the same character logs out and back in, the capture continues, with a
  logout and a login marker. A recorder that starts after a login, or after a
  crash, sets `startContext` to mid-session and `previousCaptureId` to the
  capture it continues, or all zero if it knows none. No timer ends a capture.
- **Durability.** A writer hands each frame to the operating system as soon as
  it is written, and reports any write error.
- **Empty captures** still get a header, extension blocks, and a footer with no
  index entries.

## Conformance

`tests/vectors/` holds test files, each with a JSON file of its expected
reading. Every binding reads all of them in CI, and `tests/spec_reader.py`, a
reader written from this document alone, reads them too.

## Worked example

The conformance file `tests/vectors/converted.xicap`, whole: a converted
capture with no dictionary, its exclusion policy and source blocks, one frame of
four packets, and the footer. Offsets are in hex.

```
00000000  89 58 43 50 0d 0a 1a 0a 03 00 80 01 02 00 00 00  magic; version 3.0; headerSize 384; extensionCount 2
00000010  00 00 00 00 00 00 00 00 33 33 33 33 33 33 33 33  reserved; captureId
00000020  33 33 33 33 33 33 33 33 55 55 00 00 00 00 00 00  previousCaptureId
00000030  00 00 00 00 00 00 00 00 00 6c 50 c4 a0 01 00 00  startTimestamp
00000040  00 00 00 02 02 02 00 00 00 00 00 00 00 00 00 00  reserved; clockSource 2 (converted), origin 2 (converted), network 2 (private), startContext 0 (unknown); reserved; dictionaryId 0: no dictionary; reserved
00000050  d7 59 79 3b bc 13 a2 81 9a 82 7c 76 ad b6 fb a8  signingKey
00000060  a4 9a ee 00 7f 49 f2 d0 99 2d 99 b8 25 ad 2c 48
00000070  78 69 63 61 70 5f 6d 61 6b 65 5f 76 65 63 74 6f  captureAgent
00000080  72 73 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00000090  76 65 63 74 6f 72 73 2d 31 2e 30 00 00 00 00 00  clientVersion
000000a0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
000000b0  04 03 02 01 0d 0c 0b 0a 2a 00 00 00 4e 6f 75 75  contentId; characterId; worldId; characterName
000000c0  72 73 00 00 00 00 00 00 00 00 00 00 41 73 75 72  worldName
000000d0  61 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  reserved
000000e0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
000000f0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00000100  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00000110  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00000120  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00000130  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00000140  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00000150  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00000160  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00000170  00 00 00 00 00 00 00 00 00 00 00 00 2a af 64 38  headerCrc
00000180  09 00 00 00 50 00 00 00 78 69 63 61 70 2d 64 65  extension block: type 0x0009 (exclusion policy), length 80; policy name
00000190  66 61 75 6c 74 00 00 00 00 00 00 00 00 00 00 00
000001a0  00 00 00 00 00 00 00 00 01 00 00 00 05 00 00 00  version 1, 5 rules, reserved
000001b0  00 00 01 00 17 00 00 00 00 01 01 00 b5 00 00 00  rules: channel, direction, action 1 (stub), reserved, opcode, rangeCount
000001c0  00 01 01 00 b6 00 00 00 00 00 01 00 cc 00 00 00
000001d0  00 01 01 00 e2 00 00 00 a2 a5 72 ea 0a 00 00 00  block CRC; extension block: type 0x000A (source), length 197
000001e0  c5 00 00 00 63 61 70 74 61 69 6e 00 00 00 00 00  format
000001f0  00 00 00 00 31 2e 31 33 2e 30 00 00 00 00 00 00  formatVersion
00000200  00 00 00 00 03 00 00 00 a0 ab ff ff aa aa aa aa  skippedRecords 3, utcOffsetSeconds -21600; sourceHash
00000210  aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa
00000220  aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa
00000230  aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa
00000240  aa aa aa aa aa aa aa aa aa aa aa aa 59 00 00 00  metadataLength
00000250  7b 20 43 61 70 74 61 69 6e 20 3d 20 7b 20 56 65  metadata: the manifest
00000260  72 73 69 6f 6e 20 3d 20 22 31 2e 31 33 2e 30 22
00000270  20 7d 2c 20 46 46 58 49 20 3d 20 7b 20 49 73 52
00000280  65 74 61 69 6c 20 3d 20 66 61 6c 73 65 20 7d 2c
00000290  20 53 74 61 72 74 54 69 6d 65 20 3d 20 31 37 39
000002a0  30 30 30 30 30 30 30 20 7d b2 bf ce 4c 58 43 46  block CRC; frame: magic XCFR, kind 0x80 (packets), reserved, markerCount 0
000002b0  52 80 00 00 00 34 00 00 00 04 00 00 00 00 6c 50  payloadSize 52, packetCount 4; baseTimestamp
000002c0  c4 a0 01 00 00 00 00 00 00 28 b5 2f fd 24 70 3d  zoneId 0, reserved; payload: one zstd frame (decompressed below)
000002d0  01 00 a8 00 00 00 00 00 00 df 00 10 00 00 00 df
000002e0  08 01 00 0a 01 02 03 03 07 20 20 37 1d 6e 08 05
000002f0  c6 8d 02 8c 7b 1d c3 05 30 37 f3 26 47 4f ee 6e  frame CRC
00000300  c2 00 6c 50 c4 a0 01 00 00 ad 02 00 00 00 00 00  footer index entry: timestamp, fileOffset, zoneId, reserved
00000310  00 00 00 00 00 00 00 00 00 1e 6c 50 c4 a0 01 00  trailer: endTimestamp
00000320  00 04 00 00 00 00 00 00 00 00 00 00 00 01 00 00  totalPacketCount 4; reserved, entryCount 1
00000330  00 01 03 00 00 00 00 00 00 6c 75 f8 5f 01 00 00  indexOffset; indexCrc, frameCount 1
00000340  00 b8 98 a5 04 0c 94 1d ca 9b 0c d9 20 86 9b 17  signature
00000350  8a 31 fc 81 55 39 64 5b 50 4f 8d 5c 89 5c c3 8c
00000360  18 65 93 8d 0d 81 48 28 fa 2f bd 39 6a a9 0c 59
00000370  fa ea 0f dc 6b 30 11 18 d6 70 62 ef 34 6e 82 82
00000380  09 82 c2 ce 48 58 43 50 46                       trailerCrc, magic XCPF
```

The frame's payload, decompressed:

```
00000000  00 00 00 00 00 00 df 00 10 00 00 00 df 08 01 00  entry: deltaMs 0, flags 0, channel 0, opcode 0x0DF, length 16; packet bytes, from the 4-byte FFXI header
00000010  00 00 00 00 00 00 00 00 00 00 00 00 0a 00 00 00  entry: deltaMs 10, flags 0, channel 0, opcode 0x0DF, length 16
00000020  00 00 df 00 10 00 00 00 df 08 01 00 01 01 01 01  packet bytes, from the 4-byte FFXI header
00000030  01 01 01 01 01 01 01 01 0a 00 00 00 00 00 df 00  entry: deltaMs 10, flags 0, channel 0, opcode 0x0DF, length 16
00000040  10 00 00 00 df 08 01 00 02 02 02 02 02 02 02 02  packet bytes, from the 4-byte FFXI header
00000050  02 02 02 02 0a 00 00 00 00 00 df 00 10 00 00 00  entry: deltaMs 10, flags 0, channel 0, opcode 0x0DF, length 16
00000060  df 08 01 00 03 03 03 03 03 03 03 03 03 03 03 03  packet bytes, from the 4-byte FFXI header
```

`tests/spec_reader.py --example FORMAT.md` checks that these bytes are the
conformance file and that it reads them.

## Versioning

| Change | Version |
|--------|---------|
| Layout of an existing structure changes, except the header growing as [Header](#header) allows | major |
| A new frame kind, packet flag, channel, extension type, marker kind, or a field in reserved bytes that old readers can ignore | minor |
| Anything an old reader would misread without a must-understand frame kind or flag to stop it | major |
| A new check readers make | none |

A reader refuses a different major version. It reads a newer minor version,
skipping what it does not know, unless a must-understand frame kind or flag
tells it to refuse.

Before production, a draft may change anything. From production on, readers
keep reading every released version.

## Dependencies

The C++ library vendors Monocypher 4.0.3 in `third_party/monocypher`
(`monocypher.c` and `optional/monocypher-ed25519.c`) for Ed25519 and SHA-512.
Renovate cannot update a vendored file; check Monocypher's releases when
releasing xicap.
