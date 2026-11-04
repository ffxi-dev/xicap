# xicap format

Format 5. This document is normative: a reader built from it alone, with the
references below, must read every capture the library writes.

**Status: draft.** Until the format is declared stable, a change may break
compatibility.

## Conventions

- Every integer is little-endian. Structures are byte-packed, with no padding.
- Offsets and sizes are in bytes; a KiB is 2^10 bytes and a MiB 2^20. `u8`,
  `u16`, `u32`, `u64` are unsigned.
- A text field of N bytes holds UTF-8, padded with zero bytes. It holds at
  most N - 1 bytes of text, cut only between characters, so it always ends
  with a zero byte. A reader takes the text up to the first zero byte, or the
  whole field if it finds none.
- Text, in fields and markers, is UTF-8, and writers write nothing else. A
  reader that finds bytes that are not UTF-8 does not refuse the file; it may
  yield them as stored or replace them with U+FFFD.
- Timestamps are milliseconds since the Unix epoch, in UTC.
- A byte range `a..b` includes byte `a` and stops before byte `b`.
- A **varint** is unsigned LEB128: 7 bits per byte, low bits first, the high
  bit set on every byte but the last. Each varint fills a field 8, 16, or 32
  bits wide. A reader refuses one longer than 2, 3, or 5 bytes, or whose value
  does not fit its field. Within those limits it accepts a varint with more
  bytes than its value needs.
- **Zigzag** maps a signed 16-bit change `n` to the unsigned 16-bit
  `(n << 1) ^ (n >> 15)`, so small changes either way take one byte. Its
  inverse is `(z >> 1) ^ -(z & 1)`.
- A rule that says what a field holds binds writers. A reader checks only what
  [Reading](#reading) lists, and accepts any other value.

| Reference | Used for |
|-----------|----------|
| CRC-32 | Polynomial `0x04C11DB7` reflected (`0xEDB88320`), initial value `0xFFFFFFFF`, final XOR `0xFFFFFFFF` (CRC-32/ISO-HDLC, as zlib computes it). The CRC of ASCII `123456789` is `0xCBF43926`. |
| zstd | RFC 8878. |
| LEB128 | Unsigned LEB128, as DWARF and WebAssembly use it. |

## File layout

```
+--------------------+
| Header             |  160 bytes
+--------------------+
| Blocks             |  Header.blockCount blocks
+--------------------+
| Frames             |  0 or more
+--------------------+
| Trailer            |  24 bytes, once the writer closes the file
+--------------------+
```

A writer only appends, and never changes what it has written, so every copy of
a file being recorded is a prefix of the finished file. A file whose last 24
bytes are a valid trailer is **complete**. A file without one is **cut off**:
the recorder crashed, or is still recording. A trailer whose CRC fails is not a
valid trailer, so a file that ends with one is cut off.

## Header

A writer writes the header, with every field final, along with the first
frame, or when it closes a capture that holds no packet.

| Off | Size | Field | Notes |
|----:|-----:|-------|-------|
| 0 | 8 | `magic` | `89 58 43 50 0D 0A 1A 0A`, see below |
| 8 | 1 | `version` | `5` |
| 9 | 1 | `origin` | `0` unknown, `1` recorded live, `2` converted from another format |
| 10 | 1 | `network` | `0` unknown, `1` retail, `2` private server |
| 11 | 1 | `blockCount` | blocks after the header |
| 12 | 16 | `captureId` | 16 random bytes |
| 28 | 16 | `previousCaptureId` | the capture this one continues, or all zero |
| 44 | 8 | `startTimestamp` | the first packet's timestamp; `0` if the capture holds no packet |
| 52 | 32 | `captureAgent` | text: the program that wrote the capture, with its version |
| 84 | 32 | `clientVersion` | text: the game client's build |
| 116 | 4 | `contentId` | the character's POL id (`ffxi_id`) |
| 120 | 4 | `characterId` | the character's id on its world, as the zone-in's `UniqueNo` holds it |
| 124 | 16 | `characterName` | text |
| 140 | 16 | `worldName` | text |
| 156 | 4 | `crc` | CRC-32 of header bytes `0..156` |

The magic follows PNG's:

```
89 58 43 50 0D 0A 1A 0A
    X  C  P \r \n ^Z \n
```

A capture holds one character's session. A recorder that starts a capture after
a login, or after a crash, sets `previousCaptureId` to the capture it
continues, if it knows it.

## Blocks

| Off | Size | Field |
|----:|-----:|-------|
| 0 | 4 | `type` |
| 4 | 4 | `length`: payload size, at most 16 MiB |
| 8 | `length` | payload |
| 8 + `length` | 4 | `crc`: CRC-32 of the type, length, and payload |

| Type | Name | Present | Payload |
|-----:|------|---------|---------|
| `1` | exclusion policy | always, exactly once | [Exclusion](#exclusion) |
| `2` | source | at most once, in converted captures | [Source](#source) |

Readers skip blocks of other types. A later version of this document may
define them; types from `0x8000` are for other programs.

### Source

What a converted capture was converted from.

| Off | Size | Field | Notes |
|----:|-----:|-------|-------|
| 0 | 16 | `format` | text: the source format, such as `captain` |
| 16 | 16 | `formatVersion` | text: the source program's version |
| 32 | 4 | `skippedRecords` | source records not converted |
| 36 | rest | `metadata` | the source's own metadata as found, such as captain's `manifest.txt`, to the end of the payload |

## Frames

A frame holds packets: a 28-byte header, the payload, and a CRC.

| Off | Size | Field | Notes |
|----:|-----:|-------|-------|
| 0 | 4 | `magic` | ASCII `XCFR` |
| 4 | 4 | `payloadSize` | at most 17 MiB |
| 8 | 4 | `plainSize` | bytes the payload decodes to, 1 to 16 MiB |
| 12 | 4 | `packetCount` | 1 to 1,048,576 |
| 16 | 4 | `markerCount` | |
| 20 | 8 | `baseTimestamp` | the first packet's timestamp |
| 28 | `payloadSize` | payload | |
| 28 + `payloadSize` | 4 | `crc` | CRC-32 of frame bytes `0..28+payloadSize` |

The payloads of the file's frames, in order, are one zstd stream (RFC 8878)
with no dictionary and a window of at most 8 MiB. Each frame's payload, fed to
a decoder that has decoded the payloads before it, yields exactly `plainSize`
bytes with no later input. So a frame decodes as soon as it is written, but
only after the frames before it. A writer flushes the stream at the end of
each frame; it need not end the zstd frame.

### Plaintext

A frame's decoded payload, its plaintext, holds its packets in columns. In
order:

| # | Section | Holds |
|--:|---------|-------|
| 1 | `deltaMs` | `packetCount` 32-bit varints: milliseconds since the previous packet of this frame; `0` for the first |
| 2 | `flags` | `packetCount` 16-bit varints: see [Packet flags](#packet-flags) |
| 3 | `channel` | `packetCount` 8-bit varints: see [Channels](#channels) |
| 4 | `opcode` | `packetCount` 16-bit varints: meaning set by the channel |
| 5 | `length` | `packetCount` 32-bit varints: `0` means the game header's `size` × 4; otherwise the packet's length + 1 |
| 6 | `sync` | one zigzag 16-bit varint per game-channel packet, in packet order: the change from the sync of the previous game-channel packet in the same direction in this frame, or from 0 for the first. The change is `(sync - previous) mod 2^16` read as a signed 16-bit value; the reader adds it back modulo 2^16 |
| 7 | markers | `markerCount` markers, see below |
| 8 | group sizes | one 32-bit varint per group: the group's byte count |
| 9 | group bytes | each group's packet bytes, back to back, groups in the order of section 8 |

A packet's timestamp is the frame's `baseTimestamp` plus the `deltaMs` of every
packet of the frame up to and including its own.

A **group** is every packet of the frame with the same channel, direction
(`flags` bit 0), and opcode. Groups are ordered by their first packet. A reader
learns the groups from sections 2 to 4, so section 8 holds no keys. A group's
bytes are its packets' bytes in packet order.

On the game channel, a packet sits in its group with bytes 2 and 3, its sync
counter, set to zero; the reader puts back the sync from section 6. A writer
writes `length` 0 exactly when the packet is on the game channel, its header's
`size` is not 0, and its length is `size` × 4.

Each **marker** is:

| Field | Notes |
|-------|-------|
| `packetIndex` | 32-bit varint: the packet of this frame the marker sits just before, from 0 |
| `kind` | `u8`: `0` note, `1` login, `2` logout; readers yield other kinds unchanged |
| `textLength` | 16-bit varint |
| text | `textLength` bytes, no terminator |

A marker marks a moment between two packets, so it sits just before the next
packet written after it. A marker with no packet after it when the capture
closes is dropped. A frame's markers follow the order they were written in.

**Decoding** is one pass. Read sections 1 to 7 front to back, each counted by
`packetCount`, the number of game-channel packets, or `markerCount`. Find the
groups from sections 2 to 4, read section 8, and check that the group sizes add
up to the bytes left. Then, packet by packet, take the next bytes from the
packet's group: for a game-channel packet, its 4-byte header first, which gives
`size` when `length` is 0, then the rest, then put back its sync.

#### Packet flags

| Bit | Flag |
|----:|------|
| 0 | direction: `0` to the client, `1` from the client |
| 1 | injected by an addon |
| 2 | blocked by an addon |
| 3 | modified by an addon |
| 4 | first packet of its datagram |
| 8 | excluded: a stub, see [Exclusion](#exclusion) |
| 9 | redacted: byte ranges zeroed, see [Exclusion](#exclusion) |

Writers write the other bits as zero; readers yield them as stored.

Packet bytes are the packet as the client's hook delivered it, decrypted and
decompressed, before any addon changed it. For an injected packet, they are
the bytes the addon injected.

#### Example

Three game packets to the client, opcode `0x0DF`, 16 bytes each, 10 ms apart,
with syncs 1, 2, and 3. The plaintext is 70 bytes:

```
00 0a 0a                   deltaMs: 0, 10, 10
00 00 00                   flags
00 00 00                   channel: game
df 01 df 01 df 01          opcode: 0x0DF as a varint
00 00 00                   length: the header's size x 4 (4 words, 16 bytes)
02 02 02                   sync, to the client: +1, +1, +1, zigzag-encoded
                           (no markers)
30                         group sizes: one group (game, to the client, 0x0DF) of 48 bytes
df 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00   packet 0, sync zeroed
df 08 00 00 01 01 01 01 01 01 01 01 01 01 01 01   packet 1
df 08 00 00 02 02 02 02 02 02 02 02 02 02 02 02   packet 2
```

## Channels

| Channel | Name | Packet bytes | `opcode` | A stub keeps |
|--------:|------|--------------|----------|--------------|
| 0 | game | the FFXI packet, from its 4-byte header | the header's 9-bit id | the 4-byte header |
| 1 | search | the plaintext request or reply, from its 4-byte size | byte `0x0B`, the request type, as the writer's caller gives it | not defined |

Other channels are reserved. A reader yields their packets with the channel's
number.

The first 4 bytes of a game packet are its FFXI header:

```
byte 0     byte 1             byte 2     byte 3
[id_lo:8]  [size:7 | id_hi:1] [sync_lo:8] [sync_hi:8]
```

Byte 1 holds bit 8 of `id` in its lowest bit and `size` in its high 7 bits:

- `id` = `u16(bytes 0..2) & 0x01FF`
- `size` = `u16(bytes 0..2) >> 9`, in 4-byte words
- `sync` = `u16(bytes 2..4)`, a sequence counter per direction

A writer refuses a game packet shorter than 4 bytes, and sets `opcode` to its
`id`.

## Exclusion

Every capture carries the exclusion policy its writer applied, in its policy
block. The writer applies it to each packet before compressing it, so
excluded bytes never reach the file. A policy with no rules says the writer
kept everything, chat included.

| Off | Size | Field |
|----:|-----:|-------|
| 0 | 32 | `name`: text |
| 32 | 4 | `version` |
| 36 | 2 | `ruleCount` |
| 38 | | `ruleCount` rules, to the end of the payload |

Each rule:

| Off | Size | Field | Notes |
|----:|-----:|-------|-------|
| 0 | 1 | `channel` | |
| 1 | 1 | `direction` | `0` to the client, `1` from the client, `2` both |
| 2 | 1 | `action` | `1` stub, `2` zero byte ranges |
| 3 | 2 | `opcode` | |
| 5 | 2 | `rangeCount` | `0` for a stub |
| 7 | | `rangeCount` ranges of `u32 offset, u32 length` | a length of `0xFFFFFFFF` runs to the packet's end |

The first rule that matches a packet's channel, direction, and opcode applies.

- **Stub:** the packet keeps its timestamp, channel, direction, provenance
  flags, and opcode, sets the excluded flag, and keeps only what its channel's
  row in [Channels](#channels) says a stub keeps. A writer refuses a stub rule
  for a channel whose row does not say.
- **Zero byte ranges:** the packet keeps its length, sets the redacted flag,
  and has each range zeroed. A range that runs past the packet's end stops at
  the end. On the game channel no range may start inside the 4-byte header; a
  writer refuses such a rule.

The library's default policy, `xicap-default` version 2, zeroes the text
players write to each other on the game channel, and nothing else, so each
packet keeps its length and its other fields. Offsets count the 4-byte header.

| Opcode | Direction | Packet | Zeroed |
|-------:|-----------|--------|--------|
| `0x017` | to the client | chat, in every channel | `0x17` to the end (`Mes`) |
| `0x0B5` | from the client | chat | `0x06` to the end (`Str`) |
| `0x0B6` | from the client | tell | `0x15` to the end (`Mes`) |
| `0x0B7` | from the client | the Assist Channel | `0x15` to the end (`Mes`) |
| `0x0CC` | to the client | linkshell message board | `0x08`, 128 bytes (`sMessage`) |
| `0x0E2` | from the client | linkshell message board post | `0x10`, 128 bytes (`sMessage`) |

Opcodes and field names follow atom0s's XiPackets.

## Trailer

| Off | Size | Field | Notes |
|----:|-----:|-------|-------|
| 0 | 4 | `magic` | ASCII `XCPF` |
| 4 | 8 | `endTimestamp` | the last packet's timestamp; `0` if none |
| 12 | 8 | `packetCount` | packets in the file |
| 20 | 4 | `crc` | CRC-32 of trailer bytes `0..20` |

The last 24 bytes of a complete file are its trailer, so a reader can learn
the end time from them alone.

## Reading

A reader refuses the file, wherever it meets the cause, when:

- the file ends before its header and blocks do, an empty file included;
- the magic differs, `version` is not 5, or the header's CRC fails;
- a block's `length` is over 16 MiB, the block runs past the end of the file,
  or its CRC fails;
- there is no policy block, a second policy block, or a second source block;
- a policy block's rules and ranges do not end exactly at the end of its
  payload, or a source block's payload is under 36 bytes;
- the file is complete and holds a bad frame;
- its frames end at a valid trailer that is not the file's last 24 bytes, or
  the trailer's `packetCount` or `endTimestamp` differs from the packets read.

A reader that has already passed on packets reports the refusal, and its
caller drops them.

A **bad frame** is one that is cut short, lacks the `XCFR` magic, has a
`payloadSize` over 17 MiB, fails its CRC, has a `plainSize` or `packetCount`
out of range, makes the zstd decoder fail, does not decode to exactly
`plainSize` bytes with its whole payload, or has a bad plaintext:

- a section runs past the end of the plaintext, or a varint breaks the rules
  in [Conventions](#conventions);
- the group sizes do not add up to the bytes left, or a group's bytes are not
  used exactly;
- a game-channel packet is shorter than 4 bytes, or its `opcode` differs from
  its header's `id`;
- a packet off the game channel has `length` 0;
- a marker's `packetIndex` is not below `packetCount`, or is below the
  previous marker's;
- the first packet's `deltaMs` is not 0, or a timestamp passes 2^64 − 1;
- its `baseTimestamp` is earlier than the last packet of the frame before it.

Since a frame decodes only after the frames before it, the frames after a bad
one cannot be read. A cut-off file ends at its first bad frame.

A reader of a file that arrives as it downloads reads frames until it meets a
valid trailer, or bytes that are neither a whole, valid frame nor a valid
trailer, and stops there. It refuses the file if more bytes arrive after a
valid trailer.

## Writer rules

These rules are part of the format: a capture that breaks them is wrong even
if it reads.

- **Timestamps never go backwards** in file order, across every channel. Equal
  timestamps are allowed. Given an earlier time than the last, a writer
  records the last again.
- **Frames.** A writer ends the frame being built before adding a packet that
  would push its `deltaMs` past 2^32 − 1, its `packetCount` past 1,048,576, or
  its plaintext past 16 MiB. It also ends frames by its own settings and when
  its host asks it to. The library's two settings:

  | | live (the default) | archive |
  |---|---|---|
  | zstd level | 7 | 19 |
  | window | 2 MiB | 8 MiB |
  | match table (`hashLog`) | 2^19 | the level's own |
  | frame ends | 5 s, 1,000 packets, 64 KiB of plaintext, host flush | 1 MiB of plaintext |

- **Durability.** A writer hands each frame to the operating system as soon as
  it is written. After a write fails, it writes nothing more, trailer
  included, so the file reads as cut off before the failure.
- **Empty captures** still get a header, blocks, and a trailer.
- **Rewriting.** A program may rewrite a capture with other frames and
  compression. It keeps the header's fields, the blocks, and every packet and
  marker in order; the bytes depend on the compressor.

## Conformance

`tests/vectors/` holds test files, each with a JSON file of its expected
reading. The C++ library and every binding read all of them in CI, and
`tests/spec_reader.py`, a reader written from this document alone, reads them
too.

A refused file's JSON is `{"refused": true}`. Any other holds `refused`,
`complete`, `endTimestamp` and `packetCount` from the trailer (both `0` in a
cut-off file), `metadata`, and `packets`. Header text fields are JSON strings;
capture ids, source metadata, packet bytes, and marker text are lowercase hex.
A policy rule's ranges are `[offset, length]` pairs. Each packet lists
`timestamp`, `flags`, `channel`, `opcode`, `data`, and `markers`, each marker
with its `kind` and `text`.

## Worked example

The conformance file `tests/vectors/5-example.xicap`, whole: a live capture of
the three packets of [the example above](#example), with the default policy,
one frame, and the trailer. Offsets are in hex.

```
00000000  89 58 43 50 0d 0a 1a 0a 05 01 01 01 33 33 33 33  magic; version 5; origin 1 (live); network 1 (retail); blockCount 1; captureId
00000010  33 33 33 33 33 33 33 33 33 33 33 33 00 00 00 00  previousCaptureId (from 1c)
00000020  00 00 00 00 00 00 00 00 00 00 00 00 00 a8 da 76  startTimestamp (from 2c)
00000030  9b 01 00 00 78 69 63 61 70 20 74 65 73 74 73 00  captureAgent (from 34)
00000040  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00000050  00 00 00 00 33 30 32 35 31 31 30 31 5f 32 00 00  clientVersion (from 54)
00000060  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00000070  00 00 00 00 04 03 02 01 0d 0c 0b 0a 52 68 61 76  contentId (from 74); characterId; characterName
00000080  79 6e 00 00 00 00 00 00 00 00 00 00 41 73 75 72  worldName (from 8c)
00000090  61 00 00 00 00 00 00 00 00 00 00 00 bc a9 a7 b4  header crc (from 9c)
000000a0  01 00 00 00 80 00 00 00 78 69 63 61 70 2d 64 65  block: type 1 (exclusion policy), length 128; name
000000b0  66 61 75 6c 74 00 00 00 00 00 00 00 00 00 00 00
000000c0  00 00 00 00 00 00 00 00 02 00 00 00 06 00 00 00  version 2 (from c8), ruleCount 6, first rule (from ce)
000000d0  02 17 00 01 00 17 00 00 00 ff ff ff ff 00 01 02  game, to the client, zero ranges, 0x017, 1 range: 0x17 to the end
000000e0  b5 00 01 00 06 00 00 00 ff ff ff ff 00 01 02 b6
000000f0  00 01 00 15 00 00 00 ff ff ff ff 00 01 02 b7 00
00000100  01 00 15 00 00 00 ff ff ff ff 00 00 02 cc 00 01
00000110  00 08 00 00 00 80 00 00 00 00 01 02 e2 00 01 00
00000120  10 00 00 00 80 00 00 00 70 24 c1 57 58 43 46 52  block crc (from 128); frame: magic XCFR (from 12c)
00000130  3c 00 00 00 46 00 00 00 03 00 00 00 00 00 00 00  payloadSize 60, plainSize 70, packetCount 3, markerCount 0
00000140  00 a8 da 76 9b 01 00 00 28 b5 2f fd 00 58 9c 01  baseTimestamp; payload (from 148): the plaintext above, compressed
00000150  00 94 02 00 0a 0a 00 df 01 df 01 df 01 00 00 00
00000160  02 02 02 30 df 08 00 df 08 00 00 01 df 08 00 00
00000170  02 02 02 02 02 02 02 02 02 02 02 02 03 10 00 86
00000180  76 eb 22 02 7c 89 a4 65 58 43 50 46 14 a8 da 76  frame crc (from 184); trailer: magic XCPF (from 188), endTimestamp
00000190  9b 01 00 00 03 00 00 00 00 00 00 00 3e 01 fd c2  packetCount 3 (from 194), crc (from 19c)
```

`tests/spec_reader.py --example FORMAT.md` checks that these bytes are the
conformance file and that it reads them.

## Versioning

A reader refuses a version other than 5. Changes old readers already handle as
this document says, such as a new channel, marker kind, or block type, keep
version 5. Any other change gets a new version.
