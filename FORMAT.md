# xicap format

Format version 5. This specification is normative. It is a draft: until the
format is declared stable, a change may break compatibility.

A capture holds one character's session.

## Conventions

- Every integer is little-endian. Structures are byte-packed, with no padding.
- Offsets and sizes are in bytes; a KiB is 2^10 bytes and a MiB 2^20. `u8`,
  `u16`, `u32`, `u64` are unsigned.
- Writers encode text, in fields and markers, as UTF-8. An N-byte text field
  holds at most N - 1 bytes of text, cut at a character boundary and padded
  with zero bytes. A reader takes the text up to the first zero byte, or the
  whole field if it finds none.
- A reader accepts text that is not UTF-8, and may yield it as stored or
  replace the bad bytes with U+FFFD.
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

Writers append without modifying earlier bytes. A file whose last 24 bytes are
a valid trailer, one with the `XCPF` magic and a matching CRC, is **complete**.
A file without one is **cut off**: the recorder crashed, or is still recording.

## Header

| Off | Size | Field | Notes |
|----:|-----:|-------|-------|
| 0 | 8 | `magic` | `89 58 43 50 0D 0A 1A 0A`, see below |
| 8 | 1 | `version` | `5` |
| 9 | 1 | `origin` | `0` unknown, `1` recorded live, `2` converted from another format |
| 10 | 1 | `serverKind` | `0` unknown, `1` retail, `2` private server |
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


## Blocks

| Off | Size | Field |
|----:|-----:|-------|
| 0 | 4 | `type` |
| 4 | 4 | `length`: payload size, at most 16 MiB |
| 8 | `length` | payload |
| 8 + `length` | 4 | `crc`: CRC-32 of the type, length, and payload |

| Type | Name | Present | Payload |
|-----:|------|---------|---------|
| `2` | source | at most once, in converted captures | [Source](#source) |

Readers skip blocks of other types. Types from `0x8000` are for other
programs.

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
bytes with no later input. A writer flushes the stream at the end of each
frame; it need not end the zstd frame.

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
learns the groups from sections 2 to 4. A group's bytes are its packets' bytes
in packet order.

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

To decode a game-channel packet, read its 4-byte header from its group first,
which gives its length when `length` is 0, then restore its sync from section 6.

#### Packet flags

| Bit | Flag |
|----:|------|
| 0 | direction: `0` to the client, `1` from the client |
| 1 | injected by an addon |
| 2 | blocked by an addon |
| 3 | modified by an addon |
| 4 | first packet of its datagram |
| 8 | excluded: a stub, see [Redaction](#redaction) |
| 9 | redacted: chat text zeroed, see [Redaction](#redaction) |

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

| Channel | Name | Packet bytes | `opcode` |
|--------:|------|--------------|----------|
| 0 | game | the FFXI packet, from its 4-byte header | the header's 9-bit id |
| 1 | search | the plaintext request or reply, from its 4-byte size | byte `0x0B`, the request type, as the writer's caller gives it |

Other channels are reserved. A reader yields their packets with the channel's
number.

The first 4 bytes of a game packet are its FFXI header:

- `id` = `u16(bytes 0..2) & 0x01FF`
- `size` = `u16(bytes 0..2) >> 9`, in 4-byte words
- `sync` = `u16(bytes 2..4)`, a sequence counter per direction

A writer refuses a game packet shorter than 4 bytes.

## Redaction

A writer zeroes the ranges below in each game-channel packet with the listed
opcode and direction, before compression, and sets the packet's redacted flag.
A range that runs past the packet's end stops there. The packet keeps its
length and every byte outside the ranges. Offsets count the 4-byte header.

| Opcode | Direction | Packet | Zeroed |
|-------:|-----------|--------|--------|
| `0x017` | to the client | chat, in every channel | `0x17` to the end (`Mes`) |
| `0x0B5` | from the client | chat | `0x06` to the end (`Str`) |
| `0x0B6` | from the client | tell | `0x15` to the end (`Mes`) |
| `0x0B7` | from the client | the Assist Channel | `0x15` to the end (`Mes`) |
| `0x0CC` | to the client | linkshell message board | `0x08`, 128 bytes (`sMessage`) |
| `0x0E2` | from the client | linkshell message board post | `0x10`, 128 bytes (`sMessage`) |

Opcodes and field names follow atom0s's XiPackets. When configured to keep
chat, writers preserve those bytes. Changing the table needs a new format
version.

A packet with the excluded flag is a stub: it holds only its 4-byte game
header, and keeps its timestamp, channel, direction, provenance flags, and
opcode. Converted captures may preserve four-byte stubs from older formats.

## Trailer

| Off | Size | Field | Notes |
|----:|-----:|-------|-------|
| 0 | 4 | `magic` | ASCII `XCPF` |
| 4 | 8 | `endTimestamp` | the last packet's timestamp; `0` if none |
| 12 | 8 | `packetCount` | packets in the file |
| 20 | 4 | `crc` | CRC-32 of trailer bytes `0..20` |

## Reading

A reader refuses the file, wherever it meets the cause, when:

- the file ends before its header and blocks do, an empty file included;
- the magic differs, `version` is not 5, or the header's CRC fails;
- a block's `length` is over 16 MiB, the block runs past the end of the file,
  or its CRC fails;
- there is a second source block, or a source block's payload is under 36
  bytes;
- the file is complete and holds a bad frame;
- its frames end at a valid trailer that is not the file's last 24 bytes, or
  the trailer's `packetCount` or `endTimestamp` differs from the packets read.

A refusal found after packets were passed on refuses the whole file.

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

A cut-off file ends at its first bad frame.

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
  its host asks it to.
- **Header.** A writer writes the header and blocks with the first frame, or at
  close for an empty capture, so `startTimestamp` is final.
- **Durability.** A writer hands each frame to the operating system as soon as
  it is written. After a write fails, it writes nothing more, trailer
  included, so the file reads as cut off before the failure.
- **Empty captures** have a header, their blocks, and a trailer.
- **Rewriting.** A program may rewrite a capture with other frames and
  compression. It keeps the header's fields, the blocks, and every packet and
  marker in order; the bytes depend on the compressor.

## Conformance

`tests/vectors/` holds test files, each with a JSON file of its expected
reading. A refused file's JSON is `{"refused": true}`. Any other holds
`refused`, `complete`, `endTimestamp` and `packetCount` from the trailer (both
`0` in a cut-off file), `metadata`, and `packets`. Header text fields are JSON
strings; capture ids, source metadata, packet bytes, and marker text are
lowercase hex. Each packet lists `timestamp`, `flags`, `channel`, `opcode`,
`data`, and `markers`, each marker with its `kind` and `text`.

## Worked example

The conformance file `tests/vectors/5-example.xicap`, whole: a live capture of
the three packets of [the example above](#example), with no blocks, one
frame, and the trailer. Offsets are in hex.

```
00000000  89 58 43 50 0d 0a 1a 0a 05 01 01 00 33 33 33 33  magic; version 5; origin 1 (live); serverKind 1 (retail); blockCount 0; captureId
00000010  33 33 33 33 33 33 33 33 33 33 33 33 00 00 00 00  previousCaptureId (from 1c)
00000020  00 00 00 00 00 00 00 00 00 00 00 00 00 a8 da 76  startTimestamp (from 2c)
00000030  9b 01 00 00 78 69 63 61 70 20 74 65 73 74 73 00  captureAgent (from 34)
00000040  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00000050  00 00 00 00 33 30 32 35 31 31 30 31 5f 32 00 00  clientVersion (from 54)
00000060  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00000070  00 00 00 00 04 03 02 01 0d 0c 0b 0a 52 68 61 76  contentId (from 74); characterId; characterName
00000080  79 6e 00 00 00 00 00 00 00 00 00 00 41 73 75 72  worldName (from 8c)
00000090  61 00 00 00 00 00 00 00 00 00 00 00 a1 52 e9 ec  header crc (from 9c)
000000a0  58 43 46 52 3c 00 00 00 46 00 00 00 03 00 00 00  frame: magic XCFR, payloadSize 60, plainSize 70, packetCount 3
000000b0  00 00 00 00 00 a8 da 76 9b 01 00 00 28 b5 2f fd  markerCount 0; baseTimestamp (from b4); payload (from bc): the plaintext above, compressed
000000c0  00 58 9c 01 00 94 02 00 0a 0a 00 df 01 df 01 df
000000d0  01 00 00 00 02 02 02 30 df 08 00 df 08 00 00 01
000000e0  df 08 00 00 02 02 02 02 02 02 02 02 02 02 02 02
000000f0  03 10 00 86 76 eb 22 02 7c 89 a4 65 58 43 50 46  frame crc (from f8); trailer: magic XCPF (from fc)
00000100  14 a8 da 76 9b 01 00 00 03 00 00 00 00 00 00 00  endTimestamp; packetCount 3 (from 108)
00000110  3e 01 fd c2                                      crc
```

`tests/reference_reader.py --example FORMAT.md` checks that these bytes are the
conformance file and that it reads them.

## Versioning

Changes old readers already handle as this document says, such as a new
channel, marker kind, or block type, keep version 5. Any other change gets a
new version.
