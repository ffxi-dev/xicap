# XICAP Binary Format

Version 4.0. This document is normative: a reader built from it alone, with the
references below, must read every format-4 capture the library writes.
[FORMAT-3.md](FORMAT-3.md) specifies format 3, which readers keep reading.

**Status: in production** since 2026-11-03, when Mogsafe deployed xicap 4.0
and began archiving format 4. Captures are kept for the long term, so readers
keep reading every released version of format 4, and a change that an older
reader cannot follow needs a new major version.

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
- A **varint** is unsigned LEB128: 7 bits per byte, low bits first, the high
  bit set on every byte but the last. Each varint fills a field of a stated
  width: 8, 16, or 32 bits. It takes at most 2, 3, or 5 bytes, and its value
  fits the field. A reader refuses a longer varint or a larger value.
- **Zigzag** maps a signed 16-bit change `n` to the unsigned 16-bit
  `(n << 1) ^ (n >> 15)`, so small changes either way take one byte. Its
  inverse is `(z >> 1) ^ -(z & 1)`.

### References

| Name | Used for |
|------|----------|
| CRC-32 | Polynomial `0x04C11DB7` reflected (`0xEDB88320`), initial value `0xFFFFFFFF`, final XOR `0xFFFFFFFF` (CRC-32/ISO-HDLC, as zlib). Check value: CRC of ASCII `123456789` is `0xCBF43926`. |
| SHA-512 | FIPS 180-4. |
| Ed25519 | RFC 8032, pure Ed25519 (not Ed25519ph or Ed25519ctx). |
| zstd | RFC 8878. |
| LEB128 | Unsigned LEB128, as DWARF and WebAssembly use it. |

## File layout

```
+--------------------+
| Header             |  headerSize bytes (384 in 4.0)
+--------------------+
| Extension blocks   |  Header.extensionCount blocks
+--------------------+
| Frames             |  0..N frames: packet frames and checkpoint frames
+--------------------+
| Footer index       |  only after a clean close
+--------------------+
| Seal               |  160 bytes, only in a file another program rewrote
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
| 8 | 1 | `versionMajor` | `4` |
| 9 | 1 | `versionMinor` | `0` |
| 10 | 2 | `headerSize` | `384` in 4.0. Readers accept any value from 384 to 4096 and skip to it |
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
| 72 | 4 | `dictionaryId` | `0`. A reader refuses any other value |
| 76 | 4 | `reserved` | |
| 80 | 32 | `signingKey` | the signer's Ed25519 public key |
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
stops DOS `type`. 2.x files start with `XCAP`, so a reader refuses them as a
bad magic.

`headerCrc` is always the last 4 bytes of the header. A later minor version may
grow the header: it adds fields in the reserved bytes or after them, moves the
CRC to the new end, and raises `headerSize`.

A reader refuses the file if the magic differs, `headerSize` is out of range,
`headerCrc` fails, or `dictionaryId` is not 0. A reader of format 4 reads
`versionMajor` 3 by [FORMAT-3.md](FORMAT-3.md) and refuses any other value.

`dictionaryId` stays in the header so a later version can add a dictionary
behind a check old readers already make.

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
| `0x0008` | `ZSTD_DICT` | never: a reader refuses it in format 4 | |
| `0x0009` | `EXCLUSION_POLICY` | always, exactly once | [Exclusion](#exclusion) |
| `0x000A` | `SOURCE` | when `origin` is 2, or the file was rewritten from another major version | [Source](#source) |

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

Converted captures (`origin` 2) carry this block, and so does a capture
rewritten from another major version.

| Off | Size | Field | Notes |
|----:|-----:|-------|-------|
| 0 | 16 | `format` | text: the source format, such as `captain`, or `xicap` for packets from another capture |
| 16 | 16 | `formatVersion` | text: the source program's version, or for `xicap` the source file's `major.minor` |
| 32 | 4 | `skippedRecords` | source records not converted |
| 36 | 4 | `utcOffsetSeconds` | `i32`: offset added to the source's times to get UTC |
| 40 | 64 | `sourceHash` | SHA-512 of the source file as uploaded |
| 104 | 4 | `metadataLength` | |
| 108 | `metadataLength` | `metadata` | the source's metadata as found, such as captain's `manifest.txt` |

A writer that rewrites a capture of another major version under its own key
(see [Rewriting a capture](#rewriting-a-capture)) keeps the source's SOURCE
block, if it has one. Otherwise it adds one: `format` `xicap`, `formatVersion`
the source's version, and `metadata` that starts with these lines, each ended by
`\n`, then anything the rewriter adds:

```
signing-key <the source's signingKey, 64 hex digits>
signed-to-end yes|no
verified-packets <packets the source's signatures covered, in decimal>
footer-signature <the source's footer signature, 128 hex digits>|none
transcoded-by <the rewriting program, with its version>
```

## Frames

Every frame starts with the same 32-byte header and ends with a CRC.

| Off | Size | Field | Notes |
|----:|-----:|-------|-------|
| 0 | 4 | `magic` | ASCII `XCFR` |
| 4 | 1 | `kind` | see below |
| 5 | 1 | `frameFlags` | packet frames: bit 0 **restart**, see [Streams](#streams). Other bits reserved |
| 6 | 2 | `markerCount` | markers in the payload; `0` for other kinds |
| 8 | 4 | `payloadSize` | bytes between this header and the CRC |
| 12 | 4 | `packetCount` | packets in the payload, 1 to 1,048,576; `0` for other kinds |
| 16 | 8 | `baseTimestamp` | first packet's timestamp; for other kinds, the last packet's timestamp before the frame |
| 24 | 2 | `zoneId` | zone named by the last zone-in at or before the frame's first packet; `0` if none. For other kinds, the zone in effect |
| 26 | 2 | `reserved` | |
| 28 | 4 | `plainSize` | packet frames: bytes the payload decodes to, 1 to 16 MiB; `0` for other kinds |
| 32 | `payloadSize` | payload | |
| 32 + `payloadSize` | 4 | `crc` | CRC-32 of frame bytes `0..32+payloadSize` |

| Kind | Name | Readers that do not know it |
|-----:|------|-----------------------------|
| `0x01` | checkpoint | skip it |
| `0x80` | packets | refuse the file |

A reader that does not know a kind below `0x80` may skip it after checking its
CRC. Kinds from `0x80` must be understood: a reader refuses a file holding one
it does not know.

### Streams

The payloads of the packet frames form zstd streams. Each stream is one zstd
frame (RFC 8878) that runs across one or more packet frames:

- A packet frame with the restart bit starts a stream: its payload begins a new
  zstd frame. The first packet frame of a file always has the bit.
- A packet frame without the bit continues the stream of the packet frame
  before it. Frames of other kinds in between are not part of any stream.
- The zstd frame has no dictionary id and no `Frame_Content_Size`, has
  `Content_Checksum_flag` set, and has a `Window_Size` of at most 8 MiB
  (2^23). A reader refuses a larger window.
- Each packet frame's payload is whole zstd blocks: fed to a decoder that has
  decoded the stream's earlier packet frames, it yields exactly `plainSize`
  bytes, with no later input.
- The last packet frame of a stream may end the zstd frame (last block and
  checksum). A reader checks the checksum when a stream ends. After the end, the
  next packet frame must start a stream.

A writer ends a stream after a frame when the plaintext since the restart, plus
its own frame size limit, would pass its restart setting (4 MiB by default, at
most 16 MiB), and it ends the last stream when it closes the file with a frame
still to write. A stream may also stop without its end, at the end of a cut-off
file or after a frame the writer flushed before it knew no more would come.
Readers do not rely on a stream's end.

A reader checks `plainSize` and `packetCount` before allocating.

### Packet frames

The decoded payload, its plaintext, holds the frame's packets in columns. In
order:

| # | Section | Holds |
|--:|---------|-------|
| 1 | `deltaMs` | `packetCount` 32-bit varints: milliseconds since the previous packet of this frame; `0` for the first |
| 2 | `flags` | `packetCount` 16-bit varints: see [Packet flags](#packet-flags) |
| 3 | `channel` | `packetCount` 8-bit varints: see [Channels](#channels) |
| 4 | `opcode` | `packetCount` 16-bit varints: meaning set by the channel |
| 5 | `length` | `packetCount` 32-bit varints: `0` means the game header's `size` × 4; otherwise the packet's length + 1 |
| 6 | `sync` | one zigzag 16-bit varint per game-channel packet, in packet order: the change from the sync of the previous game-channel packet in the same direction in this frame, or from 0 for the first |
| 7 | markers | `markerCount` markers, see below |
| 8 | group sizes | one 32-bit varint per group: the group's byte count |
| 9 | group bytes | each group's packet bytes, back to back, groups in the order of section 8 |

A packet's timestamp is the frame's `baseTimestamp` plus the `deltaMs` of every
packet of the frame up to and including its own.

A **group** is every packet of the frame with the same channel, direction
(`flags` bit 0), and opcode. Groups are ordered by their first packet. A reader
learns how many groups there are, and their order, from sections 2 to 4, so
section 8 holds no keys. A group's bytes are its packets' bytes in packet order.

On the game channel, a packet sits in its group with bytes 2 and 3, its sync
counter, set to zero; the reader puts back the sync from section 6. A writer
writes `length` 0 exactly when the packet is on the game channel, its header's
`size` is not 0, and its length is `size` × 4. A stub keeps the 4-byte header
and an explicit length of 4 (written 5).

Each **marker** is:

| Field | Notes |
|-------|-------|
| `packetIndex` | 32-bit varint: the packet in this frame the marker sits just before, from 0 |
| `kind` | `u8`: `0` note, `1` login, `2` logout; readers treat unknown kinds as notes |
| `textLength` | 16-bit varint |
| text | UTF-8, no terminator |

A marker marks a moment between two packets, so it sits just before the next
packet written after it. A logout marker therefore sits before the first packet
of the next login, and a marker with no packet after it when the capture closes
is dropped. A frame's markers follow the order they were written in.

**Decoding** is one pass. Read sections 1 to 7 front to back, each counted by
`packetCount`, the number of game-channel packets, or `markerCount`. Find the
groups from sections 2 to 4, read section 8, and check that the group sizes add
up to the bytes left. Then, packet by packet, take the next bytes from the
packet's group. For a game-channel packet, read its 4-byte header first, which
gives `size` when `length` is 0, then the rest, then put back its sync. The
frame is bad if:

- a section runs past the end of the plaintext, or a varint breaks the rules in
  [Conventions](#conventions);
- the group sizes do not add up to the bytes left, or a group's bytes are not
  used exactly;
- a game-channel packet is shorter than 4 bytes, or its `opcode` differs from
  its header's `id`;
- a packet off the game channel has `length` 0;
- a marker's `packetIndex` is not below `packetCount`, or is below the
  previous marker's.

#### Packet flags

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

### Checkpoint frames

The payload is 136 bytes, not compressed:

| Off | Size | Field |
|----:|-----:|-------|
| 0 | 8 | `packets`: packets the checkpoint covers, from the start of the capture |
| 8 | 64 | `digest`: `D(packets)`, see [Signatures](#signatures) |
| 72 | 64 | `signature`: `Ed25519(signingKey, "xicap/4 checkpoint" ‖ digest)` |

A checkpoint frame sits at a frame boundary: after the packet frame that holds
packet `packets` − 1, counting from 0, and before the one that holds packet
`packets`. A reader that finds one elsewhere reports it as failed.

## Channels

| Channel | Name | Packet bytes | `opcode` | A stub keeps |
|--------:|------|--------------|----------|--------------|
| 0 | game | the FFXI packet, from its 4-byte header | the header's 9-bit id | the 4-byte header |
| 1 | search | the plaintext request or reply, from its 4-byte size | byte `0x0B`, the request type | not defined |
| 2 to 255 | reserved | | | |

Channel 1 follows Memoria's hooks.

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
`id`.

## Footer

A clean close writes the footer index, the seal if there is one, then the
trailer.

### `FooterIndexEntry` (24 bytes)

One per packet frame, in file order. Checkpoint frames have no entry.

| Off | Size | Field |
|----:|-----:|-------|
| 0 | 8 | `timestamp`: the frame's `baseTimestamp` |
| 8 | 8 | `fileOffset`: the frame's first byte |
| 16 | 2 | `zoneId` |
| 18 | 1 | `flags`: bit 0, the frame has the restart bit. Other bits reserved |
| 19 | 5 | `reserved` |

### Seal (160 bytes)

Present when bit 0 of `trailerFlags` is set: a program other than the signer
rewrote the file. See [Signatures](#signatures).

| Off | Size | Field | Notes |
|----:|-----:|-------|-------|
| 0 | 4 | `magic` | ASCII `XCSL` |
| 4 | 4 | `reserved` | |
| 8 | 8 | `sealedAt` | when the rewriter sealed the file |
| 16 | 32 | `key` | the rewriter's Ed25519 public key |
| 48 | 32 | `agent` | text: the rewriter, with its version, such as `mogsafe 2026.11.4` |
| 80 | 64 | `signature` | `Ed25519(key, "xicap/4 seal" ‖ D(end) ‖ seal bytes 0..80)` |
| 144 | 12 | `reserved` | |
| 156 | 4 | `crc` | CRC-32 of seal bytes `0..156` |

### `FooterTrailer` (112 bytes, the last bytes of the file)

| Off | Size | Field | Notes |
|----:|-----:|-------|-------|
| 0 | 8 | `endTimestamp` | the last packet's timestamp; `0` if none |
| 8 | 8 | `totalPacketCount` | |
| 16 | 4 | `trailerFlags` | bit 0: a seal precedes the trailer. Bit 1: the signer never signed the end, so `signature` is zero (a cut-off recording, rewritten). Other bits reserved |
| 20 | 4 | `entryCount` | footer index entries |
| 24 | 8 | `indexOffset` | file offset of the first index entry |
| 32 | 4 | `indexCrc` | CRC-32 of the whole index |
| 36 | 4 | `frameCount` | frames of every kind |
| 40 | 64 | `signature` | the signer's: `Ed25519(signingKey, "xicap/4 footer" ‖ D(end))`; zero when bit 1 is set |
| 104 | 4 | `trailerCrc` | CRC-32 of trailer bytes `0..104` |
| 108 | 4 | `magic` | ASCII `XCPF` |

The footer is valid when all of these hold:

- the file is at least `dataStart + 112` bytes long, where `dataStart` is the
  end of the extension blocks;
- the last 4 bytes are `XCPF` and `trailerCrc` is correct;
- no bit of `trailerFlags` from 2 up is set;
- `indexOffset >= dataStart` and `indexOffset + 24 * entryCount + S + 112`
  equals the file size, where `S` is 160 when bit 0 of `trailerFlags` is set
  and 0 otherwise;
- `indexCrc` is correct;
- with bit 0 set, the seal's magic is `XCSL` and its `crc` is correct.

A reader reads a file whose footer is not valid as cut off. If its last 4 bytes
are `XCPF` anyway, the reader also reports a damaged footer.

The last 112 bytes of a complete file start with the end time and end with
`XCPF`, as in format 3, so a reader can learn the end time from them alone.

## Signatures

Every signature covers the **signed stream**, which depends only on what the
capture records, never on frames or compression:

```
signed stream = header             all headerSize bytes, as the signer wrote them
              ‖ extension blocks   each from type to crc, in file order
              ‖ for each packet, in order:
                    its markers    'M' kind:u8 textLength:u16 text      (each marker sitting before it, in order)
                    the packet     'P' timestamp:u64 flags:u16 channel:u8 opcode:u16 length:u32 bytes
              ‖ end record         'E' totalPacketCount:u64 endTimestamp:u64
```

`'M'`, `'P'`, and `'E'` are single ASCII bytes, and the integers are
little-endian. A packet record holds the packet as a reader yields it: its
absolute timestamp, and its bytes with the sync in place.

- `D(k)` is the SHA-512 of the header, the blocks, and the records of the first
  `k` packets with the markers before each.
- `D(end)` is the SHA-512 of the whole signed stream, end record included. The
  end record takes `totalPacketCount` and `endTimestamp` from the trailer.

A writer runs one SHA-512 over the stream as it writes; a checkpoint finishes a
copy of it.

Three signatures cover the stream. The prefixes are ASCII, with no terminator.

- A **checkpoint**: `signature = Ed25519(signingKey, "xicap/4 checkpoint" ‖ D(packets))`.
- The **footer**: `signature = Ed25519(signingKey, "xicap/4 footer" ‖ D(end))`.
- The **seal**: `signature = Ed25519(key, "xicap/4 seal" ‖ D(end) ‖ seal bytes 0..80)`,
  so the seal's time, key, and agent are signed too.

A reader computes the stream from the packets it reads and reports:

- the signing key;
- **signed to the end** if the footer's signature verifies;
- otherwise the last checkpoint that sits where its `packets` says, whose
  `digest` equals `D(packets)`, and whose signature verifies, and its `packets`;
- the file offset of the first checkpoint that fails, or of the footer index if
  the footer's signature fails;
- for a sealed file, the seal's key, agent, and time, and whether its signature
  verifies.

A failed signature never stops a reader from reading packets.

### Rewriting a capture

Since signatures cover packets, not bytes, a program may rewrite a capture with
other frames and other compression:

- **Sealing.** A rewriter without the signer's key keeps the header and every
  extension block byte for byte, and every packet and marker in order. For a
  complete file, it keeps the footer's signature. For a cut-off file, it may
  carry the last checkpoint that verifies: it ends a frame after packet
  `packets` − 1 and writes the checkpoint frame there, unchanged. It drops every
  other checkpoint, sets bit 1 of `trailerFlags`, and writes a zero
  `signature`. Either way it adds a seal made with its own key and sets bit 0.
  `D(k)` does not depend on frames, so the carried checkpoint and the footer
  signature still verify.
- **Re-signing.** A rewriter may sign a file anew with its own key: it changes
  the header's `signingKey`, which changes every digest. A file rewritten this
  way from another major version names its source in a SOURCE block, as
  [Source](#source) says.

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

- **Stub:** the packet keeps its timestamp, channel, direction, provenance
  flags, and opcode, sets the excluded flag, and keeps only what its channel's
  row in [Channels](#channels) says a stub keeps. On the game channel that is
  the 4-byte header, whose `size` still gives the original length.
- **Zero byte ranges:** the packet keeps its length and sets the redacted flag,
  and the writer zeroes each range. A range that runs past the packet's end
  stops at the end. On the game channel no range may start inside the 4-byte
  header, which holds the opcode the packet's `opcode` repeats; a writer refuses
  such a policy before it writes anything.

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
   the policy and dictionary rules above, and refuses the file if any check
   fails;
2. checks the footer;
3. reads frames, starting at the end of the extension blocks, and decodes each
   packet frame with the decoder its stream left.

A **bad frame** is one that is cut short, lacks the `XCFR` magic, fails its CRC,
or breaks a rule of this document once read: a `plainSize` or `packetCount` out
of range, a zstd error, a payload that does not decode to exactly `plainSize`
bytes, a frame without the restart bit with no stream to continue, or a bad
plaintext (see [Packet frames](#packet-frames)). A packet frame whose stream
holds a bad frame before it is bad too, since its copies may reach back into
the bad one.

In a complete file, frames run up to `indexOffset`, and a bad frame makes the
reader refuse the file.

In a cut-off file, frames run up to the first bad frame. The capture ends there,
and the reader reports how many bytes it did not read.

In **recovery mode**, a reader that meets a bad frame searches forward, byte by
byte, for the next `XCFR` whose frame passes its CRC, and goes on from there,
skipping packet frames until one starts a stream. It reports each skipped
region, with adjacent regions joined. Recovery mode is for salvage; Mogsafe and
other archive checks read in the normal mode.

To **seek** to a packet frame, a reader walks back through the index to the
nearest frame with the restart bit and decodes from there.

## Writer rules

These rules are part of the format: a capture that breaks them is wrong even if
it parses.

- **Timestamps never go backwards** in file order, across every channel. Equal
  timestamps are allowed. Given an earlier time than the last, a writer records
  the last again. Live recorders read the wall clock once and add a monotonic
  clock after.
- **Frame boundaries.** A writer ends the packet frame being built before adding
  a packet that would push its `deltaMs` past 2^32 − 1, its `packetCount` past
  1,048,576, its markers past 65,535, or its plaintext past its frame size
  limit (at most 16 MiB), and when the server sends a zone-in, so a frame never
  spans two zones. It also ends frames by its own packet and time settings and
  when the host asks for a flush. The library's settings:

  | | live (the default) | archive |
  |---|---|---|
  | zstd level | 7 | 19 |
  | window | 2 MiB | 4 MiB |
  | match table (`hashLog`) | 2^19 | the level's own |
  | frame ends | every zone-in, 5 s, 1,000 packets, 64 KiB of plaintext, host flush | every zone-in, 1 MiB of plaintext |
  | stream restart | 4 MiB | 4 MiB |
  | checkpoints | yes | none |

- **Streams.** A writer compresses each frame's plaintext and flushes, so a
  frame written live is on disk and decodable the moment it is written. It
  restarts as [Streams](#streams) says.
- **Checkpoints.** A writer that writes checkpoints writes one, covering every
  packet so far, at the first frame boundary after 60 seconds of frames without
  one, when a flush finds the capture idle with frames since the last
  checkpoint, and when the host marks a login or logout: it ends the frame being
  built and writes the checkpoint then, so the marker lands in the next frame.
  It never writes one when it has written no frame since the last, so a
  capture's opening login has none.
- **When captures start.** A recorder starts a new capture when a character logs
  in and the current capture holds another character or none. When the same
  character logs out and back in, the capture continues, with a logout and a
  login marker. A recorder that starts after a login, or after a crash, sets
  `startContext` to mid-session and `previousCaptureId` to the capture it
  continues, or all zero if it knows none. No timer ends a capture.
- **Durability.** A writer hands each frame to the operating system as soon as
  it is written, and reports any write error.
- **Empty captures** still get a header, extension blocks, and a footer with no
  index entries.

## Conformance

`tests/vectors/` holds test files, each with a JSON file of its expected
reading. The files whose names start with `4-` are format 4; the others are
format 3. Every binding reads all of them in CI, and `tests/spec_reader.py`, a
reader written from this document and [FORMAT-3.md](FORMAT-3.md) alone, reads
them too.

## Worked example

The conformance file `tests/vectors/4-example.xicap`, whole: a live capture of
the three packets of [the example above](#example), with its exclusion policy,
one packet frame, and the footer. Offsets are in hex.

```
00000000  89 58 43 50 0d 0a 1a 0a 04 00 80 01 01 00 00 00  magic; version 4.0; headerSize 384; extensionCount 1
00000010  00 00 00 00 00 00 00 00 33 33 33 33 33 33 33 33  reserved; captureId
00000020  33 33 33 33 33 33 33 33 00 00 00 00 00 00 00 00  previousCaptureId
00000030  00 00 00 00 00 00 00 00 00 6c 50 c4 a0 01 00 00  startTimestamp
00000040  00 00 00 01 01 01 01 00 00 00 00 00 00 00 00 00  reserved; clockSource 1 (live), origin 1 (live), network 1 (retail), startContext 1 (login); reserved; dictionaryId 0; reserved
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
00000170  00 00 00 00 00 00 00 00 00 00 00 00 19 3b 9d 72  headerCrc
00000180  09 00 00 00 50 00 00 00 78 69 63 61 70 2d 64 65  extension block: type 0x0009 (exclusion policy), length 80; policy name
00000190  66 61 75 6c 74 00 00 00 00 00 00 00 00 00 00 00
000001a0  00 00 00 00 00 00 00 00 01 00 00 00 05 00 00 00  version 1, 5 rules, reserved
000001b0  00 00 01 00 17 00 00 00 00 01 01 00 b5 00 00 00  rules: channel, direction, action 1 (stub), reserved, opcode, rangeCount
000001c0  00 01 01 00 b6 00 00 00 00 00 01 00 cc 00 00 00
000001d0  00 01 01 00 e2 00 00 00 a2 a5 72 ea 58 43 46 52  block CRC; frame: magic XCFR
000001e0  80 01 00 00 31 00 00 00 03 00 00 00 00 6c 50 c4  kind 0x80 (packets), frameFlags 1 (restart), markerCount 0, payloadSize 49, packetCount 3; baseTimestamp
000001f0  a0 01 00 00 00 00 00 00 46 00 00 00 28 b5 2f fd  zoneId 0, reserved, plainSize 70; payload: a whole zstd stream (decoded below)
00000200  04 00 25 01 00 90 00 0a 0a 00 df 01 00 00 00 02
00000210  02 02 30 df 08 00 01 02 07 00 38 13 10 00 67 37
00000220  33 08 b8 43 b9 c0 17 20 02 2e 49 ba 6a a0 90 f4  frame CRC
00000230  43 00 6c 50 c4 a0 01 00 00 dc 01 00 00 00 00 00  footer index entry: timestamp, fileOffset, zoneId, flags 1 (restart), reserved
00000240  00 00 00 01 00 00 00 00 00 14 6c 50 c4 a0 01 00  trailer: endTimestamp
00000250  00 03 00 00 00 00 00 00 00 00 00 00 00 01 00 00  totalPacketCount 3; trailerFlags 0, entryCount 1
00000260  00 31 02 00 00 00 00 00 00 38 ee d7 f4 01 00 00  indexOffset; indexCrc, frameCount 1
00000270  00 3b 4c ba 00 07 0b 7d 18 fa d5 82 cf 4e 2e 0b  signature
00000280  5d c4 06 4c 49 3a 54 24 62 5d 60 1d 91 93 96 06
00000290  9f 38 7c f1 eb f7 78 cc dc 7a bd 87 cb b5 a4 c4
000002a0  bd 7a 74 b5 58 25 b7 9f 5a 56 4a 17 dc 7e 94 b2
000002b0  01 d6 f5 0a 44 58 43 50 46                       trailerCrc, magic XCPF
```

The frame's payload, decoded:

```
00000000  00 0a 0a 00 00 00 00 00 00 df 01 df 01 df 01 00  deltaMs 0, 10, 10; flags 0, 0, 0; channel 0, 0, 0; opcode 0x0DF three times; length 0 (implied) ...
00000010  00 00 02 02 02 30 df 08 00 00 00 00 00 00 00 00  ... twice more; sync +1, +1, +1; group size 48; packet 0 from its header, sync zeroed
00000020  00 00 00 00 00 00 df 08 00 00 01 01 01 01 01 01  packet 1
00000030  01 01 01 01 01 01 df 08 00 00 02 02 02 02 02 02  packet 2
00000040  02 02 02 02 02 02
```

`tests/spec_reader.py --example FORMAT.md` checks that these bytes are the
conformance file and that it reads them.

## Versioning

| Change | Version |
|--------|---------|
| Layout of an existing structure changes, except the header growing as [Header](#header) allows | major |
| A new frame kind, packet flag, channel, extension type, marker kind, trailer flag, or a field in reserved bytes that old readers can ignore | minor |
| Anything an old reader would misread without a must-understand frame kind, flag, or check to stop it | major |
| A new check readers make | none |

A reader refuses a major version it does not know. It reads a newer minor
version, skipping what it does not know, unless a must-understand frame kind or
flag tells it to refuse.

Before production, a draft may change anything. From production on, readers
keep reading every released version.

## Dependencies

The C++ library vendors Monocypher 4.0.3 in `third_party/monocypher`
(`monocypher.c` and `optional/monocypher-ed25519.c`) for Ed25519 and SHA-512.
Renovate cannot update a vendored file; check Monocypher's releases when
releasing xicap.
