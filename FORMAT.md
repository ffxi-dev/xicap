# XICAP Binary Format

Version 2.1. Little-endian throughout; all structs are byte-packed.

```
+----------------------+
|        Header        |   256 bytes (fixed)
+----------------------+
|   Extension blocks   |   0..N blocks, sized by Header.extensionCount
+----------------------+
|        Frames        |   1..M zstd-compressed frames
+----------------------+
|     Footer index     |   only present after a clean close
|         …            |
+----------------------+
|    Footer trailer    |   24 bytes; magic identifies a clean close
+----------------------+
```

Frames are independently decodable. The footer is optional; absent on
truncated captures, readers scan frames in that case.

## Header — 256 bytes

| Off | Size | Field              | Notes |
|----:|-----:|--------------------|-------|
| 0   |  4   | `magic`            | `'XCAP'` little-endian = `0x50414358` |
| 4   |  1   | `versionMajor`     | `2` |
| 5   |  1   | `versionMinor`     | `1` |
| 6   | 32   | `captureAgent`     | NUL-terminated UTF-8, max 31 chars |
| 38  |  2   | `extensionCount`   | number of extension blocks following |
| 40  | 32   | `clientVersion`    | NUL-terminated UTF-8, max 31 chars |
| 72  |  2   | `startZoneId`      | zone at capture start; frames carry it until a `GP_SERV_LOGIN` changes it |
| 74  |  8   | `startTimestamp`   | Unix-epoch milliseconds of first packet (back-patched on first flush) |
| 82  | 44   | `lobby`            | `LobbyIdentity` — see below |
| 126 |  1   | `startWeather`     | weather id at capture start |
| 127 |  1   | `padding0`         | 0 |
| 128 |  4   | `dictionaryId`     | zstd dict id (`ZSTD_getDictID_fromDict`) of the dictionary frames were compressed with; `0` if none. See [Dictionary](#dictionary) |
| 132 |  8   | `endTimestamp`     | last packet's timestamp; back-patched on `close()`, `0` on truncated captures |
| 140 |  8   | `totalPacketCount` | back-patched on `close()`, `0` on truncated captures |
| 148 |  2   | `endZoneId`        | back-patched on `close()`, `0` on truncated captures |
| 150 | 106  | `reserved`         | zeroed |

### `LobbyIdentity` — 44 bytes

| Off | Size | Field             | Notes |
|----:|-----:|-------------------|-------|
| 0   |  4   | `contentId`       | POL FFXI character ID (a.k.a. `ffxi_id`) |
| 4   |  2   | `worldContentId`  | world-specific id component |
| 6   |  2   | `worldId`         | server / world ID |
| 8   |  2   | `status`          | character status at lobby select |
| 10  |  1   | flags             | bit 0 = pending rename; bit 1 = pending race change; bits 2–7 reserved |
| 11  |  1   | `worldTableIndex` | |
| 12  | 16   | `characterName`   | NUL-terminated, max 15 chars |
| 28  | 16   | `worldName`       | NUL-terminated, max 15 chars |

The flags byte at offset 10 packs LSB-first: bit 0 is the lowest-order bit of
the byte. (xicap's C++ struct uses C++ bitfields; the on-disk layout is what
this table specifies, regardless of language ABI.)

The runtime `TC_OPERATION_MAKE` blob (job levels, fame, gil, etc.) that POL
also delivers in the lobby packet is written as an `EXT_LOBBY_SNAPSHOT`
extension block, not in the Header.

## Extension block

```
+--------+---------+-----------------------+
| type:4 | length:4|   payload (length B)  |
+--------+---------+-----------------------+
```

Payload layout is defined by the capture agent, not this library. Verify
`Header.clientVersion` before memcpy'ing a snapshot back into client memory.

### Type id ranges

| Range                    | Use |
|--------------------------|-----|
| `0x0000_0000`–`0x0000_7FFF` | Reserved for this repository (well-known ids below). |
| `0x0000_8000`–`0xFFFF_FFFE` | Vendor namespace. Allocate via the registry below or fork-prefix. |
| `0xFFFF_FFFF`              | Reserved (must not be used). |

### Well-known type ids

| Id     | Conventional payload |
|-------:|----------------------|
| 0x0001 | FFXI client player struct |
| 0x0002 | FFXI client inventory struct |
| 0x0003 | FFXI client entity struct (one block per populated entity) |
| 0x0004 | FFXI client `g_MissionData` region |
| 0x0005 | Known-spell bitmask (bit N = spell id N is known) |
| 0x0006 | Known-ability bitmask (`GP_SERV_COMMAND_DATA` layout) |
| 0x0007 | POL `TC_OPERATION_MAKE` lobby snapshot |
| 0x0008 | `EXT_ZSTD_DICT` — the zstd dictionary this capture was compressed with |

Unknown type ids are preserved verbatim and surfaced via `Reader::extensions()`.

`EXT_ZSTD_DICT` is the one exception: it is format-level rather than agent data,
so the reader consumes it and does **not** return it from `extensions()`. It is
still counted in `Header.extensionCount`, so a reader that does not know the id
skips it like any other unknown block.

## Dictionary

Frames are compressed with a zstd dictionary. Writers embed a copy of that
dictionary in the capture as an `EXT_ZSTD_DICT` block, written before any other
extension so a streaming consumer can decode frames as they arrive. A reader
therefore never depends on having been built with a matching dictionary, and
retraining the dictionary never invalidates existing captures.

Resolution order when opening a capture:

1. If an `EXT_ZSTD_DICT` block is present, use its bytes.
2. Otherwise, if `Header.dictionaryId` is non-zero (a 2.0 capture, which
   recorded only the id), use the reader's built-in dictionary.
3. Otherwise the capture uses no dictionary.

In cases 1 and 2 the resolved dictionary's id must equal `Header.dictionaryId`,
or the reader fails with `xicap::ErrorCode::DictionaryMismatch`.

Retrain with zstd's own trainer and hand the result to the writer via
`FramePolicy::dictionary`:

```
zstd --train samples/* -o ffxi.dict --maxdict=65536
```

## Frame

```
+----------+--------------+--------+--------+--------+
| compSize | packetCount  | baseTs | zoneId | mkrCnt |
|    4 B   |     4 B      |  8 B   |  2 B   |  2 B   |
+----------+--------------+--------+--------+--------+
|       zstd-compressed payload (compSize bytes)     |
+----------------------------------------------------+
|       crc32 (4 B)                                  |
+----------------------------------------------------+
```

Frame header is 20 bytes. The compressed payload is a single raw zstd frame
produced with `ZSTD_compress2`, with `ZSTD_c_checksumFlag` enabled (zstd embeds
its own 4-byte XXH64 trailer inside the compressed frame and verifies on
decode) and the dictionary described under [Dictionary](#dictionary) loaded via
`ZSTD_CCtx_loadDictionary`.

Readers must reject a frame whose zstd content-size field exceeds what the
frame's own `packetCount` and `markerCount` could account for
(`packetCount * (8 + 65535) + markerCount * (4 + 65535)`), or 16 MiB, whichever
is smaller. The field is attacker-controlled and otherwise sizes an allocation.

After the compressed payload, an additional 4-byte CRC-32/IEEE checksum covers
the 20-byte `FrameHeader` plus the `compressedSize` bytes of compressed
payload (not including the CRC itself). Polynomial `0xEDB88320`, initial value
`0xFFFFFFFF`, output XOR `0xFFFFFFFF`. Readers reject the frame on mismatch
(`xicap::ErrorCode::FrameChecksumMismatch`).

The decompressed payload is laid out as:

```
PacketEntry[0]  (8 B)  data (length B)
PacketEntry[1]  (8 B)  data (length B)
...
PacketEntry[N-1] data
FrameMarker[0]  (4 B)  text (textLength B)   # only if mkrCnt > 0
FrameMarker[1]  (4 B)  text (textLength B)
...
```

### `PacketEntry` — 8 bytes

| Off | Size | Field      | Notes |
|----:|-----:|------------|-------|
| 0   | 2    | `deltaMs`  | delta from previous packet timestamp; writers force a frame boundary before this would clip |
| 2   | 2    | `length`   | packet payload length (includes the 4-byte FFXI header); writers reject anything over 65535 rather than truncate |
| 4   | 2    | `opcode`   | FFXI 9-bit opcode |
| 6   | 2    | `flags`    | bit 0 = direction (`0` server→client, `1` client→server); bits 1–15 reserved |

### `FrameMarker` — 4 bytes

| Off | Size | Field         |
|----:|-----:|---------------|
| 0   | 2    | `packetIndex` |
| 2   | 2    | `textLength`  |

Markers are followed by `textLength` bytes of UTF-8 text (no NUL terminator).
A reader associates each marker with the packet whose 0-based index equals
`packetIndex` within the same frame.

### Frame flush conditions

A frame is closed and a new one started when any of these is true:

* `framePacketCount >= maxPacketsPerFrame` (default 1000)
* `frameBuffer size >= maxFrameSize` (default 64 KiB)
* time from frame's first packet `>= maxFrameTimeMs` (default 5000 ms)
* the next packet's `deltaMs` from the current would exceed `UINT16_MAX`

The first frame's `baseTimestamp` is back-patched into the Header's
`startTimestamp` field via a one-time seek.

## FFXI packet header layout

The first 4 bytes of every packet payload are the FFXI wire header:

```
byte 0     byte 1     byte 2     byte 3
[id_lo:8] [size:7|id_hi:1] [sync_lo:8] [sync_hi:8]
```

In integer terms:

* `opcode` = `(read_le_u16(bytes 0..2)) & 0x01FF`           — 9 bits
* `size`   = `(read_le_u16(bytes 0..2) >> 9) & 0x007F`      — 7 bits, in 4-byte words
* `sync`   = `read_le_u16(bytes 2..4)`                       — 16 bits

## Footer

When the writer closes cleanly it appends a frame index and a trailer:

```
FooterIndexEntry[0]  (24 B)
FooterIndexEntry[1]  (24 B)
...
FooterIndexEntry[N-1]
FooterTrailer        (24 B)   # last 24 bytes of file
```

`FooterIndexEntry`:

| Off | Size | Field         |
|----:|-----:|---------------|
| 0   | 8    | `timestamp`   |
| 8   | 8    | `fileOffset`  |
| 16  | 2    | `zoneId`      |
| 18  | 6    | `reserved`    |

`FooterTrailer`:

| Off | Size | Field         | Notes |
|----:|-----:|---------------|-------|
| 0   | 4    | `magic`       | `'XCPF'` little-endian = `0x46504358` |
| 4   | 4    | `entryCount`  | number of preceding `FooterIndexEntry` records |
| 8   | 8    | `indexOffset` | file offset of `FooterIndexEntry[0]` |
| 16  | 8    | `reserved`    | zeroed |

The trailer is recognised when:

* the file is at least `dataStartOffset + sizeof(FooterTrailer)` bytes long, and
* `magic == 0x46504358`, and
* `indexOffset >= dataStartOffset`, and
* `indexOffset + entryCount * 24 + 24 == fileSize`.

If any check fails the reader rebuilds the index by reading frame headers
sequentially and stopping at the last whose compressed payload + CRC fits in
the file.

## Worked example

A minimal capture with one extension and one packet, hex-dumped:

```
00000000  58 43 41 50 02 00 4d 65 6d 6f 72 69 61 00 00 00   XCAP..Memoria...
00000010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00000020  00 00 00 00 00 00 00 00 01 00 33 30 32 35 31 31   ..........302511
00000030  30 31 5f 32 00 00 00 00 00 00 00 00 00 00 00 00   01_2............
00000040  00 00 00 00 00 00 00 00 64 00 00 00 00 00 00 00   ........d.......
00000050  00 00 00 00 ef be ad de ...                       ...........
                      ^^^^^^^^^^^ contentId = 0xDEADBEEF (LobbyIdentity start)
... (remainder of LobbyIdentity, startWeather, padding, dictionaryId, ...)
00000100  01 00 00 00 04 00 00 00 de ad be ef               (extension type=1, length=4, payload=DEADBEEF)
0000010c  XX XX XX XX YY YY YY YY ...                        (FrameHeader: compressedSize, packetCount, ...)
... compressed zstd frame ...
... 4-byte CRC32 ...
```

The `EXT_ZSTD_DICT` block is omitted from this example for brevity; a real
capture carries it as the first extension block.

## Versioning policy

| Change                                              | Bump     |
|-----------------------------------------------------|----------|
| layout-breaking: field added/removed/resized        | major    |
| new well-known extension type                       | minor    |
| new reader-side validation rule                     | none     |
| documentation, comment, or non-format-breaking code | none     |

Major-version mismatch is a hard read error. Minor mismatches are accepted —
unknown extension types are returned as opaque blobs.
