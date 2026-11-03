"""A reader for xicap formats 3 and 4, written from FORMAT-3.md and FORMAT.md alone.

It is a test, not a binding: it proves the specifications are enough to read a
capture without this repository's library. It reads every file in the
conformance set and compares its reading with the recorded one.

    pip install zstandard cryptography
    python tests/spec_reader.py tests/vectors
"""

from __future__ import annotations

import hashlib
import json
import struct
import sys
import zlib
from pathlib import Path

import zstandard
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MAGIC = bytes([0x89, 0x58, 0x43, 0x50, 0x0D, 0x0A, 0x1A, 0x0A])
FRAME_MAGIC = b"XCFR"
FOOTER_MAGIC = b"XCPF"
HEADER_SIZE, HEADER_SIZE_MAX = 384, 4096
TRAILER, INDEX_ENTRY, ENTRY, MARKER, SEAL = 112, 24, 12, 6, 160
MAX_PACKETS, MAX_WINDOW = 1024 * 1024, 1 << 23
MAX_CONTENT = 16 * 1024 * 1024
MAX_EXTENSION = 16 * 1024 * 1024
DICT_MAGIC = 0xEC30A437
EXT_DICT, EXT_POLICY, EXT_SOURCE = 0x0008, 0x0009, 0x000A
KIND_CHECKPOINT, KIND_PACKETS = 0x01, 0x80
RESTART, SEALED, END_UNSIGNED = 0x01, 0x01, 0x02
GAME = 0


class Refused(Exception):
    """The file must be refused. `kind` is the class of rule it broke."""

    def __init__(self, kind: str, why: str) -> None:
        super().__init__(why)
        self.kind = kind


class BadFrame(Exception):
    pass


def crc(b: bytes) -> int:
    return zlib.crc32(b) & 0xFFFFFFFF


def text(b: bytes) -> str:
    return b.split(b"\0", 1)[0].decode("utf-8")


def varint(b: bytes, pos: int, bits: int) -> tuple[int, int]:
    """An unsigned LEB128 varint filling a field `bits` wide, and the position after it."""
    value = 0
    for i in range((bits + 6) // 7):
        if pos >= len(b):
            raise BadFrame("varint past the end")
        byte = b[pos]
        pos += 1
        value |= (byte & 0x7F) << (7 * i)
        if not byte & 0x80:
            if value >> bits:
                raise BadFrame("varint too large for its field")
            return value, pos
    raise BadFrame("varint too long")


def unzigzag(z: int) -> int:
    return (z >> 1) ^ -(z & 1)


def columns(plain: bytes, packet_count: int, marker_count: int, base: int) -> list:
    """A format-4 packet frame's plaintext, decoded as FORMAT.md, Packet frames, says."""
    pos = 0

    def column(bits: int, n: int) -> list:
        nonlocal pos
        out = []
        for _ in range(n):
            v, pos = varint(plain, pos, bits)
            out.append(v)
        return out

    delta = column(32, packet_count)
    flags = column(16, packet_count)
    if any(f & 0xFC00 for f in flags):
        raise Refused("unknown-required", "packet flags")
    channel = column(8, packet_count)
    opcode = column(16, packet_count)
    length = column(32, packet_count)
    sync = column(16, sum(1 for c in channel if c == GAME))
    markers = []
    for _ in range(marker_count):
        index, pos = varint(plain, pos, 32)
        if pos >= len(plain):
            raise BadFrame("marker past the end")
        kind = plain[pos]
        size, pos = varint(plain, pos + 1, 16)
        if pos + size > len(plain):
            raise BadFrame("marker text past the end")
        if index >= packet_count or (markers and index < markers[-1][0]):
            raise BadFrame("marker out of place")
        markers.append((index, kind, plain[pos : pos + size].decode("utf-8")))
        pos += size
    groups: dict = {}
    group = [groups.setdefault((c, f & 1, o), len(groups)) for c, f, o in zip(channel, flags, opcode)]
    sizes = column(32, len(groups))
    if sum(sizes) != len(plain) - pos:
        raise BadFrame("group sizes do not add up")
    cursor, end = [], []
    for size in sizes:
        cursor.append(pos)
        pos += size
        end.append(pos)
    packets, ts, last_sync, game = [], base, [0, 0], 0
    for i in range(packet_count):
        g = group[i]
        if channel[i] == GAME:
            if end[g] - cursor[g] < 4:
                raise BadFrame("game packet under 4 bytes")
            word = struct.unpack_from("<H", plain, cursor[g])[0]
            if word & 0x1FF != opcode[i]:
                raise BadFrame("opcode is not the header's id")
            size = (word >> 9) * 4 if length[i] == 0 else length[i] - 1
            if size < 4:
                raise BadFrame("game packet under 4 bytes")
        else:
            if length[i] == 0:
                raise BadFrame("implied length off the game channel")
            size = length[i] - 1
        if size > end[g] - cursor[g]:
            raise BadFrame("packet past its group")
        data = bytearray(plain[cursor[g] : cursor[g] + size])
        cursor[g] += size
        if channel[i] == GAME:
            d = flags[i] & 1
            last_sync[d] = (last_sync[d] + unzigzag(sync[game])) & 0xFFFF
            game += 1
            struct.pack_into("<H", data, 2, last_sync[d])
        ts += delta[i]
        packets.append([ts, channel[i], opcode[i], flags[i], bytes(data), []])
    if cursor != end:
        raise BadFrame("group bytes left over")
    for index, kind, txt in markers:
        packets[index][5].append([kind, txt])
    return packets


class Stream:
    """The zstd stream that runs across a format-4 file's packet frames."""

    def __init__(self) -> None:
        self.obj = None

    def reset(self) -> None:
        self.obj = None

    def decode(self, frame: bytes, header: int) -> bytes:
        _, kind, flags, marker_count, payload_size, packet_count, base, zone, _, plain_size = struct.unpack_from("<4sBBHIIQHHI", frame, 0)
        obj, self.obj = self.obj, None
        if flags & RESTART:
            obj = zstandard.ZstdDecompressor(max_window_size=MAX_WINDOW).decompressobj(write_size=MAX_CONTENT + 1)
        elif obj is None:
            raise BadFrame("no stream to continue")
        if not 1 <= plain_size <= MAX_CONTENT or not 1 <= packet_count <= MAX_PACKETS:
            raise BadFrame("sizes out of range")
        try:
            plain = obj.decompress(frame[header : header + payload_size])
        except zstandard.ZstdError as e:
            raise BadFrame("zstd") from e
        if len(plain) != plain_size or obj.unused_data:
            raise BadFrame("payload is not plainSize bytes")
        if not obj.eof:
            self.obj = obj
        return plain


class Capture:
    def __init__(self, data: bytes, recovery: bool = False) -> None:
        self.data = data
        self.recovery = recovery
        self.stream = Stream()
        self.read_header()
        self.read_extensions()
        self.read_footer()
        self.skipped: dict[int, int] = {}
        self.unread = 0
        self.mismatch = False
        if self.complete:
            self.end = self.index_offset
        else:
            self.scan_cut_off()

    # Header -----------------------------------------------------------------
    def read_header(self) -> None:
        d = self.data
        if len(d) < HEADER_SIZE:
            raise Refused("header", "short header")
        if d[0:8] != MAGIC:
            raise Refused("header", "bad magic")
        if d[8] not in (3, 4):
            raise Refused("header", "unsupported version")
        self.v4 = d[8] == 4
        self.frame_header = 32 if self.v4 else 28
        size = struct.unpack_from("<H", d, 10)[0]
        if not HEADER_SIZE <= size <= HEADER_SIZE_MAX or size > len(d):
            raise Refused("header", "header size out of range")
        if crc(d[: size - 4]) != struct.unpack_from("<I", d, size - 4)[0]:
            raise Refused("header", "header crc")
        self.header_bytes = d[:size]
        self.version = f"{d[8]}.{d[9]}"
        self.extension_count = struct.unpack_from("<I", d, 12)[0]
        self.capture_id = d[24:40]
        self.previous_capture_id = d[40:56]
        self.start_timestamp = struct.unpack_from("<Q", d, 56)[0]
        self.clock_source, self.origin, self.network, self.start_context = d[67], d[68], d[69], d[70]
        self.dictionary_id = struct.unpack_from("<I", d, 72)[0]
        if self.v4 and self.dictionary_id:
            raise Refused("dictionary", "format 4 has no dictionary")
        self.signing_key = d[80:112]
        self.capture_agent = text(d[112:144])
        self.client_version = text(d[144:176])
        content_id, character_id, world_id = struct.unpack_from("<IIH", d, 176)
        self.character = [content_id, character_id, world_id, text(d[188:204]), text(d[204:220])]

    # Extension blocks -------------------------------------------------------
    def read_extensions(self) -> None:
        d, offset = self.data, len(self.header_bytes)
        self.blocks: list[bytes] = []
        self.dictionary = None
        self.policy = None
        self.source = None
        self.extensions = []
        for i in range(self.extension_count):
            if offset + 8 > len(d):
                raise Refused("extension", "short extension")
            type_, length = struct.unpack_from("<II", d, offset)
            if length > MAX_EXTENSION:
                raise Refused("extension", "extension over 16 MiB")
            end = offset + 8 + length + 4
            if end > len(d):
                raise Refused("extension", "extension runs past the file")
            block = d[offset:end]
            if crc(block[:-4]) != struct.unpack_from("<I", block, len(block) - 4)[0]:
                raise Refused("extension", "extension crc")
            payload = block[8:-4]
            self.blocks.append(block)
            offset = end
            if i == 0 and self.dictionary_id and type_ != EXT_DICT:
                raise Refused("dictionary", "dictionary missing")
            if type_ == EXT_DICT:
                if self.v4 or i != 0 or not self.dictionary_id:
                    raise Refused("dictionary", "dictionary out of place")
                magic, dict_id = struct.unpack_from("<II", payload, 0)
                if magic != DICT_MAGIC or dict_id != self.dictionary_id:
                    raise Refused("dictionary", "dictionary id")
                self.dictionary = zstandard.ZstdCompressionDict(payload, dict_type=zstandard.DICT_TYPE_FULLDICT)
            elif type_ == EXT_POLICY:
                if self.policy is not None:
                    raise Refused("extension", "two policies")
                self.policy = self.parse_policy(payload)
            elif type_ == EXT_SOURCE:
                self.source = self.parse_source(payload)
            else:
                self.extensions.append([type_, payload.hex()])
        if self.dictionary_id and self.dictionary is None:
            raise Refused("dictionary", "dictionary missing")
        if self.policy is None:
            raise Refused("extension", "no policy")
        self.data_start = offset

    @staticmethod
    def parse_policy(p: bytes) -> list:
        try:
            name = text(p[0:32])
            version, rule_count = struct.unpack_from("<IH", p, 32)
            pos, rules = 40, []
            for _ in range(rule_count):
                channel, direction, action, _, opcode, range_count = struct.unpack_from("<BBBBHH", p, pos)
                pos += 8
                ranges = []
                for _ in range(range_count):
                    ranges.append(list(struct.unpack_from("<II", p, pos)))
                    pos += 8
                rules.append([channel, direction, action, opcode, ranges])
        except struct.error as e:
            raise Refused("extension", "malformed policy") from e
        if pos != len(p):
            raise Refused("extension", "malformed policy")
        return [name, version, rules]

    @staticmethod
    def parse_source(p: bytes) -> list:
        if len(p) < 108 or len(p) - 108 != struct.unpack_from("<I", p, 104)[0]:
            raise Refused("extension", "malformed source")
        skipped, offset = struct.unpack_from("<Ii", p, 32)
        return [text(p[0:16]), text(p[16:32]), skipped, offset, p[40:104].hex(), p[108:].hex()]

    # Footer -----------------------------------------------------------------
    def read_footer(self) -> None:
        d = self.data
        self.complete = self.footer_damaged = False
        if len(d) < self.data_start + TRAILER or d[-4:] != FOOTER_MAGIC:
            return
        self.footer_damaged = True
        t = d[-TRAILER:]
        if crc(t[:104]) != struct.unpack_from("<I", t, 104)[0]:
            return
        end_ts, total, flags, entries, index_offset, index_crc, frame_count = struct.unpack_from("<QQIIQII", t, 0)
        flags = flags if self.v4 else 0
        if flags & ~(SEALED | END_UNSIGNED):
            return
        seal_size = SEAL if flags & SEALED else 0
        index_bytes = entries * INDEX_ENTRY
        if index_offset < self.data_start or index_offset + index_bytes + seal_size + TRAILER != len(d):
            return
        index = d[index_offset : index_offset + index_bytes]
        if crc(index) != index_crc:
            return
        self.seal = None
        if seal_size:
            seal = d[len(d) - TRAILER - SEAL : len(d) - TRAILER]
            if seal[0:4] != b"XCSL" or crc(seal[:156]) != struct.unpack_from("<I", seal, 156)[0]:
                return
            self.seal = seal
        self.trailer_flags = flags
        self.complete, self.footer_damaged = True, False
        self.end_timestamp, self.total_packets = end_ts, total
        self.index_offset, self.index, self.trailer = index_offset, index, t

    # Frames -----------------------------------------------------------------
    def raw_frame(self, offset: int, limit: int):
        """The frame at offset if it is whole, has the magic, and passes its CRC."""
        d = self.data
        if offset + self.frame_header + 4 > limit or d[offset : offset + 4] != FRAME_MAGIC:
            return None
        payload_size = struct.unpack_from("<I", d, offset + 8)[0]
        end = offset + self.frame_header + payload_size + 4
        if end > limit:
            return None
        if crc(d[offset : end - 4]) != struct.unpack_from("<I", d, end - 4)[0]:
            return None
        return d[offset:end]

    def resync(self, start: int, limit: int):
        pos = start
        while True:
            pos = self.data.find(FRAME_MAGIC, pos, limit)
            if pos < 0:
                return None
            if self.raw_frame(pos, limit) is not None:
                return pos
            pos += 1

    def scan_cut_off(self) -> None:
        offset, size = self.data_start, len(self.data)
        while offset < size:
            frame = self.raw_frame(offset, size)
            if frame is None:
                if not self.recovery:
                    self.unread = size - offset
                    break
                nxt = self.resync(offset + 1, size)
                self.skip(offset, (nxt if nxt is not None else size) - offset)
                offset = nxt if nxt is not None else size
                continue
            kind = frame[4]
            if kind not in (KIND_PACKETS, KIND_CHECKPOINT) and kind >= 0x80:
                raise Refused("unknown-required", f"frame kind {kind:#x}")
            offset += len(frame)
        self.end = size if self.recovery else offset

    def decode(self, frame: bytes) -> list:
        if self.v4:
            _, _, _, marker_count, _, packet_count, base = struct.unpack_from("<4sBBHIIQ", frame, 0)
            packets = columns(self.stream.decode(frame, self.frame_header), packet_count, marker_count, base)
            self.check_character(packets)
            return packets
        _, kind, _, marker_count, payload_size, packet_count, base, zone, _ = struct.unpack_from("<4sBBHIIQHH", frame, 0)
        payload = frame[self.frame_header : self.frame_header + payload_size]
        try:
            size = zstandard.frame_content_size(payload)
        except zstandard.ZstdError as e:
            raise BadFrame("not a zstd frame") from e
        if size < 0 or size > MAX_CONTENT or packet_count == 0:
            raise BadFrame("bad content size")
        try:
            dctx = zstandard.ZstdDecompressor(dict_data=self.dictionary) if self.dictionary else zstandard.ZstdDecompressor()
            obj = dctx.decompressobj()
            content = obj.decompress(payload)
            if not obj.eof or obj.unused_data:
                raise BadFrame("payload is not exactly one zstd frame")
        except zstandard.ZstdError as e:
            raise BadFrame("zstd") from e
        if len(content) != size:
            raise BadFrame("content size")
        pos, ts, packets = 0, base, []
        for _ in range(packet_count):
            if pos + ENTRY > size:
                raise BadFrame("entry past the frame")
            delta, flags, channel, _, opcode, length = struct.unpack_from("<HHBBHI", content, pos)
            pos += ENTRY
            if pos + length > size:
                raise BadFrame("packet past the frame")
            if flags & 0xFC00:
                raise Refused("unknown-required", f"packet flags {flags:#x}")
            data = content[pos : pos + length]
            if channel == GAME and (length < 4 or (struct.unpack_from("<H", data, 0)[0] & 0x1FF) != opcode):
                raise BadFrame("game packet header")
            ts += delta
            packets.append([ts, channel, opcode, flags, data, []])
            pos += length
        for _ in range(marker_count):
            if pos + MARKER > size:
                raise BadFrame("marker past the frame")
            index, kind_, _, length = struct.unpack_from("<HBBH", content, pos)
            pos += MARKER
            if pos + length > size or index >= packet_count:
                raise BadFrame("bad marker")
            packets[index][5].append([kind_, content[pos : pos + length].decode("utf-8")])
            pos += length
        if pos != size:
            raise BadFrame("bytes after the last marker")
        self.check_character(packets)
        return packets

    def check_character(self, packets: list) -> None:
        # A zone-in names the character: UniqueNo at byte 4, name at 132.
        for _, channel, opcode, flags, data, _ in packets:
            if channel == GAME and opcode == 0x00A and not flags & 0x0301 and len(data) >= 148:
                if struct.unpack_from("<I", data, 4)[0] != self.character[1] or text(data[132:148]) != self.character[3]:
                    self.mismatch = True

    def skip(self, offset: int, length: int) -> None:
        """Records a skipped region, joined to the one before when they touch."""
        if self.skipped:
            last = max(self.skipped)
            if last + self.skipped[last] == offset:
                self.skipped[last] += length
                return
        self.skipped[offset] = length

    def packets(self):
        offset = self.data_start
        self.stream.reset()
        while True:
            if offset in self.skipped:
                offset += self.skipped[offset]
                self.stream.reset()
            if offset >= self.end:
                return
            frame = self.raw_frame(offset, self.end)
            if frame is None:
                if self.recovery:
                    nxt = self.resync(offset + 1, self.end)
                    self.skip(offset, (nxt if nxt is not None else self.end) - offset)
                    offset = nxt if nxt is not None else self.end
                    self.stream.reset()
                    continue
                if self.complete:
                    raise Refused("frame", f"bad frame at {offset}")
                return
            kind = frame[4]
            if kind != KIND_PACKETS:
                if kind != KIND_CHECKPOINT and kind >= 0x80:
                    raise Refused("unknown-required", f"frame kind {kind:#x}")
                offset += len(frame)
                continue
            try:
                decoded = self.decode(frame)
            except BadFrame as e:
                if self.complete and not self.recovery:
                    raise Refused("frame", str(e)) from e
                if self.recovery:
                    self.skip(offset, len(frame))
                    offset += len(frame)
                    continue
                self.end = offset
                self.unread = len(self.data) - offset
                return
            for p in decoded:
                yield p[:4] + [p[4].hex(), p[5]]
            offset += len(frame)

    # Signatures -------------------------------------------------------------
    def check(self, prefix: bytes, chain: bytes, signature: bytes) -> bool:
        try:
            Ed25519PublicKey.from_public_bytes(self.signing_key).verify(signature, prefix + chain)
            return True
        except InvalidSignature:
            return False

    def verify4(self) -> list:
        s = hashlib.sha512(self.header_bytes + b"".join(self.blocks))
        limit = self.index_offset if self.complete else len(self.data)
        offset, packets = self.data_start, 0
        signed_to_end, verified, good, failure = False, 0, 0, None
        stream = Stream()
        while offset < limit:
            frame = self.raw_frame(offset, limit)
            if frame is None:
                if self.complete and failure is None:
                    failure = offset
                break
            payload = frame[self.frame_header : -4]
            if frame[4] == KIND_CHECKPOINT and len(payload) == 136:
                count, digest, signature = struct.unpack_from("<Q", payload)[0], payload[8:72], payload[72:136]
                ok = count == packets and digest == s.copy().digest() and self.check(b"xicap/4 checkpoint", digest, signature)
                if failure is None:
                    if ok:
                        good, verified = good + 1, packets
                    else:
                        failure = offset
            elif frame[4] == KIND_PACKETS:
                _, _, _, marker_count, _, packet_count, base = struct.unpack_from("<4sBBHIIQ", frame, 0)
                try:
                    decoded = columns(stream.decode(frame, self.frame_header), packet_count, marker_count, base)
                except (BadFrame, Refused):
                    if self.complete and failure is None:
                        failure = offset
                    break
                for ts, channel, opcode, flags, data, markers in decoded:
                    for kind, txt in markers:
                        t = txt.encode("utf-8")
                        s.update(b"M" + struct.pack("<BH", kind, len(t)) + t)
                    s.update(b"P" + struct.pack("<QHBHI", ts, flags, channel, opcode, len(data)) + data)
                    packets += 1
            offset += len(frame)
        self.seal_reading = None
        if self.complete and offset == limit:
            s.update(b"E" + struct.pack("<QQ", self.total_packets, self.end_timestamp))
            end = s.digest()
            if not self.trailer_flags & END_UNSIGNED:
                ok = self.check(b"xicap/4 footer", end, self.trailer[40:104])
                if failure is None:
                    if ok:
                        signed_to_end, verified = True, packets
                    else:
                        failure = self.index_offset
            if self.seal:
                key, signature = self.seal[16:48], self.seal[80:144]
                try:
                    Ed25519PublicKey.from_public_bytes(key).verify(signature, b"xicap/4 seal" + end + self.seal[:80])
                    ok = True
                except InvalidSignature:
                    ok = False
                self.seal_reading = [key.hex(), text(self.seal[48:80]), struct.unpack_from("<Q", self.seal, 8)[0], ok]
        return [signed_to_end, verified, good, failure is not None]

    def verify(self) -> list:
        if self.v4:
            return self.verify4()
        h = hashlib.sha512(self.header_bytes).digest()
        for block in self.blocks:
            h = hashlib.sha512(h + block).digest()
        limit = self.index_offset if self.complete else len(self.data)
        offset, packets = self.data_start, 0
        signed_to_end, verified, good, failure = False, 0, 0, None
        while offset < limit:
            frame = self.raw_frame(offset, limit)
            if frame is None:
                if self.complete and failure is None:
                    failure = offset
                break
            payload = frame[self.frame_header : -4]
            if frame[4] == KIND_CHECKPOINT and len(payload) == 128:
                ok = payload[:64] == h and self.check(b"xicap/3 checkpoint", h, payload[64:])
                if failure is None:
                    if ok:
                        good, verified = good + 1, packets
                    else:
                        failure = offset
            h = hashlib.sha512(h + frame).digest()
            if frame[4] == KIND_PACKETS:
                packets += struct.unpack_from("<I", frame, 12)[0]
            offset += len(frame)
        if self.complete and offset == limit:
            h = hashlib.sha512(h + self.index + self.trailer[:40]).digest()
            ok = self.check(b"xicap/3 footer", h, self.trailer[40:104])
            if failure is None:
                if ok:
                    signed_to_end, verified = True, packets
                else:
                    failure = self.index_offset
        return [signed_to_end, verified, good, failure is not None]


def reading(path: Path) -> dict:
    data = path.read_bytes()
    out: dict = {}
    try:
        c = Capture(data)
        out["result"] = "ok"
        out["header"] = {
            "version": c.version,
            "captureId": c.capture_id.hex(),
            "previousCaptureId": c.previous_capture_id.hex(),
            "startTimestamp": c.start_timestamp,
            "clockSource": c.clock_source,
            "origin": c.origin,
            "network": c.network,
            "startContext": c.start_context,
            "signingKey": c.signing_key.hex(),
            "captureAgent": c.capture_agent,
            "clientVersion": c.client_version,
            "character": c.character,
        }
        out["policy"] = c.policy
        out["source"] = c.source
        out["extensions"] = c.extensions
        out["complete"] = c.complete
        out["footerDamaged"] = c.footer_damaged
        out["endTimestamp"] = c.end_timestamp if c.complete else 0
        out["totalPacketCount"] = c.total_packets if c.complete else 0
        out["packets"] = list(c.packets())
        out["characterMismatch"] = c.mismatch
        out["unreadBytes"] = c.unread
        out["verify"] = c.verify()
        if c.v4 and c.seal_reading:
            out["seal"] = c.seal_reading
    except Refused as e:
        out = {"refusal": e.kind}
    try:
        r = Capture(data, recovery=True)
        count = sum(1 for _ in r.packets())
        out["recovery"] = [count, [[k, v] for k, v in sorted(r.skipped.items())]]
    except Refused as e:
        out["recovery"] = e.kind
    return out


def main(directory: str) -> int:
    failures = 0
    files = sorted(Path(directory).glob("*.xicap"))
    for path in files:
        expected = json.loads(path.with_suffix(".json").read_text())
        expected.pop("result", None)  # this library's error name; refusal classes are compared
        got = reading(path)
        got.pop("result", None)
        if got != expected:
            failures += 1
            print(f"MISMATCH {path.name}")
            for key in sorted(set(got) | set(expected)):
                if got.get(key) != expected.get(key):
                    print(f"  {key}: spec reader {json.dumps(got.get(key))[:300]}")
                    print(f"  {key}: recorded    {json.dumps(expected.get(key))[:300]}")
        else:
            print(f"ok {path.name}")
    print(f"{len(files) - failures}/{len(files)} match")
    return 1 if failures or not files else 0


def example(format_md: str) -> int:
    """Checks FORMAT.md's worked example: its dump is the conformance file it
    names, this reader reads it, and the second dump is its frame decompressed."""
    import re

    md = Path(format_md).read_text(encoding="utf-8")
    section = md[md.index("## Worked example") : md.index("## Versioning")]
    blocks = re.findall(r"```\n(.*?)```", section, re.S)
    dumps = [bytes.fromhex("".join(line[10:57] for line in b.splitlines())) for b in blocks]
    name = re.search(r"`(tests/vectors/[\w-]+\.xicap)`", section).group(1)
    path = Path(format_md).parent / name
    capture, content = dumps
    if capture != path.read_bytes():
        print(f"the worked example is not {name}")
        return 1
    c = Capture(capture)
    packets = list(c.packets())
    if not c.complete or not c.verify()[0]:
        print("the worked example does not read as complete and signed")
        return 1
    frame = c.raw_frame(c.data_start, c.end)
    plain = Stream().decode(frame, c.frame_header) if c.v4 else zstandard.ZstdDecompressor().decompress(frame[c.frame_header : -4])
    if plain != content:
        print("the decompressed dump is not the frame's content")
        return 1
    print(f"worked example ok: {len(capture)} bytes, {len(packets)} packets")
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "--example":
        sys.exit(example(sys.argv[2]))
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else str(Path(__file__).parent / "vectors")))
