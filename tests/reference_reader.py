"""A reader written from FORMAT.md alone, to show the document is enough to read every capture.

    python reference_reader.py <vectors dir>      reads each vector and compares with its JSON
    python reference_reader.py --example FORMAT.md checks the worked example against its vector

Needs the zstandard package. For tests only: it is slow and not a binding.
"""

import json
import re
import struct
import sys
import zlib
from pathlib import Path

import zstandard

MAGIC = bytes.fromhex("89584350 0d0a1a0a")
MIB = 1 << 20


class Refused(Exception):
    pass


class Bad(Exception):
    pass


def text(field):
    return field.split(b"\0", 1)[0]


def crc_ok(b):
    return zlib.crc32(b[:-4]) == struct.unpack_from("<I", b, len(b) - 4)[0]


def varint(b, pos, bits):
    value = 0
    for i in range((bits + 6) // 7):
        if pos >= len(b):
            raise Bad("varint runs past the end")
        byte = b[pos]
        pos += 1
        value |= (byte & 0x7F) << (7 * i)
        if not byte & 0x80:
            if value >> bits:
                raise Bad("varint too large for its field")
            return value, pos
    raise Bad("varint too long")


def policy(p):
    if len(p) < 38:
        raise Refused("short policy")
    name, version, count = struct.unpack_from("<32sIH", p)
    pos, rules = 38, []
    for _ in range(count):
        if pos + 7 > len(p):
            raise Refused("short rule")
        channel, direction, action, opcode, ranges = struct.unpack_from("<BBBHH", p, pos)
        pos += 7
        if pos + 8 * ranges > len(p):
            raise Refused("short ranges")
        rs = [list(struct.unpack_from("<II", p, pos + 8 * i)) for i in range(ranges)]
        pos += 8 * ranges
        rules.append({"channel": channel, "direction": direction, "action": action, "opcode": opcode, "ranges": rs})
    if pos != len(p):
        raise Refused("policy does not fill its block")
    return {"name": text(name).decode(), "version": version, "rules": rules}


def source(p):
    if len(p) < 36:
        raise Refused("short source")
    fmt, version, skipped = struct.unpack_from("<16s16sI", p)
    return {"format": text(fmt).decode(), "formatVersion": text(version).decode(), "skippedRecords": skipped, "metadata": p[36:].hex()}


def plaintext(plain, count, markers, base):
    pos = 0

    def column(bits, n):
        nonlocal pos
        out = []
        for _ in range(n):
            v, pos = varint(plain, pos, bits)
            out.append(v)
        return out

    delta, flags, channel, opcode, length = (column(b, count) for b in (32, 16, 8, 16, 32))
    sync = column(16, channel.count(0))
    marks = []
    for _ in range(markers):
        index, pos = varint(plain, pos, 32)
        if pos >= len(plain):
            raise Bad("short marker")
        kind = plain[pos]
        size, pos = varint(plain, pos + 1, 16)
        if pos + size > len(plain) or index >= count or (marks and index < marks[-1][0]):
            raise Bad("bad marker")
        marks.append((index, {"kind": kind, "text": plain[pos : pos + size].hex()}))
        pos += size
    if delta[0] != 0:
        raise Bad("first delta is not 0")

    keys = [(c, f & 1, o) for c, f, o in zip(channel, flags, opcode)]
    order = list(dict.fromkeys(keys))
    sizes = column(32, len(order))
    if sum(sizes) != len(plain) - pos:
        raise Bad("group sizes do not add up")
    cursor, end = {}, {}
    for key, size in zip(order, sizes):
        cursor[key], end[key] = pos, pos + size
        pos += size

    packets, last, t, games = [], [0, 0], base, iter(sync)
    for i, key in enumerate(keys):
        at = cursor[key]
        if channel[i] == 0:
            if end[key] - at < 4:
                raise Bad("game packet under 4 bytes")
            word = struct.unpack_from("<H", plain, at)[0]
            if word & 0x1FF != opcode[i]:
                raise Bad("opcode differs from the header")
            n = (word >> 9) * 4 if length[i] == 0 else length[i] - 1
            if n < 4:
                raise Bad("game packet under 4 bytes")
        else:
            if length[i] == 0:
                raise Bad("implied length off the game channel")
            n = length[i] - 1
        if at + n > end[key]:
            raise Bad("packet runs past its group")
        data = bytearray(plain[at : at + n])
        cursor[key] = at + n
        if channel[i] == 0:
            z = next(games)
            d = flags[i] & 1
            last[d] = (last[d] + ((z >> 1) ^ -(z & 1))) & 0xFFFF
            struct.pack_into("<H", data, 2, last[d])
        t += delta[i]
        if t >= 1 << 64:
            raise Bad("timestamp past 2^64")
        packets.append({"timestamp": t, "flags": flags[i], "channel": channel[i], "opcode": opcode[i], "data": data.hex(),
                        "markers": [m for j, m in marks if j == i]})
    if cursor != end:
        raise Bad("group bytes left over")
    return packets


def read(b):
    if len(b) < 160 or b[:8] != MAGIC or b[8] != 5 or not crc_ok(b[:160]):
        raise Refused("bad header")
    origin, network, blocks = b[9], b[10], b[11]
    cid, prev, start, agent, client, content, character, name, world = struct.unpack_from("<16s16sQ32s32sII16s16s", b, 12)
    meta = {
        "captureId": cid.hex(), "previousCaptureId": prev.hex(), "startTimestamp": start, "origin": origin, "network": network,
        "captureAgent": text(agent).decode(), "clientVersion": text(client).decode(),
        "character": {"contentId": content, "characterId": character, "name": text(name).decode(), "world": text(world).decode()},
        "policy": None, "source": None,
    }
    pos = 160
    for _ in range(blocks):
        if pos + 8 > len(b):
            raise Refused("short block")
        kind, size = struct.unpack_from("<II", b, pos)
        if size > 16 * MIB or pos + 12 + size > len(b) or not crc_ok(b[pos : pos + 12 + size]):
            raise Refused("bad block")
        payload = b[pos + 8 : pos + 8 + size]
        if kind == 1:
            if meta["policy"] is not None:
                raise Refused("second policy")
            meta["policy"] = policy(payload)
        elif kind == 2:
            if meta["source"] is not None:
                raise Refused("second source")
            meta["source"] = source(payload)
        pos += 12 + size
    if meta["policy"] is None:
        raise Refused("no policy")

    trailer = b[-24:] if len(b) >= pos + 24 else b""
    complete = trailer[:4] == b"XCPF" and crc_ok(trailer)
    end = len(b) - 24 if complete else len(b)

    packets, decoder, last = [], zstandard.ZstdDecompressor().decompressobj(), 0
    while pos < end:
        if b[pos : pos + 4] == b"XCPF" and pos + 24 <= len(b) and crc_ok(b[pos : pos + 24]):
            raise Refused("bytes follow a trailer")
        try:
            if end - pos < 28 or b[pos : pos + 4] != b"XCFR":
                raise Bad("not a frame")
            size, plain_size, count, markers, base = struct.unpack_from("<IIIIQ", b, pos + 4)
            if size > 17 * MIB or pos + 32 + size > end or not crc_ok(b[pos : pos + 32 + size]):
                raise Bad("bad frame")
            if not 1 <= plain_size <= 16 * MIB or not 1 <= count <= MIB or base < last:
                raise Bad("frame out of range")
            plain = decoder.decompress(b[pos + 28 : pos + 28 + size])
            if len(plain) != plain_size:
                raise Bad("wrong plain size")
            frame = plaintext(plain, count, markers, base)
        except (Bad, zstandard.ZstdError):
            if complete:
                raise Refused("bad frame in a complete file")
            break
        packets += frame
        last = frame[-1]["timestamp"]
        pos += 32 + size

    end_time, count = struct.unpack_from("<QQ", trailer, 4) if complete else (0, 0)
    if complete and (count != len(packets) or end_time != last):
        raise Refused("trailer disagrees")
    return {"refused": False, "complete": complete, "endTimestamp": end_time, "packetCount": count, "metadata": meta, "packets": packets}


def describe(path):
    try:
        return read(Path(path).read_bytes())
    except Refused:
        return {"refused": True}


def main(args):
    if args[:1] == ["--example"]:
        doc = Path(args[1]).read_text(encoding="utf-8").split("## Worked example", 1)[1]
        rows = re.findall(r"^[0-9a-f]{8}  ((?:[0-9a-f]{2} ?){1,16})", doc, re.M)
        example = bytes.fromhex("".join(rows))
        vector = Path(args[1]).parent / "tests" / "vectors" / "5-example.xicap"
        assert example == vector.read_bytes(), "the worked example is not tests/vectors/5-example.xicap"
        assert len(read(example)["packets"]) == 3
        print("worked example: ok")
        return 0
    failed = 0
    for want in sorted(Path(args[0]).glob("*.json")):
        ok = describe(want.with_suffix(".xicap")) == json.loads(want.read_text())
        failed += not ok
        print(f"{want.stem}: {'ok' if ok else 'DIFFERS'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
