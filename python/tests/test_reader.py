import json
import struct
import zlib
from pathlib import Path

import pytest

import xicap


# Written by tools/xicap_make_fixture; see its comments for the contents.
FIXTURE = Path(__file__).parent.parent.parent / "js" / "test" / "fixtures" / "sample.xicap"


def test_header_and_packets():
    r = xicap.Reader(FIXTURE)

    assert r.version_major == 4
    assert r.client_version == "fixture-1.0"
    assert r.capture_agent == "xicap_make_fixture"
    assert r.capture_id == bytes([0x11] * 16)
    assert r.previous_capture_id == bytes(16)
    assert r.start_timestamp_ms == 1_700_000_000_000
    assert r.end_timestamp_ms == 1_700_000_002_500
    assert r.total_packet_count == 51
    assert r.complete is True
    assert r.network == xicap.Network.Retail
    assert r.start_context == xicap.StartContext.Login
    assert r.policy["name"] == "xicap-default"

    character = r.character
    assert character["contentId"] == 0xDEADBEEF
    assert character["worldId"] == 42
    assert character["characterName"] == "Mehdi"
    assert character["worldName"] == "Asura"

    assert r.extension_types() == [0x8000]
    assert r.get_extension(0x8000) == bytes([1, 2, 3, 4, 5])
    assert r.get_extension(0xBADBAD) is None

    packets = list(r)
    assert len(packets) == 51
    for i, pkt in enumerate(packets[:50]):
        assert pkt.channel == 0
        assert pkt.opcode == 0x100 + (i % 4)
        assert pkt.direction == (
            xicap.PacketDirection.ClientToServer if i % 2 else xicap.PacketDirection.ServerToClient
        )
        assert isinstance(pkt.data, bytes)
        assert len(pkt.data) == 32
        assert pkt.markers == ([(xicap.MarkerKind.Note, "tenth")] if i == 10 else [])
    search = packets[50]
    assert (search.channel, search.opcode, len(search.data)) == (1, 5, 40)


def test_signatures():
    v = xicap.Reader(FIXTURE).verify()
    assert v["signedToEnd"] is True
    assert v["verifiedPackets"] == 51
    assert v["firstFailureOffset"] is None


def test_cut_off_copy(tmp_path):
    data = FIXTURE.read_bytes()
    cut = tmp_path / "cut.xicap"
    cut.write_bytes(data[:-50])
    r = xicap.Reader(cut)
    assert r.complete is False
    assert len(list(r)) == 51
    assert r.verify()["signedToEnd"] is False


def test_seek_results():
    r = xicap.Reader(FIXTURE)
    assert r.seek_to_frame(0) == xicap.SeekResult.Ok
    assert r.seek_to_frame(99999) == xicap.SeekResult.OutOfRange
    assert r.seek_to_zone(9999) == xicap.SeekResult.NotFound


def test_typed_error_on_bad_path(tmp_path):
    with pytest.raises(xicap.Error) as exc_info:
        xicap.Reader(tmp_path / "missing.xicap")
    assert exc_info.value.code == xicap.ErrorCode.OpenFailed


def test_typed_error_on_bad_magic(tmp_path):
    bad = tmp_path / "bad.xicap"
    bad.write_bytes(b"NOPE" + b"\x00" * 508)
    with pytest.raises(xicap.Error) as exc_info:
        xicap.Reader(bad)
    assert exc_info.value.code == xicap.ErrorCode.BadMagic


def test_typed_error_on_damaged_header(tmp_path):
    data = bytearray(FIXTURE.read_bytes())
    data[200] ^= 1
    bad = tmp_path / "bad.xicap"
    bad.write_bytes(bytes(data))
    with pytest.raises(xicap.Error) as exc_info:
        xicap.Reader(bad)
    assert exc_info.value.code == xicap.ErrorCode.HeaderChecksumMismatch


VECTORS = Path(__file__).parent.parent.parent / "tests" / "vectors"


@pytest.mark.parametrize("path", sorted(VECTORS.glob("*.xicap")), ids=lambda p: p.stem)
def test_conformance_set(path):
    expected = json.loads(path.with_suffix(".json").read_text())
    if "refusal" in expected:
        with pytest.raises(xicap.Error) as exc_info:
            list(xicap.Reader(path))
        assert exc_info.value.code.name == expected["result"]
        return
    r = xicap.Reader(path)
    packets = [
        [p.timestampMs, p.channel, p.opcode, p.flags, p.data.hex(), [[int(k), t] for k, t in p.markers]]
        for p in r
    ]
    assert packets == expected["packets"]
    assert r.complete == expected["complete"]
    assert r.footer_damaged == expected["footerDamaged"]
    assert r.unread_bytes == expected["unreadBytes"]
    assert r.character_mismatch == expected["characterMismatch"]
    v = r.verify()
    assert [v["signedToEnd"], v["verifiedPackets"], v["goodCheckpoints"], v["firstFailureOffset"] is not None] == expected["verify"]
    seal = v["seal"]
    assert (seal and [seal["key"].hex(), seal["agent"], seal["sealedAtMs"], seal["good"]]) == expected.get("seal")


def test_transcode_seal(tmp_path):
    out = tmp_path / "sealed.xicap"
    result = xicap.transcode(FIXTURE, out, seal=True, seed=bytes([9] * 32), agent="mogsafe test")
    assert result["packets"] == 51
    v = xicap.Reader(out).verify()
    assert v["signedToEnd"] is True
    assert v["key"] == xicap.Reader(FIXTURE).signing_key
    assert v["seal"]["good"] is True
    assert v["seal"]["agent"] == "mogsafe test"
    assert xicap.Reader(FIXTURE).verify()["seal"] is None


def test_transcode_reissue(tmp_path):
    out = tmp_path / "reissued.xicap"
    signer = {"key": bytes([5] * 32), "signedToEnd": True, "verifiedPackets": 51}
    # The fixture is not converted, so it has no source block for a signer.
    with pytest.raises(xicap.Error) as exc_info:
        xicap.transcode(FIXTURE, out, seal=False, seed=bytes([0x22] * 32), agent="x", signer=signer)
    assert exc_info.value.code == xicap.ErrorCode.TranscodeRefused
    xicap.transcode(FIXTURE, out, seal=False, seed=bytes([0x22] * 32), agent="x")
    r = xicap.Reader(out)
    assert r.verify()["signedToEnd"] is True
    assert [p.data for p in r] == [p.data for p in xicap.Reader(FIXTURE)]


def test_transcode_refuses_and_leaves_nothing(tmp_path):
    out = tmp_path / "refused.xicap"
    with pytest.raises(xicap.Error) as exc_info:
        xicap.transcode(FIXTURE, out, seal=False, seed=bytes(32), agent="x")
    assert exc_info.value.code == xicap.ErrorCode.TranscodeRefused
    assert not out.exists()


def capture_with_marker(text: bytes) -> bytes:
    """A cut-off format-4 capture of one 16-byte 0x0DF packet with a note marker; its frame is a raw zstd block of a
    stream with a checksum that the file stops before ending."""
    crc = lambda b: zlib.crc32(b) & 0xFFFFFFFF
    header = bytearray(384)
    header[0:8] = bytes([0x89, 0x58, 0x43, 0x50, 0x0D, 0x0A, 0x1A, 0x0A])
    struct.pack_into("<BBHI", header, 8, 4, 0, 384, 1)
    header[24:40] = bytes([0x11] * 16)
    struct.pack_into("<I", header, 380, crc(header[:380]))
    policy = b"empty".ljust(32, bytes(1)) + struct.pack("<IHH", 1, 0, 0)
    block = struct.pack("<II", 9, len(policy)) + policy
    block += struct.pack("<I", crc(block))
    packet = struct.pack("<H", (4 << 9) | 0x0DF) + bytes(14)
    plain = bytes([0, 0, 0, 0xDF, 0x01, 0, 0, 0, 0, len(text)]) + text + bytes([16]) + packet
    payload = struct.pack("<I", 0xFD2FB528) + bytes([0x04, 0x00]) + (len(plain) << 3).to_bytes(3, "little") + plain
    frame = b"XCFR" + struct.pack("<BBHIIQHHI", 0x80, 1, 1, len(payload), 1, 1_790_000_000_000, 0, 0, len(plain)) + payload
    return bytes(header) + block + frame + struct.pack("<I", crc(frame))


def test_marker_text_not_utf8_reads(tmp_path):
    # Memoria's notes come from Ashita in Shift-JIS: 0x93 0x8C is not UTF-8.
    path = tmp_path / "sjis.xicap"
    path.write_bytes(capture_with_marker(bytes.fromhex("938c") + "東京".encode()))
    packets = list(xicap.Reader(path))
    assert [p.markers for p in packets] == [[(xicap.MarkerKind.Note, "��東京")]]
