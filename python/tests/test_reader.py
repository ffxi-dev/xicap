from pathlib import Path

import pytest

import xicap


# Written by tools/xicap_make_fixture; see its comments for the contents.
FIXTURE = Path(__file__).parent.parent.parent / "js" / "test" / "fixtures" / "sample.xicap"


def test_header_and_packets():
    r = xicap.Reader(FIXTURE)

    assert r.version_major == 3
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
