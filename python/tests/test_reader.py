from pathlib import Path

import pytest

import xicap


FIXTURE = Path(__file__).parent.parent.parent / "js" / "test" / "fixtures" / "sample.xicap"


def test_header_and_packets():
    r = xicap.Reader(FIXTURE)

    assert r.version_major == 2
    assert r.client_version == "fixture-1.0"
    assert r.capture_agent == "xicap_make_fixture"
    assert r.start_zone_id == 100
    assert r.start_timestamp_ms == 1_700_000_000_000
    assert r.total_packet_count == 50
    assert r.has_footer is True

    lobby = r.lobby
    assert lobby["contentId"] == 0xDEADBEEF
    assert lobby["worldId"] == 42
    assert lobby["characterName"] == "Mehdi"
    assert lobby["worldName"] == "Asura"
    assert lobby["pendingRename"] is True

    assert r.extension_types() == [0x0001]
    ext = r.get_extension(0x0001)
    assert ext == bytes([1, 2, 3, 4, 5])
    assert r.get_extension(0xBADBAD) is None

    packets = list(r)
    assert len(packets) == 50

    for i, pkt in enumerate(packets):
        assert pkt.opcode == 0x100 + (i % 4)
        assert pkt.direction == (
            xicap.PacketDirection.ClientToServer
            if i % 2
            else xicap.PacketDirection.ServerToClient
        )
        assert isinstance(pkt.data, bytes)
        assert len(pkt.data) == 32
        if i == 9:
            assert pkt.markers == ["after-tenth"]
        else:
            assert pkt.markers == []


def test_seek_results():
    r = xicap.Reader(FIXTURE)
    assert r.seek_to_frame(0) == xicap.SeekResult.Ok
    assert r.seek_to_frame(99999) == xicap.SeekResult.OutOfRange
    assert r.seek_to_zone(9999) == xicap.SeekResult.NotFound


def test_typed_error_on_bad_path(tmp_path):
    bogus = tmp_path / "missing.xicap"
    with pytest.raises(xicap.Error) as exc_info:
        xicap.Reader(bogus)
    assert exc_info.value.code == xicap.ErrorCode.OpenFailed


def test_typed_error_on_bad_magic(tmp_path):
    bad = tmp_path / "bad.xicap"
    bad.write_bytes(b"NOPE" + b"\x00" * 252)
    with pytest.raises(xicap.Error) as exc_info:
        xicap.Reader(bad)
    assert exc_info.value.code == xicap.ErrorCode.BadMagic
