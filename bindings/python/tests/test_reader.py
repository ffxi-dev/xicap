import json
from pathlib import Path

import pytest

import xicap

VECTORS = sorted((Path(__file__).parents[3] / "tests" / "vectors").glob("*.json"))


def describe(r, packets):
    m, c, s = r.metadata, r.metadata.character, r.metadata.source
    return {
        "refused": False,
        "complete": r.complete,
        "endTimestamp": r.end_timestamp,
        "packetCount": r.packet_count,
        "metadata": {
            "captureId": m.capture_id.hex(),
            "previousCaptureId": m.previous_capture_id.hex(),
            "startTimestamp": m.start_timestamp,
            "origin": int(m.origin),
            "serverKind": int(m.server_kind),
            "captureAgent": m.capture_agent,
            "clientVersion": m.client_version,
            "character": {"contentId": c.content_id, "characterId": c.character_id, "name": c.name, "world": c.world},
            "source": s and {
                "format": s.format,
                "formatVersion": s.format_version,
                "skippedRecords": s.skipped_records,
                "metadata": s.metadata.hex(),
            },
        },
        "packets": [
            {
                "timestamp": k.timestamp,
                "flags": k.flags,
                "channel": k.channel,
                "opcode": k.opcode,
                "data": k.data.hex(),
                "markers": [{"kind": int(x.kind), "text": x.text.encode().hex()} for x in k.markers],
            }
            for k in packets
        ],
    }


def test_there_are_vectors():
    assert len(VECTORS) >= 15


@pytest.mark.parametrize("path", VECTORS, ids=lambda p: p.stem)
def test_vector(path):
    want = json.loads(path.read_text())
    capture = path.with_suffix(".xicap")
    if want["refused"]:
        with pytest.raises(xicap.Error):
            list(xicap.Reader(capture))
        return
    r = xicap.Reader(capture)
    packets = list(r)
    assert describe(r, packets) == want


def test_constants_compare_with_what_the_reader_returns():
    r = xicap.Reader(Path(__file__).parents[3] / "tests" / "vectors" / "5-packets.xicap")
    packets = list(r)
    assert r.metadata.origin == xicap.Origin.Live and r.metadata.server_kind == xicap.ServerKind.Retail
    assert any(p.channel == xicap.Channel.Game for p in packets)
    assert any(p.channel == xicap.Channel.Search for p in packets)
    unknown = [p.channel for p in packets if p.channel not in (xicap.Channel.Game, xicap.Channel.Search)]
    assert unknown == [7] and type(unknown[0]) is int
    kinds = [m.kind for p in packets for m in p.markers]
    assert xicap.MarkerKind.Login in kinds and 9 in kinds
    assert any(p.flags & xicap.PacketFlag.ClientToServer for p in packets)
