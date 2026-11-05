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


def test_constants():
    assert xicap.PacketFlag.ClientToServer == 1 and xicap.PacketFlag.FirstInDatagram == 0x10
    assert int(xicap.Channel.Search) == 1
