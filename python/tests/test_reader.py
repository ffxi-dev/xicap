import json
from pathlib import Path

import pytest

import xicap

VECTORS = sorted((Path(__file__).parents[2] / "tests" / "vectors").glob("*.json"))


def test_there_are_vectors():
    assert len(VECTORS) >= 15


@pytest.mark.parametrize("path", VECTORS, ids=lambda p: p.stem)
def test_vector_reads_as_its_json_says(path):
    want = json.loads(path.read_text())
    capture = path.with_suffix(".xicap")
    if want["refused"]:
        with pytest.raises(xicap.Error):
            list(xicap.Reader(capture))
        return

    r = xicap.Reader(capture)
    c = r.character
    source = r.source and {
        "format": r.source.format,
        "formatVersion": r.source.format_version,
        "skippedRecords": r.source.skipped_records,
        "metadata": r.source.metadata.hex(),
    }
    m = want["metadata"]
    assert {
        "captureId": r.capture_id.hex(),
        "previousCaptureId": r.previous_capture_id.hex(),
        "startTimestamp": r.start_timestamp,
        "origin": int(r.origin),
        "network": int(r.network),
        "captureAgent": r.capture_agent,
        "clientVersion": r.client_version,
        "character": {"contentId": c.content_id, "characterId": c.character_id, "name": c.name, "world": c.world},
        "policy": {"name": r.policy_name, "version": r.policy_version, "rules": r.policy_rules},
        "source": source,
    } == {**m, "policy": {**m["policy"], "rules": len(m["policy"]["rules"])}}
    assert (r.complete, r.end_timestamp, r.packet_count) == (want["complete"], want["endTimestamp"], want["packetCount"])

    packets = list(r)
    assert [
        {
            "timestamp": p.timestamp,
            "flags": p.flags,
            "channel": p.channel,
            "opcode": p.opcode,
            "data": p.data.hex(),
            "markers": [{"kind": int(k), "text": t.encode().hex()} for k, t in p.markers],
        }
        for p in packets
    ] == want["packets"]
    assert [int(p.direction) for p in packets] == [p["flags"] & 1 for p in want["packets"]]
