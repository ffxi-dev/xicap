import json
from pathlib import Path

import pytest

import xicap

VECTORS = sorted((Path(__file__).parents[3] / "tests" / "vectors").glob("*.json"))


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
    m = want["metadata"]
    assert (r.start_timestamp, int(r.network), r.client_version, r.character.name, r.character.character_id) == (
        m["startTimestamp"],
        m["network"],
        m["clientVersion"],
        m["character"]["name"],
        m["character"]["characterId"],
    )
    assert (r.end_timestamp, r.packet_count) == (want["endTimestamp"], want["packetCount"])
    assert [
        {"timestamp": p.timestamp, "flags": p.flags, "channel": p.channel, "opcode": p.opcode, "data": p.data.hex(), "direction": int(p.direction)}
        for p in r
    ] == [{**{k: p[k] for k in ("timestamp", "flags", "channel", "opcode", "data")}, "direction": p["flags"] & 1} for p in want["packets"]]
