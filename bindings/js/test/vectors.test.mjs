import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { test } from "node:test";

import { Channel, MarkerKind, Origin, PacketFlag, Reader, ServerKind, StreamReader, configureXicap } from "../dist/index.js";

const dir = new URL("../../../tests/vectors/", import.meta.url);
const names = (await readdir(dir)).filter((n) => n.endsWith(".json")).map((n) => n.slice(0, -5));
const hex = (bytes) => Buffer.from(bytes).toString("hex");

function describe(r, packets) {
    const m = r.metadata;
    return {
        refused: false,
        complete: r.complete,
        endTimestamp: r.endTimestamp,
        packetCount: r.packetCount,
        metadata: {
            ...m,
            captureId: hex(m.captureId),
            previousCaptureId: hex(m.previousCaptureId),
            source: m.source && { ...m.source, metadata: hex(m.source.metadata) },
        },
        packets: packets.map((p) => ({
            ...p,
            data: hex(p.data),
            markers: p.markers.map((k) => ({ kind: k.kind, text: hex(Buffer.from(k.text)) })),
        })),
    };
}

test("there are vectors", () => assert.ok(names.length >= 15));

// The vectors' numbers are FORMAT.md's; this catches a constant that drifts from them.
test("the constants match the vectors", async () => {
    const r = await Reader.open(await readFile(new URL("5-packets.xicap", dir)));
    const [first, second, third] = r;
    assert.equal(r.metadata.origin, Origin.Live);
    assert.equal(r.metadata.serverKind, ServerKind.Retail);
    assert.equal(first.channel, Channel.Game);
    assert.equal(first.markers[0].kind, MarkerKind.Login);
    assert.equal(second.flags, PacketFlag.ClientToServer | PacketFlag.Modified | PacketFlag.FirstInDatagram);
    assert.equal(third.flags, PacketFlag.Redacted);
    r.close();
    assert.throws(() => r.complete, /closed/);
    assert.throws(() => configureXicap({}), /before the first/);
});

for (const name of names) {
    test(name, async () => {
        const want = JSON.parse(await readFile(new URL(`${name}.json`, dir), "utf8"));
        const bytes = await readFile(new URL(`${name}.xicap`, dir));
        if (want.refused) {
            await assert.rejects(async () => [...(await Reader.open(bytes))]);
            return;
        }

        const r = await Reader.open(bytes);
        const packets = [...r];
        assert.deepEqual(describe(r, packets), want);
        r.close();

        // Fed in 7-byte pieces, a stream reader reads the same packets.
        const s = await StreamReader.create();
        const streamed = [];
        for (let at = 0; at < bytes.length; at += 7) streamed.push(...s.push(bytes.subarray(at, at + 7)));
        assert.deepEqual(streamed, packets);
        assert.equal(s.complete, want.complete);
        s.close();
    });
}
