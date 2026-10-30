import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { Reader, XicapError, ErrorCode } from "../dist/index.js";

// Written by tools/xicap_make_fixture; see its comments for the contents.
const here = path.dirname(fileURLToPath(import.meta.url));
const fixturePath = path.resolve(here, "fixtures/sample.xicap");

test("reads header and packets from the fixture", async () => {
    const r = await Reader.open(await readFile(fixturePath));
    try {
        assert.equal(r.versionMajor, 3);
        assert.equal(r.clientVersion, "fixture-1.0");
        assert.equal(r.captureAgent, "xicap_make_fixture");
        assert.deepEqual(Array.from(r.captureId), new Array(16).fill(0x11));
        assert.equal(r.startTimestampMs, 1_700_000_000_000);
        assert.equal(r.endTimestampMs, 1_700_000_002_500);
        assert.equal(r.totalPacketCount, 51);
        assert.equal(r.complete, true);
        assert.equal(r.network, 1); // retail
        assert.equal(r.policy.name, "xicap-default");

        const character = r.character;
        assert.equal(character.contentId, 0xdeadbeef);
        assert.equal(character.worldId, 42);
        assert.equal(character.characterName, "Mehdi");
        assert.equal(character.worldName, "Asura");

        assert.deepEqual(r.extensionTypes(), [0x8000]);
        assert.deepEqual(Array.from(r.getExtension(0x8000)), [1, 2, 3, 4, 5]);
        assert.equal(r.getExtension(0xbadbad), null);

        const packets = [...r];
        assert.equal(packets.length, 51);
        packets.slice(0, 50).forEach((pkt, i) => {
            assert.equal(pkt.channel, 0);
            assert.equal(pkt.opcode, 0x100 + (i % 4));
            assert.equal(pkt.data.length, 32);
            assert.equal(pkt.direction, i % 2);
            assert.deepEqual(pkt.markers, i === 10 ? [{ kind: 0, text: "tenth" }] : []);
        });
        const search = packets[50];
        assert.deepEqual([search.channel, search.opcode, search.data.length], [1, 5, 40]);

        const v = r.verify();
        assert.equal(v.signedToEnd, true);
        assert.equal(v.verifiedPackets, 51);
        assert.equal(v.firstFailureOffset, null);
    } finally {
        r.close();
    }
});

test("a cut-off copy reads every frame and is not signed to the end", async () => {
    const bytes = new Uint8Array(await readFile(fixturePath));
    const r = await Reader.open(bytes.subarray(0, bytes.length - 50));
    try {
        assert.equal(r.complete, false);
        assert.equal([...r].length, 51);
        assert.equal(r.verify().signedToEnd, false);
    } finally {
        r.close();
    }
});

test("bad magic raises XicapError with ErrorCode.BadMagic", async () => {
    const bogus = new Uint8Array(512);
    bogus.set(new TextEncoder().encode("NOPE"), 0);
    await assert.rejects(Reader.open(bogus), (e) => e instanceof XicapError && e.code === ErrorCode.BadMagic);
});

test("a damaged header raises HeaderChecksumMismatch", async () => {
    const bytes = new Uint8Array(await readFile(fixturePath));
    bytes[200] ^= 1;
    await assert.rejects(Reader.open(bytes), (e) => e instanceof XicapError && e.code === ErrorCode.HeaderChecksumMismatch);
});
