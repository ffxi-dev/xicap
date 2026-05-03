import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { Reader, XicapError, ErrorCode } from "../dist/index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const fixturePath = path.resolve(here, "fixtures/sample.xicap");

test("reads header and packets from the fixture", async () => {
    const bytes = await readFile(fixturePath);
    const r = await Reader.open(bytes);

    try {
        assert.equal(r.versionMajor, 2);
        assert.equal(r.clientVersion, "fixture-1.0");
        assert.equal(r.captureAgent, "xicap_make_fixture");
        assert.equal(r.startZoneId, 100);
        assert.equal(r.startTimestampMs, 1_700_000_000_000);
        assert.equal(r.totalPacketCount, 50);
        assert.equal(r.hasFooter, true);

        const lobby = r.lobby;
        assert.equal(lobby.contentId, 0xdeadbeef);
        assert.equal(lobby.worldId, 42);
        assert.equal(lobby.characterName, "Mehdi");
        assert.equal(lobby.worldName, "Asura");
        assert.equal(lobby.pendingRename, true);

        // Extensions
        const types = r.extensionTypes();
        assert.deepEqual(types, [0x0001]);
        const ext = r.getExtension(0x0001);
        assert.ok(ext instanceof Uint8Array);
        assert.deepEqual(Array.from(ext), [1, 2, 3, 4, 5]);

        // Iterate every packet
        let count = 0;
        let markerCount = 0;
        let opcodes = [];
        for (const pkt of r) {
            opcodes.push(pkt.opcode);
            assert.equal(pkt.data.length, 32);
            // Direction alternates: even=S2C(0), odd=C2S(1)
            assert.equal(pkt.direction, count % 2);
            if (count === 9) {
                assert.deepEqual(pkt.markers, ["after-tenth"]);
                markerCount++;
            } else {
                assert.equal(pkt.markers.length, 0);
            }
            count++;
        }
        assert.equal(count, 50);
        assert.equal(markerCount, 1);

        // Opcodes cycle through 0x100-0x103
        for (let i = 0; i < 50; i++) {
            assert.equal(opcodes[i], 0x100 + (i % 4));
        }
    } finally {
        r.close();
    }
});

test("bad magic raises XicapError with ErrorCode.BadMagic", async () => {
    const bogus = new Uint8Array(256);
    bogus.set(new TextEncoder().encode("NOPE"), 0);
    try {
        await Reader.open(bogus);
        assert.fail("expected throw");
    } catch (e) {
        assert.ok(e instanceof XicapError, `expected XicapError, got ${e?.constructor?.name}`);
        assert.equal(e.name, "XicapError");
        assert.equal(e.code, ErrorCode.BadMagic);
    }
});

test("dictionary id mismatch raises XicapError with ErrorCode.DictionaryMismatch", async () => {
    const bytes = await readFile(fixturePath);
    const u8 = new Uint8Array(bytes);
    // Header.dictionaryId offset = 128.
    u8.set([0xef, 0xbe, 0xad, 0xde], 128);
    try {
        await Reader.open(u8);
        assert.fail("expected throw");
    } catch (e) {
        assert.ok(e instanceof XicapError);
        assert.equal(e.code, ErrorCode.DictionaryMismatch);
    }
});
