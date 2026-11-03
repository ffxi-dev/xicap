import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { Reader, StreamReader, XicapError, ErrorCode } from "../dist/index.js";

// Written by tools/xicap_make_fixture; see its comments for the contents.
const here = path.dirname(fileURLToPath(import.meta.url));
const fixturePath = path.resolve(here, "fixtures/sample.xicap");

test("reads header and packets from the fixture", async () => {
    const r = await Reader.open(await readFile(fixturePath));
    try {
        assert.equal(r.versionMajor, 4);
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
        assert.equal(v.seal, null);
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

test("reads the conformance set as recorded", async () => {
    const dir = path.resolve(here, "../../tests/vectors");
    const names = (await readdir(dir)).filter((n) => n.endsWith(".xicap"));
    assert.ok(names.length >= 17);
    for (const name of names) {
        const expected = JSON.parse(await readFile(path.join(dir, name.replace(".xicap", ".json")), "utf8"));
        const bytes = await readFile(path.join(dir, name));
        if (expected.refusal) {
            await assert.rejects(
                (async () => {
                    const r = await Reader.open(bytes);
                    try {
                        [...r];
                    } finally {
                        r.close();
                    }
                })(),
                (e) => e instanceof XicapError,
                name,
            );
            continue;
        }
        const r = await Reader.open(bytes);
        try {
            const hex = (u8) => Buffer.from(u8).toString("hex");
            const packets = [...r].map((p) => [p.timestampMs, p.channel, p.opcode, p.flags, hex(p.data), p.markers.map((m) => [m.kind, m.text])]);
            assert.deepEqual(packets, expected.packets, name);
            assert.equal(r.complete, expected.complete, name);
            assert.equal(r.footerDamaged, expected.footerDamaged, name);
            assert.equal(r.unreadBytes, expected.unreadBytes, name);
            assert.equal(r.characterMismatch, expected.characterMismatch, name);
            const v = r.verify();
            assert.deepEqual([v.signedToEnd, v.verifiedPackets, v.goodCheckpoints, v.firstFailureOffset !== null], expected.verify, name);
            assert.deepEqual(v.seal && [hex(v.seal.key), v.seal.agent, v.seal.sealedAtMs, v.seal.good], expected.seal ?? null, name);
        } finally {
            r.close();
        }
    }
});

test("the stream reader gives the same packets in chunks of any size", async () => {
    const dir = path.resolve(here, "../../tests/vectors");
    const files = [fixturePath, ...(await readdir(dir)).filter((n) => n.endsWith(".xicap")).map((n) => path.join(dir, n))];
    const shape = (p) => [p.timestampMs, p.channel, p.opcode, p.flags, Buffer.from(p.data).toString("hex"), p.markers];
    for (const file of files) {
        const bytes = new Uint8Array(await readFile(file));
        let whole;
        try {
            const r = await Reader.open(bytes);
            whole = [...r].map(shape);
            r.close();
        } catch {
            continue; // refused
        }
        for (const size of [1, 7, 4096, 65536]) {
            const s = await StreamReader.create();
            const got = [];
            for (let at = 0; at < bytes.length; at += size) {
                got.push(...s.push(bytes.subarray(at, at + size)).map(shape));
            }
            assert.equal(s.ready, true, file);
            assert.deepEqual(got, whole, `${file} in chunks of ${size}`);
            s.close();
        }
    }
});
