// The xicap C++ reader, compiled to WebAssembly.
// @ts-expect-error: emcc writes this file.
import createXicap from "../dist/xicap.js";

export const Origin = { Unknown: 0, Live: 1, Converted: 2 } as const;
export const Network = { Unknown: 0, Retail: 1, Private: 2 } as const;
export const MarkerKind = { Note: 0, Login: 1, Logout: 2 } as const;
export const PacketFlag = {
    ClientToServer: 0x0001,
    Injected: 0x0002,
    Blocked: 0x0004,
    Modified: 0x0008,
    FirstInChunk: 0x0010,
    Excluded: 0x0100,
    Redacted: 0x0200,
} as const;

export interface Metadata {
    captureId: Uint8Array;
    previousCaptureId: Uint8Array;
    startTimestamp: number; // Unix ms
    origin: number;
    network: number;
    captureAgent: string;
    clientVersion: string;
    character: { contentId: number; characterId: number; name: string; world: string };
    policy: { name: string; version: number; rules: number }; // no rules: chat was kept
    source: { format: string; formatVersion: string; skippedRecords: number; metadata: Uint8Array } | null;
}

export interface Packet {
    timestamp: number; // Unix ms
    flags: number;
    channel: number;
    opcode: number;
    data: Uint8Array;
    markers: { kind: number; text: string }[]; // the markers just before this packet
}

let module: Promise<any> | undefined;

/** Sets the options Emscripten's loader gets, such as locateFile for a bundler's wasm URL. Call before the first open. */
export function configureXicap(options: object): void {
    module = createXicap(options);
}

const load = () => (module ??= createXicap());

let files = 0;

/** Reads a whole capture. A complete one is read whole or refused; a cut-off one reads up to its first bad frame. */
export class Reader {
    static async open(bytes: ArrayBuffer | Uint8Array): Promise<Reader> {
        const m = await load();
        const path = `/capture-${files++}.xicap`;
        m.FS.writeFile(path, bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes));
        try {
            return new Reader(new m.Reader(path), () => m.FS.unlink(path));
        } catch (e) {
            m.FS.unlink(path);
            throw e;
        }
    }

    readonly metadata: Metadata;

    private constructor(private native: any, private release: () => void) {
        this.metadata = native.metadata();
    }

    /** True when the file ends with a valid trailer. */
    get complete(): boolean { return this.native.complete(); }
    /** The trailer's end time, or 0 in a cut-off file. */
    get endTimestamp(): number { return this.native.endTimestamp(); }
    get packetCount(): number { return this.native.packetCount(); }

    *[Symbol.iterator](): IterableIterator<Packet> {
        for (let p = this.native.next(); p; p = this.native.next()) yield p;
    }

    close(): void {
        if (!this.native) return;
        this.native.delete();
        this.native = null;
        this.release();
    }
}

/** Reads a capture as its bytes arrive, as a download does. */
export class StreamReader {
    static async create(): Promise<StreamReader> {
        return new StreamReader(new (await load()).StreamReader());
    }

    private constructor(private native: any) {}

    /** The packets whose frames these bytes completed. Throws for a capture that must be refused. */
    push(chunk: Uint8Array): Packet[] { return this.native.push(chunk); }
    /** True once the header and blocks are read, so that metadata holds them. */
    get ready(): boolean { return this.native.ready(); }
    get metadata(): Metadata { return this.native.metadata(); }
    /** True once the trailer is read, which comes after every packet. */
    get complete(): boolean { return this.native.complete(); }
    /** True once the reader has met bytes that are neither a whole, valid frame nor a trailer; it reads nothing more. */
    get stopped(): boolean { return this.native.stopped(); }

    close(): void {
        this.native?.delete();
        this.native = null;
    }
}
