// @ts-expect-error: emcc writes this file.
import createXicap from "../dist/xicap.js";

export const Origin = { Unknown: 0, Live: 1, Converted: 2 } as const;
export const ServerKind = { Unknown: 0, Retail: 1, Private: 2 } as const;
export const MarkerKind = { Note: 0, Login: 1, Logout: 2 } as const;
export const Channel = { Game: 0, Search: 1 } as const;
export const PacketFlag = {
    ClientToServer: 0x0001,
    Injected: 0x0002,
    Blocked: 0x0004,
    Modified: 0x0008,
    FirstInDatagram: 0x0010,
    Excluded: 0x0100,
    Redacted: 0x0200,
} as const;

export interface Metadata {
    captureId: Uint8Array;
    previousCaptureId: Uint8Array;
    startTimestamp: number;
    origin: number;
    serverKind: number;
    captureAgent: string;
    clientVersion: string;
    character: { contentId: number; characterId: number; name: string; world: string };
    source: { format: string; formatVersion: string; skippedRecords: number; metadata: Uint8Array } | null;
}

export interface Packet {
    timestamp: number;
    flags: number;
    channel: number;
    opcode: number;
    data: Uint8Array;
    markers: { kind: number; text: string }[]; // those just before this packet
}

/** Packets as columns, packet i at index i of each; its data is the sizes[i] bytes of data after those before it. */
export interface Columns {
    timestamps: Float64Array;
    flags: Uint16Array;
    channels: Uint8Array;
    opcodes: Uint16Array;
    sizes: Uint32Array;
    data: Uint8Array;
    markers: { packet: number; kind: number; text: string }[]; // each just before the packet at that index
}

interface NativeReader {
    metadata(): Metadata;
    complete(): boolean;
    endTimestamp(): number;
    packetCount(): number;
    next(): Packet | undefined;
    delete(): void;
}

interface NativeStreamReader {
    push(chunk: Uint8Array): Packet[];
    pushColumns(chunk: Uint8Array): Columns;
    metadata(): Metadata;
    ready(): boolean;
    complete(): boolean;
    stopped(): boolean;
    delete(): void;
}

interface Module {
    FS: { writeFile(path: string, data: Uint8Array): void; unlink(path: string): void };
    Reader: new (path: string) => NativeReader;
    StreamReader: new () => NativeStreamReader;
}

let options: object = {};
let module: Promise<Module> | undefined;

/** Sets the options Emscripten's loader gets, such as locateFile for a bundler's wasm URL. Call before the first open. */
export function configureXicap(loaderOptions: object): void {
    if (module) throw new Error("xicap: configureXicap must come before the first Reader.open or StreamReader.create");
    options = loaderOptions;
}

const load = (): Promise<Module> =>
    (module ??= (createXicap(options) as Promise<Module>).catch((e: unknown) => {
        module = undefined;
        throw e;
    }));

function open<T>(native: T | null): T {
    if (!native) throw new Error("xicap: the reader is closed");
    return native;
}

/** Reads a whole capture. A complete one is read whole or refused; a cut-off one reads up to its first bad frame. */
export class Reader {
    static async open(bytes: ArrayBuffer | Uint8Array): Promise<Reader> {
        const m = await load();
        // The synchronous open/unlink sequence lets each reader retain its own MEMFS file.
        const path = "/capture.xicap";
        m.FS.writeFile(path, bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes));
        try {
            return new Reader(new m.Reader(path));
        } finally {
            m.FS.unlink(path);
        }
    }

    readonly metadata: Metadata;

    private constructor(private native: NativeReader | null) {
        this.metadata = open(native).metadata();
    }

    /** True when the file ends with a valid trailer. */
    get complete(): boolean { return open(this.native).complete(); }
    /** The trailer's end time, or 0 in a cut-off file. */
    get endTimestamp(): number { return open(this.native).endTimestamp(); }
    /** The trailer's packet count, or 0 in a cut-off file. */
    get packetCount(): number { return open(this.native).packetCount(); }

    *[Symbol.iterator](): IterableIterator<Packet> {
        for (let p = open(this.native).next(); p; p = open(this.native).next()) yield p;
    }

    close(): void {
        this.native?.delete();
        this.native = null;
    }
}

/** Reads a capture as its bytes arrive. */
export class StreamReader {
    static async create(): Promise<StreamReader> {
        return new StreamReader(new (await load()).StreamReader());
    }

    private constructor(private native: NativeStreamReader | null) {}

    /** The packets whose frames these bytes completed. Throws for a capture that must be refused. */
    push(chunk: Uint8Array): Packet[] { return open(this.native).push(chunk); }
    /** push's packets as columns, many times faster for many packets. */
    pushColumns(chunk: Uint8Array): Columns { return open(this.native).pushColumns(chunk); }
    /** True once the header and blocks are read, so that metadata holds them. */
    get ready(): boolean { return open(this.native).ready(); }
    get metadata(): Metadata { return open(this.native).metadata(); }
    /** True once the trailer is read. */
    get complete(): boolean { return open(this.native).complete(); }
    /** True once the reader meets bytes that are neither a valid frame nor a trailer; it reads nothing more. */
    get stopped(): boolean { return open(this.native).stopped(); }

    close(): void {
        this.native?.delete();
        this.native = null;
    }
}
