# xicap

A file format and C++23 library for recording Final Fantasy XI network
packets, with Go, Python, and JavaScript bindings.

A capture holds one character's session. Frames store packets in columns in a
zstd stream. A cut-off capture reads up to its last valid frame. Writers zero
chat text unless configured to keep it.

[FORMAT.md](FORMAT.md) specifies the format.

## C++

```cpp
#include <xicap/xicap.h>

xicap::Metadata m;
m.captureAgent  = "MyRecorder 1.0";
m.clientVersion = "30251101_2";
m.serverKind    = xicap::ServerKind::Retail;
m.character     = { .contentId = contentId, .characterId = id, .name = "Rhavyn", .world = "Asura" };

xicap::Writer w("session.xicap", m);   // zeroes chat text; pass xicap::Chat::Keep to keep it
w.mark(xicap::MarkerKind::Login);
w.write({ .timestamp = ms, .direction = xicap::PacketDirection::ServerToClient, .data = bytes });
w.flush();                          // on a timer: what was written is on disk and readable
w.close();                          // adds the trailer

xicap::Reader r("session.xicap");
for (const auto& p : r)
{
    // p.timestamp, p.channel, p.opcode, p.flags, p.direction(), p.data, p.markers
}

xicap::StreamReader s;              // a capture as it downloads
s.push(chunk);
xicap::Packet p;
while (s.next(p)) { }

xicap::transcode("upload.xicap", "archived.xicap");   // smaller, checked packet by packet
```

Build with CMake 3.21 or later and a C++23 compiler. The library uses the
system's zstd, or fetches it.

```
cmake -S . -B build -G Ninja -DXICAP_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build
```

Projects that use CMake can add the library with `FetchContent` and link
`xicap`.

A writer frames and compresses by a `FramePolicy`. The two presets:

| | `FramePolicy::live()`, the default | `FramePolicy::archive()` |
|---|---|---|
| zstd level | 7 | 19 |
| window | 2 MiB | 8 MiB |
| match table (`hashLog`) | 2^19 | the level's own |
| frame ends | 5 s, 1,000 packets, 64 KiB of plaintext, `flush()` | 1 MiB of plaintext |

File readers expose the trailer's completion status, end timestamp and packet
count. Without a valid trailer, completion is false and the numeric fields are
zero.

## Go

```go
import xicap "github.com/ffxi-dev/xicap/v7/bindings/go"

r, err := xicap.Open("session.xicap")   // r.Metadata, r.Complete, r.EndTimestamp, r.PacketCount
defer r.Close()
for {
    p, err := r.Next()   // io.EOF after the last packet
    ...                  // p.Timestamp, p.Flags, p.Channel, p.Opcode, p.Data, p.Markers
}

w, err := xicap.Create("session.xicap", xicap.Metadata{CaptureAgent: "MyRecorder 1.0", Character: c}, xicap.WriterOptions{})
w.Write(xicap.WritePacket{Timestamp: ms, Data: bytes})
w.Close()

err = xicap.Transcode("upload.xicap", "archived.xicap")
```

The package builds the C++ library with cgo, so it needs a C++23 compiler and
libzstd 1.4 or later (`apt install libzstd-dev`).

## Python

```
pip install ./bindings/python
```

```python
import xicap

r = xicap.Reader("session.xicap")   # r.metadata, r.complete, r.packet_count, r.end_timestamp
for p in r:
    ...  # p.timestamp, p.channel, p.opcode, p.flags, p.data (bytes), p.markers
```

## JavaScript

The library compiled to WebAssembly, for browsers and Node 17 or later. Build
it in `bindings/js/` with Emscripten and Ninja on the path:
`npm ci && npm run build`.

```js
import { Reader, StreamReader } from "./bindings/js/dist/index.js";

const r = await Reader.open(bytes);   // r.metadata, r.complete, r.packetCount, r.endTimestamp
for (const p of r) { /* p.timestamp, p.channel, p.opcode, p.flags, p.data, p.markers */ }
r.close();

const s = await StreamReader.create();
for await (const chunk of download) for (const p of s.push(chunk)) { /* ... */ }
s.close();
```

`s.pushColumns(chunk)` reads the same packets as columns: `timestamps`,
`flags`, `channels`, `opcodes` and `sizes`, one `data` buffer holding each
packet's bytes in turn, and `markers` with the index of the packet each comes
before. A JS object per packet costs about a microsecond; for a capture of
millions of packets, columns read ten times faster.

## Contributing

- A change to the format changes FORMAT.md, the vectors, and
  `tests/reference_reader.py`, a reader written from FORMAT.md alone that CI
  runs over the vectors. Regenerate the vectors with
  `build/tests/make_vectors tests/vectors`.
- Run the fuzzers in `tests/fuzz/` after changing a decoder. They need Clang:
  `cmake -S . -B build-fuzz -G Ninja -DCMAKE_CXX_COMPILER=clang++ -DXICAP_BUILD_FUZZERS=ON`,
  `cmake --build build-fuzz`, then `build-fuzz/tests/fuzz/fuzz_reader`. CI runs
  each for a minute.
- A release sets its version in `CMakeLists.txt`, which the Python package
  reads too, then tags `v<version>`. A major release also changes the `/vN`
  suffix of the module path in `go.mod` and in the Go import above.

## License

MIT, see [LICENSE](LICENSE).
