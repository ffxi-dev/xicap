# xicap

A file format and C++23 library for recording Final Fantasy XI network
packets, with readers for Go, Python, and JavaScript.

A capture holds one character's session: a header and packets in frames. Each frame stores its packets in columns and continues one
zstd stream, so captures are small, and each frame can be read as soon as it
is written: a capture can upload while it records, and a capture cut off by a
crash reads up to its last whole frame. Every block and frame carries a CRC.
Writers zero the text of chat before it reaches disk, keeping each packet's
layout, unless told to keep chat.

[FORMAT.md](FORMAT.md) specifies the format, with enough detail to write a
reader from it alone.

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

## Go

```go
import xicap "github.com/ffxi-dev/xicap/v7/bindings/go"

r, err := xicap.Open("session.xicap")   // r.Metadata, r.Complete, r.EndTimestamp, r.PacketCount
defer r.Close()
for {
    p, err := r.Next()   // io.EOF after the last packet
    ...                  // p.Timestamp, p.Flags, p.Channel, p.Opcode, p.Data, p.Markers
}

w, err := xicap.Create("session.xicap", xicap.WriterInfo{CaptureAgent: "MyRecorder 1.0", Character: c})
w.Write(xicap.OutPacket{Timestamp: ms, Data: bytes})
w.Close()

err = xicap.Transcode("upload.xicap", "archived.xicap")
```

The package builds the C++ library with cgo, so it needs a C++23 compiler and
libzstd (`apt install libzstd-dev`).

In every binding, `complete`, `endTimestamp`, and `packetCount` come from the
trailer, so a reader knows them before reading a packet, and are 0 in a
cut-off capture. For a cut-off capture, count the packets as you read them.

## Python

```
pip install ./bindings/python
```

```python
import xicap

r = xicap.Reader("session.xicap")   # r.metadata, r.complete, r.packet_count, r.end_timestamp
for p in r:
    ...  # p.timestamp, p.channel, p.opcode, p.flags, p.direction, p.data (bytes), p.markers
```

## JavaScript

The library compiled to WebAssembly, for browsers and Node 17 or later. Build
it in `bindings/js/` with Emscripten and Ninja on the path: `npm ci && npm run build`.

```js
import { Reader, StreamReader } from "./bindings/js/dist/index.js";

const r = await Reader.open(bytes);   // r.metadata, r.complete, r.packetCount, r.endTimestamp
for (const p of r) { /* p.timestamp, p.channel, p.opcode, p.flags, p.data, p.markers */ }
r.close();

const s = await StreamReader.create();
for await (const chunk of download) for (const p of s.push(chunk)) { /* ... */ }
s.close();
```

## Contributing

- A change to the format changes FORMAT.md, the vectors, and
  `tests/reference_reader.py`, a reader written from FORMAT.md alone that CI
  runs over the vectors. Regenerate the vectors with
  `build/tests/make_vectors tests/vectors`.
- `tests/vectors/` holds captures with the reading each must give. The C++
  tests and each binding read all of them.
- The bindings wrap the C++ library; none reimplements the format.
- The fuzzers in `tests/fuzz/` need Clang (`-DXICAP_BUILD_FUZZERS=ON`). CI
  does not build them; run them by hand after changing a decoder.
- A release sets its version in `CMakeLists.txt`, which the Python package
  reads too, then tags `v<version>`. A major release also changes the `/vN`
  suffix of the module path in `go.mod` and in the Go import above.

## License

MIT, see [LICENSE](LICENSE).
