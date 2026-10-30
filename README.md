# xicap

Binary capture format and C++20 library for Final Fantasy XI network packets.

A capture is a fixed header + optional extension blocks (memory snapshots,
character info) + zstd-compressed packet frames + an optional footer index.
Truncated captures remain readable; the reader rebuilds the index by scanning.
Each capture embeds the zstd dictionary it was compressed with, so it stays
readable on any build.

See [FORMAT.md](FORMAT.md) for the on-disk specification.

## Library

```cpp
#include <xicap/xicap.h>

xicap::WriterConfig cfg{
    .clientVersion = "30251101_2",
    .captureAgent  = "Memoria 1.0",
    .startZoneId   = 100,
};

xicap::Writer w("session.xicap", cfg);
w.write(timestampMs, xicap::PacketDirection::ServerToClient,
        std::as_bytes(std::span{packetBytes, packetLen}));
w.close();   // appends footer

xicap::Reader r("session.xicap");
for (const auto& pkt : r) {
    // pkt.timestamp, pkt.opcode, pkt.direction, pkt.data
}
```

## Build

```
cmake -S . -B build -G Ninja
cmake --build build
```

Tools (`xicap_dump`) require the Ashita SDK; set `ASHITA4_SDK_PATH` in the
environment or disable with `-DXICAP_BUILD_TOOLS=OFF`. FFXI is a 32-bit client,
so anything that consumes Ashita SDK structs must be built x86.

Tests are off by default. Enable with `-DXICAP_BUILD_TESTS=ON` (fetches Catch2
via FetchContent). Run via `ctest` or the produced `xicap_tests` executable.

## Bindings

* **Python** — see [`python/`](python/). pybind11 module; `pip install ./python`.
* **JavaScript / TypeScript** — see [`js/`](js/). C++ reader compiled to
  WebAssembly via Emscripten + Embind. Works in browsers and Node.

## License

MIT — see [LICENSE](LICENSE).
