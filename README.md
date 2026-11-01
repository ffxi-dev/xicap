# xicap

Binary capture format and C++20 library for Final Fantasy XI network packets.

A capture is a header written once, format-level extension blocks (the zstd
dictionary, the exclusion policy, the source of converted captures),
zstd-compressed packet frames, and a footer index once the capture is closed.
The file only ever grows, so a capture can be uploaded while it records, and a
cut-off capture reads up to its last intact frame. Every block carries a CRC,
every capture is signed by its recorder's Ed25519 key, and the exclusion policy
stubs chat before it reaches disk.

See [FORMAT.md](FORMAT.md) for the on-disk specification (format 3).

## Library

```cpp
#include <xicap/xicap.h>

xicap::WriterConfig cfg{};
cfg.clientVersion = "30251101_2";
cfg.captureAgent  = "Logbook 1.0";
cfg.character     = character;   // content id, world, names
cfg.network       = xicap::Network::Retail;
cfg.signingSeed   = installSeed; // the recorder's Ed25519 seed

xicap::Writer w("session.xicap", cfg);
w.mark(xicap::MarkerKind::Login);
w.write(timestampMs, xicap::PacketDirection::ServerToClient,
        std::as_bytes(std::span{packetBytes, packetLen}));
w.write({ .timestamp = t, .direction = dir, .data = searchBytes,
          .channel = 1, .opcode = type });   // search channel
w.flush();   // on a timer: ends the frame, signs an idle capture
w.close();   // appends the signed footer

// A packet as a writer with this policy stores it: opcode, flags, and bytes.
const auto stored = xicap::applyPolicy(cfg.policy, packet);

xicap::Reader r("session.xicap");
for (const auto& pkt : r) {
    // pkt.timestamp, pkt.channel, pkt.opcode, pkt.flags, pkt.direction,
    // pkt.data, pkt.markers
}
const auto v = r.verify();   // v.signedToEnd, v.verifiedPackets
```

## Build

```
cmake -S . -B build -G Ninja
cmake --build build
```

`xicap_dump <file>` prints what a capture holds: header, provenance,
signatures, zones, and packet statistics (`--dump` adds hex dumps).

Tests are off by default. Enable with `-DXICAP_BUILD_TESTS=ON` (fetches Catch2
via FetchContent). Run via `ctest` or the produced `xicap_tests` executable.

## Bindings

* **Python** — see [`python/`](python/). pybind11 module; `pip install ./python`.
* **JavaScript / TypeScript** — see [`js/`](js/). C++ reader compiled to
  WebAssembly via Emscripten + Embind. Works in browsers and Node.
* **Go** — see [`go/`](go/). cgo wrapper that builds the C++ reader in place;
  needs a C++20 compiler and libzstd (`apt install libzstd-dev`). Import
  `github.com/ffxi-dev/xicap/v3/go`.

## License

MIT — see [LICENSE](LICENSE).
