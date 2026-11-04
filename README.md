# xicap

Binary capture format and C++23 library for Final Fantasy XI network packets.

A capture is a header, extension blocks (the exclusion policy, and the source of
a converted capture), packet frames, and, once closed, a footer index. Packet
frames hold their packets in columns, compressed as one zstd stream that runs
across frames and restarts every 4 MiB. The file only grows, and each frame
decodes the moment it is written, so a capture can be uploaded while it records
and a cut-off capture reads up to its last intact frame.

Every block carries a CRC. The exclusion policy zeroes the text of chat before
it reaches disk and keeps each packet's layout; a recording that keeps chat
carries a policy with no rules. The recorder's Ed25519 key signs the packets,
not the bytes, so a capture can be recompressed and keep its signature.

[FORMAT.md](FORMAT.md) specifies format 4, the only one the library reads or
writes.

## Library

```cpp
#include <xicap/xicap.h>

xicap::WriterConfig cfg{};
cfg.clientVersion = "30251101_2";
cfg.captureAgent  = "Logbook 1.0";
cfg.character     = character;   // content id, world, names
cfg.network       = xicap::Network::Retail;
cfg.signingSeed   = installSeed; // the recorder's Ed25519 seed

xicap::Writer w("session.xicap", cfg);   // FramePolicy::live(): level 7, about 5.5 MB
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
const auto v = r.verify();   // v.signedToEnd, v.verifiedPackets, v.seal

// Rewrite a capture at archive size and check it packet by packet. The rewrite
// keeps the packets, the capture id, and the recorder's signatures, and adds the
// archive's seal, which covers them all. Its bytes depend on the zstd version.
xicap::transcode("upload.xicap", "archived.xicap",
                 { .policy = xicap::FramePolicy::archive(),
                   .seed = archiveSeed, .agent = "mogsafe 2026.11.4" });

// The archive cut an upload off after its first `held` bytes: write the rest
// of the recording as a new capture that names it as previous.
const auto sent = xicap::continueFrom("session.xicap", held, "session-rest.xicap",
                                      installSeed);   // 0: nothing to send, no file

// Read a capture as it downloads.
xicap::StreamReader s;
s.push(chunk);
xicap::ReadPacket p{};
while (s.next(p)) { /* every packet whose frame has arrived */ }
```

## Build

```
cmake -S . -B build -G Ninja
cmake --build build
```

`xicap_dump <file>` prints what a capture holds: header, provenance,
signatures, zones, and packet statistics (`--dump` adds hex dumps).

`-DXICAP_BUILD_TESTS=ON` builds the tests, fetching Catch2; run them with
`ctest` or `xicap_tests`.

## Bindings

* **Python**, in [`python/`](python/): a pybind11 module; `pip install ./python`.
* **JavaScript and TypeScript**, in [`js/`](js/): the C++ reader compiled to
  WebAssembly with Emscripten and Embind, for browsers and Node.
* **Go**, in [`go/`](go/): a cgo wrapper that builds the C++ library in place;
  it needs a C++23 compiler and libzstd (`apt install libzstd-dev`). Import
  `github.com/ffxi-dev/xicap/v6/go`.

## License

MIT, in [LICENSE](LICENSE).
