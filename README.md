# xicap

Binary capture format and C++20 library for Final Fantasy XI network packets.

A capture is a header written once, format-level extension blocks (the
exclusion policy, the source of converted captures and its signer), packet
frames, and a footer index once the capture is closed. Packet frames hold their packets in columns,
compressed as one zstd stream that runs across frames and restarts every 4 MiB.
The file only ever grows, and each frame is decodable the moment it is written,
so a capture can be uploaded while it records, and a cut-off capture reads up to
its last intact frame. Every block carries a CRC, the exclusion policy stubs
chat before it reaches disk unless the header's recording mode says the
recorder kept everything, and the recorder's Ed25519 key signs the packets
themselves, so a capture can be recompressed and keep its signature.

See [FORMAT.md](FORMAT.md) for the on-disk specification, format 4, the only
one the library reads or writes. Library 5.0 reads and writes format 4.0; 4.x
libraries also read format 3 and are not compatible.

## Library

```cpp
#include <xicap/xicap.h>

xicap::WriterConfig cfg{};
cfg.clientVersion = "30251101_2";
cfg.captureAgent  = "Logbook 1.0";
cfg.character     = character;   // content id, world, names
cfg.network       = xicap::Network::Retail;
cfg.signingSeed   = installSeed; // the recorder's Ed25519 seed
cfg.recordingMode = xicap::RecordingMode::Default; // Everything takes a policy with no rules

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

// Rewrite a capture at archive size and check it packet by packet. Seal keeps
// the recorder's signatures and adds the archive's seal, which also covers the
// recorder's footer signature and kept checkpoint. Reissue lets a signer write
// its own file again, naming a signed source in a SOURCE_SIGNER block. A
// rewrite keeps the packets and the capture id; its bytes depend on the zstd
// version.
xicap::transcode("upload.xicap", "archived.xicap",
                 { .policy = xicap::FramePolicy::archive(),
                   .signing = xicap::Signing::Seal,
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

Tests are off by default. Enable with `-DXICAP_BUILD_TESTS=ON` (fetches Catch2
via FetchContent). Run via `ctest` or the produced `xicap_tests` executable.

## Bindings

* **Python** — see [`python/`](python/). pybind11 module; `pip install ./python`.
* **JavaScript / TypeScript** — see [`js/`](js/). C++ reader compiled to
  WebAssembly via Emscripten + Embind. Works in browsers and Node.
* **Go** — see [`go/`](go/). cgo wrapper that builds the C++ reader in place;
  needs a C++20 compiler and libzstd (`apt install libzstd-dev`). Import
  `github.com/ffxi-dev/xicap/v5/go`.

## License

MIT — see [LICENSE](LICENSE).
