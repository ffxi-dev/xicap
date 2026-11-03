# xicap

Binary capture format and C++20 library for Final Fantasy XI network packets.

A capture is a header written once, format-level extension blocks (the
exclusion policy, the source of converted captures), packet frames, and a footer
index once the capture is closed. Packet frames hold their packets in columns,
compressed as one zstd stream that runs across frames and restarts every 4 MiB.
The file only ever grows, and each frame is decodable the moment it is written,
so a capture can be uploaded while it records, and a cut-off capture reads up to
its last intact frame. Every block carries a CRC, the exclusion policy stubs
chat before it reaches disk, and the recorder's Ed25519 key signs the packets
themselves, so a capture can be recompressed and keep its signature.

See [FORMAT.md](FORMAT.md) for the on-disk specification (format 4) and
[FORMAT-3.md](FORMAT-3.md) for format 3, which readers keep reading. The
library writes format 4 only.

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

// Rewrite a capture at archive size and check it packet by packet. Seal keeps
// the recorder's signatures and adds the archive's; Resign signs anew, and
// names a format-3 source in a SOURCE block.
xicap::transcode("upload.xicap", "archived.xicap",
                 { .policy = xicap::FramePolicy::archive(),
                   .signing = xicap::Signing::Seal,
                   .seed = archiveSeed, .agent = "mogsafe 2026.11.4" });

// Cut packets 1174 to 1883 into a capture of their own, signed anew.
xicap::cut("recording.xicap", "session.xicap",
           { .first = 1174, .last = 1883, .seed = mogsafeSeed, .agent = "mogsafe",
             .sourceHash = sha512OfRecording, .metadata = {} });

// Read a capture as it downloads.
xicap::StreamReader s;
s.push(chunk);
xicap::ReadPacket p{};
while (s.next(p)) { /* every packet whose frame has arrived */ }
```

### Cuts

A cut starts mid-zone, so `cut` writes ahead of the range the packets from
before it that a reader needs to know the zone and what is in view, each with
the carried flag and the range's first timestamp (FORMAT.md, Carried packets).
They are the last zone-in (`0x00A`) before the range and, since it, the last
packet of each kind below:

| Packets | One kept per |
|---------|--------------|
| `0x00D`, `0x00E`: player and NPC updates | entity and part sent (position, claim, general, name, model); an entity that despawns keeps none |
| `0x037` status, `0x051` gear look, `0x057` weather, `0x061` job and stats, `0x076` party icons, `0x0C8` party list | opcode |
| `0x05F` music, `0x063` status icons and more | slot or type (u16 at byte 4) |
| `0x0DD`, `0x0DF`, `0x0E2`: party members | member (u32 at byte 4) |
| `0x015` from the client: the recorder's position | opcode |

These are what Theater and Scholar read to draw the recorder and the entities
around it. Events (`0x028` actions, `0x029` messages, chat) are not carried.

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
  `github.com/ffxi-dev/xicap/v4/go`.

## License

MIT — see [LICENSE](LICENSE).
