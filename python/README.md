# xicap (Python)

Python bindings for the [xicap](../README.md) reader. The C++ library is
linked into a native extension via pybind11; reader behaviour matches the
native build byte-for-byte.

## Install (from source)

```
pip install ./python
```

Requires a C++23 toolchain (MSVC, GCC, or Clang) and CMake. The wheel build
fetches Catch2 / pybind11 / zstd via FetchContent.

For development:

```
pip install -e ./python[test]
pytest python/tests
```

## Usage

```python
import xicap

r = xicap.Reader("session.xicap")
print(r.client_version, r.start_timestamp_ms)
print(r.character["characterName"], "@", r.character["worldName"])

for pkt in r:
    if pkt.direction == xicap.PacketDirection.ServerToClient:
        # pkt.timestampMs, pkt.opcode, pkt.data: bytes, pkt.markers: [(MarkerKind, text)]
        ...

# Random access
r.seek_to_zone(245)
r.seek_to_time(1_700_000_500_000)

# Signatures, and a repacker's seal
v = r.verify()   # v["signedToEnd"], v["seal"]

# Rewrite at archive size; checked packet by packet before dst appears
xicap.transcode("upload.xicap", "archived.xicap", seed=seed32, agent="mogsafe 2026.11.4")
```

## API

* `xicap.Reader(path)` — opens a `.xicap` file.
* `xicap.Packet` — `timestamp_ms`, `opcode`, `direction`, `data: bytes`,
  `markers: list[str]`.
* `xicap.PacketDirection` — `ServerToClient` / `ClientToServer`.
* `xicap.SeekResult` — `Ok` / `EmptyIndex` / `OutOfRange` / `NotFound`.
* `xicap.Error` — raised on format errors; carries a `.code` of type
  `xicap.ErrorCode`.

The reader is read-only. A writer would be a small additional binding; ask if
you need it.
