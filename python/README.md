# xicap (Python)

Python bindings for the [xicap](../README.md) reader: the C++ library, linked
into a native module with pybind11.

## Install (from source)

```
pip install ./python
```

It needs a C++23 compiler (MSVC, GCC, or Clang) and CMake. The build fetches
pybind11 and zstd.

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

# Signatures, and a sealer's seal
v = r.verify()   # v["signedToEnd"], v["seal"]

# Rewrite at archive size; checked packet by packet before dst appears
xicap.transcode("upload.xicap", "archived.xicap", seed=seed32, agent="mogsafe 2026.11.4")
```

## API

* `xicap.Reader(path, recovery=False)` opens a `.xicap` file.
* `xicap.Packet` has `timestampMs`, `channel`, `opcode`, `flags`, `direction`,
  `data: bytes`, and `markers: list[tuple[MarkerKind, str]]`.
* `xicap.PacketDirection` is `ServerToClient` or `ClientToServer`.
* `xicap.SeekResult` is `Ok`, `EmptyIndex`, `OutOfRange`, or `NotFound`.
* `xicap.Error` is raised for a file the reader refuses; its `.code` is an
  `xicap.ErrorCode`.
* `xicap.transcode(src, dst, *, seed, agent, level=0)` rewrites and seals a
  capture.

The module reads and transcodes captures; it does not write new ones.
