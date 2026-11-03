"""Python bindings for the xicap FFXI packet capture format.

Example
-------

>>> import xicap
>>> r = xicap.Reader("session.xicap")
>>> r.client_version
'30251101_2'
>>> for pkt in r:
...     # pkt.timestampMs, pkt.channel, pkt.opcode, pkt.flags, pkt.direction,
...     # pkt.data (bytes), pkt.markers ([(MarkerKind, text)])
...     pass
>>> r.verify()["signedToEnd"]
True
>>> xicap.transcode("session.xicap", "archived.xicap", seal=True, seed=key, agent="mogsafe 2026.11.4")
{'packets': ..., 'markers': ..., 'bytesIn': ..., 'bytesOut': ...}
"""

from __future__ import annotations

from collections.abc import Iterator
from os import PathLike
from typing import Optional

from . import _xicap as _native
from ._xicap import (
    ClockSource,
    Error,
    ErrorCode,
    MarkerKind,
    Network,
    Origin,
    Packet,
    PacketDirection,
    SeekResult,
    StartContext,
    transcode,
)

__all__ = [
    "ClockSource",
    "Error",
    "ErrorCode",
    "MarkerKind",
    "Network",
    "Origin",
    "Packet",
    "PacketDirection",
    "Reader",
    "SeekResult",
    "StartContext",
    "transcode",
]


class Reader:
    """Reads packets from an xicap capture file.

    Returned ``Packet`` objects own their byte payload (a ``bytes`` instance),
    so they may be retained across iterations. ``recovery=True`` skips damaged
    frames instead of refusing a complete file or ending a cut-off one.
    """

    def __init__(self, path: str | PathLike[str], recovery: bool = False) -> None:
        self._native = _native.Reader(str(path), recovery)

    def __iter__(self) -> Iterator[Packet]:
        while True:
            pkt = self._native.next()
            if pkt is None:
                return
            yield pkt

    def __getattr__(self, name: str):
        # Header and footer properties, verify(), seeks, and the rest come
        # straight from the native reader.
        return getattr(self._native, name)

    def get_extension(self, type_id: int) -> Optional[bytes]:
        return self._native.get_extension(type_id)
