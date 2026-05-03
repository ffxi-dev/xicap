"""Python bindings for the xicap FFXI packet capture format.

Example
-------

>>> import xicap
>>> r = xicap.Reader("session.xicap")
>>> r.client_version
'30251101_2'
>>> for pkt in r:
...     # pkt.timestamp_ms, pkt.opcode, pkt.direction, pkt.data (bytes), pkt.markers
...     pass
"""

from __future__ import annotations

from collections.abc import Iterator
from os import PathLike
from typing import Optional

from . import _xicap as _native
from ._xicap import (
    Error,
    ErrorCode,
    Packet,
    PacketDirection,
    SeekResult,
)

__all__ = [
    "Error",
    "ErrorCode",
    "Packet",
    "PacketDirection",
    "Reader",
    "SeekResult",
]


class Reader:
    """Reads packets from an xicap capture file.

    Returned ``Packet`` objects own their byte payload (a ``bytes`` instance),
    so they may be retained across iterations.
    """

    def __init__(self, path: str | PathLike[str]) -> None:
        self._native = _native.Reader(str(path))

    def __iter__(self) -> Iterator[Packet]:
        while True:
            pkt = self._native.next()
            if pkt is None:
                return
            yield pkt

    # Header accessors --------------------------------------------------------
    @property
    def version_major(self) -> int: return self._native.version_major
    @property
    def version_minor(self) -> int: return self._native.version_minor
    @property
    def client_version(self) -> str: return self._native.client_version
    @property
    def capture_agent(self) -> str: return self._native.capture_agent
    @property
    def start_zone_id(self) -> int: return self._native.start_zone_id
    @property
    def end_zone_id(self) -> int: return self._native.end_zone_id
    @property
    def start_weather(self) -> int: return self._native.start_weather
    @property
    def start_timestamp_ms(self) -> int: return self._native.start_timestamp_ms
    @property
    def end_timestamp_ms(self) -> int: return self._native.end_timestamp_ms
    @property
    def duration_ms(self) -> int: return self._native.duration_ms
    @property
    def total_frames(self) -> int: return self._native.total_frames
    @property
    def total_packet_count(self) -> int: return self._native.total_packet_count
    @property
    def has_footer(self) -> bool: return self._native.has_footer
    @property
    def lobby(self) -> dict: return self._native.lobby

    def extension_types(self) -> list[int]:
        return self._native.extension_types()

    def get_extension(self, type_id: int) -> Optional[bytes]:
        return self._native.get_extension(type_id)

    def list_zones(self) -> list[dict]:
        return self._native.list_zones()

    # Iteration controls ------------------------------------------------------
    def reset(self) -> None: self._native.reset()
    def skip_current_frame(self) -> None: self._native.skip_current_frame()
    def seek_to_frame(self, frame_index: int) -> SeekResult: return self._native.seek_to_frame(frame_index)
    def seek_to_time(self, timestamp_ms: int) -> SeekResult: return self._native.seek_to_time(timestamp_ms)
    def seek_to_zone(self, zone_id: int) -> SeekResult: return self._native.seek_to_zone(zone_id)
