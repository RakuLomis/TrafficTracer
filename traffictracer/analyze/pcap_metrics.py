"""Bounded-memory packet counts for classic PCAP/common PCAPNG; no dissection.

Return None for other containers so the caller can use its existing dissector.
Original (wire) lengths match tshark frame.len, not truncated captured lengths.
"""

from pathlib import Path
import struct
from .process import analysis_checkpoint


def classic_pcap_metrics(path: Path) -> tuple[int, int] | None:
    byte_orders = {
        b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
        b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">",
    }
    with path.open("rb") as stream:
        header = stream.read(24)
        if header[:4] == b"\x0a\x0d\x0d\x0a":
            stream.seek(0)
            return _pcapng_metrics(stream, path.stat().st_size)
        order = byte_orders.get(header[:4])
        if order is None:
            return None
        if len(header) != 24:
            raise ValueError("truncated PCAP header")
        major, minor = struct.unpack(order + "HH", header[4:8])
        if (major, minor) != (2, 4):
            return None
        size = path.stat().st_size
        count = total = 0
        while stream.tell() < size:
            if count % 4096 == 0:
                analysis_checkpoint()
            record = stream.read(16)
            if len(record) != 16:
                raise ValueError("truncated PCAP record")
            _, _, captured, original = struct.unpack(order + "IIII", record)
            if captured > original or captured > size - stream.tell():
                raise ValueError("invalid PCAP packet length")
            stream.seek(captured, 1)
            count += 1
            total += original
        return count, total


def _pcapng_metrics(stream, size: int) -> tuple[int, int] | None:
    order = None
    count = total = 0
    while stream.tell() < size:
        if count % 4096 == 0:
            analysis_checkpoint()
        start = stream.tell()
        header = stream.read(12)
        if len(header) != 12:
            raise ValueError("truncated PCAPNG block")
        section = header[:4] == b"\x0a\x0d\x0d\x0a"
        if section:
            order = {b"\x4d\x3c\x2b\x1a": "<", b"\x1a\x2b\x3c\x4d": ">"}.get(header[8:12])
        if order is None:
            raise ValueError("invalid PCAPNG byte order")
        kind, length = struct.unpack(order + "II", header[:8])
        if length < 12 or length % 4 or length > size - start:
            raise ValueError("invalid PCAPNG block length")
        if section and length < 28:
            raise ValueError("truncated PCAPNG section")
        if kind == 6:  # Enhanced Packet Block, including multiple interfaces.
            if length < 32:
                raise ValueError("truncated PCAPNG packet")
            stream.seek(start + 20)
            captured, original = struct.unpack(order + "II", stream.read(8))
            if captured > original or ((captured + 3) // 4) * 4 > length - 32:
                raise ValueError("invalid PCAPNG packet length")
            count += 1
            total += original
        elif kind not in {0x0A0D0D0A, 1, 4, 5}:
            # Unknown, simple, obsolete, or custom packet blocks need the
            # existing dissector; never silently omit possible packet records.
            return None
        stream.seek(start + length - 4)
        if struct.unpack(order + "I", stream.read(4))[0] != length:
            raise ValueError("PCAPNG block trailer mismatch")
    return count, total
