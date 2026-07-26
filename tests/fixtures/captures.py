"""Generate small, non-sensitive PCAPNG fixtures without external tools."""

from __future__ import annotations

import struct
from collections.abc import Iterable
from pathlib import Path

_ETHERNET_LINK_TYPE = 1
_TIMESTAMP_BASE_SECONDS = 1_700_000_000
_TIMESTAMP_STEP_MICROSECONDS = 250_000


def write_capture_fixtures(directory: Path) -> dict[str, Path]:
    """Write the documented synthetic captures and return their paths."""
    directory.mkdir(parents=True, exist_ok=True)
    captures = {
        "normal": directory / "synthetic-normal.pcapng",
        "midstream": directory / "synthetic-midstream.pcapng",
        "empty": directory / "synthetic-empty.pcapng",
    }
    _write_pcapng(captures["normal"], _normal_packets())
    _write_pcapng(captures["midstream"], _midstream_packets())
    _write_pcapng(captures["empty"], ())
    return captures


def _normal_packets() -> tuple[bytes, ...]:
    packets = [
        _tcp_packet(flags=0x02, sequence=1),
        _tcp_packet(flags=0x12, sequence=10, reverse=True),
        _tcp_packet(flags=0x10, sequence=2),
    ]
    packets.extend(
        _tcp_packet(flags=0x18, sequence=3 + index, payload=b"x") for index in range(7)
    )
    return tuple(packets)


def _midstream_packets() -> tuple[bytes, ...]:
    return tuple(
        _tcp_packet(flags=0x18, sequence=100 + index, payload=b"x")
        for index in range(10)
    )


def _tcp_packet(
    *,
    flags: int,
    sequence: int,
    payload: bytes = b"",
    reverse: bool = False,
) -> bytes:
    source_ip = bytes((192, 0, 2, 1))
    destination_ip = bytes((198, 51, 100, 2))
    source_port, destination_port = 49_152, 443
    source_mac = bytes.fromhex("020000000001")
    destination_mac = bytes.fromhex("020000000002")
    if reverse:
        source_ip, destination_ip = destination_ip, source_ip
        source_port, destination_port = destination_port, source_port
        source_mac, destination_mac = destination_mac, source_mac

    tcp_header = struct.pack(
        "!HHIIHHHH",
        source_port,
        destination_port,
        sequence,
        0,
        (5 << 12) | flags,
        65_535,
        0,
        0,
    )
    tcp_checksum = _internet_checksum(
        source_ip
        + destination_ip
        + struct.pack("!BBH", 0, 6, len(tcp_header) + len(payload))
        + tcp_header
        + payload
    )
    tcp_header = tcp_header[:16] + struct.pack("!H", tcp_checksum) + tcp_header[18:]

    total_length = 20 + len(tcp_header) + len(payload)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        sequence,
        0x4000,
        64,
        6,
        0,
        source_ip,
        destination_ip,
    )
    ip_checksum = _internet_checksum(ip_header)
    ip_header = ip_header[:10] + struct.pack("!H", ip_checksum) + ip_header[12:]

    ethernet_header = destination_mac + source_mac + struct.pack("!H", 0x0800)
    return ethernet_header + ip_header + tcp_header + payload


def _internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    words = struct.unpack(f"!{len(data) // 2}H", data)
    total = sum(words)
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _write_pcapng(path: Path, packets: Iterable[bytes]) -> None:
    blocks = [
        _pcapng_block(
            0x0A0D0D0A,
            struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1),
        ),
        _pcapng_block(
            0x00000001,
            struct.pack("<HHI", _ETHERNET_LINK_TYPE, 0, 65_535),
        ),
    ]
    timestamp = _TIMESTAMP_BASE_SECONDS * 1_000_000
    for packet in packets:
        body = struct.pack(
            "<IIIII",
            0,
            timestamp >> 32,
            timestamp & 0xFFFFFFFF,
            len(packet),
            len(packet),
        )
        blocks.append(_pcapng_block(0x00000006, body + packet))
        timestamp += _TIMESTAMP_STEP_MICROSECONDS
    path.write_bytes(b"".join(blocks))


def _pcapng_block(block_type: int, body: bytes) -> bytes:
    padded_body = body + bytes((-len(body)) % 4)
    total_length = 12 + len(padded_body)
    return (
        struct.pack("<II", block_type, total_length)
        + padded_body
        + struct.pack("<I", total_length)
    )
