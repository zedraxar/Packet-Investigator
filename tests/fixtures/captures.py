"""Generate small, non-sensitive PCAPNG fixtures without external tools."""

from __future__ import annotations

import struct
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

_ETHERNET_LINK_TYPE = 1
_TIMESTAMP_BASE_SECONDS = 1_700_000_000
_TIMESTAMP_STEP_MICROSECONDS = 250_000
_CLIENT_IP = bytes((192, 0, 2, 10))
_SERVER_IP = bytes((198, 51, 100, 20))
_CLIENT_IPV6 = bytes.fromhex("20010db8000000000000000000000010")
_SERVER_IPV6 = bytes.fromhex("20010db8000000000000000000000020")
_CLIENT_MAC = bytes.fromhex("020000000001")
_SERVER_MAC = bytes.fromhex("020000000002")


@dataclass(frozen=True, slots=True)
class _TCPPacket:
    flags: int
    sequence: int
    acknowledgment: int = 0
    payload_length: int = 0
    window: int = 65_535
    reverse: bool = False
    source_port: int = 49_152
    destination_port: int = 443


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


def write_tcp_capture_matrix(directory: Path) -> dict[str, Path]:
    """Write deterministic Phase 5 TCP scenarios into a temporary directory."""
    directory.mkdir(parents=True, exist_ok=True)
    scenarios: dict[str, tuple[bytes, ...]] = {
        "complete_orderly_close": _packets(_complete_orderly_close()),
        "syn_retries": _packets(_syn_retries()),
        "syn_ack_retries": _packets(_syn_ack_retries()),
        "reset_after_syn": _packets(_reset_after_syn()),
        "reset_after_establishment": _packets(_reset_after_establishment()),
        "midstream": _packets(_midstream_bidirectional()),
        "incomplete_close": _packets(_incomplete_close()),
        "zero_window": _packets(_zero_window()),
        "retransmission": _packets(_retransmission()),
        "one_way_payload": _packets(_one_way_payload()),
        "sequence_wraparound": _packets(_sequence_wraparound()),
        "simultaneous_open": _packets(_simultaneous_open()),
        "multiple_conversations": _packets(_multiple_conversations()),
        "ipv6": _packets_ipv6(_complete_orderly_close()),
        "tuple_reuse": _packets(_tuple_reuse()),
        "empty": (),
        "no_tcp": tuple(_icmp_packet(identifier=index) for index in range(10)),
    }
    captures: dict[str, Path] = {}
    for name, packets in scenarios.items():
        path = directory / f"{name.replace('_', '-')}.pcapng"
        _write_pcapng(path, packets)
        captures[name] = path
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
    acknowledgment: int = 0,
    payload: bytes = b"",
    reverse: bool = False,
    window: int = 65_535,
    source_port: int = 49_152,
    destination_port: int = 443,
) -> bytes:
    source_ip = _CLIENT_IP
    destination_ip = _SERVER_IP
    source_mac = _CLIENT_MAC
    destination_mac = _SERVER_MAC
    if reverse:
        source_ip, destination_ip = destination_ip, source_ip
        source_port, destination_port = destination_port, source_port
        source_mac, destination_mac = destination_mac, source_mac

    tcp_header = struct.pack(
        "!HHIIHHHH",
        source_port,
        destination_port,
        sequence & 0xFFFFFFFF,
        acknowledgment & 0xFFFFFFFF,
        (5 << 12) | flags,
        window,
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
        sequence & 0xFFFF,
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


def _packets(specifications: Iterable[_TCPPacket]) -> tuple[bytes, ...]:
    return tuple(
        _tcp_packet(
            flags=packet.flags,
            sequence=packet.sequence,
            acknowledgment=packet.acknowledgment,
            payload=b"x" * packet.payload_length,
            reverse=packet.reverse,
            window=packet.window,
            source_port=packet.source_port,
            destination_port=packet.destination_port,
        )
        for packet in specifications
    )


def _packets_ipv6(specifications: Iterable[_TCPPacket]) -> tuple[bytes, ...]:
    return tuple(
        _tcp_ipv6_packet(
            flags=packet.flags,
            sequence=packet.sequence,
            acknowledgment=packet.acknowledgment,
            payload=b"x" * packet.payload_length,
            reverse=packet.reverse,
            window=packet.window,
            source_port=packet.source_port,
            destination_port=packet.destination_port,
        )
        for packet in specifications
    )


def _tcp_ipv6_packet(
    *,
    flags: int,
    sequence: int,
    acknowledgment: int,
    payload: bytes,
    reverse: bool,
    window: int,
    source_port: int,
    destination_port: int,
) -> bytes:
    source_ip = _CLIENT_IPV6
    destination_ip = _SERVER_IPV6
    source_mac = _CLIENT_MAC
    destination_mac = _SERVER_MAC
    if reverse:
        source_ip, destination_ip = destination_ip, source_ip
        source_port, destination_port = destination_port, source_port
        source_mac, destination_mac = destination_mac, source_mac

    tcp_header = struct.pack(
        "!HHIIHHHH",
        source_port,
        destination_port,
        sequence & 0xFFFFFFFF,
        acknowledgment & 0xFFFFFFFF,
        (5 << 12) | flags,
        window,
        0,
        0,
    )
    tcp_length = len(tcp_header) + len(payload)
    pseudo_header = (
        source_ip
        + destination_ip
        + struct.pack("!I", tcp_length)
        + b"\x00\x00\x00"
        + b"\x06"
    )
    checksum = _internet_checksum(pseudo_header + tcp_header + payload)
    tcp_header = tcp_header[:16] + struct.pack("!H", checksum) + tcp_header[18:]
    ipv6_header = struct.pack(
        "!IHBB16s16s",
        6 << 28,
        tcp_length,
        6,
        64,
        source_ip,
        destination_ip,
    )
    return (
        destination_mac
        + source_mac
        + struct.pack("!H", 0x86DD)
        + ipv6_header
        + tcp_header
        + payload
    )


def _complete_orderly_close() -> tuple[_TCPPacket, ...]:
    return (
        _TCPPacket(0x02, 1_000),
        _TCPPacket(0x12, 5_000, 1_001, reverse=True),
        _TCPPacket(0x10, 1_001, 5_001),
        _TCPPacket(0x18, 1_001, 5_001, payload_length=4),
        _TCPPacket(0x10, 5_001, 1_005, reverse=True),
        _TCPPacket(0x18, 5_001, 1_005, payload_length=4, reverse=True),
        _TCPPacket(0x10, 1_005, 5_005),
        _TCPPacket(0x11, 1_005, 5_005),
        _TCPPacket(0x10, 5_005, 1_006, reverse=True),
        _TCPPacket(0x11, 5_005, 1_006, reverse=True),
        _TCPPacket(0x10, 1_006, 5_006),
    )


def _syn_retries() -> tuple[_TCPPacket, ...]:
    return tuple(_TCPPacket(0x02, 1_000) for _ in range(10))


def _syn_ack_retries() -> tuple[_TCPPacket, ...]:
    packets = [_TCPPacket(0x02, 1_000)]
    packets.extend(_TCPPacket(0x12, 5_000, 1_001, reverse=True) for _ in range(9))
    return tuple(packets)


def _reset_after_syn() -> tuple[_TCPPacket, ...]:
    packets = [
        _TCPPacket(0x02, 1_000),
        _TCPPacket(0x14, 5_000, 1_001, reverse=True),
    ]
    packets.extend(_TCPPacket(0x10, 1_001, 5_001) for _ in range(8))
    return tuple(packets)


def _reset_after_establishment() -> tuple[_TCPPacket, ...]:
    packets = list(_complete_orderly_close()[:7])
    packets.append(_TCPPacket(0x14, 5_005, 1_005, reverse=True))
    packets.extend(_TCPPacket(0x10, 1_005, 5_005) for _ in range(2))
    return tuple(packets)


def _midstream_bidirectional() -> tuple[_TCPPacket, ...]:
    return tuple(
        _TCPPacket(
            0x18,
            10_000 + index * 2,
            20_000 + index * 2,
            payload_length=2,
            reverse=bool(index % 2),
        )
        for index in range(10)
    )


def _incomplete_close() -> tuple[_TCPPacket, ...]:
    packets = list(_complete_orderly_close()[:7])
    packets.append(_TCPPacket(0x11, 1_005, 5_005))
    packets.extend(
        (
            _TCPPacket(0x10, 5_005, 1_006, reverse=True),
            _TCPPacket(0x10, 5_005, 1_006, reverse=True),
        )
    )
    return tuple(packets)


def _zero_window() -> tuple[_TCPPacket, ...]:
    packets = list(_complete_orderly_close()[:7])
    packets.extend(
        _TCPPacket(0x10, 5_005, 1_005, reverse=True, window=0) for _ in range(3)
    )
    packets.extend(_complete_orderly_close()[7:])
    return tuple(packets)


def _retransmission() -> tuple[_TCPPacket, ...]:
    packets = list(_complete_orderly_close()[:3])
    segment = _TCPPacket(0x18, 1_001, 5_001, payload_length=4)
    packets.extend((segment, segment))
    packets.extend(
        (
            _TCPPacket(0x10, 5_001, 1_005, reverse=True),
            _TCPPacket(0x11, 1_005, 5_001),
            _TCPPacket(0x10, 5_001, 1_006, reverse=True),
            _TCPPacket(0x11, 5_001, 1_006, reverse=True),
            _TCPPacket(0x10, 1_006, 5_002),
        )
    )
    return tuple(packets)


def _one_way_payload() -> tuple[_TCPPacket, ...]:
    packets = list(_complete_orderly_close()[:3])
    for offset in range(4):
        packets.extend(
            (
                _TCPPacket(0x18, 1_001 + offset, 5_001, payload_length=1),
                _TCPPacket(0x10, 5_001, 1_002 + offset, reverse=True),
            )
        )
    return tuple(packets)


def _sequence_wraparound() -> tuple[_TCPPacket, ...]:
    packets = [
        _TCPPacket(0x02, 0xFFFFFFFF),
        _TCPPacket(0x12, 0xFFFFFFFF, 0, reverse=True),
        _TCPPacket(0x10, 0, 0),
    ]
    packets.extend(
        _TCPPacket(0x10, 0, 0, reverse=bool(index % 2)) for index in range(7)
    )
    return tuple(packets)


def _simultaneous_open() -> tuple[_TCPPacket, ...]:
    packets = [
        _TCPPacket(0x02, 1_000),
        _TCPPacket(0x02, 5_000, reverse=True),
        _TCPPacket(0x12, 1_000, 5_001),
        _TCPPacket(0x12, 5_000, 1_001, reverse=True),
    ]
    packets.extend(
        _TCPPacket(0x10, 1_001, 5_001, reverse=bool(index % 2)) for index in range(6)
    )
    return tuple(packets)


def _multiple_conversations() -> tuple[_TCPPacket, ...]:
    first = _complete_orderly_close()
    second = tuple(
        _TCPPacket(
            packet.flags,
            packet.sequence + 20_000,
            packet.acknowledgment + 20_000 if packet.acknowledgment else 0,
            packet.payload_length,
            packet.window,
            packet.reverse,
            source_port=49_153,
            destination_port=8443,
        )
        for packet in _complete_orderly_close()
    )
    return tuple(packet for pair in zip(first, second, strict=True) for packet in pair)


def _tuple_reuse() -> tuple[_TCPPacket, ...]:
    first = _complete_orderly_close()
    second = tuple(
        _TCPPacket(
            packet.flags,
            packet.sequence + 20_000,
            packet.acknowledgment + 20_000 if packet.acknowledgment else 0,
            packet.payload_length,
            packet.window,
            packet.reverse,
        )
        for packet in first
    )
    return first + second


def _icmp_packet(*, identifier: int) -> bytes:
    body = struct.pack("!BBHHH", 8, 0, 0, identifier, 1)
    checksum = _internet_checksum(body)
    icmp = body[:2] + struct.pack("!H", checksum) + body[4:]
    total_length = 20 + len(icmp)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        identifier,
        0x4000,
        64,
        1,
        0,
        _CLIENT_IP,
        _SERVER_IP,
    )
    checksum = _internet_checksum(ip_header)
    ip_header = ip_header[:10] + struct.pack("!H", checksum) + ip_header[12:]
    return _SERVER_MAC + _CLIENT_MAC + struct.pack("!H", 0x0800) + ip_header + icmp


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
