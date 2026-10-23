"""Small deterministic two-point PCAPNG evidence, generated only in temp dirs."""

import struct
from pathlib import Path

from tests.fixtures.captures import (
    _complete_orderly_close,
    _icmp_packet,
    _normal_packets,
    _packets_ipv6,
    _pcapng_block,
)


def _write(
    path: Path, frames: tuple[tuple[int, bytes], ...], *, truncate: bool = False
) -> None:
    blocks = [
        _pcapng_block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)),
        _pcapng_block(1, struct.pack("<HHI", 1, 0, 65535)),
    ]
    for index, (time, packet) in enumerate(frames):
        captured = len(packet) - (1 if truncate and index == 4 else 0)
        body = struct.pack(
            "<IIIII", 0, time >> 32, time & 0xFFFFFFFF, captured, len(packet)
        )
        blocks.append(_pcapng_block(6, body + packet[:captured]))
    path.write_bytes(b"".join(blocks))


def write_comparison_pair(directory: Path, scenario: str) -> tuple[Path, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    packets = _normal_packets()
    if scenario == "ipv6":
        packets = _packets_ipv6(_complete_orderly_close())
    if scenario == "duplicates":
        packets = (packets[4],) * 10
    if scenario == "no_tcp":
        packets = tuple(_icmp_packet(identifier=i) for i in range(10))
    if scenario == "empty":
        packets = ()
    left = tuple(
        (1_700_000_000_000_000 + i * 250_000, packet)
        for i, packet in enumerate(packets)
    )
    right = left
    if scenario == "one_sided":
        right = left[:4] + left[5:]
    if scenario in {"offset", "nonoverlap"}:
        right = tuple((time + 10_000_000, packet) for time, packet in right)
    a, b = directory / "left.pcapng", directory / "right.pcapng"
    _write(a, left)
    _write(b, right, truncate=scenario == "truncated")
    return a, b
