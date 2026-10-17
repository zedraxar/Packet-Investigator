"""Deterministic synthetic DNS captures for real-TShark acceptance tests.

All packets use documentation-only addresses and names. No capture bytes are
stored in Git; each test generates its own temporary PCAPNG files.
"""

from __future__ import annotations

import struct
from pathlib import Path

from tests.fixtures.captures import (
    _CLIENT_IP,
    _CLIENT_IPV6,
    _CLIENT_MAC,
    _SERVER_IP,
    _SERVER_IPV6,
    _SERVER_MAC,
    _icmp_packet,
    _internet_checksum,
    _tcp_packet,
    _write_pcapng,
)


def _name(value: str) -> bytes:
    return b"".join(bytes((len(label),)) + label.encode("ascii") for label in value.split(".")) + b"\x00"


def _dns(*, response: bool = False, rcode: int = 0, truncated: bool = False,
         qtype: int = 1, name: str = "service.example", dns_id: int = 0x1234,
         answer: bool = True) -> bytes:
    flags = (0x8180 if response else 0x0100) | rcode
    if truncated:
        flags |= 0x0200
    count = int(response and answer and rcode == 0 and not truncated)
    question = _name(name) + struct.pack("!HH", qtype, 1)
    header = struct.pack("!HHHHHH", dns_id, flags, 1, count, 0, 0)
    if not count:
        return header + question
    value = (bytes((198, 51, 100, 25)) if qtype == 1 else
             bytes.fromhex("20010db8000000000000000000000025"))
    resource = b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 300, len(value)) + value
    return header + question + resource


def _udp(payload: bytes, *, response: bool = False, ipv6: bool = False) -> bytes:
    src_port, dst_port = (53, 49152) if response else (49152, 53)
    src_mac, dst_mac = (_SERVER_MAC, _CLIENT_MAC) if response else (_CLIENT_MAC, _SERVER_MAC)
    udp_len = 8 + len(payload)
    header = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)
    if ipv6:
        src, dst = ((_SERVER_IPV6, _CLIENT_IPV6) if response else
                    (_CLIENT_IPV6, _SERVER_IPV6))
        pseudo = src + dst + struct.pack("!I", udp_len) + b"\x00\x00\x00\x11"
        checksum = _internet_checksum(pseudo + header + payload)
        header = header[:6] + struct.pack("!H", checksum or 0xffff)
        ip = struct.pack("!IHBB16s16s", 6 << 28, udp_len, 17, 64, src, dst)
        return dst_mac + src_mac + b"\x86\xdd" + ip + header + payload

    src, dst = ((_SERVER_IP, _CLIENT_IP) if response else
                (_CLIENT_IP, _SERVER_IP))
    pseudo = src + dst + struct.pack("!BBH", 0, 17, udp_len)
    checksum = _internet_checksum(pseudo + header + payload)
    header = header[:6] + struct.pack("!H", checksum or 0xffff)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + udp_len, 1,
                     0x4000, 64, 17, 0, src, dst)
    ip = ip[:10] + struct.pack("!H", _internet_checksum(ip)) + ip[12:]
    return dst_mac + src_mac + b"\x08\x00" + ip + header + payload


def _query(**kwargs: object) -> bytes:
    return _udp(_dns(**kwargs))


def _reply(**kwargs: object) -> bytes:
    return _udp(_dns(response=True, **kwargs), response=True)


def _tcp_exchange() -> tuple[bytes, ...]:
    """TCP handshake and DNS length-prefixed request/answer on port 53."""
    query = _dns()
    reply = _dns(response=True)
    request_payload = struct.pack("!H", len(query)) + query
    response_payload = struct.pack("!H", len(reply)) + reply
    return (
        _tcp_packet(flags=0x02, sequence=1000, destination_port=53),
        _tcp_packet(flags=0x12, sequence=5000, acknowledgment=1001,
                    reverse=True, source_port=49152, destination_port=53),
        _tcp_packet(flags=0x10, sequence=1001, acknowledgment=5001,
                    destination_port=53),
        _tcp_packet(flags=0x18, sequence=1001, acknowledgment=5001,
                    destination_port=53, payload=request_payload),
        _tcp_packet(flags=0x18, sequence=5001,
                    acknowledgment=1001 + len(request_payload),
                    reverse=True, source_port=49152, destination_port=53,
                    payload=response_payload),
    )


def write_dns_capture_matrix(directory: Path) -> dict[str, Path]:
    """Generate the 14 approved classic-DNS wire scenarios in a temp folder."""
    directory.mkdir(parents=True, exist_ok=True)
    scenarios: dict[str, tuple[bytes, ...]] = {
        "successful_a_udp": (_query(), _reply()),
        "successful_aaaa_ipv6": (
            _udp(_dns(qtype=28), ipv6=True),
            _udp(_dns(response=True, qtype=28), response=True, ipv6=True),
        ),
        "nxdomain": (_query(), _reply(rcode=3, answer=False)),
        "servfail": (_query(), _reply(rcode=2, answer=False)),
        "refused": (_query(), _reply(rcode=5, answer=False)),
        "retry_then_answer": (_query(), _query(), _reply()),
        "unanswered_query": (_query(),),
        "response_only": (_reply(),),
        "truncated_udp": (_query(), _reply(truncated=True, answer=False)),
        "udp_tc_then_tcp": (
            _query(), _reply(truncated=True, answer=False), *_tcp_exchange(),
        ),
        "multiple_responses": (_query(), _reply(), _reply()),
        "multiple_transactions": (
            _query(name="one.example", dns_id=0x1001),
            _query(name="two.example", dns_id=0x1002),
            _reply(name="two.example", dns_id=0x1002),
            _reply(name="one.example", dns_id=0x1001),
        ),
        "empty": (),
        "no_dns": (_icmp_packet(identifier=1), _icmp_packet(identifier=2)),
    }
    result: dict[str, Path] = {}
    for name, packets in scenarios.items():
        path = directory / f"dns-{name.replace('_', '-')}.pcapng"
        _write_pcapng(path, packets)
        result[name] = path
    return result
