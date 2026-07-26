# Synthetic capture fixtures

The integration suite generates three small PCAPNG files in pytest-managed
temporary directories. Binary captures are not stored in the repository.

- `synthetic-normal.pcapng` contains a synthetic TCP handshake followed by
  acknowledged data packets. It validates the ordinary end-to-end workflow.
- `synthetic-midstream.pcapng` contains TCP data and acknowledgements without a
  preceding SYN. It validates cautious midstream-capture reporting.
- `synthetic-empty.pcapng` contains valid PCAPNG section and interface blocks
  but no packet blocks. It validates insufficient-evidence handling.

The generator uses only Python's standard library. Ethernet, IPv4, and TCP
headers are assembled deterministically with locally administered MAC
addresses and IANA documentation address ranges. Payloads contain only the
single ASCII character `x`; there are no credentials, hostnames, or production
data.

All three captures are safe to regenerate by calling
`tests.fixtures.captures.write_capture_fixtures()` with a destination directory.

## Phase 5 TCP matrix

`write_tcp_capture_matrix()` generates 17 additional temporary scenarios:

- complete three-way handshake with orderly close;
- SYN retries;
- SYN/ACK retries;
- reset after an opening SYN;
- reset after establishment;
- bidirectional midstream traffic;
- incomplete FIN closure;
- zero-window observations;
- a TShark-recognized retransmission;
- one-way TCP payload;
- 32-bit sequence wraparound;
- simultaneous open;
- multiple independent conversations;
- an IPv6 conversation;
- four-tuple reuse across two closed connection epochs;
- a valid empty capture;
- a valid ICMP-only capture with no TCP conversations.

The suite independently asks real TShark to open every file and validate packet
counts and documentation endpoints before exercising the complete Packet
Investigator pipeline. The captures exist only under pytest temporary
directories. No PCAP or PCAPNG binary is committed.

Tuple/stream conflicts, malformed field rows, timestamp regressions, and
tracking-limit exhaustion remain focused normalized-row tests. Those behaviors
cannot be represented portably and honestly by a small packet file without
depending on unstable TShark internals or generating an impractically large
fixture.
