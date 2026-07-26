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
