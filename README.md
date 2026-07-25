# Packet Investigator

Packet Investigator is a local, vendor-agnostic application planned for offline
PCAP and PCAPNG analysis with TShark and Python. It is intended to correlate
network evidence, explain what the packets demonstrate, and identify useful
next capture points without overstating responsibility.

## Evidence-driven philosophy

Reports will keep packet observations separate from interpretation. Each
finding will follow this evidence model:

1. Observed Facts
2. Technical Interpretation
3. Ownership Guidance
4. Limitations
5. Recommended Next Capture

Ownership statements must never be stronger than the available packet evidence.

## Planned operating modes

These modes are planned and are not yet implemented:

- **Single Capture** — analyze one capture and describe supported findings.
- **Endpoint Comparison** — compare client-side and server-side captures.
- **Multi-point Correlation** — correlate captures from firewalls, VPN
  gateways, proxies, servers, and other observation points.

## Installation

Python 3.12 or newer and TShark are required. From the repository root:

```bash
source .venv/bin/activate
python -m pip install --editable ".[dev]"
```

The current development environment targets Python 3.14 while retaining a
Python 3.12 minimum wherever practical.

## Development environment

Run the project checks with:

```bash
ruff check .
ruff format --check .
mypy src
pytest
```

See [docs/development.md](docs/development.md) for the complete workflow.

## CLI examples

```bash
packet-investigator version
packet-investigator info
python -m packet_investigator version
```

## Privacy guidance

Packet captures can contain credentials, personal data, internal addresses, and
sensitive payloads. Keep captures local, use only legally authorized data, and
do not commit private captures. Any capture intentionally committed must be
synthetic, sanitized, authorized, and free of credentials or sensitive payloads.

## Current project status

Phase 2 provides the package scaffold, CLI shell, documentation, and development
tooling. Packet parsing, analysis, correlation, and report generation are not
implemented yet.
