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

## Capture metadata inspection

The implemented `inspect` command reads basic capture metadata without
performing diagnostic analysis:

```bash
packet-investigator inspect path/to/capture.pcapng
packet-investigator inspect path/to/capture.pcap --json
```

It reports the resolved path, filename, extension-inferred format, byte size and
human-readable size, packet count, first and last packet timestamps, duration,
observed interface IDs when available, TShark version, and inspection status.
The JSON form emits the same core metadata without terminal formatting.

TShark remains the final validator of capture contents. The command does not
inspect payloads, reconstruct conversations, diagnose protocols, or make
ownership claims. Diagnostic packet analysis is not implemented.

## Capture-quality assessment

The implemented `quality` command assesses whether a PCAP or PCAPNG capture is
suitable evidence for further investigation:

```bash
packet-investigator quality path/to/capture.pcapng
packet-investigator quality path/to/capture.pcapng --json
```

The assessment considers capture-level evidence including:

- empty and very short captures;
- visibility of TCP SYN packets and possible midstream TCP conversations;
- frames whose captured length is shorter than their reported original length;
- checksum-warning caveats, including possible capture-host offload effects;
- observed capture interfaces; and
- explicit limits on bounded TCP flow tracking.

Findings keep observations separate from cautious interpretations, limitations,
and recommended next capture actions. The command does not provide root-cause
protocol diagnosis, TCP performance diagnosis, TLS certificate diagnosis,
SMB-specific diagnosis, or firewall-policy correlation.

### Terminal example

The terminal report is intentionally concise at the top, followed by supporting
metadata, statistics, findings, limitations, and recommendations:

```text
Packet Investigator — Capture Quality
Capture: synthetic-midstream.pcapng
Overall status: USABLE WITH LIMITATIONS
The capture is usable with explicit limitations.

Findings
MIDSTREAM_TCP_OBSERVED
Observation: Established TCP behavior appeared before an observed SYN for 1 tracked directional flows.
```

### JSON example

Use `--json` for machine-readable output with no Rich banner or surrounding
prose. This representative excerpt uses the actual schema and enum values:

```json
{
  "schema_version": "1.0",
  "status": "usable_with_limitations",
  "capture": {
    "filename": "synthetic-midstream.pcapng"
  }
}
```

The complete JSON document also contains the tool version, capture metadata,
findings, limitations, recommendations, statistics, and status summary. The
absolute capture path is omitted by default.

### Exit codes

Assessment statuses and operational failures share a small, established exit
code contract:

- `0` — the assessment status is `usable` or `usable_with_limitations`.
- `1` — the assessment status is `limited`, or an expected non-validation
  capture/TShark execution error occurred.
- `2` — the assessment status is `insufficient`, or capture-path validation
  failed.

An assessment-status exit means the capture was read and assessed. An error
message instead indicates that input validation or capture/TShark execution
prevented a completed assessment.

## Other CLI examples

```bash
packet-investigator version
packet-investigator info
python -m packet_investigator version
```

## Privacy guidance

Packet captures can contain credentials, personal data, internal addresses, and
sensitive payloads. Keep captures local, use only legally authorized data, and
never commit sensitive captures. Any capture intentionally committed must be
synthetic, sanitized, authorized, and free of credentials or sensitive payloads.

## Current project status

Phase 4 currently provides safe capture-file metadata inspection and
capture-quality assessment in addition to the package scaffold and development
tooling. Protocol diagnosis, conversation reconstruction, ownership guidance,
capture correlation, and HTML or other file-report generation are not
implemented yet.
