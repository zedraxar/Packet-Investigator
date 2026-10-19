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

## Operating modes

The current single-capture commands inspect metadata, assess capture quality,
and analyze TCP conversations. These broader modes remain planned:

- **Endpoint Comparison** — compare client-side and server-side captures.
- **Multi-point Correlation** — correlate captures from firewalls, VPN
  gateways, proxies, servers, and other observation points.

## Installation

Python 3.12 or newer and TShark are required. Confirm TShark is available:

```bash
tshark --version
```

Packet Investigator is not currently published to a package index. Install a
locally built wheel:

```bash
python -m pip install dist/packet_investigator-0.5.0-py3-none-any.whl
```

Or install directly from an authorized local repository checkout:

```bash
python -m pip install .
```

Verify the installed command:

```bash
packet-investigator --version
packet-investigator info
packet-investigator --help
```

For a capture-to-report walkthrough using the implemented `inspect`, `quality`,
`tcp`, and `dns` commands, see the
[first local PCAP investigation](docs/local-cli-first-run.md). It explains
capture limitations, report privacy, and evidence-based interpretation.

Typical local-capture commands are:

```bash
packet-investigator inspect path/to/capture.pcapng
packet-investigator quality path/to/capture.pcapng
packet-investigator tcp path/to/capture.pcapng
packet-investigator tcp path/to/capture.pcapng --json
```

## Development environment

For contributor work, install the checkout in editable mode:

```bash
source .venv/bin/activate
python -m pip install --editable ".[dev]"
```

The current development environment targets Python 3.14 while retaining Python
3.12 as the declared minimum.

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

TShark remains the final validator of capture contents. The `inspect` command
reports metadata only and ends its terminal output with guidance to the
implemented analysis commands. Assess capture suitability first, then choose
the protocol evidence relevant to your investigation:

```bash
packet-investigator quality path/to/capture.pcapng
packet-investigator tcp path/to/capture.pcapng
packet-investigator dns path/to/capture.pcapng
```

These commands report capture-bounded evidence and limitations; they do not
establish root cause or technical ownership. `inspect --json` continues to emit
only metadata, without next-step guidance.

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

## TCP conversation analysis

The implemented `tcp` command performs deterministic, offline TCP conversation
analysis using the evidence visible in a PCAP or PCAPNG capture:

```bash
packet-investigator tcp path/to/capture.pcapng
packet-investigator tcp path/to/capture.pcapng --json
```

Python 3.12 or newer and TShark on `PATH` are required. Packet Investigator
first inspects and assesses capture quality, then asks TShark for a minimal set
of TCP header fields and analysis indicators. It does not use live interfaces
or network access.

The report can describe:

- canonical IPv4 and IPv6 TCP conversations and observed direction;
- visible handshake, retry, reset, and FIN-close evidence;
- packet, frame-byte, and TCP payload-length totals in each direction;
- TShark-derived retransmission, duplicate-ACK, out-of-order, flow-control,
  and keepalive indicators when those fields are available;
- observed timing intervals and their limitations; and
- evidence-linked recommendations for collecting or correlating better data.

Representative finding codes include `TCP_SYN_RETRY_OBSERVED`,
`TCP_MIDSTREAM_CONVERSATION`, `TCP_RESET_AFTER_ESTABLISHMENT`,
`TCP_RETRANSMISSION_INDICATORS_OBSERVED`, and
`TCP_ZERO_WINDOW_OBSERVED`.

### Terminal example

```text
Packet Investigator — TCP Conversation Analysis
Capture: reset-after-establishment.pcapng
Overall status: ANALYZED WITH FINDINGS
1 TCP conversations were analyzed with findings or partial visibility.

Conversation summary
tcp-000001  192.0.2.10:49152 ↔ 198.51.100.20:443
Handshake: COMPLETE
Closure: RESET
Status: COMPLETE WITH FINDINGS

TCP_RESET_AFTER_ESTABLISHMENT
Observed: A TCP reset was observed from endpoint B.

Scope: TCP evidence only. This report does not establish root cause or
technical ownership.
```

Spacing and wrapping vary with terminal width; the facts and ordering do not.
Long reports show bounded terminal summaries with explicit omitted counts. JSON
always contains every tracked conversation.

### JSON example

`--json` writes only the complete schema `1.0` document to standard output.
This shortened example shows representative fields:

```json
{
  "capture": {
    "filename": "complete-orderly-close.pcapng"
  },
  "conversations": [
    {
      "identity": {
        "conversation_id": "tcp-000001"
      },
      "status": "complete"
    }
  ],
  "schema_version": "1.0",
  "status": "analyzed"
}
```

Equal reports serialize deterministically. The absolute capture path is omitted
from terminal and JSON output. Endpoint addresses and ports remain sensitive
capture metadata, so generated reports should be handled with the same care as
captures.

### Statuses and exit codes

Conversation statuses describe analytical completeness, not connection health:

- `complete`
- `complete_with_findings`
- `partial`
- `limited`
- `insufficient`

Report statuses are `analyzed`, `analyzed_with_findings`, `limited`, and
`insufficient`. Exit codes are:

- `0` — analysis completed, with or without TCP findings;
- `1` — analysis completed with material limitations, or an expected
  non-validation capture/TShark execution error occurred;
- `2` — TCP evidence was insufficient, or input validation failed.

A reset, retry, zero window, or retransmission indicator is evidence in a
successful report and does not by itself make command execution fail.

### Interpretation limits

The analyzer reports only evidence present at the capture point. It does not:

- prove traffic was absent outside the capture;
- determine root cause or assign firewall, network, client, server, endpoint,
  application, ISP, or team responsibility;
- prove packet loss from a retransmission-like TShark indicator;
- inspect or retain application payload content;
- decrypt traffic; or
- replace endpoint, firewall, routing, or application telemetry.

Conclusions may be limited by capture position, truncation, capture drops,
missing direction, a midstream start, timestamp quality, bounded conversation
tracking, or unavailable optional TShark fields. Compare independent telemetry
and captures from other authorized observation points before drawing causal
conclusions.

## Other CLI examples

```bash
packet-investigator version
packet-investigator info
python -m packet_investigator version
```

## DNS transaction analysis

Analyze visible classic DNS transactions with `packet-investigator dns CAPTURE_PATH`
(or add `--json` for structured output). Findings distinguish observed query,
response, retry, truncation, and response-code evidence from possible causes.
For a practical interpretation and privacy checklist, see the
[DNS troubleshooting quickstart](docs/dns-troubleshooting-quickstart.md).

## Privacy guidance

Packet captures can contain credentials, personal data, internal addresses, and
sensitive payloads. Keep captures local, use only legally authorized data, and
never commit sensitive captures. Any capture intentionally committed must be
synthetic, sanitized, authorized, and free of credentials or sensitive payloads.

## Current project status

Packet Investigator currently provides capture-file metadata inspection,
capture-quality assessment, deterministic TCP conversation analysis, and
classic DNS transaction analysis. Root-cause diagnosis, technical ownership
assignment, capture correlation, other application-protocol analyzers, and
HTML or other file-report generation are not implemented.

## License

Packet Investigator is distributed under the MIT License. See
[LICENSE](LICENSE) for the full terms.
