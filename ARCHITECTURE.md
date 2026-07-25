# Architecture

## Project philosophy

Packet Investigator is designed as a local, vendor-agnostic, evidence-driven
tool for offline PCAP and PCAPNG investigation. Deterministic observations
should be reproducible, interpretations should state their basis, and ownership
guidance should remain cautious when captures are incomplete.

## Evidence model

Every finding is expected to distinguish:

1. **Observed Facts** — measurements directly supported by packets or capture
   metadata.
2. **Technical Interpretation** — protocol-aware meaning derived from those
   observations.
3. **Ownership Guidance** — bounded guidance about the likely responsible
   domain.
4. **Limitations** — missing viewpoints, ambiguity, and capture constraints.
5. **Recommended Next Capture** — the observation point most likely to reduce
   uncertainty.

## Package responsibilities

- `parsers`: safely invoke TShark and normalize capture metadata; richer packet
  parsing remains planned.
- `models`: define typed capture metadata now and evidence, findings, and report
  structures in later phases.
- `analyzers`: run deterministic protocol and transport analyses.
- `correlation`: align events across multiple capture locations.
- `ownership`: derive cautiously worded confidence assessments.
- `reporting`: render terminal, JSON, and HTML output.
- `utils`: hold small shared utilities without domain ownership.
- `cli`: expose user workflows and output controls.

## Implemented capture inspection boundary

`CaptureMetadata` is the typed, immutable Pydantic result for basic inspection.
It stores the resolved path, file identity and size, capture format inferred
from the supported extension, packet count, UTC packet-boundary timestamps,
duration, observed interface IDs, TShark version, and status. It never stores
packet records or payloads. Empty captures consistently use a zero packet count
and absent timestamps and duration.

The reusable TShark wrapper in `parsers` owns executable discovery, path
validation, argument construction, process execution, timeout enforcement,
stderr sanitization, output parsing, and categorized failures. Isolating this
boundary keeps subprocess concerns out of the CLI and gives future callers one
safe, testable integration point. TShark is invoked directly with an argument
list, never through a shell, and name resolution is disabled.

Packet-field output is read line by line through a bounded queue. The parser
retains only the count, first and last timestamp, and unique interface IDs, so
memory does not grow with packet count. Stderr retention is bounded while its
pipe is continuously drained. A monotonic deadline covers field streaming and
process completion; timed-out or malformed executions are terminated and then
killed if they do not exit during a short grace period.

Current inspection is metadata-only. It supports `.pcap` and `.pcapng`, relies
on TShark for final content validation, and does not expose capture-level
metadata that is unavailable through the selected frame fields. Interface IDs
may therefore be absent, and no protocol diagnosis, conversation
reconstruction, ownership guidance, or packet-content analysis is performed.

## Operating modes

- **Single Capture** will assess one packet capture.
- **Endpoint Comparison** will compare client-side and server-side evidence.
- **Multi-point Correlation** will combine evidence from endpoints, firewalls,
  VPN gateways, proxies, servers, and other capture points.

All operating modes are planned; none is implemented in the initial scaffold.

## Planned deterministic analyzers

Focused analyzers are planned for TCP, DNS, TLS, MTU behavior, fragmentation,
retransmissions, and session termination. Analyzers should emit observations
and bounded interpretations rather than opaque scores or unsupported diagnoses.

## Multi-capture correlation

Correlation will account for clock offsets, address translation, encapsulation,
capture loss, and differing visibility. It should match flows and events using
explicit evidence and preserve uncertainty when observations cannot be aligned.

## Ownership confidence model

Ownership guidance will use controlled confidence levels:

- Demonstrated
- Strongly Favored
- Moderately Favored
- Weakly Suggested
- Not Demonstrated
- Inconclusive

Each level must be tied to supporting and contradictory evidence. A confidence
label identifies evidentiary strength, not organizational blame.

## Capture quality validation

Before interpreting behavior, the application should evaluate truncation,
dropped packets, timestamp quality, capture duration, interface placement,
offload artifacts, directionality, filtering, and whether critical handshake or
termination traffic is missing.

## Security and privacy principles

Analysis should remain local by default. Captures and generated reports may
contain sensitive data and must not be uploaded or shared automatically.
Parsers must treat capture content and external tool output as untrusted input.
Logging and reports should minimize payload exposure, and private captures must
remain excluded from version control.
