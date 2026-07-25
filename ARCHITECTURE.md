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

## Planned package responsibilities

- `parsers`: invoke TShark and normalize capture data.
- `models`: define typed evidence, findings, captures, and report structures.
- `analyzers`: run deterministic protocol and transport analyses.
- `correlation`: align events across multiple capture locations.
- `ownership`: derive cautiously worded confidence assessments.
- `reporting`: render terminal, JSON, and HTML output.
- `utils`: hold small shared utilities without domain ownership.
- `cli`: expose user workflows and output controls.

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
