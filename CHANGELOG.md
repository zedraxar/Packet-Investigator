# Changelog

Notable changes to Packet Investigator are documented in this file.

## [0.5.0] - 2026-07-26

### Added

- Immutable TCP conversation evidence and report models.
- Streaming, bounded-memory TShark-backed TCP evidence collection.
- Deterministic TCP handshake, retry, role, reset, closure, flow-control, and
  delivery-indicator analysis.
- Rich terminal and structured JSON TCP reports.
- `packet-investigator tcp` with analysis-completeness statuses and
  deterministic exit codes.
- Privacy-safe capture-path handling for TCP reports and expected errors.
- Deterministic synthetic PCAPNG generation for TCP acceptance scenarios.
- Real-TShark end-to-end validation of collection, analysis, rendering, and
  command behavior.
- TCP usage, interpretation, privacy, and maintainer documentation.
- Distribution under the MIT License.

### Changed

- TShark boolean normalization accepts both textual `True`/`False` and numeric
  `1`/`0` field output.
- Capture-quality analysis remains the prerequisite context for TCP reports.

### Limitations

- Findings describe evidence visible at the capture point; they do not prove
  packet loss, determine root cause, assign technical ownership, inspect
  application payload content, or decrypt traffic.
- DNS, TLS, HTTP, SMB, and other protocol analyzers are not included.

### Testing and quality

- 462 deterministic unit and integration tests passed for the release
  candidate, including 40 Phase 5.6 tests using the real installed TShark.
- Generated captures use documentation addresses and are created only in
  temporary directories; no capture binaries are committed.

## [0.4.0] - 2026-07-26

### Added

- Capture-quality engineering specification.
- Immutable, typed capture-quality domain models.
- Streaming TShark-backed evidence collection with bounded flow state.
- Deterministic capture-quality analysis with evidence, limitations, and
  recommendations.
- Rich terminal and structured JSON capture-quality reporting.
- `packet-investigator quality` with deterministic status-based exit codes.
- End-to-end TShark-backed validation.
- Deterministic generation of small, non-sensitive synthetic PCAPNG fixtures.
- Capture-quality usage, privacy, output, and exit-code documentation.

### Testing and quality

- 201 passing unit and integration tests for the release candidate.
- Generated fixtures contain only synthetic packet data and are not committed
  as binary captures.
- TShark-backed integration tests skip with a precise reason when TShark is
  unavailable.
- Capture-path privacy and assessment exit-code behavior are documented.
