# Changelog

Notable changes to Packet Investigator are documented in this file.

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
