# Packet Investigator Roadmap

Packet Investigator advances through small, reviewable milestones while
preserving these principles:

- evidence before conclusions;
- observation separated from interpretation and recommendation;
- deterministic, typed, testable behavior;
- bounded memory where practical;
- safe handling of untrusted capture files;
- local processing with no automatic upload;
- no unsupported root-cause or ownership claims; and
- accurate documentation of implemented and planned behavior.

## Current status

### Phase 1 — Development environment ✅

- Python virtual environment and editable workflow
- Git repository
- Ruff, strict mypy, and pytest
- TShark development dependency

### Phase 2 — Professional project scaffold ✅

- Modern `src/` package layout
- Setuptools/`pyproject.toml` packaging
- Typer CLI and Rich terminal output
- Package version and information commands
- Architecture and development documentation
- Private-capture and generated-artifact exclusions

### Phase 3 — Capture metadata inspection ✅

Implemented:

```bash
packet-investigator inspect CAPTURE_PATH
packet-investigator inspect CAPTURE_PATH --json
```

The command validates PCAP/PCAPNG input, streams basic frame fields through
TShark, and reports packet counts, capture boundaries, duration, interfaces,
file metadata, and TShark version without retaining packet records.

### Phase 4 — Capture Quality Assessment ✅

Implemented:

```bash
packet-investigator quality CAPTURE_PATH
packet-investigator quality CAPTURE_PATH --json
```

Completed capabilities include immutable quality models, bounded streaming
collection, deterministic quality findings, explicit limitations and
recommendations, Rich and JSON rendering, path-private reports, status-based
exit codes, generated synthetic captures, and real-TShark validation.

The historical implementation contract is
[docs/specs/phase-4-capture-quality.md](docs/specs/phase-4-capture-quality.md).

### Phase 5 — TCP Conversation Analysis ✅

Implemented:

```bash
packet-investigator tcp CAPTURE_PATH
packet-investigator tcp CAPTURE_PATH --json
```

Completed milestones:

- Phase 5.0 — approved TCP engineering specification
- Phase 5.1 — immutable TCP evidence and report models
- Phase 5.2 — bounded streaming TShark collector
- Phase 5.3 — deterministic TCP analyzer
- Phase 5.4/5.5 — Rich/JSON rendering and CLI orchestration
- Phase 5.6 — generated real-TShark acceptance matrix and user documentation

The analyzer reports captured handshake, role, retry, reset, closure,
directional, flow-control, delivery-indicator, and timing evidence with
conservative wording. It does not prove packet loss, diagnose root cause,
inspect payload content, decrypt traffic, or assign ownership.

The historical implementation contract is
[docs/specs/phase-5-tcp-conversation-analysis.md](docs/specs/phase-5-tcp-conversation-analysis.md).

## Current milestone — Phase 6 DNS acceptance verification

Packet Investigator v0.5.0 is the last documented release baseline. The
working tree now includes classic DNS transaction models, collection,
analysis, Rich/JSON rendering, CLI integration, and focused tests. The
Phase 6.0 specification is a historical implementation contract.

DNS transaction analysis code is present on this branch, but generated real-TShark DNS acceptance is not yet demonstrated. See [the DNS implementation audit](docs/dns-implementation-audit.md) for evidence and remaining gaps. After the
specification is approved, Phase 6.1 is the next milestone and is limited to
immutable DNS transaction domain models:
[docs/specs/phase-6-dns-transaction-analysis.md](docs/specs/phase-6-dns-transaction-analysis.md).

## Future work

Future phases require separate engineering specifications and approval. Possible
directions include:

- additional protocol-specific analyzers;
- normalized shared packet evidence where multiple implemented consumers
  justify it;
- endpoint capture comparison;
- multi-point correlation;
- deterministic privacy/redaction controls;
- additional report formats; and
- broader cross-version Python and TShark validation.

These are possibilities, not implemented capabilities or release commitments.
No future phase may weaken current capture inspection, quality, TCP, privacy,
streaming, schema, or CLI contracts without explicit compatibility review.

## Historical roadmap note

Earlier roadmap drafts proposed a generic normalized packet model, conversation
builder, finding engine, and TCP analyzer as separate later phases. Phase 5
instead delivered a focused, bounded TCP subsystem using the approved hybrid
conversation-identity design. Those earlier milestone numbers are superseded;
their useful concepts may be reconsidered only through a new specification.
