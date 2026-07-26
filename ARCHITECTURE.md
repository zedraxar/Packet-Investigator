# Architecture

## Project philosophy

Packet Investigator is a local, vendor-agnostic, evidence-driven tool for
offline PCAP and PCAPNG investigation. Observations remain separate from
interpretations, limitations remain visible, and recommendations never exceed
the evidence available at the capture point.

The implemented evidence sequence is:

```text
Observed evidence
        ↓
Deterministic interpretation
        ↓
Evidence strength
        ↓
Limitations
        ↓
Recommended next action
```

Statuses describe analysis completeness or capture suitability. They are not
network-health scores and do not assign technical ownership.

## Implemented v0.5.0 pipeline

```text
capture file
    ↓
capture inspection
    ↓
capture-quality streaming evidence collection
    ↓
capture-quality deterministic analysis
    ↓
TCP streaming evidence collection
    ↓
TCP deterministic analysis
    ↓
immutable report models
    ↓
Rich terminal or JSON rendering
    ↓
CLI orchestration and exit-code mapping
```

Capture quality and TCP use separate bounded TShark field passes. This preserves
the stable Phase 4 contract and keeps each field projection focused. Sharing a
future normalized stream is permissible only if existing public results remain
backward compatible.

## Package responsibilities

- `models` defines strict, immutable capture, quality, TCP evidence, and report
  contracts. Models contain no subprocess, parser, analyzer, renderer, or CLI
  behavior.
- `parsers.tshark` owns capture-path validation, executable discovery,
  capability queries, argument-list process execution, bounded streaming,
  timeout enforcement, stderr sanitization, cancellation, and cleanup.
- `parsers.capture_quality` and `parsers.tcp_conversations` normalize TShark
  fields and retain bounded evidence. They do not create findings or statuses.
- `analyzers.capture_quality` and `analyzers.tcp_conversations` are
  deterministic transformations from immutable evidence into immutable
  assessments. They perform no file, subprocess, network, name-resolution,
  clock, locale, or terminal access.
- `renderers` presents existing assessments as Rich terminal output or
  deterministic JSON. It does not recalculate findings, roles, severity,
  recommendations, or status.
- `utils` holds small presentation-neutral helpers.
- `cli` validates user workflows, calls public layers in order, handles typed
  expected failures, selects one renderer, and maps final statuses to exit
  codes.

No generic protocol framework, plugin system, live-capture layer, payload
model, or cross-protocol abstraction is implemented.

## Safe TShark boundary

Capture paths and contents are untrusted input. TShark is discovered explicitly
and invoked with an argument list, never through a shell. Commands disable name
resolution, read captures without modification, request only required fields,
and never select a live interface.

The shared runner drains stdout and stderr concurrently. A bounded queue feeds
stdout rows to streaming consumers, stderr retention is capped, and one
monotonic deadline covers streaming and process completion. Timeout,
cancellation, and parser failure terminate the child and escalate to kill after
a short grace period.

Expected failures are represented by typed exceptions for validation,
executable discovery, timeout, unreadable captures, nonzero execution, and
malformed output. Normal CLI use does not expose a traceback or raw packet row.

## Bounded evidence collection

Capture inspection retains packet counts, boundary timestamps, and interface
identifiers rather than packet objects.

Capture quality retains aggregate counters and at most 50,000 normalized
directional flow identities. Reaching the cap stops new flow registration
without evicting existing state and creates a visible limitation.

TCP collection retains bounded state for at most 50,000 conversations. It
verifies TShark stream identifiers against canonical bidirectional tuples,
handles tuple epochs conservatively, and never exposes `tcp.stream` as a public
identity. Findings retain at most eight representative frame numbers and parser
warnings retain at most 100 summaries. Exact counters continue independently
of representative sampling.

Collectors retain TCP payload length only. Payload bytes never enter production
evidence, models, reports, logs, or analysis.

## Evidence and analysis boundaries

TCP evidence distinguishes:

1. raw frame, IP, and TCP header facts;
2. TShark-derived sequence-analysis indicators; and
3. Packet Investigator interpretations.

The TCP analyzer applies deterministic sequence arithmetic, handshake and
closure matching, role-evidence precedence, finding suppression, limitation
aggregation, recommendation deduplication, and status reduction. TShark
indicators remain labeled as derived and are not converted into proof of wire
loss or causal ownership.

Equal immutable inputs produce equal assessments. Conversation, finding,
limitation, recommendation, evidence-frame, and JSON ordering is stable.

## Presentation and privacy

Rich renderers use bounded summaries and explicit omitted counts so terminal
output remains usable for large reports. JSON always serializes the complete
tracked assessment according to schema `1.0`.

Capture-quality and TCP reports omit the absolute source path by default.
Renderers cannot reconstruct a path that is absent from a model. TCP expected
errors sanitize resolved paths. Endpoint addresses and ports remain necessary,
sensitive report metadata and should be handled with the same care as captures.

Packet Investigator performs no upload, external communication, payload
extraction, traffic decryption, or automatic sharing.

## Status and exit semantics

Capture-quality statuses describe suitability:

- `usable`
- `usable_with_limitations`
- `limited`
- `insufficient`

TCP conversation statuses describe analytical completeness:

- `complete`
- `complete_with_findings`
- `partial`
- `limited`
- `insufficient`

TCP report statuses are `analyzed`, `analyzed_with_findings`, `limited`, and
`insufficient`. Findings such as resets or retransmission indicators do not
make successful analysis fail. The CLI returns zero for completed TCP analysis
with or without findings, one for limited analysis or expected execution
failure, and two for insufficient evidence or input validation failure.

## Validation architecture

Unit tests isolate model validation, field parsing, process handling, bounded
collection, analyzer rules, rendering, and CLI orchestration. Phase 5.6 adds 17
deterministic PCAPNG scenarios generated with Python's standard library into
pytest temporary directories.

Real TShark independently validates each generated file before the complete
inspection → quality → TCP → report → CLI pipeline is exercised. The matrix
covers IPv4, IPv6, handshake and closure evidence, retries, resets, midstream
traffic, flow control, retransmission indicators, sequence wraparound, tuple
reuse, multiple conversations, empty capture, and non-TCP capture behavior. No
binary capture fixture is committed.

## Current boundaries

v0.5.0 does not implement root-cause or ownership determination, application
payload inspection, decryption, live capture, capture comparison, multi-point
correlation, HTML/file reports, or DNS, TLS, HTTP, SMB, UDP, QUIC, and other
protocol analyzers. These remain possible future work and must preserve the
same evidence, privacy, bounded-memory, and deterministic-contract principles.
