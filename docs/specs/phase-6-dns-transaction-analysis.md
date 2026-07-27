# Packet Investigator Phase 6 DNS Transaction Analysis

**Status:** Engineering Specification — Not Yet Implemented
**Phase:** 6.0 — Discovery and specification
**Proposed capability:** DNS transaction analysis
**Approval gate:** Production implementation begins only after this specification
is reviewed and approved.

## 1. Background

Packet Investigator v0.5.0 provides capture inspection, capture-quality
assessment, and TCP conversation analysis. Its implementation separates safe,
streaming TShark collection from pure deterministic analysis, immutable public
models, Rich and JSON rendering, and CLI orchestration. It retains bounded
state, never retains payload bytes, protects absolute capture paths by default,
and reports only conclusions supported at the capture point.

The largest remaining single-capture investigation gap is application-facing
transaction evidence. TCP can show connection establishment, termination,
flow-control, and delivery indicators, but it cannot show whether a name lookup
was answered, how it was answered, or whether visible application progress was
blocked before a later connection could begin.

This specification proposes a narrow DNS transaction analyzer. It is a second
concrete analyzer, not the beginning of a generic protocol framework.

## 2. Discovery and candidate comparison

### 2.1 Current strengths and remaining gap

The v0.5.0 product does these things well:

- validates untrusted capture paths and invokes TShark with argument lists;
- streams bounded field output and handles timeouts, cancellation, stderr, and
  typed operational errors;
- distinguishes raw observations, TShark-derived indicators, Packet
  Investigator derivations, findings, limitations, and recommendations;
- represents reports as strict immutable Pydantic models;
- gives capture-quality context to TCP conclusions;
- provides deterministic ordering, status reduction, JSON, and concise Rich
  output;
- validates synthetic captures through the real installed TShark; and
- avoids payload retention, causal overclaiming, and ownership assignment.

The major gap is that a completed TCP analysis still cannot describe a common
pre-connection dependency: DNS query/response behavior. Investigators must
manually determine whether a query was visible, whether a matching response was
visible, which response code was returned, whether retry or truncation evidence
appeared, and what the capture cannot establish.

### 2.2 Evaluation criteria

Candidates were compared for troubleshooting value, architectural fit, stable
TShark evidence, usefulness with encrypted applications, deterministic and
bounded analysis, privacy, overclaiming risk, fixture feasibility, CLI/schema
impact, dependencies, complexity, value as a second reference analyzer, and
future workflow value.

Scores use 1 (weak) through 5 (strong). Complexity is scored inversely: 5 is
the smallest, safest scope.

| Criterion | DNS transactions | TLS handshakes | Capture-level summary |
|---|---:|---:|---:|
| Common troubleshooting value | 5 | 5 | 4 |
| Architectural fit | 5 | 4 | 3 |
| Stable TShark evidence | 5 | 3 | 5 |
| Useful with encrypted applications | 4 | 5 | 4 |
| Deterministic bounded analysis | 5 | 4 | 3 |
| Privacy/manageable exposure | 3 | 3 | 4 |
| Low overclaiming risk | 4 | 3 | 3 |
| Deterministic fixture feasibility | 5 | 3 | 5 |
| Real-TShark testability | 5 | 3 | 5 |
| Small CLI/schema impact | 4 | 4 | 3 |
| No new dependencies | 5 | 5 | 5 |
| Appropriately sized complexity | 4 | 3 | 2 |
| Second reference-analyzer value | 5 | 4 | 1 |
| Future correlation value | 5 | 4 | 5 |
| **Total** | **64** | **53** | **52** |

The scores express a planning judgment, not a product-health metric.

### 2.3 Candidate one — DNS transaction analysis

**User problem solved.** Determine what classic DNS request/response behavior
is visible before or during an incident: matched responses, response codes,
unanswered visible queries, retries, truncation, and observed timing.

**Available evidence.** Frame number and timestamp; IPv4/IPv6 endpoints;
UDP/TCP ports and TCP stream where present; DNS transaction ID; query/response
flag; opcode; response code; truncation and recursion flags; query name, type,
and class; response record types, names, TTLs, and address/CNAME values where
requested; and TShark-derived response linkage, response time,
retransmission, and unsolicited-response indicators. Phase 6 intentionally
uses only the subset defined in section 8.

**Unavailable evidence.** Queries or responses outside the capture, resolver
cache state, endpoint resolver policy, encrypted DNS contents, authoritative
server state outside captured messages, name ownership, application intent,
and root cause.

**Public behavior.** A flat `dns CAPTURE_PATH [--json]` command would emit a
capture-level DNS report containing deterministically ordered transaction
assessments, exact message and result-code counts, findings, limitations, and
recommendations.

**Probable findings.** Query retry indicators, no matching response observed,
response codes observed, truncated response, unsolicited response indicator,
ambiguous matching, and multiple visible responses.

**Limitations.** A missing response is capture-bounded; transaction IDs are
not globally unique; DNS over HTTPS/TLS/QUIC is not decoded as classic DNS;
capture truncation, midstream starts, multiple observation points, malformed
messages, and tracking caps weaken conclusions.

**Complexity.** Medium. Matching must account for transport, endpoints,
transaction IDs, query keys, direction, reuse, and TShark linkage without
claiming completeness.

**Testing.** Model, normalized-row, collector, analyzer decision-table,
renderer, JSON, CLI, subprocess, capacity, and real-TShark tests.

**Fixture feasibility.** High. Ethernet, IPv4/IPv6, UDP/TCP, and DNS wire
messages can be written using the existing standard-library PCAPNG generator.

**Architectural impact.** Adds DNS-specific model, collector, analyzer, and
renderer modules and one future CLI command. Existing layers need no generic
abstraction or TCP change.

**Likely status model.** Transaction statuses `complete`,
`complete_with_findings`, `partial`, `limited`, and `insufficient`; report
statuses `analyzed`, `analyzed_with_findings`, `limited`, and `insufficient`.

**Risks.** Sensitive query names; multi-valued TShark fields; transaction-ID
reuse; DNS-over-TCP framing; TShark-derived linkage differences; false causal
interpretation of missing replies or error codes.

**Choose because.** It addresses a frequent dependency, works alongside
encrypted applications when classic DNS remains visible, has stable fields,
and is independently releasable.

**Approved privacy boundary.** The owner permits the sensitive investigative
metadata defined in section 22 to appear by default. Any future redaction
behavior requires a separate specification.

### 2.4 Candidate two — TLS handshake/session analysis

**User problem solved.** Describe visible TLS handshakes, negotiated parameters,
alerts, and certificate metadata without decrypting application content.

**Available evidence.** Record content types and versions, visible handshake
message types, legacy/offered version fields, server name when present,
cipher-suite identifiers, visible certificate bytes/metadata if explicitly
parsed, and alerts. TCP context can qualify visibility.

**Unavailable evidence.** Encrypted application data, secrets, endpoint trust
store decisions, complete TLS 1.3 handshake contents, hidden ECH names, traffic
not captured, and causal ownership.

**Public behavior.** A `tls CAPTURE_PATH [--json]` report of visible handshake
epochs, selected parameters when unambiguous, alert observations, limitations,
and recommendations.

**Probable findings.** Incomplete visible handshake, TLS alert observed,
multiple ClientHello attempts, negotiated-version evidence, and certificate
visibility limitations.

**Major limitations.** TLS 1.3 encrypts later handshake messages; ECH reduces
name visibility; resumed and zero-RTT sessions complicate state; record and
handshake fields can be multi-valued; TCP reassembly and dissector preferences
matter. A capture cannot prove certificate validation outcome from handshake
bytes alone.

**Complexity.** Medium-high. Version negotiation, epochs, resumption, alerts,
TCP reassembly, and TLS-version compatibility require careful modeling.

**Testing and fixtures.** Normalized rows are feasible, but portable real-TShark
fixtures require deterministic TLS records and certificates. Standard-library
generation is possible but materially more complex and version-sensitive than
DNS.

**Architectural impact.** A concrete analyzer fits existing boundaries. It may
need deeper integration with TCP conversation identity, increasing coupling.

**Likely status model.** Handshake completeness plus report-level analyzed,
findings, limited, and insufficient states.

**Risks.** Overstating negotiation or trust, sensitive SNI/certificate
identities, field drift, and shrinking plaintext evidence.

**Choose because.** It directly helps encrypted-traffic investigations and is
high value for connection setup.

**Defer because.** DNS offers more stable evidence, simpler deterministic
fixtures, lower semantic risk, and a cleaner second-analyzer boundary. TLS
should follow a dedicated compatibility study.

### 2.5 Candidate three — capture-level investigation summary

**User problem solved.** Give one concise view of capture quality and TCP
findings, with prioritized limitations and next actions.

**Available evidence.** Existing immutable capture-quality and TCP reports.
Future protocol reports could be added later.

**Unavailable evidence.** Any new protocol fact, cross-capture evidence, issue
context, endpoint telemetry, or reliable root cause.

**Public behavior.** An orchestration command or extension that runs existing
analyzers and reduces their statuses, findings, limitations, and
recommendations into a stable case summary.

**Probable findings.** Preferably none invented at the summary layer; it would
reference existing findings and correlations such as limited capture quality
qualifying TCP analysis.

**Major limitations.** With only quality and TCP, orchestration risks adding a
new abstraction and schema before enough concrete consumers exist. A
prioritized summary can look causal even when it merely co-locates evidence.

**Complexity.** Medium-high because cross-report identity, precedence,
deduplication, schema evolution, partial analyzer failure, and exit-code
semantics must be decided.

**Testing and fixtures.** Existing captures provide strong validation, but
correlation semantics would mostly be synthetic combinations of reports.

**Architectural impact.** Introduces multi-analyzer orchestration and perhaps a
generic report envelope, which the current architecture explicitly avoids.

**Likely CLI/status model.** A future `analyze` or `summary` command with
per-analyzer results and an orchestration completeness status.

**Risks.** Premature generic architecture, duplicated language, misleading
correlations, long runtime from repeated TShark passes, and an unstable schema.

**Choose because.** It improves usability and becomes compelling after several
concrete analyzers exist.

**Defer because.** A second protocol analyzer supplies more new investigative
evidence and provides the concrete experience needed to design orchestration.

### 2.6 Other candidates

HTTP metadata has high value but is unavailable for most HTTPS traffic and
would expose paths, hosts, methods, and other sensitive application metadata.
SMB is specialized and stateful, with greater dialect, encryption, and fixture
complexity. Batch processing and report export improve workflow but add no new
investigative evidence. Multi-analyzer orchestration and evidence correlation
should wait for at least two concrete analyzers. None is selected for Phase 6.

## 3. Recommendation

Phase 6 should implement **classic DNS transaction analysis**.

It is the most valuable appropriately sized next milestone because it answers a
common pre-connection investigation question using stable, locally verified
TShark fields. It remains useful when later application traffic is encrypted,
provided the relevant DNS exchange itself is visible and decoded. It fits the
v0.5.0 collector/analyzer/model/renderer/CLI separation, supports bounded
streaming state and deterministic synthetic captures, and creates a second
reference analyzer without a generic protocol framework.

The milestone intentionally excludes encrypted DNS, DNSSEC validation,
authoritative-chain reconstruction, cache inference, ownership, root cause,
payload retention, and cross-analyzer correlation. TLS should be reconsidered
after a field/version and fixture study. A capture-level summary should wait
until DNS supplies a second concrete analyzer whose contracts can inform
orchestration.

## 4. Problem statement

Given one authorized PCAP or PCAPNG capture, report what classic unicast DNS
transactions and result evidence were visible, which visible requests and
responses can be matched conservatively, what limitations prevent stronger
conclusions, and which next investigative actions are supported.

The analyzer must never equate “not observed” with “did not occur,” label a
resolver or network as faulty from a single capture, or interpret a DNS result
code as proof of the underlying cause.

## 5. Goals

- Collect a minimal, explicit DNS field projection through TShark.
- Support classic unicast DNS decoded over UDP and TCP, IPv4 and IPv6.
- Match request and response observations conservatively and deterministically.
- Report exact counts independently of bounded representative frames.
- Report visible result codes, retries, truncation, unmatched messages, and
  timing facts without causal thresholds.
- Use strict immutable DNS-specific schema `1.0` models.
- Keep memory and output deterministic under explicit capacity bounds.
- Provide Rich and JSON contracts and a future flat `dns` command.
- Validate stable wire behavior with generated real-TShark captures.
- Preserve all v0.5.0 safety, privacy, error, and exit-code principles.

## 6. Non-goals and boundary

### 6.1 In scope

- DNS messages dissected by TShark as classic unicast DNS over UDP or TCP;
- standard query/response transactions with opcode `QUERY` (numeric zero);
- DNS transaction ID, query name/type/class, response code, selected flags,
  endpoints, transport, timestamps, frames, and bounded answer summaries;
- deterministic matching and timing calculation;
- exact message, transaction, response-code, retry-indicator, truncation, and
  unmatched-observation counts;
- findings, limitations, recommendations, statuses, Rich, JSON, CLI contract,
  and layered tests.

### 6.2 Out of scope

- DNS over HTTPS, TLS, or QUIC; traffic decryption; mDNS, LLMNR, NBNS, and
  other name-resolution protocols;
- dynamic-update, zone-transfer, notify, and inverse-query analysis;
- DNSSEC cryptographic or trust-chain validation;
- EDNS option interpretation, ECS, cookies, padding, TSIG, and extended DNS
  errors in the initial release;
- resolver cache inference, recursive/iterative chain reconstruction, or
  authoritative-server discovery;
- endpoint ownership attribution, root-cause determination, application intent,
  SLA thresholds, or a “DNS health” score;
- raw DNS message, raw RDATA, certificate, or application payload retention;
- live capture, packet modification, remediation automation, cloud/external
  upload, SIEM integration, GUI/web interface, or production captures;
- changes to `inspect`, `quality`, or `tcp` behavior;
- a generic protocol, transaction, finding, report, or orchestration framework;
- capture comparison, batch processing, case summaries, TLS/HTTP/SMB analysis,
  and all Phase 7 capabilities.

## 7. Terminology and evidence rules

### 7.1 Raw evidence

Raw evidence is a directly normalized TShark field or packet/frame observation:
frame number and timestamp, interface ID, IP addresses, transport ports and
protocol, TCP stream when applicable, DNS transaction ID, flags, opcode,
response code, query key, and selected answer metadata.

TShark field output is not retained as a row. A parsed DNS name or selected
answer value is protocol metadata, not retained raw payload; it remains
sensitive and is governed by section 18.

### 7.2 TShark-derived evidence

`dns.response_in`, `dns.response_to`, `dns.time`, `dns.retransmission`,
`dns.retransmit_request`, `dns.retransmit_response`, and `dns.unsolicited` are
TShark-derived indicators. When used, provenance must remain
`tshark_derived`; they are not silently converted into raw facts.

### 7.3 Packet Investigator-derived evidence

Derived evidence includes canonical endpoint ordering, request/response
direction, query-key normalization, bounded transaction matching, elapsed time
from captured timestamps, duplicate grouping, count aggregation, and role
labels based on observed request direction. These derivations are deterministic
and carry `packet_investigator_derived` provenance.

“Requester” and “responder” describe observed DNS message direction. They do
not prove operating-system client/server roles or ownership.

### 7.4 Findings, limitations, and recommendations

A finding is a conservative classification supported by raw or explicitly
labeled derived evidence. A limitation states why stronger conclusions cannot
be made. A recommendation is an evidence-appropriate next investigative step,
not automated remediation.

The implementation must prohibit:

- interpreting absence from one capture as proof of global absence;
- assigning client, server, resolver, authoritative server, firewall, or
  network fault without direct evidence;
- claiming packet loss solely from retransmission indicators;
- claiming application failure from transport or DNS symptoms alone;
- treating a partial, multi-interface, truncated, or midstream capture as a
  complete observation;
- treating `NXDOMAIN`, `SERVFAIL`, `REFUSED`, or another response code as proof
  of its external cause;
- exposing raw payload, raw rows, credentials, or absolute capture paths; and
- inferring encrypted DNS merely because no classic DNS was observed.

## 8. Architecture and collector contract

### 8.1 Placement

Likely production files for later milestones are:

```text
src/packet_investigator/
├── models/dns_transactions.py
├── parsers/dns_transactions.py
├── analyzers/dns_transactions.py
├── renderers/dns_transactions.py
└── cli.py
```

Tests mirror each concrete module. No common protocol base class is added.
Existing `parsers.tshark` process infrastructure is reused. Capture inspection
and quality assessment run before DNS collection, as they do for TCP.

### 8.2 Public collector signature

Proposed API:

```python
def collect_dns_transaction_evidence(
    capture_path: Path,
    *,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    executable: str = "tshark",
) -> DNSCollectionResult: ...
```

`capture_path` is validated through the shared TShark boundary. The result is
immutable normalized evidence, not a report. `executable` supports deterministic
tests and controlled local discovery; it is not initially a CLI option.

### 8.3 Required TShark projection

The collector requests tab-separated fields with occurrence aggregation
disabled or explicitly normalized, no name resolution, and a display filter
limited to classic DNS. It must account for multiple field occurrences rather
than relying on an ambiguous comma separator.

Required fields:

- `frame.number`
- `frame.time_epoch`
- `frame.interface_id` (optional per row)
- `ip.src`, `ip.dst`, `ipv6.src`, `ipv6.dst`
- `udp.srcport`, `udp.dstport`, `tcp.srcport`, `tcp.dstport`
- `tcp.stream` for DNS over TCP
- `dns.id`
- `dns.flags.response`
- `dns.flags.opcode`
- `dns.flags.rcode`
- `dns.flags.truncated`
- `dns.flags.recdesired`
- `dns.flags.recavail`
- `dns.qry.name`
- `dns.qry.type`
- `dns.qry.class`

Optional compatibility fields, enabled only when advertised by
`tshark -G fields`:

- `dns.response_in`
- `dns.response_to`
- `dns.time`
- `dns.retransmission`
- `dns.retransmit_request`
- `dns.retransmit_response`
- `dns.unsolicited`
- `dns.resp.name`
- `dns.resp.type`
- `dns.resp.ttl`
- `dns.a`
- `dns.aaaa`
- `dns.cname`

The installed TShark 4.6.6 registry was inspected during Phase 6.0 and
advertised the core fields plus `dns.response_in`, `dns.time`,
`dns.retransmission`, `dns.retransmit_request`, and `dns.unsolicited`.
Implementation must repeat capability discovery and must not assume every
optional field is present on every supported installation.

Required-field absence is an atomic `TsharkOutputError` or a more specific
future typed compatibility error. Optional-field absence disables only the
dependent rule and produces a stable limitation.

### 8.4 Streaming and state bounds

- TShark stdout and stderr use the existing bounded concurrent draining,
  monotonic timeout, cancellation, terminate/kill, and sanitized-error contract.
- Rows are consumed once. Raw rows and packet objects are never retained.
- Exact global counters continue for every successfully normalized DNS row.
- At most 50,000 transaction candidates are retained. Once reached, existing
  candidates are not evicted, no new candidates are registered, stateless
  counters continue, and `DNS_TRANSACTION_TRACKING_LIMIT_REACHED` is reported.
- At most eight representative frame numbers are retained per evidence item.
- At most 100 bounded parser-warning summaries may be retained if a warning
  class is approved; malformed required data otherwise fails atomically.
- At most 16 answer summaries are retained per response and at most 100,000
  answer summaries report-wide. Exact answer-record counts continue after
  sampling caps where TShark output permits an exact count.
- Query names are length-limited after valid DNS normalization; over-limit or
  invalid text fails the affected row atomically rather than entering an
  unbounded model.

### 8.5 Row normalization and optional fields

Frame number, finite epoch timestamp, one source/destination IP family, one
transport, valid ports, DNS ID, response flag, opcode, and response code are
required for an in-scope row. A standard query key requires exactly one
normalizable question name/type/class tuple.

Empty optional fields become `None` or empty tuples according to the model.
Boolean fields accept the textual/numeric forms already normalized by v0.5.0.
Unknown numeric response, query-type, or class values remain numeric evidence;
human-readable labels are additive presentation metadata and never replace
numeric keys.

Multiple DNS messages dissected from one frame must become distinct message
observations if TShark can expose their occurrences unambiguously. If the
selected field format cannot align occurrences safely, the collector must fail
or report a compatibility limitation; it must not zip unequal lists and invent
a message.

Malformed required values raise typed output errors with row numbers and no raw
row, name, address, or absolute path. A row outside the specified QUERY opcode
scope increments an out-of-scope message count and is not analyzed as a standard
transaction.

### 8.6 Timestamp behavior

Epoch text is parsed with `Decimal`, converted to aware UTC datetimes at the
model boundary, and used in capture order. Negative transaction intervals,
non-finite values, or conversion overflow do not produce timing. They add a
timestamp limitation while preserving non-timing evidence when safe.

No latency threshold is defined. The report may state exact observed intervals
but may not call them slow or acceptable without an approved, context-specific
policy.

### 8.7 Identifier and matching strategy

Public transaction IDs are report-local `dns-000001`, `dns-000002`, and so on,
assigned after final deterministic ordering. `dns.id` is evidence, never a
public unique identity.

Matching proceeds in this precedence:

1. Valid TShark response linkage whose referenced frames are present, direction
   is reversed, transport context is compatible, DNS IDs agree, and query keys
   do not conflict.
2. Exact Packet Investigator key match within the capture: transport, TCP
   stream when applicable, unordered endpoint pair, DNS ID, opcode, normalized
   query name, query type, and query class, with a response in the reverse
   direction after the request.
3. No match when multiple candidates remain. Ambiguity is retained and
   reported; capture order alone must not select among conflicting candidates.

For UDP, endpoint addresses and ports are part of the matching context. For
TCP, `tcp.stream` is verified against endpoints and is internal only. Missing
TCP stream data falls back conservatively to endpoint context and creates a
limitation.

An ASCII DNS name is lowercased and a single terminal root dot is removed for
matching while the first observed presentation is retained for display.
Internationalized labels remain the decoded ASCII form supplied by TShark; no
network lookup or Unicode transformation occurs.

A later identical request can be a duplicate/retry candidate only when query
key, direction, transport context, and DNS ID agree. TShark retransmission
fields remain separately counted. The analyzer reports “retry indicators,” not
packet loss or application retry intent.

Multiple compatible responses are retained as multiple response observations.
The first unambiguous response supplies primary timing; later responses are
evidence, not silently discarded. DNS ID reuse after a completed transaction
may begin a new candidate when its query frame is later and matching is
unambiguous. No wall-clock reuse heuristic is introduced.

## 9. Domain model

All public models use `ConfigDict(frozen=True, strict=True)`, tuples rather than
mutable sequences, deterministic string enums, aware datetimes, finite numeric
values, and validated machine codes. Internal maps may use `MappingProxyType`;
JSON serializers emit ordinary objects with sorted keys where mappings exist.

### 9.1 Enums

`DNSTransport`: `udp`, `tcp`.

`DNSMessageDirection`: `requester_to_responder`,
`responder_to_requester`, `unknown`.

`DNSMatchBasis`: `tshark_linkage`, `exact_query_key`, `unmatched`,
`ambiguous`.

`DNSEvidenceProvenance`: `raw_header`, `tshark_derived`,
`packet_investigator_derived`.

`DNSFindingCategory`: `transaction`, `response`, `retry`, `truncation`,
`visibility`.

`DNSFindingSeverity`: `informational`, `warning`.

`DNSTransactionStatus`: `complete`, `complete_with_findings`, `partial`,
`limited`, `insufficient`.

`DNSAnalysisStatus`: `analyzed`, `analyzed_with_findings`, `limited`,
`insufficient`.

Statuses describe completeness and notable evidence, not service health.

### 9.2 Evidence models

`DNSEndpoint`:

- `ip_version: Literal[4, 6]` — required;
- `address: IPv4Address | IPv6Address` — required, canonical serialization;
- `port: int` in 0–65535 — required.

`DNSQueryKey`:

- `name: str` — required normalized matching name and sensitive metadata;
- `display_name: str` — required first observed bounded spelling;
- `query_type: int` in 0–65535 — required;
- `query_class: int` in 0–65535 — required.

`DNSMessageEvidence`:

- `frame_number: positive int` — required;
- `timestamp: aware datetime` — required;
- `interface_id: str | None` — optional;
- `source`, `destination: DNSEndpoint` — required;
- `transport: DNSTransport` — required;
- `tcp_stream: non-negative int | None` — optional, internal evidence omitted
  from public JSON unless compatibility review requires it;
- `transaction_id: int` in 0–65535 — required;
- `is_response: bool`, `opcode: int`, `response_code: int`,
  `truncated: bool`, `recursion_desired: bool`,
  `recursion_available: bool` — required;
- `query: DNSQueryKey | None` — optional only when the question cannot be
  safely represented or the message is out of standard-query scope;
- `answer_record_count: non-negative int` — required;
- `answers: tuple[DNSAnswerSummary, ...]` — required, bounded;
- `tshark_response_frame`, `tshark_request_frame: positive int | None` —
  optional;
- `tshark_response_time_seconds: non-negative finite float | None` — optional;
- TShark retry/unsolicited indicator booleans — required with capability flags
  separately recorded.

`DNSAnswerSummary`:

- `record_type: int` — required;
- `owner_name: str | None` — optional sensitive metadata;
- `ttl_seconds: non-negative int | None` — optional;
- `value: str | None` — optional only for bounded A, AAAA, and CNAME values;
- `representative_frame: positive int` — required;
- `provenance: DNSEvidenceProvenance` — required.

No raw RDATA is retained. Unknown record types contribute counts without a
serialized value.

`DNSTransactionIdentity`:

- `transaction_id: str` matching `dns-[0-9]{6}` — required report-local ID;
- `requester`, `responder: DNSEndpoint` — required when direction is observed;
- `transport: DNSTransport` — required;
- `dns_id: int` — required raw protocol identifier;
- `query: DNSQueryKey` — required;
- `match_basis: DNSMatchBasis` — required.

`DNSTransactionEvidence`:

- identity;
- request and response counts;
- first request/response frames and timestamps;
- observed response codes as sorted `(code, count)` values;
- exact retry-indicator counts by provenance;
- truncated-response count;
- unsolicited-response-indicator count;
- elapsed-to-first-response seconds and provenance when available;
- sorted unique interface IDs;
- bounded representative frames;
- `tracking_complete: bool`;
- `answer_collection_complete: bool`.

### 9.3 Finding, limitation, and recommendation models

`DNSTransactionFinding`:

- stable `code`;
- category and severity;
- factual `observation`;
- optional conservative `interpretation`;
- provenance tuple;
- exact `observation_count`;
- bounded `representative_frames`;
- immutable deterministic evidence mapping;
- finding-local limitation codes;
- recommendation codes.

`DNSLimitation`:

- stable `code`;
- description;
- affected capability tuple;
- optional transaction ID;
- representative frames;

`DNSRecommendation`:

- stable `code`;
- positive priority;
- action;
- rationale;
- triggering finding/limitation codes.

Observation counts are exact even when representative frames are sampled.

### 9.4 Report models

`DNSTransactionAssessment` contains identity, status, evidence, findings,
limitations, and recommendations.

`DNSAnalysisStatistics` contains at least:

- `rows_processed`;
- `dns_messages`;
- `standard_query_messages`;
- `query_messages`;
- `response_messages`;
- `tracked_transactions`;
- `transaction_tracking_limit`;
- `transaction_tracking_complete`;
- `matched_transactions`;
- `unmatched_query_messages`;
- `unmatched_response_messages`;
- `ambiguous_message_matches`;
- `response_code_counts` as sorted code/count entries;
- `retry_indicator_messages`;
- `truncated_response_messages`;
- `answer_records_observed`;
- `answer_records_retained`;
- `out_of_scope_dns_messages`;
- advertised optional capability codes.

`DNSAnalysisReport`:

- `schema_version: Literal["1.0"]`;
- `tool_version`;
- privacy-safe `capture: CaptureQualityCapture`;
- `capture_quality_status`;
- sorted capture-quality limitation codes;
- `status: DNSAnalysisStatus`;
- `status_summary`;
- `transactions: tuple[DNSTransactionAssessment, ...]`;
- report-level findings, limitations, and recommendations;
- statistics.

Every field is required unless explicitly optional above. Optional scalar
evidence serializes as JSON `null`; tuples always serialize as arrays, including
empty arrays. The capture `path` remains absent by construction. Enum values
serialize as lowercase strings. Datetimes serialize in UTC ISO 8601. Equal
reports serialize byte-for-byte identically.

Schema `1.x` may add optional, unambiguous fields and new machine codes.
Renaming fields, changing meanings, removing enum values, or changing null and
ordering behavior requires a schema-major change.

## 10. Analyzer contract

### 10.1 Public signature and purity

```python
def analyze_dns_transactions(
    collection: DNSCollectionResult,
    *,
    capture: CaptureQualityCapture,
    capture_quality_status: CaptureQualityStatus,
    capture_quality_limitation_codes: tuple[str, ...],
) -> DNSAnalysisReport: ...
```

The analyzer performs no file, subprocess, network, DNS lookup, clock, locale,
environment, terminal, or logging I/O. Equal immutable inputs produce equal
reports.

### 10.2 Ordering

Messages are interpreted in ascending `(frame_number, occurrence_index)`.
Transactions are ordered by first observed frame, canonical requester endpoint,
responder endpoint, transport, DNS ID, and query key before report-local IDs
are assigned.

Within each transaction:

1. findings use the fixed precedence in section 11;
2. limitations use catalog order then code and frame;
3. recommendations use priority then code;
4. representative frames are ascending unique values;
5. response codes and answer summaries use numeric/type/name/value order.

Report-level collections use the same stable catalog ordering. Input set or map
iteration order must not affect output.

### 10.3 Exact counts and representative frames

All message/finding counters are exact for rows successfully processed,
independent of the eight-frame representative cap. Frames are selected as the
earliest unique frames supporting the classification. If evidence exists in
both directions, the earliest four from each direction are preferred before
filling remaining slots in ascending order.

### 10.4 Ambiguity and insufficient evidence

Ambiguous matches remain unmatched and create
`DNS_TRANSACTION_MATCH_AMBIGUOUS`; they are never assigned by nearest time.
Missing question data, incompatible linkage, negative timing, capacity bounds,
and capture-quality limitations are explicit limitations.

No decoded in-scope DNS messages produces report status `insufficient`; it does
not prove DNS was unused or encrypted. Responses without visible queries and
queries without visible responses produce partial evidence, not synthetic
transactions marked complete. If all potentially analyzable state is lost to a
capacity or compatibility bound, status is `limited`.

### 10.5 Aggregation

Transaction findings remain attached to transactions. Report-level findings
aggregate only when a stable code occurs in more than one transaction or has
capture-wide meaning. Aggregation records exact affected-transaction and
observation counts and never discards transaction evidence. Recommendations
are deduplicated by code and keep their highest priority.

## 11. Finding catalog and precedence

Initial finding precedence is:

1. `DNS_TRANSACTION_MATCH_AMBIGUOUS`
2. `DNS_RESPONSE_WITHOUT_QUERY_OBSERVED`
3. `DNS_QUERY_WITHOUT_RESPONSE_OBSERVED`
4. `DNS_QUERY_RETRY_INDICATORS_OBSERVED`
5. `DNS_MULTIPLE_RESPONSES_OBSERVED`
6. `DNS_TRUNCATED_RESPONSE_OBSERVED`
7. `DNS_RESPONSE_CODE_OBSERVED`
8. `DNS_UNSOLICITED_RESPONSE_INDICATOR_OBSERVED`

### `DNS_QUERY_WITHOUT_RESPONSE_OBSERVED`

Raw observation: one or more in-scope query messages had no unambiguous
matching response in the capture. Interpretation: the capture does not show a
matching response. It must not say the responder failed or no response existed.
Severity warning; status partial unless a stronger limitation applies.

### `DNS_RESPONSE_WITHOUT_QUERY_OBSERVED`

Raw observation: one or more response messages had no unambiguous matching
query in the capture. This may reflect an earlier query, another observation
point, missing packets, or ambiguity. Severity informational; status partial.

### `DNS_TRANSACTION_MATCH_AMBIGUOUS`

Derived observation: multiple compatible candidates prevented a deterministic
match. No response timing or completion conclusion is produced for the
ambiguous messages. Severity warning; status limited for affected candidates.

### `DNS_QUERY_RETRY_INDICATORS_OBSERVED`

Observation: repeated matching query observations or TShark retry indicators
were present. Evidence distinguishes raw repeated-query grouping from
TShark-derived indicators. It does not prove packet loss, resolver timeout, or
application retry intent. Severity warning; a matched transaction may be
`complete_with_findings`.

### `DNS_MULTIPLE_RESPONSES_OBSERVED`

Observation: more than one compatible response was visible for a query
candidate. No duplicate, malicious, or incorrect classification follows
without stronger evidence. Severity informational.

### `DNS_TRUNCATED_RESPONSE_OBSERVED`

Raw observation: the DNS TC flag was set on a visible response. Interpretation:
the response indicates truncation and a requester may retry using another
transport; the capture alone does not prove that fallback occurred. Severity
warning.

### `DNS_RESPONSE_CODE_OBSERVED`

Raw observation: a nonzero DNS response code was present. Evidence includes the
numeric code and, when known locally, a standard label. Separate instances may
be consolidated by code. Wording is “response code observed,” never “lookup
failed because.” Severity warning for initial nonzero codes. `NOERROR` is normal
statistics and does not create this finding.

An empty `NOERROR` answer is not an error finding in Phase 6; negative-answer
interpretation requires authority-section and record-type semantics deferred
from this scope.

### `DNS_UNSOLICITED_RESPONSE_INDICATOR_OBSERVED`

TShark-derived observation: TShark marked a response unsolicited. It remains
an indicator and does not prove spoofing or malicious behavior. Severity
informational.

## 12. Decision table and statuses

| Evidence condition | Required finding | Transaction status | Report effect |
|---|---|---|---|
| Query plus one unambiguous response, code 0, no notable evidence | None | `complete` | `analyzed` if all else complete |
| Matched response has nonzero response code | `DNS_RESPONSE_CODE_OBSERVED` | `complete_with_findings` | `analyzed_with_findings` |
| Matched response has TC set | `DNS_TRUNCATED_RESPONSE_OBSERVED` | `complete_with_findings` | `analyzed_with_findings` |
| Repeated query/retry indicator, later response matched | retry finding | `complete_with_findings` | `analyzed_with_findings` |
| Query has no unambiguous response | no-response-observed finding | `partial` | at least `analyzed_with_findings`; may be `limited` by breadth |
| Response has no visible query | response-without-query finding | `partial` | at least `analyzed_with_findings` |
| Multiple candidates prevent matching | ambiguity finding | `limited` | `limited` |
| Tracking cap reached but retained transactions analyzable | cap limitation | retained statuses unchanged | `limited` |
| Required field incompatible | no report | n/a | typed operational error |
| No in-scope decoded DNS messages | none | no transactions | `insufficient` |
| Only out-of-scope DNS opcodes | scope limitation | no transactions | `insufficient` |
| Capture quality is insufficient | capture limitation | as evidence permits | no stronger than `limited`, or `insufficient` with no DNS |

Report reduction order is `insufficient`, `limited`,
`analyzed_with_findings`, then `analyzed`, applied by explicit rules rather
than enum order:

- no analyzable in-scope DNS evidence → `insufficient`;
- incomplete tracking, material matching ambiguity, or materially insufficient
  capture context → `limited`;
- otherwise any finding or partial transaction →
  `analyzed_with_findings`;
- otherwise at least one complete transaction → `analyzed`.

Findings do not make successful analysis an operational failure.

## 13. Limitations

Initial stable limitation codes:

- `DNS_NOT_OBSERVED_LIMITATION` — no classic DNS was decoded; use cannot be
  inferred.
- `DNS_CAPTURE_POINT_LIMITATION` — evidence applies only at this capture point.
- `DNS_CAPTURE_QUALITY_LIMITATION` — named capture-quality conditions qualify
  conclusions.
- `DNS_ENCRYPTED_NAME_RESOLUTION_NOT_VISIBLE` — this analyzer cannot inspect
  encrypted DNS contents; it does not assert encrypted DNS was present.
- `DNS_TRANSACTION_TRACKING_LIMIT_REACHED` — new state stopped at the cap.
- `DNS_ANSWER_RETENTION_LIMIT_REACHED` — answer summaries were sampled.
- `DNS_OPTIONAL_FIELDS_UNAVAILABLE` — named optional TShark-derived rules were
  disabled.
- `DNS_QUESTION_UNAVAILABLE` — a safe standard query key could not be formed.
- `DNS_MATCH_AMBIGUOUS_LIMITATION` — transaction linkage was not unique.
- `DNS_TIMESTAMP_LIMITATION` — timing could not be safely calculated.
- `DNS_TCP_STREAM_UNAVAILABLE` — TCP matching used a weaker endpoint context.
- `DNS_MULTIPLE_INTERFACES_LIMITATION` — interface IDs do not establish capture
  topology or packet independence.
- `DNS_UNSUPPORTED_OPCODE_LIMITATION` — messages were counted but not analyzed
  as standard transactions.

Descriptions must state consequences, not suspected causes.

## 14. Recommendations

Initial stable recommendations:

- `CAPTURE_BEFORE_DNS_QUERY` — begin capture before reproducing the lookup and
  continue through the dependent application outcome.
- `CAPTURE_BOTH_DIRECTIONS` — collect both directions at an authorized point
  near the requester when unmatched evidence matters.
- `COMPARE_RESOLVER_TELEMETRY` — compare visible IDs, names, types, codes, and
  times with authorized requester/resolver logs.
- `CORRELATE_CAPTURE_POINTS` — capture at another authorized observation point
  to distinguish visibility from behavior.
- `REVIEW_DNS_RESPONSE_CODE_CONTEXT` — inspect resolver and authoritative data
  appropriate to the observed code without assuming its cause.
- `VERIFY_TRUNCATION_FALLBACK` — look for a later authorized TCP or other
  resolver event after a TC response.
- `NARROW_CAPTURE_OR_FILTER` — use an issue-focused capture when transaction
  tracking capacity was reached.
- `VALIDATE_WITH_SUPPORTED_TSHARK` — compare field capability and decoding when
  optional or required compatibility is limited.

Mappings are deterministic. No recommendation changes configuration,
restarts services, edits DNS records, uploads data, or assigns an owner.

## 15. Renderer contract

### 15.1 Rich

The terminal report contains:

1. title: `Packet Investigator — DNS Transaction Analysis`;
2. filename-only capture metadata and capture-quality status;
3. overall DNS status and concise summary;
4. bounded statistics including message, transaction, matched, unmatched,
   retry, truncation, and response-code counts;
5. a bounded transaction summary table with ID, requester/responder, transport,
   query name/type, response code summary, observed interval, and status;
6. bounded finding details with observed facts, provenance, exact count, and
   representative frames;
7. limitations;
8. prioritized recommendations; and
9. scope language stating that the report covers visible classic DNS only and
   does not determine root cause or ownership.

Terminal output shows at most 100 transaction rows, 50 detailed findings, 50
limitations, and 25 recommendations, with exact omitted counts. JSON contains
all retained assessments.

Query names, IP addresses, ports, and selected answers are sensitive capture
metadata. Rich may display the query names, requester/responder endpoint
addresses and ports, and bounded A, AAAA, and CNAME answer summaries because
they are core to the explicitly requested DNS report and are approved in
section 22. These observed endpoints provide client/server investigative
context without proving endpoint roles, ownership, or fault. The absolute
capture path is never displayed.

### 15.2 JSON

`--json` emits exactly one complete schema `1.0` document followed by a newline
to stdout. It emits no Rich markup, banner, progress, warning, or explanatory
text. Keys use Pydantic model order, mappings use deterministic key order, and
arrays follow section 10 ordering. The source path is absent. Operational
errors leave stdout empty and write one concise sanitized message to stderr.
The JSON contract includes approved query names, requester/responder endpoint
addresses and ports, and bounded A, AAAA, and CNAME summaries by default. It
does not include arbitrary RDATA, unrelated packet contents, or raw payload.

Human-readable wording may improve within schema `1.x`; schema names, enum
values, codes, numeric evidence, null behavior, and ordering are stable.

## 16. CLI and exit codes

Proposed command, not implemented in Phase 6.0:

```bash
packet-investigator dns CAPTURE_PATH
packet-investigator dns CAPTURE_PATH --json
```

Argument:

- `CAPTURE_PATH`: readable `.pcap` or `.pcapng`, using existing validation.

Option:

- `--json`: emit only machine-readable JSON.

No timeout, capacity, include-path, redaction, protocol-port, or heuristic
option is added initially. Help text:

> Analyze deterministic classic DNS transaction evidence in a capture.

Execution order is inspection → capture-quality collection/analysis → DNS
collection → DNS analysis → one renderer → exit mapping.

Exit codes remain consistent with TCP:

| Condition | Output | Exit |
|---|---|---:|
| `analyzed` | report on stdout | 0 |
| `analyzed_with_findings` | report on stdout | 0 |
| `limited` | report on stdout | 1 |
| `insufficient`, including no matching classic DNS | report on stdout | 2 |
| Missing/invalid path or unsupported extension | sanitized stderr only | 2 |
| TShark missing, timeout, unreadable capture, nonzero execution, malformed output, required-field incompatibility | sanitized stderr only | 1 |
| Keyboard interrupt | no traceback; child cleaned up | conventional 130 |

A visible error response, retry indicator, or truncated response is a completed
analysis with findings and exits zero unless an independent completeness rule
makes the report limited. CLI validation errors remain Typer exit two.

## 17. Deterministic generated scenarios

All real-TShark captures are generated in pytest temporary directories with the
Python standard library. They use locally administered MAC addresses,
`192.0.2.0/24`, `198.51.100.0/24`, `2001:db8::/32`, fixed timestamps, explicit
UDP/TCP checksums, and synthetic non-sensitive names under `.example`. No root,
live interface, external networking, Scapy, DNS library, production capture,
or committed binary is permitted.

The initial matrix has **14 generated real-TShark scenarios**:

| Scenario | Synthetic sequence | Expected evidence/finding | Limitation | Status / exit |
|---|---|---|---|---|
| Successful A/UDP | query then matching NOERROR A response | one complete transaction; A summary | capture-point | `analyzed` / 0 |
| Successful AAAA/IPv6 | IPv6 query then matching AAAA response | complete IPv6 transaction | capture-point | `analyzed` / 0 |
| NXDOMAIN | query then RCODE 3 response | response-code finding | cause unknown | `analyzed_with_findings` / 0 |
| SERVFAIL | query then RCODE 2 response | response-code finding | cause unknown | `analyzed_with_findings` / 0 |
| REFUSED | query then RCODE 5 response | response-code finding | policy/owner unknown | `analyzed_with_findings` / 0 |
| Query retry then answer | identical query twice, one answer | exact repeat/retry evidence | loss/intent unknown | `analyzed_with_findings` / 0 |
| Unanswered query | query only | query-without-response | capture-bounded absence | `analyzed_with_findings` / 0 |
| Response only | response only | response-without-query | capture may be midstream | `analyzed_with_findings` / 0 |
| Truncated UDP response | query then response with TC | truncation finding | fallback not established | `analyzed_with_findings` / 0 |
| UDP TC then TCP success | UDP query/TC response, TCP DNS query/response | two transport transactions; TC finding | cross-transport causality not claimed | `analyzed_with_findings` / 0 |
| Multiple responses | query then two compatible responses | multiple-response finding | duplication cause unknown | `analyzed_with_findings` / 0 |
| Multiple transactions | interleaved distinct names/IDs | stable ordering and exact totals | capture-point | `analyzed` / 0 |
| Empty capture | no frames | no DNS evidence | not-observed limitation | `insufficient` / 2 |
| Non-DNS capture | deterministic ICMP/TCP frames | zero DNS messages | DNS use cannot be inferred | `insufficient` / 2 |

Each generated file is first independently validated with real TShark, then
exercised through collector, analyzer, renderer, and CLI. Assertions target
stable fields and codes, not incidental TShark text or platform formatting.

Normalized-row unit tests, not capture fixtures, cover:

- ambiguous transaction-ID reuse;
- conflicting or unavailable TShark linkage;
- multiple occurrences that cannot be aligned;
- unknown query types/classes/codes;
- malformed fields and timestamp regression;
- absent optional capabilities;
- tracking and answer-retention limits;
- TCP stream conflicts and missing stream IDs;
- out-of-scope opcodes;
- ordering independent of input-map order; and
- subprocess failure, timeout, cancellation, and bounded stderr.

## 18. Privacy and security

Capture paths and contents are untrusted. All v0.5.0 path validation, read-only
capture access, executable discovery, argument-list invocation, `-n` name
resolution disabling, no-shell execution, timeout, cleanup, and bounded stderr
rules remain mandatory.

No raw DNS message, raw row, arbitrary RDATA, payload bytes, credentials, or
packet object enters evidence, reports, logs, or errors. A query name, endpoint,
and selected A/AAAA/CNAME summary are decoded protocol metadata required for
the proposed report, but they may identify users, systems, services, or browsing
activity. Reports must be handled as sensitively as captures.

The resolved capture path is absent from the public DNS report. Errors replace
resolved paths with the supplied basename, as TCP does. Parser errors identify
row number and field category without echoing names, addresses, or raw content.
There is no network communication, reverse lookup, external enrichment, upload,
telemetry, or automatic sharing.

Phase 6 does not introduce a partial redaction option. The approved initial
public schema includes the DNS metadata described here by default. Any future
redaction behavior requires a separate coherent specification. Silent hashing
is not acceptable because unstable salt, correlation, collision, and
disclosure semantics have not been designed.

## 19. Deterministic behavior and compatibility

- Equal normalized collection input and capture context produce equal reports.
- No rule reads wall time, locale, environment, network state, or mutable
  global registries.
- Catalog precedence, canonical endpoints, query normalization, transaction
  matching, IDs, frame sampling, maps, findings, and recommendations are stable.
- Counts use integers; timing uses finite values derived from decimal epochs.
- No latency or retry-time threshold is embedded.
- TShark name resolution is disabled.
- Unknown numeric DNS values remain visible numeric evidence.
- Optional field capability is discovered per installed TShark and recorded.
- Required stable raw fields are a compatibility floor; their absence fails
  clearly rather than silently weakening identity.
- TShark-derived linkage and retry fields are verified against raw context and
  retain provenance.
- Tests should exercise the project minimum supported TShark environment when
  one is declared. Until then, capability tests plus the current development
  TShark are required, and documentation must state the validated version.
- Pydantic, Rich, and Typer remain the only runtime Python dependencies.

## 20. Test strategy

### 20.1 Models

Test strict immutability, endpoint families, bounds, machine codes, aware
timestamps, finite timing, transaction-ID format, query normalization,
representative-frame uniqueness/order, tuple conversion, enum serialization,
path absence, null behavior, unknown numeric values, and deterministic JSON.

### 20.2 Collector

Test argument lists and filters, capabilities, UDP/TCP and IPv4/IPv6 rows,
multi-occurrence alignment, optional blanks, boolean forms, Decimal timestamps,
matching context, DNS ID reuse, retries, duplicate responses, bounds, no
eviction, continued exact counters, malformed atomic failure, safe errors,
timeout, cancellation, and cleanup.

### 20.3 Analyzer

Test every decision-table row, finding precedence and suppression, provenance,
response-code aggregation, exact counts beyond frame samples, primary timing,
negative timing, ambiguity, missing query/response, capture-quality
qualification, status reduction, recommendation mapping/deduplication, and
input-order independence.

### 20.4 Renderers and CLI

Test bounded Rich sections and omitted counts, complete deterministic JSON,
privacy-safe paths, sensitive-metadata contract, stdout/stderr separation,
help, command orchestration, every status exit, validation and execution
errors, no tracebacks, and unchanged existing commands.

### 20.5 Real-TShark acceptance

Generate and independently validate all 14 scenarios, assert field semantics,
run the complete pipeline, and verify Rich/JSON/CLI results. Tests skip with a
precise reason only when TShark is unavailable. No test downloads or opens a
live interface.

## 21. Incremental milestone plan

Only Phase 6.0 is authorized by this task.

### Phase 6.0 — DNS engineering specification

**Objective:** Approve scope, evidence, contracts, risks, scenarios, and
milestones without production behavior.

**Files:** this specification and a narrow `ROADMAP.md` status update.

**Public API:** none.

**Tests:** existing full quality gate; documentation diff checks.

**Acceptance criteria:** baseline/tag verified; three candidates compared; one
recommendation; complete contracts; no source/test/version/release change;
clean unstaged planning diff.

**Exclusions:** every implementation item below.

**Recommended commit:** `Add Phase 6 DNS transaction analysis specification`

### Phase 6.1 — immutable DNS domain models

**Objective:** Implement only schema `1.0` evidence and report models.

**Likely files:** `models/dns_transactions.py`, model exports, and
`tests/test_dns_transaction_models.py`.

**Public API:** the enums and models in section 9.

**Tests:** strict validation, immutability, serialization, ordering helpers,
privacy, and full representative JSON contract.

**Acceptance criteria:** models contain no I/O or analysis; schema behavior is
locked; existing tests pass.

**Exclusions:** TShark, matching, findings logic, rendering, CLI, generic bases.

**Recommended commit:** `Add immutable DNS transaction models`

### Phase 6.2 — bounded streaming DNS collector

**Objective:** Normalize the approved TShark projection and retain bounded
transaction evidence.

**Likely files:** `parsers/dns_transactions.py`, parser exports, focused shared
TShark capability changes only if immediately necessary, and collector tests.

**Public API:** `collect_dns_transaction_evidence`.

**Tests:** field and capability normalization, matching inputs, malformed data,
limits, exact counters, subprocess safety, and large synthetic row streams.

**Acceptance criteria:** one-pass bounded collection; no payload/raw rows;
typed failures; deterministic result; no TCP behavior change.

**Exclusions:** findings/status analysis, renderers, CLI, wire fixtures.

**Recommended commit:** `Add streaming DNS transaction collector`

### Phase 6.3 — pure deterministic DNS analyzer

**Objective:** Implement matching verification, findings, limitations,
recommendations, ordering, and status reduction.

**Likely files:** `analyzers/dns_transactions.py`, analyzer exports, and
analyzer tests.

**Public API:** `analyze_dns_transactions`.

**Tests:** complete decision table, ambiguity, exact counts, frame sampling,
capture-quality context, deterministic ordering, and no-I/O isolation.

**Acceptance criteria:** equal inputs give equal reports; every conclusion has
evidence/provenance; forbidden claims do not appear.

**Exclusions:** rendering, CLI, real captures, thresholds, correlation.

**Recommended commit:** `Add deterministic DNS transaction analyzer`

### Phase 6.4 — DNS renderers and CLI

**Objective:** Add Rich/JSON presentation and the flat `dns` command.

**Likely files:** `renderers/dns_transactions.py`, renderer exports, `cli.py`,
renderer/CLI/pipeline tests.

**Public API:** `render_dns_transactions_rich`,
`render_dns_transactions_json`, and `packet-investigator dns`.

**Tests:** bounded terminal output, complete JSON, path privacy,
stdout/stderr, orchestration, help, and exit-code matrix.

**Acceptance criteria:** proposed command exactly matches sections 15–16;
existing commands and exits are unchanged.

**Exclusions:** new options, generic orchestration, docs claiming final
acceptance.

**Recommended commit:** `Add DNS rendering and CLI integration`

### Phase 6.5 — architecture review and corrections

**Objective:** Audit concrete implementation against the approved boundaries
before fixtures expand confidence.

**Likely files:** DNS modules and tests only where review identifies defects;
`ARCHITECTURE.md` only after behavior is real.

**Public API:** no planned additions; corrections must remain schema-compatible.

**Tests:** regression tests for each correction plus full suite.

**Acceptance criteria:** bounded memory measured; process/error/privacy review
complete; no speculative abstraction; no TCP regression.

**Exclusions:** scope expansion, refactoring unrelated modules, version/release.

**Recommended commit:** `Correct DNS analysis architecture boundaries`

### Phase 6.6 — real-TShark acceptance and documentation

**Objective:** Generate the 14-scenario matrix, validate the complete installed
pipeline, and document only implemented behavior.

**Likely files:** `tests/fixtures/captures.py`,
`tests/test_dns_end_to_end.py`, fixture/development docs, README,
ARCHITECTURE, ROADMAP, and CHANGELOG only when release preparation is separately
authorized.

**Public API:** no new API beyond Phase 6.4.

**Tests:** all 14 real-TShark scenarios, independent validation, CLI smoke,
packaging-relevant full quality gate.

**Acceptance criteria:** stable real fields verified; no binary captures; no
root/network; privacy reviewed; documentation matches implementation.

**Exclusions:** release version, tag, publish, external captures, Phase 7.

**Recommended commit:** `Add real-TShark DNS acceptance validation`

## 22. Owner-approved DNS metadata policy

The owner approves query names, client/server endpoint addresses and ports, and
bounded A, AAAA, and CNAME answer summaries for default Rich and JSON display
because they are necessary investigative protocol metadata. Within the domain
model, requester/responder endpoint labels describe observed message direction;
they do not establish application role, ownership, or fault.

These values are potentially sensitive. Capture source paths remain private by
default. Packet Investigator does not retain raw packet payload, expose
unrelated packet contents, retain arbitrary DNS payload bytes or RDATA, upload
or transmit evidence externally, or weaken deterministic and bounded output.
The permission does not extend to TXT, MX, SRV, SOA, NS, PTR, DNSSEC material,
or other arbitrary record summaries.

Any future redaction behavior or expansion of retained DNS metadata requires a
separate specification. Phase 6.1 must not improvise pseudonymization, salts, or
additional record handling.

## 23. Completion criteria

Phase 6 is complete only when:

- this specification is approved, including the sensitive metadata decision;
- strict immutable schema `1.0` DNS models are implemented;
- the collector requests only approved fields, streams once, bounds every
  retained collection, and never retains payload or rows;
- required/optional field compatibility is explicit and tested;
- matching follows section 8 precedence and preserves ambiguity;
- the pure analyzer implements the decision table, exact counts, provenance,
  deterministic ordering, limitations, recommendations, and statuses;
- wording never turns capture absence, response codes, retries, truncation, or
  TCP symptoms into unsupported cause, loss, failure, or ownership claims;
- Rich and JSON satisfy privacy, ordering, completeness, and bounded-output
  contracts;
- the `dns` command and exit codes match section 16 without changing existing
  commands;
- all 14 generated real-TShark scenarios pass through the complete pipeline;
- no production capture, binary capture, network access, root, new runtime
  dependency, generic protocol framework, or unrelated refactor is introduced;
- README, architecture, roadmap, development, and fixture documentation describe
  implemented behavior only after implementation;
- Ruff, formatting, strict mypy, pytest, diff checks, package validation, and
  fresh-install CLI smoke tests pass; and
- release, tag, merge, push, and publication remain separately authorized.

Phase 6.0 alone is complete when this planning document and the narrow roadmap
update pass the existing quality gate while all production functionality
remains unchanged.
