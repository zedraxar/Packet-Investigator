# Packet Investigator Engineering Specification

**Project:** Packet Investigator  
**Phase:** 4  
**Feature:** Capture Quality Assessment  
**Status:** Engineering Specification Only

This document is the implementation contract for Phase 4. It defines behavior
and architecture; it does not describe functionality that is already
implemented.

## 1. Purpose

Capture Quality Assessment determines whether a capture contains enough
reliable, interpretable evidence to justify deeper investigation. It runs before
protocol diagnosis because missing beginnings, truncation, timestamp anomalies,
capture-host artifacts, and limited observation points can invalidate or weaken
later conclusions.

The assessment must:

- record directly observed capture characteristics;
- identify limitations those characteristics impose;
- make bounded interpretations with explicit confidence;
- recommend collection changes that could reduce uncertainty; and
- give downstream analyzers a stable description of capture suitability.

It supports evidence-based investigation by preserving this sequence:

```text
Observed evidence
        ↓
Interpretation
        ↓
Confidence
        ↓
Limitations
        ↓
Recommended next action
```

It must not diagnose protocols, reconstruct complete conversations, identify
root cause, attribute behavior to a device or organization, or claim that an
artifact seen at one observation point occurred on the wire. Capture quality
describes the reliability and scope of available evidence. Protocol diagnosis
explains network behavior, and root-cause analysis assigns causal significance;
both are outside Phase 4.

## 2. Architectural placement

Phase 4 extends, rather than replaces, Phase 3:

- The existing capture metadata layer continues to validate paths and provide
  `CaptureMetadata`. It remains the internal authoritative source for path, file
  size, packet count, boundary timestamps, duration, interface IDs, TShark
  version, and inspection status. Quality presentation models omit the source
  path unless the user explicitly requests its disclosure.
- The TShark parser layer owns executable discovery, safe subprocess execution,
  timeout and cancellation, field selection, streaming decoding, bounded stderr,
  and translation of TShark output into parser-neutral records or aggregates.
- A new capture-quality analyzer consumes metadata and parser-neutral
  observations. It applies deterministic rules and produces domain models. It
  must not invoke subprocesses or render output.
- Models define immutable, typed, serialization-safe assessment results.
- The CLI validates options, coordinates metadata collection and assessment,
  maps expected errors to exit statuses, and selects terminal or JSON output.
- A reporting or presentation module renders Rich output. Domain models must not
  contain Rich styles or terminal layout.
- Pydantic performs JSON serialization using the stable contract in section 6.
- Existing typed operational exceptions remain the boundary for missing TShark,
  timeouts, unreadable captures, nonzero exits, and malformed output. Quality
  findings are successful results, not exceptions.

Recommended locations are:

```text
src/packet_investigator/
├── analyzers/
│   └── capture_quality.py
├── models/
│   └── capture_quality.py
├── parsers/
│   └── tshark.py
├── reporting/
│   └── capture_quality.py
└── cli.py
```

The assessment should combine existing `CaptureMetadata` with one new streaming
pass containing only fields required by enabled quality rules. The parser may
reuse Phase 3 process infrastructure, but duplicated capture reads should be
avoided where a compatible aggregate can safely serve both features.

The first increment should request deterministic frame and TCP boundary fields,
not TShark expert summaries as its primary evidence. Expert fields may be
evaluated later because their wording and classification can vary by TShark
version. At startup, the parser must detect TShark field capabilities and
request available TCP, UDP, and IPv4 checksum-status fields. Their semantics
must be normalized at the parser boundary. Domain models must not expose raw
TShark field names or require a hardcoded TShark version range.

## 3. Data model

The smallest coherent design uses seven models or enumerations.

### `CaptureQualityAssessment`

Immutable top-level Pydantic model.

| Field | Type | Requirement | Meaning and serialization |
|---|---|---:|---|
| `schema_version` | `str` | Required | Quality JSON contract version, initially `"1.0"`. |
| `tool_version` | `str` | Required | Packet Investigator version that produced the result. |
| `capture` | `CaptureQualityCapture` | Required | Privacy-safe projection of existing metadata. It excludes the source path by default. |
| `status` | `CaptureQualityStatus` | Required | Overall suitability classification serialized as a lowercase string. |
| `findings` | `tuple[CaptureQualityFinding, ...]` | Required | Deterministically ordered findings; empty when no notable condition is found. |
| `limitations` | `tuple[CaptureLimitation, ...]` | Required | Assessment-wide constraints not already local to one finding. |
| `recommendations` | `tuple[CaptureRecommendation, ...]` | Required | Deduplicated, prioritized next actions. |
| `statistics` | `CaptureQualityStatistics` | Required | Aggregate counters used to support findings. |
| `status_summary` | `str` | Required | Concise human-readable explanation of the overall status. Not an automation key. |

### `CaptureQualityCapture`

Immutable privacy-safe projection built from `CaptureMetadata`. The analyzer may
consume full metadata internally, but the assessment contract does not expose
the absolute source path without explicit CLI authorization.

| Field | Type | Requirement | Meaning and serialization |
|---|---|---:|---|
| `filename` | `str` | Required | Base filename only. Always serialized. |
| `path` | `Path \| None` | Optional | Resolved absolute source path. Omitted from JSON by default and populated only for `--include-path`. |
| `capture_format` | `str` | Required | Extension-inferred `PCAP` or `PCAPNG`. |
| `size_bytes` | non-negative `int` | Required | Original file size. |
| `packet_count` | non-negative `int` | Required | Valid frame rows observed. |
| `start_time` | aware `datetime \| None` | Optional | First valid packet timestamp in UTC. |
| `end_time` | aware `datetime \| None` | Optional | Final valid packet timestamp in UTC. |
| `duration_seconds` | non-negative `float \| None` | Optional | Difference between boundary timestamps; absent for empty captures. |
| `interface_ids` | `tuple[str, ...]` | Required | Deterministically ordered observed IDs. |
| `tshark_version` | `str` | Required | TShark version used. |
| `inspection_status` | `str` | Required | Metadata-inspection status. |

The quality JSON serializer must omit `path` when it is `None`. This is a
deliberate exception to the schema's otherwise explicit `null` behavior.

### `CaptureQualityStatus`

String enumeration with exactly `usable`, `usable_with_limitations`, `limited`,
and `insufficient`. Its semantics are defined in section 4. Unknown enum values
must fail strict deserialization under schema `1.x`; consumers should reject an
unsupported schema major version rather than silently reinterpret status.

### `CaptureQualityFinding`

Immutable evidence-and-interpretation unit.

| Field | Type | Requirement | Meaning and serialization |
|---|---|---:|---|
| `code` | `str` | Required | Stable uppercase machine code. |
| `severity` | `QualitySeverity` | Required | Finding importance, serialized as lowercase. |
| `confidence` | `ConfidenceLevel` | Required | Confidence in the interpretation, not confidence that raw counters were read. |
| `observation` | `str` | Required | Factual statement supported by captured fields. |
| `interpretation` | `str \| None` | Optional | Bounded meaning; omitted when evidence supports only an observation. |
| `limitations` | `tuple[str, ...]` | Required | Finding-specific qualifications; may be empty. |
| `evidence` | `Mapping[str, int \| float \| str \| bool \| None]` | Required | Small, stable aggregate values supporting automation; never raw packet rows. |
| `recommendation_codes` | `tuple[str, ...]` | Required | References top-level recommendations without duplicating their text. |

Finding codes are stable API identifiers. Initial and reserved codes include
`EMPTY_CAPTURE`, `VERY_SHORT_CAPTURE`, `NO_TCP_SYN_OBSERVED`,
`MIDSTREAM_TCP_OBSERVED`, `INCOMPLETE_TCP_HANDSHAKE`,
`PACKET_TRUNCATION_OBSERVED`, `CHECKSUM_OFFLOAD_POSSIBLE`,
`MULTIPLE_INTERFACES_OBSERVED`, `INTERFACE_ID_UNAVAILABLE`,
`TIMESTAMP_REGRESSION`, `CLOCK_DISCONTINUITY`, and
`MALFORMED_PACKET_ROW`.

Stable limitation codes include `FLOW_TRACKING_LIMIT_REACHED` and
`CHECKSUM_FIELDS_UNAVAILABLE`.

Codes should remain strings rather than a closed public enum so additive codes
do not break forward-compatible consumers. The producer owns a registry that
prevents accidental renaming or reuse. Consumers must preserve and display
unknown codes, use severity and evidence where understood, and must not treat an
unknown code as success or failure by itself. Removing or changing the meaning
of a code requires a schema-major change.

### `CaptureLimitation`

Immutable assessment-wide limitation.

| Field | Type | Requirement | Meaning |
|---|---|---:|---|
| `code` | `str` | Required | Stable machine identifier. |
| `description` | `str` | Required | Human-readable consequence for interpretation. |
| `affected_capabilities` | `tuple[str, ...]` | Required | Stable capability identifiers such as `tcp_handshake_analysis`. |

### `CaptureRecommendation`

Immutable next action.

| Field | Type | Requirement | Meaning |
|---|---|---:|---|
| `code` | `str` | Required | Stable machine identifier. |
| `priority` | positive `int` | Required | Display order; `1` is highest priority. |
| `action` | `str` | Required | Specific human-readable collection action. |
| `rationale` | `str` | Required | Evidence-based reason for the action. |

### `CaptureQualityStatistics`

Immutable bounded aggregate. The initial fields are `rows_processed: int`,
`tcp_packets: int`, `tcp_syn_packets: int`, `tracked_tcp_flows: int`,
`flow_tracking_limit: int`, `flow_tracking_complete: bool`,
`candidate_midstream_flows: int`, `incomplete_handshake_flows: int`,
`truncated_frames: int`, `checksum_warning_frames: int`,
`checksum_rule_enabled: bool`, `timestamp_regressions: int`, and
`interface_ids_observed: int`. Counters and limits are required non-negative
integers; booleans serialize as JSON booleans. Later optional counters may be
added within schema `1.x` if absence has an unambiguous meaning.

### `QualitySeverity` and `ConfidenceLevel`

`QualitySeverity` is a string enumeration: `informational`, `warning`, and
`critical`. It describes effect on capture suitability, not network impact.

`ConfidenceLevel` is a string enumeration: `high`, `moderate`, and `low`.
Phase 4 should not reuse ownership-confidence vocabulary because capture-quality
interpretations answer a different question. Observations that are direct
counters normally support high confidence; causal interpretations may be
moderate or low.

Separate `CaptureQualityObservation` models are not selected. A finding already
contains one mandatory observation, and standalone normal observations can live
in `statistics`. This avoids parallel collections that could contradict one
another.

## 4. Quality status and severity

Overall status and finding severity are distinct:

- `usable`: no identified capture characteristic materially constrains the
  enabled downstream analysis. This does not certify that every relevant packet
  was captured.
- `usable_with_limitations`: analysis can proceed, but one or more explicit
  limitations must accompany conclusions. Informational or warning findings
  typically produce this status.
- `limited`: material gaps or artifacts prevent one or more important analyses
  from being reliable, although useful evidence remains.
- `insufficient`: the capture contains no usable packet evidence, or its
  integrity is so compromised that the requested downstream assessment cannot
  be supported.

Rule outcomes propose status floors. A deterministic reducer selects the most
restrictive floor. For `MIDSTREAM_TCP_OBSERVED`, the floor is
`usable_with_limitations` when candidate flows are below 25% of tracked TCP
flows and `limited` at 25% or more, but percentage escalation is valid only
when at least 20 TCP flows were tracked and tracking completed without reaching
its cap. Otherwise its floor remains `usable_with_limitations`, with a
limitation stating that the sample was too small or incomplete for
percentage-based escalation. For `PACKET_TRUNCATION_OBSERVED`, the floor is
`usable_with_limitations` below 10% of processed frames and `limited` at 10% or
more; truncation of every observed frame is always `limited`. These are
capture-suitability heuristics, not proof that downstream analysis is
impossible. The reducer must use exact integer comparisons where practical to
avoid floating-point boundary errors.

Severity describes an individual finding: informational does not materially
reduce suitability, warning may constrain interpretation, and critical can
prevent reliable use. Confidence qualifies only the interpretation.

Phase 4 must omit a numeric quality score. No defensible calibration currently
maps heterogeneous observations to a stable number, and a score would imply
precision and comparability that the evidence does not support.

## 5. CLI design

The primary interface should be:

```bash
packet-investigator quality CAPTURE_PATH
packet-investigator quality CAPTURE_PATH --json
```

A separate command preserves the established promise that `inspect` is
metadata-only, permits independent evolution of timeout and rule options, and
avoids making a boolean flag trigger a substantially different workload.
`packet-investigator inspect CAPTURE_PATH --quality` is rejected as the primary
design. The existing `inspect` command must remain backward compatible.

Required argument:

- `CAPTURE_PATH`: path validated under the existing PCAP/PCAPNG rules.

Initial options:

- `--json`: emit only the JSON contract, with no Rich output or explanatory
  prose.
- `--timeout SECONDS`: positive finite subprocess timeout, defaulting to the
  existing safe project value.
- `--short-duration SECONDS` and `--short-packet-count COUNT`: optional
  heuristic overrides. Defaults are `1.0` second and `10` packets: captures
  below either threshold are short.
- `--include-path`: explicitly include the resolved absolute source path in
  terminal and JSON output. It is absent by default.

Successful assessment exits `0` for every quality status, including `limited`
and `insufficient`. These are valid analytical results, not operational
failures. Automation should inspect `status` in JSON. Invalid arguments or
paths should exit `2`; TShark and processing failures should exit `1`, matching
existing conventions.

An empty but valid capture produces a successful `insufficient` assessment.
Limited captures likewise succeed and display limitations prominently.
Terminal output displays only the filename unless `--include-path` is present.
JSON always includes filename and non-path metadata; it includes `path` only
when that option is present. The option affects disclosure only, not path
validation or assessment behavior.

## 6. JSON contract

Stable automation fields are schema and tool versions, enum values, codes,
evidence keys, numeric statistics, metadata scalar values, and recommendation
references. Human-readable fields are `status_summary`, observations,
interpretations, limitation descriptions, actions, and rationales. Their
wording may improve without a schema change.

Complete example:

```json
{
  "schema_version": "1.0",
  "tool_version": "0.2.0",
  "capture": {
    "filename": "example.pcapng",
    "capture_format": "PCAPNG",
    "size_bytes": 25354240,
    "packet_count": 18442,
    "start_time": "2026-07-25T14:03:18.123456Z",
    "end_time": "2026-07-25T14:08:42.654321Z",
    "duration_seconds": 324.530865,
    "interface_ids": ["0"],
    "tshark_version": "4.6.6",
    "inspection_status": "Inspection complete"
  },
  "status": "usable_with_limitations",
  "status_summary": "The capture is usable, but some TCP flows were already active when first observed.",
  "findings": [
    {
      "code": "MIDSTREAM_TCP_OBSERVED",
      "severity": "warning",
      "confidence": "high",
      "observation": "TCP payload was observed for 11 flows before a SYN was observed for those flows.",
      "interpretation": "The capture may have begun after these flows were established.",
      "limitations": [
        "A SYN may have occurred at another observation point or before capture start."
      ],
      "evidence": {
        "candidate_midstream_flows": 11,
        "tracked_tcp_flows": 87,
        "candidate_midstream_percentage": 12.643678,
        "percentage_escalation_threshold": 25,
        "percentage_escalation_minimum_tracked_flows": 20,
        "flow_tracking_complete": true,
        "flow_tracking_limit": 50000
      },
      "recommendation_codes": ["CAPTURE_BEFORE_REPRODUCTION"]
    }
  ],
  "limitations": [
    {
      "code": "TCP_FLOW_START_NOT_OBSERVED",
      "description": "Handshake-dependent analysis is limited for 11 observed flows.",
      "affected_capabilities": ["tcp_handshake_analysis"]
    }
  ],
  "recommendations": [
    {
      "code": "CAPTURE_BEFORE_REPRODUCTION",
      "priority": 1,
      "action": "Start the capture before reproducing the issue and stop it after the outcome is observed.",
      "rationale": "This increases the likelihood of observing complete flow establishment and termination."
    }
  ],
  "statistics": {
    "rows_processed": 18442,
    "tcp_packets": 17300,
    "tcp_syn_packets": 76,
    "tracked_tcp_flows": 87,
    "flow_tracking_limit": 50000,
    "flow_tracking_complete": true,
    "candidate_midstream_flows": 11,
    "incomplete_handshake_flows": 2,
    "truncated_frames": 0,
    "checksum_warning_frames": 214,
    "checksum_rule_enabled": true,
    "timestamp_regressions": 0,
    "interface_ids_observed": 1
  }
}
```

Collections serialize as arrays in deterministic order. Optional timestamps and
interpretations serialize as JSON `null`, not absent keys, in schema `1.0`.
The optional `capture.path` is omitted entirely unless `--include-path` is
specified; when included, it is the resolved absolute path. Messages are not
repeated at top level and in findings; references connect findings to
deduplicated recommendations.

## 7. Quality-assessment rules

### `EMPTY_CAPTURE` — first increment

- **Purpose:** Identify absence of packet evidence.
- **Inputs:** `packet_count`.
- **Observed evidence:** Zero valid frame rows.
- **Permitted interpretation:** No packet behavior can be evaluated.
- **Confidence:** High.
- **Limitations:** A zero-packet file may be a valid empty capture; it does not
  show that no traffic existed.
- **Action:** Verify interface, capture filter, permissions, timing, and traffic
  generation; capture again across the reproduction window.
- **Severity/status:** Critical; `insufficient`.
- **False positives:** None for emptiness, but cause remains unknown.

### `VERY_SHORT_CAPTURE` — first increment

- **Purpose:** Flag an evidence window that may be too small for the intended
  investigation.
- **Inputs:** Packet count, duration, configured thresholds.
- **Evidence:** Exact count and duration compared with each threshold.
- **Interpretation:** The capture may not include enough context; never “the
  capture is invalid.”
- **Confidence:** Moderate because adequacy depends on the incident.
- **Limitations:** A one-packet event or brief handshake may be fully captured.
- **Action:** Capture before, during, and after reproduction.
- **Severity/status:** Warning; normally `usable_with_limitations`, but a
  one-packet capture is `limited`.
- **False positives:** Sparse protocols, tightly scoped filters, and brief
  reproductions.

The default thresholds are fewer than 10 packets or duration below 1.0 second.
Zero packets is handled by `EMPTY_CAPTURE` as `insufficient`. One packet is
`limited`. Two through nine packets, or a duration below 1.0 second, produces
`usable_with_limitations` unless another finding requires a stricter status.
These thresholds are configurable screening heuristics, not universal
definitions of adequacy. Finding evidence must include `packet_count`,
`duration_seconds`, `effective_packet_count_threshold`, and
`effective_duration_threshold_seconds`.

### `NO_TCP_SYN_OBSERVED` — first increment

- **Purpose:** Identify TCP evidence without any observed connection starts.
- **Inputs:** TCP packet and SYN-without-ACK counts.
- **Evidence:** TCP packets exist and SYN count is zero.
- **Interpretation:** Some TCP activity may predate capture start.
- **Confidence:** Low to moderate.
- **Limitations:** TCP may consist entirely of ACK/RST traffic; capture filters,
  asymmetric visibility, and other observation points can hide SYN packets.
- **Action:** Start capture earlier and verify bidirectional visibility.
- **Severity/status:** Warning; `usable_with_limitations`.
- **False positives:** Narrow filters and intentionally sampled traffic.

This is capture-level evidence only. It does not prove all TCP flows are
midstream. Suppress this finding when `MIDSTREAM_TCP_OBSERVED` provides stronger
flow-specific evidence. Retain all underlying TCP and SYN statistics. The broad
finding remains permitted when no stronger result exists or when flow tracking
was incomplete or unavailable.

### `MIDSTREAM_TCP_OBSERVED` — first increment

- **Purpose:** Detect stronger flow-specific indications of a missing start.
- **Inputs:** Timestamp, temporary normalized flow identity, TCP flags,
  sequence-presence indicators, and payload length.
- **Evidence:** Payload or established-flow flags occur before any observed SYN
  for the same directional flow key. Evidence must include
  `candidate_midstream_flows`, `tracked_tcp_flows`,
  `candidate_midstream_percentage`, `percentage_escalation_threshold=25`,
  `percentage_escalation_minimum_tracked_flows=20`,
  `flow_tracking_complete`, and `flow_tracking_limit`.
- **Interpretation:** The specific flow may have been established before its
  first captured packet.
- **Confidence:** High for the observation; moderate to high for interpretation.
- **Limitations:** Reordered rows, capture filtering, tuple reuse, and
  unidirectional visibility.
- **Action:** Start capture before reproduction and capture both directions.
- **Severity/status:** Warning. Use `usable_with_limitations` below 25% and
  `limited` at 25% or more only when at least 20 TCP flows were tracked and
  tracking completed. With fewer than 20 tracked TCP flows or incomplete
  tracking, remain `usable_with_limitations` and state that percentage-based
  escalation was not applied because the sample was too small or incomplete.
- **False positives:** SYN omitted by a filter, tuple reuse, and unusual TCP
  behavior.

The temporary flow identity uses the outermost directly decoded network and
transport headers:

1. IP version
2. source IP
3. destination IP
4. final transport protocol
5. source port
6. destination port

IPv4 and IPv6 are supported when TShark exposes the final transport protocol and
both ports. Phase 4 does not separately inspect or track tunneled inner flows.
Packets without usable transport ports are excluded from flow-specific
midstream detection; they still contribute to applicable packet, timestamp,
truncation, interface, and checksum statistics. Missing ports must never be
replaced with synthetic values such as zero because that could merge unrelated
traffic.

Before Phase 6, tracking is limited to whether this bounded identity has seen a
SYN and whether it first appeared established. The validated internal
application constant is 50,000 normalized five-tuples in the first
implementation and is not exposed as a CLI option. The tracker must never
silently evict. At the limit it stops registering new flows, continues all
stateless rules, adds the stable `FLOW_TRACKING_LIMIT_REACHED` assessment
limitation, records `tracked_tcp_flows`, `flow_tracking_limit`, and
`flow_tracking_complete=false`, and qualifies every midstream result as partial.
It must not reconstruct TCP state, validate sequence spaces, or diagnose a
conversation.

### `INCOMPLETE_TCP_HANDSHAKE` — later increment

- **Purpose:** Record SYNs without all expected handshake stages.
- **Inputs:** Bounded directional flow key, flags, timestamps.
- **Evidence:** An observed SYN lacks a matching SYN/ACK or final ACK within the
  observed window.
- **Interpretation:** The handshake was not fully visible.
- **Confidence:** Moderate.
- **Limitations:** The missing response may itself be the incident symptom, may
  occur after capture end, or may be invisible at this point.
- **Action:** Capture both endpoints or an additional transit point.
- **Severity/status:** Informational or warning; never automatically a quality
  defect.
- **False positives:** Failed connection attempts, asymmetric routing, short
  windows, and capture filters.

This is deferred because distinguishing a network symptom from capture
incompleteness overlaps Phase 6 conversation state.

### Conversations without observed closure — later increment

Absence of FIN or RST is weak quality evidence: long-lived connections, abrupt
capture stop, application silence, and off-path visibility are normal
explanations. It should be implemented only after the Conversation Builder can
define flow scope. If added, it is informational unless correlated with capture
end and user-supplied incident timing.

### `PACKET_TRUNCATION_OBSERVED` — first increment

- **Purpose:** Detect snap-length or per-frame truncation.
- **Inputs:** Captured frame length and reported original frame length.
- **Evidence:** `captured_length < original_length`, with count and maximum
  missing bytes. Finding evidence must include `truncated_frames`,
  `rows_processed`, `truncated_frame_percentage`, and
  `limited_status_threshold_percentage=10`.
- **Interpretation:** Bytes present in the original frame were not retained in
  this capture.
- **Confidence:** High.
- **Limitations:** Truncation may be intentional and may not affect header-only
  analysis.
- **Action:** Increase snap length or capture full frames if payload/header
  depth is required.
- **Severity/status:** Warning. Use `usable_with_limitations` when fewer than
  10% of processed frames are truncated. Use `limited` at 10% or more, and
  whenever every observed frame is truncated regardless of total count.
- **False positives:** Inconsistent producer metadata or parser semantics.

The parser must document the TShark fields used and distinguish interface snap
length metadata from observed per-frame truncation. The percentage thresholds
are capture-suitability heuristics; even a `limited` result must not claim that
all downstream analysis is impossible.

### `CHECKSUM_OFFLOAD_POSSIBLE` — first increment

- **Purpose:** Prevent capture-host checksum warnings from being mistaken for
  wire corruption.
- **Inputs:** Capability-detected TCP, UDP, and IPv4 checksum-status fields,
  interface context, packet direction where available, and counts by protocol.
- **Evidence:** Checksum warnings are observed, especially on locally
  transmitted traffic.
- **Interpretation:** Capture-host checksum offload may explain the warnings.
- **Confidence:** Low or moderate unless capture location and direction are
  known.
- **Limitations:** Offload cannot be proven from checksum warnings alone;
  genuine corruption remains possible.
- **Action:** Capture on an external observation point or disable relevant
  offload temporarily under approved operational procedures.
- **Severity/status:** Informational or warning; normally
  `usable_with_limitations`.
- **False positives:** Genuine corruption, incorrect dissection, truncation, and
  encapsulation.

No rule may label checksum warnings as wire errors without stronger independent
evidence. Capability detection, rather than a version allowlist, determines
which checksum fields can be requested. If none of the initial TCP, UDP, or IPv4
checksum-status fields are available, disable only this rule, add the stable
`CHECKSUM_FIELDS_UNAVAILABLE` limitation, and continue the complete assessment.
Partial field support enables assessment only for supported protocols and must
be disclosed in finding evidence or limitations. Missing checksum-field support
is never an operational failure.

### `MULTIPLE_INTERFACES_OBSERVED` — first increment

- **Purpose:** Expose mixed observation contexts.
- **Inputs:** Unique interface IDs and optional interface metadata.
- **Evidence:** More than one interface ID occurs.
- **Interpretation:** Frames may originate from different observation points or
  link types.
- **Confidence:** High for multiplicity; low for topology meaning.
- **Limitations:** Multiple interfaces can be deliberate and valuable.
- **Action:** Confirm interface identities and account for them in later
  correlation.
- **Severity/status:** Informational; `usable` unless combined with ambiguity.
- **False positives:** None for IDs, but IDs do not necessarily mean physical
  interfaces.

### `INTERFACE_ID_UNAVAILABLE` — first increment

- **Purpose:** Record absent or inconsistent interface attribution.
- **Inputs:** Interface ID presence per row and capture metadata.
- **Evidence:** IDs are absent for all rows or inconsistently populated.
- **Interpretation:** Per-interface attribution is unavailable or incomplete.
- **Confidence:** High.
- **Limitations:** Classic PCAP normally lacks PCAPNG-style interface IDs; a
  single interface may still be reasonably inferred.
- **Action:** Use PCAPNG with interface metadata when interface attribution
  matters.
- **Severity/status:** Informational or warning depending on intended analysis.
- **False positives:** Format-specific absence is expected, not damage.

### `TIMESTAMP_REGRESSION` — first increment

- **Purpose:** Detect processing-order timestamps that move backward.
- **Inputs:** Frame order and epoch timestamp.
- **Evidence:** A later frame row has a timestamp earlier than the preceding
  valid row; record count and largest regression.
- **Interpretation:** Timing-based analysis may be unreliable across affected
  frames.
- **Confidence:** High for the observation, moderate for clock-quality meaning.
- **Limitations:** Merged multi-interface captures and timestamp precision can
  produce legitimate ordering effects.
- **Action:** Inspect interface clocks and merge method; recapture from
  synchronized points when timing matters.
- **Severity/status:** Warning; `usable_with_limitations` or `limited` for
  material regressions.
- **False positives:** Multi-interface merging and equal/rounded timestamps.

### `CLOCK_DISCONTINUITY` — later increment

- **Purpose:** Detect unusually large gaps within an otherwise active stream.
- **Inputs:** Consecutive timestamps, traffic density, interface IDs, and a
  configurable contextual threshold.
- **Evidence:** Exact gap and surrounding packet rates.
- **Interpretation:** Capture pause, clock adjustment, traffic silence, or
  collection interruption may have occurred.
- **Confidence:** Low without external timing context.
- **Limitations:** Capture duration alone cannot distinguish a clock issue from
  legitimate silence.
- **Action:** Compare against reproduction time and capture-tool logs.
- **Severity/status:** Informational or warning.
- **False positives:** Legitimately idle networks and sparse filters.

It is deferred until contextual thresholds and interface-aware behavior are
approved.

### `MALFORMED_PACKET_ROW` — operational failure in first increment

- **Purpose:** Detect required TShark fields that cannot be normalized.
- **Inputs:** Parser row and expected schema.
- **Evidence:** Missing required columns or invalid types.
- **Interpretation:** None within a partial quality result.
- **Confidence:** High for parser failure.
- **Limitations:** Cause may be malformed capture data, a TShark version change,
  locale/output incompatibility, or an application parser defect.
- **Action:** Report tool versions and bounded stderr; retry with a supported
  TShark version or validate the capture independently.
- **Severity/status:** Operational failure, not a capture-quality status.
- **False positives:** Parser incompatibility.

The first implementation should fail atomically rather than silently skip
malformed rows and issue a potentially misleading assessment.

### Large captures — first increment operational behavior

File size and rows processed should be reported as statistics, not a negative
quality finding. Large captures affect runtime, disk I/O, timeout selection, and
flow-state memory; they do not reduce evidentiary quality. The CLI may provide
progress information when attached to a terminal, but JSON must remain clean.

### Capture relative to reported issue time — future

Future optional reproduction start/end times could determine whether the
capture brackets the reported issue. Evidence would compare supplied times with
capture boundaries; it would not assume an issue occurred. This is not required
initially because Phase 4 has no incident-context model or agreed CLI contract.

## 8. Evidence wording

User-facing text must:

- state measured facts with counts, durations, or scopes;
- use “may,” “is consistent with,” or “cannot determine” for interpretations
  that have alternatives;
- identify the capture point and visibility limitation when known;
- avoid converting absence of evidence into evidence of absence;
- avoid device, team, or vendor attribution; and
- pair material limitations with a specific next collection action.

Forbidden categorical forms include “the capture is bad,” “the network dropped
packets,” “the firewall caused the reset,” and “the conversation is
incomplete.” Preferred structure is:

```text
Observed:
TCP payload was present for 11 flows before a SYN was observed for those flows.

Interpretation:
The capture may have begun after those flows were already established.

Confidence:
High

Limitation:
Traffic not visible at this capture point cannot be evaluated.

Recommended action:
Begin the capture before reproducing the issue.
```

Terminal output may combine observation and a short interpretation on adjacent
lines when the labels remain explicit. JSON must always keep `observation`,
`interpretation`, `confidence`, and `limitations` in separate fields.

## 9. Rich terminal presentation

Use modest semantic styling: green for `usable`, yellow for limitation states,
red for `insufficient` or operational errors, cyan for observations, and bold
labels. Every state must also have text and symbols so color is never the only
indicator. Avoid panels per finding and excessive borders.

Example:

```text
Packet Investigator — Capture Quality

Capture
  File:                 example.pcapng
  Packets:              18,442
  Duration:             324.531 seconds
  Interfaces:           0

Overall status:         USABLE WITH LIMITATIONS
The capture contains useful evidence, but some TCP flow starts were not observed.

Observations
  [MIDSTREAM_TCP_OBSERVED] Warning — Confidence: High
  Observed: TCP payload appeared for 11 flows before a SYN was observed.
  Interpretation: The capture may have begun after those flows were established.

  [MULTIPLE_INTERFACES_OBSERVED] Informational — Confidence: High
  Observed: Frames from interface IDs 0 and 1 were present.
  Interpretation: The capture contains more than one observation context.

Limitations
  - Handshake-dependent analysis is limited for 11 observed flows.
  - Interface IDs do not establish physical capture locations.

Recommended next actions
  1. Start capture before reproducing the issue and stop after the outcome.
  2. Record the identity and location of each capture interface.

Capture-quality assessment only. No root-cause or ownership conclusion was made.
```

## 10. Error and exit-status behavior

| Condition | Result | Exit |
|---|---|---:|
| Missing capture | Concise path error; no assessment | 2 |
| Unsupported extension | State supported extensions; no assessment | 2 |
| TShark missing | Installation/PATH guidance; no traceback | 1 |
| TShark timeout | State timeout and suggest adjustment or narrower input | 1 |
| TShark execution failure | Bounded sanitized stderr and exit code | 1 |
| Malformed TShark output | Identify parser incompatibility possibility; no partial assessment | 1 |
| Empty capture | Successful `insufficient` assessment | 0 |
| Limited capture | Successful `limited` assessment | 0 |
| Insufficient capture | Successful `insufficient` assessment | 0 |

Operational failures mean no trustworthy assessment was produced. Quality
statuses mean assessment completed and found limitations. JSON operational
errors should follow a future common CLI error contract; until that contract is
approved, errors go to stderr and stdout remains empty.

## 11. Performance and resource requirements

- TShark stdout must be streamed; full output must never be retained.
- Stderr retention must remain bounded while the pipe is drained.
- Aggregate counters and timestamp state are constant-size.
- Midstream detection may retain a compact state per normalized five-tuple
  formed from the outermost directly decoded IP version, source and destination
  addresses, final transport protocol, and source and destination ports:
  first-seen order/time, whether SYN was seen, and whether established behavior
  preceded SYN.
- Five-tuple state is capped at 50,000 entries by default. On reaching it, the
  analyzer stops registering new flows, continues stateless rules, emits
  `FLOW_TRACKING_LIMIT_REACHED`, reports tracked count and effective limit, and
  marks midstream findings partial. It must not evict silently because eviction
  changes findings. The cap is a validated internal application constant and
  must not be exposed as a Phase 4 CLI option. A future configuration system may
  expose it only after memory behavior and safe bounds are established.
- IPv4 and IPv6 are eligible when TShark supplies the final protocol and ports.
  Tunneled inner flows are not tracked separately. Portless packets consume no
  flow state and continue through stateless assessment.
- No raw payload, full row, or complete packet object may be retained.
- The subprocess deadline must cover streaming and process completion. Timeout
  cleanup must terminate and then kill after a bounded grace period.
- Ctrl-C must terminate the child process, drain or close resources, and return
  the conventional interrupted exit without a traceback.
- Progress is optional initially. If added, use byte-position data only when
  reliable, emit it to stderr/terminal rendering, suppress it for `--json`, and
  avoid extra capture passes.
- Large synthetic streams must demonstrate bounded row buffering. Flow-cardinality
  behavior must be tested independently.

## 12. Security and privacy

Capture paths and contents are untrusted. The implementation must preserve Phase
3 validation, pass paths as one subprocess argument, never invoke a shell, never
use `shell=True`, and never interpolate a command string.

The source file is opened read-only by TShark and is never modified, copied, or
uploaded. No automatic network communication is permitted. Stderr and parser
errors must be sanitized and bounded.

Payloads are not requested or retained. Addresses and ports may be needed
internally for ephemeral flow keys, but default terminal and JSON output should
report aggregate counts rather than five-tuples. Domain models should allow
future address hashing or redaction without changing finding codes. Debug
logging must not expose packet rows, addresses, payloads, credentials, or
unbounded tool output by default.

The resolved capture path is sensitive metadata. Terminal output shows only the
filename by default, and default JSON omits the `path` key. The
`--include-path` option is the sole initial mechanism for explicit absolute-path
disclosure. Errors should avoid absolute paths unless needed to identify an
invalid user-supplied target; future shared redaction controls may further
restrict error output.

## 13. Test plan

No private captures are required. Prefer pure synthetic field rows for rule
logic and process doubles for operational behavior.

### Unit tests

- Normal usable capture produces `usable`, stable empty finding collections,
  and deterministic statistics.
- Empty capture produces `insufficient` and `EMPTY_CAPTURE`.
- Zero-, one-, two-, and nine-packet cases verify the exact default status
  rules. Tests at 0.999 and 1.0 seconds verify the duration boundary. Override
  tests report effective thresholds in evidence.
- A complete TCP handshake is not classified as midstream.
- TCP payload before an observed SYN produces `MIDSTREAM_TCP_OBSERVED`.
- Flow-identity tests cover IPv4, IPv6 with a final transport protocol, reversed
  directions, tunneled traffic using only outer headers, and absent ports.
  Portless packets create no synthetic flow but still update applicable
  stateless statistics.
- Midstream status tests cover 19 and 20 tracked TCP flows, ratios immediately
  below and exactly at 25%, and incomplete tracking. Percentage escalation is
  applied only with at least 20 flows and complete tracking; evidence includes
  every effective threshold and count.
- `NO_TCP_SYN_OBSERVED` is suppressed by a stronger complete midstream result,
  statistics remain present, and the broad finding remains when tracking is
  incomplete or unavailable.
- SYN without SYN/ACK records only the deferred/approved handshake behavior and
  is never automatically called poor capture quality.
- Captured length below original length produces truncation evidence; equal
  lengths do not.
- Truncation status tests cover ratios immediately below and exactly at 10%,
  every-frame truncation for small and large captures, and evidence containing
  the effective 10% threshold.
- Checksum warning patterns produce offload-possible wording, never wire-error
  wording.
- Ambiguous genuine checksum warnings retain low/moderate confidence and explicit
  alternatives.
- Capability tests cover full, partial, and absent TCP/UDP/IPv4 checksum fields.
  Absent support disables only the checksum rule and adds
  `CHECKSUM_FIELDS_UNAVAILABLE`.
- Multiple interface IDs and missing/inconsistent IDs produce their respective
  findings.
- Timestamp regression records count and maximum regression.
- A clock gap does not trigger without an approved contextual threshold; later
  tests cover legitimate silence and configured detection.
- Malformed rows fail atomically and distinguish parser incompatibility in the
  error message.
- Finding, limitation, and recommendation ordering is deterministic regardless
  of input set ordering.
- Status reduction covers finding combinations.
- Unknown finding codes survive consumer-side model handling where applicable.

### Parser and integration tests

- Process doubles cover TShark missing, timeout, nonzero exit, bounded stderr,
  cancellation, and child cleanup.
- A large generated field stream verifies bounded row buffering and flow-state
  cap behavior at 49,999, 50,000, and 50,001 distinct normalized five-tuples
  without creating a capture. It verifies no eviction, continued stateless
  findings, tracked-flow statistics, the stable limitation, and partial
  qualification.
- CLI help tests confirm that no flow-limit option is exposed.
- Tiny generated PCAP and PCAPNG fixtures may verify field semantics for
  complete handshake, truncation, checksum metadata, and interfaces. Fixtures
  must be synthetic, legally generated, payload-free, documented, and reviewed
  before repository inclusion.
- TShark-version integration tests should assert normalized semantics rather
  than exact incidental stderr wording.

Synthetic rows are preferred for empty, one-packet, short, midstream, handshake,
timestamp, malformed-row, ordering, status, and large-stream cases. Generated
capture fixtures are reserved for validating actual TShark field behavior that
row tests cannot prove. Public captures should not be downloaded during tests;
if ever used, their license, provenance, sanitization, and checksum must be
documented.

### CLI and contract tests

- Rich output includes status, observation, limitation, recommendation, and
  metadata-only scope language.
- `--json` emits parseable JSON only and matches schema `1.0`.
- Default Rich and JSON output contain the filename but not the absolute path;
  `--include-path` includes the resolved path in both formats.
- Golden contract tests protect enum values, codes, null behavior, ordering, and
  stable automation fields.
- Empty, limited, and insufficient assessments exit `0`.
- Argument errors exit `2`; operational failures exit `1`; no expected error
  exposes a traceback.
- Existing `inspect`, `version`, and `info` tests remain unchanged and passing.

## 14. Acceptance criteria

Phase 4 is complete only when:

- implementation follows the current metadata, parser, analyzer, model, CLI,
  and reporting boundaries;
- all public models are immutable and strictly typed;
- the `quality` CLI and schema `1.0` JSON output conform to this specification;
- operational failures remain distinct from successful quality findings;
- the architect-approved first-increment rules are implemented;
- every finding separates evidence from interpretation and confidence;
- limitations and recommendations are evidence-based and deduplicated;
- processing is streaming, row buffering is bounded, and flow state has an
  enforced 50,000-entry default cap with no silent eviction;
- temporary flow identity uses only outermost directly decoded IPv4 or IPv6 and
  usable final transport protocol and ports; portless packets remain eligible
  for stateless rules and never receive synthetic ports;
- midstream status escalation uses the 25% threshold only for at least 20
  tracked TCP flows with complete tracking, and records all effective values in
  evidence;
- truncation status escalation uses the 10% threshold and every-frame rule,
  records all effective values, and does not claim downstream analysis is
  impossible;
- the flow-state cap remains internal in the first implementation, is absent
  from CLI options, and remains visible in assessment statistics;
- checksum capability detection degrades only the checksum rule when fields are
  unavailable;
- broad no-SYN findings are suppressed only when stronger complete
  flow-specific evidence exists;
- terminal and JSON output protect source paths by default and disclose the
  absolute path only through `--include-path`;
- subprocess timeout, cancellation, and cleanup are deterministic;
- tests cover normal, limited, insufficient, malformed, large-stream, and
  operational-failure cases;
- documentation describes implemented behavior without presenting deferred
  rules as available;
- `ruff check .`, `ruff format --check .`, strict `mypy`, and `pytest` pass;
- editable installation and CLI smoke tests pass; and
- existing `inspect` behavior and JSON remain backward compatible.

## 15. First implementation increment

The first increment should implement:

1. `EMPTY_CAPTURE`
2. `VERY_SHORT_CAPTURE` with configurable defaults of fewer than 10 packets or
   less than 1.0 second, including the specified one-packet status behavior
3. `NO_TCP_SYN_OBSERVED`
4. bounded, deliberately shallow `MIDSTREAM_TCP_OBSERVED` using the outermost
   decoded IPv4/IPv6 transport identity and the approved 25%/20-flow escalation
   criteria
5. `PACKET_TRUNCATION_OBSERVED` using the approved 10% and every-frame
   escalation criteria
6. `CHECKSUM_OFFLOAD_POSSIBLE`
7. `MULTIPLE_INTERFACES_OBSERVED`
8. `INTERFACE_ID_UNAVAILABLE`
9. `TIMESTAMP_REGRESSION`
10. deduplicated recommendations for earlier capture start, complete
    reproduction windows, full snap length, external/offload-independent
    observation, and interface documentation

This increment includes overall status reduction, Rich and JSON rendering, and
bounded statistics. It excludes incomplete handshakes, missing closure, clock
discontinuity, reproduction-time alignment, expert-info interpretation, and
any full conversation state. This boundary answers the primary suitability
questions while keeping review focused.

The temporary tracker has a validated internal 50,000-flow constant with no CLI
option. Its effective value remains in statistics. If the cap is reached,
midstream results must be qualified as partial, stateless rules must continue,
`FLOW_TRACKING_LIMIT_REACHED` must be present, and the overall assessment must
not claim all flows were evaluated. Packets without usable ports bypass this
tracker without losing stateless observations. Checksum rules use detected TCP,
UDP, and IPv4 field capabilities and degrade independently when unavailable.

## 16. Future compatibility

Phase 5 may replace TShark-specific normalized row structures with a Normalized
Packet Model while preserving `CaptureQualityAssessment`. Phase 6 should assume
responsibility for robust handshake and closure tracking; the temporary Phase 4
five-tuple flags can then delegate to conversation summaries without changing
finding codes or JSON structure.

Phase 7 can consume quality findings as limitations attached to evidence. Phase
8 can use quality status to qualify TCP conclusions, not suppress observations.
Endpoint comparison and multi-point correlation can attach one assessment per
capture and distinguish local timestamp/interface limitations. Reporting can
render the same models in terminal, JSON, and HTML. Privacy controls can extend
the default path omission and redact internal flow identifiers because external
findings expose aggregate evidence rather than addresses.

These phases may add statistics, recommendations, and codes under compatible
schema rules. They must not reinterpret existing codes or convert Phase 4
quality confidence into ownership confidence.

## 17. Non-goals

Phase 4 does not perform:

- root-cause analysis;
- technical ownership assignment;
- firewall or endpoint attribution;
- full TCP diagnosis;
- retransmission or packet-loss diagnosis;
- DNS, TLS, HTTP, SMB, RDP, or other application-layer analysis;
- application-layer conclusions;
- payload extraction;
- capture comparison; or
- multi-point correlation.

It also does not prove that traffic absent from a capture was absent from the
network, that a checksum warning represents wire corruption, or that an
incomplete handshake was caused by capture quality.
