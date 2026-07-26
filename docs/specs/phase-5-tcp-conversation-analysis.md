# Packet Investigator Engineering Specification

**Project:** Packet Investigator  
**Phase:** 5  
**Feature:** TCP Conversation Analysis  
**Status:** Engineering Specification Only  
**Target release:** v0.5.0

This document is the implementation contract for Phase 5. It defines
deterministic TCP conversation analysis and does not describe functionality
that is currently implemented. Phase 4 remains unchanged.

## 1. Product purpose and boundaries

Phase 5 analyzes observed TCP connection behavior at the transport layer. It
groups TCP packets into bounded conversations, records establishment,
directional traffic, termination, flow-control, and TShark analysis indicators,
and presents evidence-backed findings with explicit limitations and next
actions.

It should help an investigator answer:

- Which TCP conversations were observed?
- Which endpoint sent the first observed connection-opening SYN?
- What client/server roles are supported or only weakly suggested?
- Was an ordered three-way handshake observed?
- Did traffic appear to be in progress before capture?
- Were SYN or SYN/ACK attempts repeated?
- Were resets or an orderly FIN close observed?
- Did TShark mark retransmission, duplicate-ACK, sequence-gap, or out-of-order
  behavior?
- Were zero-window, window-full, or keepalive indicators observed?
- How many packets, captured bytes, original frame bytes, and TCP payload bytes
  were observed in each direction?
- What observable time intervals are available?
- Which evidence is consistent with delivery difficulty, receiver pressure, or
  incomplete capture visibility?
- Which collection or system evidence should be checked next?

Phase 5 must preserve the project evidence sequence:

```text
Observed TCP evidence
        ↓
Bounded transport interpretation
        ↓
Deterministic evidence strength
        ↓
Limitations and alternatives
        ↓
Recommended next action
```

### 1.1 Symptoms are not root causes

Phase 5 reports TCP symptoms, not causal ownership. It must not diagnose:

- firewall policy, NAT correctness, routing correctness, ISP quality, or
  physical-link failure;
- server health, endpoint health, application correctness, or organizational
  ownership;
- TLS certificate or negotiation failures;
- DNS, HTTP, SMB, QUIC, UDP, or other application/protocol behavior;
- exact network latency without suitable bidirectional capture context;
- packet loss solely from a TCP or TShark analysis indicator;
- whether a retransmission occurred on the wire rather than only at the
  observation point;
- whether checksum warnings are corruption;
- whether a packet was dropped, or which device dropped it; or
- whether a server, client, firewall, ISP, application, or team caused a
  symptom.

“TShark marked three frames as retransmissions” is supportable. “The network
lost three packets” is not. “A reset was observed from endpoint B” is
supportable. “The server rejected the connection” is not unless endpoint B's
application role and cause are established by independent evidence, which
Phase 5 does not do.

### 1.2 Relationship to Phase 4

Capture quality remains a prerequisite. Initial orchestration should:

1. inspect capture metadata;
2. produce the existing `CaptureQualityAssessment`;
3. stop with an `insufficient` TCP report when capture quality provides no
   packet evidence;
4. collect TCP conversation evidence in one additional streaming pass;
5. analyze and render the TCP report.

The TCP report should carry the capture-quality status and stable limitation
codes relevant to TCP interpretation. It must not reproduce or reinterpret
Phase 4 rules. A Phase 4 `limited` status sets an overall TCP status floor of
`limited`; `usable_with_limitations` adds its relevant limitations but does not
automatically prevent TCP analysis.

Two streaming field passes are acceptable in the first implementation because
they preserve proven Phase 4 behavior and isolate field contracts. A later
shared normalized packet stream may remove the duplicate read only if Phase 4
results remain backward compatible.

## 2. Terminology and evidence layers

- **Endpoint:** one IP address and TCP port.
- **Canonical tuple:** the two endpoints sorted deterministically, plus TCP.
- **Directional flow:** packets from endpoint A to endpoint B or from B to A.
- **Connection epoch:** one observed use of a canonical tuple, separated from
  another use by stream identity or defensible TCP boundary evidence.
- **Conversation:** the packets and bounded state assigned to one canonical
  tuple and connection epoch.
- **Observed initiator:** endpoint that sent the first qualifying SYN without
  ACK in the epoch.
- **Inferred client/server:** application-role guidance derived from stated
  evidence. It is distinct from the observed TCP initiator.
- **Raw fact:** value directly decoded from frame, IP, or TCP headers.
- **TShark-derived indicator:** result of TShark stateful analysis, such as
  `tcp.analysis.retransmission`.
- **Packet Investigator interpretation:** deterministic meaning applied to raw
  facts and normalized TShark indicators.
- **Representative frame:** bounded frame-number reference supporting a
  finding; it is not a stored packet.
- **Complete visibility:** sufficient observed evidence for a particular
  assessment, not proof that the capture contains every on-wire packet.

The collector must label evidence provenance as `raw_header`,
`tshark_derived`, or `packet_investigator_derived`. Findings must never present
the second or third category as a raw header fact.

## 3. Architectural placement

Recommended future locations are:

```text
src/packet_investigator/
├── analyzers/
│   └── tcp_conversations.py
├── models/
│   └── tcp_conversations.py
├── parsers/
│   └── tcp_conversations.py
├── renderers/
│   └── tcp_conversations.py
└── cli.py
```

Responsibilities:

- Existing metadata and quality layers retain their current contracts.
- The TShark wrapper retains executable discovery, path validation, argument
  list construction, timeout, bounded stderr, streaming, cancellation, and
  cleanup.
- The TCP parser owns TShark field names, capability detection, scalar
  normalization, stream/tuple grouping inputs, and bounded mutable collection
  state.
- The TCP analyzer is a pure transformation from metadata, capture quality,
  and immutable collection results to `TCPAnalysisReport`.
- TCP domain models contain no subprocess, TShark field-name, Rich, CLI, or
  mutable collector objects.
- Renderers only present an existing report.
- The CLI only validates arguments, coordinates public APIs, renders, handles
  expected operational errors, and maps report status to an exit code.

No generic rule engine, plugin framework, packet object hierarchy, application
payload model, or cross-protocol abstraction is required in Phase 5.

## 4. Conversation identity

### 4.1 Canonical tuple

Each endpoint contains:

1. IP version (`4` or `6`);
2. canonical IP address;
3. TCP port (`0` through `65535`).

The canonical bidirectional key is:

```text
TCP + min(endpoint_1, endpoint_2) + max(endpoint_1, endpoint_2)
```

Endpoint order uses `(ip_version, packed_address_bytes, port)`. Endpoint A is
the lower endpoint under this ordering; endpoint B is the higher. Textual IPv6
spelling, input direction, hostname resolution, and locale never affect the
key. Direction is separately `a_to_b` or `b_to_a`.

Packets without one layer-consistent IPv4/IPv6 source and destination and both
valid TCP ports cannot enter a conversation. They increment unusable-row
statistics and may create a bounded parser warning; synthetic addresses or
ports must never be substituted.

### 4.2 Recommended hybrid strategy

Use a hybrid design:

1. Use non-negative TShark `tcp.stream` as the primary within-invocation
   segmentation hint.
2. Verify every row assigned to that stream has the same canonical tuple.
3. Internally map `(tcp.stream, canonical_tuple)` to one collector group.
4. If a stream number is missing or unsupported, use the deterministic
   tuple/epoch fallback below.
5. Assign public conversation IDs after collection from deterministic report
   ordering; never expose `tcp.stream` as the stable external identity.

For stream-based groups sharing a canonical tuple, assign epoch numbers by
first-frame order after collection, never by the numeric stream value. If the
field is supported but blank on one row, that row may join an existing group
only when exactly one nonterminal group has the same canonical tuple. If none
exists, create a fallback group. If more than one is eligible, exclude the row
as identity-ambiguous and report a limitation. A later stream-bearing row may
bind an unbound fallback group only when tuple, ordering, and terminal state
make the binding unique; groups are never speculatively merged.

This combines TShark's established tuple-reuse handling with independent
validation. `tcp.stream` alone is rejected because its numbering is local to a
TShark run, can change with input or dissector behavior, and has no cross-capture
meaning. Tuple plus internal epoch alone is rejected as the primary method
because reliably separating all midstream tuple reuse requires more TCP state
than Phase 5 should implement.

If one `tcp.stream` value appears with more than one canonical tuple, the parser
must not merge them. It creates separately keyed collector groups, increments
`stream_tuple_conflicts`, and emits a report limitation
`TCP_STREAM_IDENTITY_CONFLICT`. Conclusions for affected groups are `limited`.

### 4.3 Tuple/epoch fallback

Epoch indices begin at `1` per canonical tuple:

- The first eligible row creates epoch 1.
- Repeated SYN without ACK in the same direction and with the same initial
  sequence number before establishment remains in the epoch and may count as a
  SYN retry.
- A new SYN after a terminal RST or completed FIN exchange creates the next
  epoch.
- A new SYN after a midstream epoch with no observed terminal boundary creates
  a new epoch but records `TCP_TUPLE_REUSE_AMBIGUOUS` on both adjacent epochs.
- A new SYN with a different initial sequence number while a nonterminal,
  handshake-started epoch is active does not silently split or merge. It
  creates a new epoch and records the same ambiguity.
- Rows after a terminal boundary remain in the terminal epoch only when TShark
  associates them with the same stream; fallback grouping starts a new epoch
  only on a new SYN. Otherwise they are retained as post-terminal observations
  and qualified.
- A capture beginning midstream creates one midstream epoch. Phase 5 does not
  guess at earlier unseen epochs.

Sequence equality uses unsigned 32-bit raw values when capability detection
finds raw sequence fields. If only relative values are available, retry and
acknowledgment matching is disabled and a limitation is emitted; flag/order
observations continue.

### 4.4 Tunnels and multiple header occurrences

The initial parser analyzes one final directly decoded TCP header and the
layer-consistent IP header enclosing it. It does not create separate outer and
inner conversations or correlate tunnels. A row with multiple candidate TCP
headers or an IP/TCP association that cannot be made deterministically is
excluded from conversation tracking and counted under
`ambiguous_encapsulation_rows`. This becomes
`TCP_ENCAPSULATED_IDENTITY_UNSUPPORTED`, not silent loss.

### 4.5 Public identifiers

After collection, conversations sort by:

1. first valid frame number;
2. canonical endpoint A;
3. canonical endpoint B;
4. epoch index.

They receive `tcp-000001`, `tcp-000002`, and so on. IDs are stable for identical
normalized input and tool capabilities within one report schema. They are not
cross-capture correlation identifiers. Future correlation must use explicit
matching evidence rather than equality of these IDs.

## 5. Initiator and role inference

Role inference is deterministic and evidence-labeled.

### 5.1 Observed initiator

- The endpoint sending the first ordered SYN without ACK is the
  `observed_initiator`.
- A matching SYN/ACK from the opposite direction supports that observation.
- SYN packets from both directions before a SYN/ACK constitute simultaneous
  open. `observed_initiator` is `null`, and both endpoints are recorded in role
  evidence.
- Midstream traffic, SYN/ACK without the preceding SYN, or a missing direction
  leaves `observed_initiator` `null`.

### 5.2 Inferred client and server

Evidence strength uses a closed string enum:

- `observed`: direct handshake-role evidence is visible.
- `supported`: a SYN/SYN-ACK pattern supports conventional initiator/responder
  roles, but not application semantics.
- `suggested`: only secondary port convention supports the role.
- `unknown`: evidence is absent, contradictory, or simultaneous.

Rules, in precedence order:

1. A complete ordered SYN, SYN/ACK, ACK pattern sets the initiator as inferred
   client and responder as inferred server with `supported` strength.
2. An initial SYN without ACK, even if unanswered, supports only observed
   initiator; client/server remain `unknown` unless secondary evidence applies.
3. Port convention may weakly suggest roles only when exactly one endpoint uses
   a system port (`0`–`1023`) and the other uses a dynamic/private port
   (`49152`–`65535`). This produces `suggested`, never `observed` or
   `supported`.
4. Registered ports, equal port classes, simultaneous open, contradictory
   handshakes, and midstream conversations remain `unknown`.

No service-name lookup is performed. Lower port alone is never proof of server
role. Reports separately serialize observed initiator, inferred client,
inferred server, evidence basis, and evidence strength.

## 6. Required TShark evidence

TShark must be invoked directly with an argument list, `-n`, `-r`, `-T fields`,
an explicit tab separator, and deterministic occurrence/aggregation settings.
The capture is read only. A TCP display filter may be applied as `-Y tcp`
because it reduces transferred rows after dissection without changing TCP
analysis state. No name resolution or live interface is allowed.

The initial argument structure is:

```text
tshark -n -r CAPTURE_PATH -Y tcp -T fields
  -E separator=\t -E quote=n -E occurrence=f
  -e frame.number ... -e tcp.analysis.initial_rtt
```

It must be constructed as an argument list, not a shell string. The existing
`occurrence=f` convention is safe only for a single unambiguous IP/TCP stack.
`frame.protocols` must exclude tunneled or repeated IP/TCP stacks from initial
conversation tracking rather than pairing a first outer IP occurrence with an
unrelated inner TCP header.

Field capabilities must be queried dynamically. Required raw identity/boundary
fields failing capability detection are an operational incompatibility.
Optional raw or derived fields disable only dependent behavior and create
explicit limitations.

| Field | Purpose | Layer/type | Absence and authority |
|---|---|---|---|
| `frame.number` | Ordering and evidence reference | Raw frame; positive integer | Required; malformed is fatal. Authoritative for capture order. |
| `frame.time_epoch` | Duration and intervals | Raw capture metadata; finite decimal epoch | Required; malformed is fatal. It is an observed timestamp, not true event time. |
| `frame.interface_id` | Observation context | Raw capture metadata; optional string/integer token | Missing is allowed and limits interface attribution. |
| `frame.cap_len` | Captured byte count | Raw frame; non-negative integer | Optional per row; malformed value is ignored and counted. |
| `frame.len` | Reported original frame bytes | Raw frame; non-negative integer | Optional per row; not payload bytes. |
| `frame.protocols` | Validate selected IP/TCP layering | TShark dissection path; colon-delimited string | Required for encapsulation safety; not a topology fact. |
| `ip.src`, `ip.dst` | IPv4 endpoints | Raw IPv4 header; canonical address | One IPv4 or IPv6 pair is required. Multiple ambiguous occurrences exclude the row. |
| `ipv6.src`, `ipv6.dst` | IPv6 endpoints | Raw IPv6 header; canonical address | Same handling as IPv4. |
| `tcp.stream` | Primary within-run grouping hint | TShark-derived; non-negative integer | Optional capability. Never externally authoritative or cross-capture stable. |
| `tcp.srcport`, `tcp.dstport` | Endpoint ports and direction | Raw TCP header; integer 0–65535 | Required for conversation tracking. |
| `tcp.seq_raw`, `tcp.ack_raw` | Retry and ACK matching | Raw TCP header; unsigned 32-bit integer | Preferred, capability-detected. Missing disables exact matching. |
| `tcp.seq`, `tcp.ack` | Display/debug fallback only | TShark-relative integer | Never substitute for raw values without a limitation; not exposed as proof. |
| `tcp.len` | TCP payload length | TShark-derived from headers; non-negative integer | Required for directional payload-byte statistics. It is length only; bytes are never requested. |
| `tcp.hdr_len` | Validate TCP boundary | Raw TCP data offset normalized to bytes | Optional; malformed values count as row warnings. |
| `tcp.window_size_value` | Advertised 16-bit window | Raw TCP header; integer 0–65535 | Optional. Supports raw min/max and zero-window facts. |
| `tcp.window_size` | Effective scaled window | TShark-derived non-negative integer | Optional and capability-sensitive; must be labeled derived. |
| `tcp.flags` | Preserve aggregate flag fact | Raw TCP header; bounded integer/hex | Required as a defensive consistency input. |
| `tcp.flags.syn` | Establishment state | Raw flag; boolean | Required. |
| `tcp.flags.ack` | Handshake/ACK state | Raw flag; boolean | Required. |
| `tcp.flags.fin` | Closure state | Raw flag; boolean | Required. |
| `tcp.flags.reset` | Reset state | Raw flag; boolean | Required. |
| `tcp.analysis.retransmission` | General retransmission indicator | TShark-derived boolean | Optional. Heuristic, never proof of wire loss. |
| `tcp.analysis.fast_retransmission` | Fast-retransmission subtype | TShark-derived boolean | Optional; counted as subtype and once in aggregate. |
| `tcp.analysis.spurious_retransmission` | Spurious-retransmission subtype | TShark-derived boolean | Optional; “spurious” is TShark's classification. |
| `tcp.analysis.lost_segment` | Prior-sequence-gap indicator | TShark-derived boolean | Optional; never call it proven packet loss. |
| `tcp.analysis.duplicate_ack` | Duplicate-ACK indicator | TShark-derived boolean | Optional; count marked frames, not inferred missing packets. |
| `tcp.analysis.out_of_order` | Out-of-order indicator | TShark-derived boolean | Optional; observation-point and capture ordering can affect it. |
| `tcp.analysis.zero_window` | Zero advertised-window indicator | TShark-derived boolean | Optional; raw window value should corroborate when available. |
| `tcp.analysis.window_full` | Sender reached calculated receive-window boundary | TShark-derived boolean | Optional; not proof of application slowness. |
| `tcp.analysis.keep_alive` | Keepalive classification | TShark-derived boolean | Optional. |
| `tcp.analysis.keep_alive_ack` | Keepalive acknowledgment classification | TShark-derived boolean | Optional. |
| `tcp.analysis.ack_lost_segment` | ACK suggests unseen prior segment | TShark-derived boolean | Optional; record separately from `lost_segment`. |
| `tcp.analysis.initial_rtt` | TShark initial RTT estimate | TShark-derived finite decimal seconds | Optional; preserve provenance and do not generalize to path latency. |

`tcp.analysis.*` fields are never authoritative root-cause evidence. If a
derived field is unsupported, only its counter/rule is disabled. Capability
sets and disabled rule codes must be returned by the collector and serialized
in report statistics or limitations.

### 6.1 Three evidence layers

1. **Raw TCP facts:** endpoints, ports, flags, raw sequence/ack values, raw
   advertised window, and header/frame lengths.
2. **TShark-derived indicators:** stream index, relative sequence values,
   effective window, payload length normalization, initial RTT, and every
   `tcp.analysis.*` value.
3. **Packet Investigator interpretations:** handshake/closure state, role
   inference, tuple epochs, findings, statuses, and recommendations.

Every JSON finding evidence key must document its layer. Rich wording must use
“TShark indicated” for layer 2 when omitting a longer provenance explanation.

## 7. Streaming collector and bounded state

### 7.1 Processing contract

The collector performs one TShark pass for TCP evidence and processes stdout
once. It must:

- reuse the current bounded 128-row stdout queue and 8,192-byte stderr limit;
- retain no full row after processing and no packet payload;
- retain only global counters, capability metadata, bounded warnings, and
  bounded per-conversation state;
- preserve frame order and count timestamp regressions without reordering;
- continue stateless counters after conversation capacity is exhausted;
- terminate, then kill after the existing bounded grace period on timeout,
  cancellation, or parser failure; and
- return immutable parser-neutral collection results.

The existing 120-second default timeout remains until measured performance
justifies a change. A later CLI timeout option may expose the existing validated
mechanism; Phase 5's first command does not require it.

### 7.2 Per-conversation retained state

For each tracked conversation retain only:

- canonical identity, epoch, internal grouping basis, and optional internal
  stream number;
- first/last frame and finite timestamp;
- first observed direction;
- observed initiator/role evidence inputs;
- first SYN and SYN/ACK raw sequence values when available;
- handshake stage and bounded stage frame references;
- FIN-seen and FIN-acknowledged state by direction;
- reset count, first reset direction, and bounded reset frames;
- packet, captured-byte, original-frame-byte, and payload-byte counters by
  direction;
- first payload time/frame by direction;
- raw and effective advertised-window minimum/maximum by direction;
- symptom counters, plus bounded first/recent frame samples per symptom;
- TShark initial RTT when available and consistent; and
- limitation flags, never arbitrary warning text.

Do not retain packet objects, payload bytes, every sequence number, every ACK,
or retransmission history. Phase 5 does not implement reassembly, scoreboard
logic, sequence-space validation, or packet-loss calculation.

### 7.3 Exact bounds

- Maximum tracked conversations: **50,000**.
- Maximum representative frames per finding: **8**.
- Sampling policy for repetitive evidence: first four and most recent four
  distinct qualifying frames; final serialization sorts and deduplicates them.
- Maximum retained parser-warning summaries: **100**.
- Each warning summary contains only row number, stable reason code, and at most
  two field names; it must not contain the raw row, addresses, or payload.
- Global warning and unusable-row counters continue beyond 100.

These are validated internal constants in the initial implementation, not CLI
options.

When the 50,001st distinct conversation would be registered:

- do not register it and never evict an existing conversation;
- set `conversation_tracking_complete=false`;
- increment `untracked_conversation_rows` for every later row not belonging to
  an existing tracked conversation;
- continue updating global row, malformed-field, timestamp, interface, and
  capability statistics;
- add `TCP_FLOW_TRACKING_LIMIT_REACHED`;
- qualify report-wide counts and findings as applying only to tracked
  conversations; and
- set overall status to at least `limited`.

Merely reaching exactly 50,000 does not mark tracking incomplete. Incompleteness
begins when an additional eligible distinct conversation is encountered.

### 7.4 Malformed and unusable rows

- Wrong column count, invalid frame number, or invalid required timestamp is a
  fatal `TsharkOutputError`; no partial report is emitted.
- Missing/invalid layer-consistent address or port increments
  `unusable_tcp_rows`; the row is excluded from conversations.
- Malformed optional raw or derived values increment
  `malformed_optional_fields`, disable that value for the row, and do not crash.
- Unknown boolean spellings for analysis indicators are malformed optional
  values, never truthy by accident.
- If no usable TCP rows remain, the report is `insufficient`.
- Any skipped eligible TCP row creates a visible limitation. The analyzer must
  not infer a universal malformed-row percentage threshold.

## 8. Domain model proposal

All public models use strict, frozen Pydantic configuration, tuples for ordered
collections, non-negative strict integers for counters, finite non-negative
floats for durations, timezone-aware datetimes, and defensive copies for
mappings. Booleans are rejected where integers are expected. Unknown stable
finding codes remain strings so additive codes are forward compatible.

### 8.1 Core identity and direction

#### `Endpoint`

| Field | Type | Requirement |
|---|---|---|
| `ip_version` | `Literal[4, 6]` | Required and consistent with address. |
| `address` | IPv4/IPv6 address type | Required; canonical string in JSON. |
| `port` | strict integer `0..65535` | Required. |

No hostname or service name is stored.

#### `TCPConversationIdentity`

| Field | Type | Requirement |
|---|---|---|
| `conversation_id` | machine string `tcp-\d{6}` | Required; report-local. |
| `endpoint_a` | `Endpoint` | Required; canonical lower endpoint. |
| `endpoint_b` | `Endpoint` | Required; canonical higher endpoint. |
| `protocol` | `Literal["tcp"]` | Required. |
| `epoch` | positive strict integer | Required; starts at 1 per tuple. |
| `grouping_basis` | `TCPGroupingBasis` | Required: `stream_and_tuple` or `tuple_epoch`. |

TShark stream number is collector metadata and is not serialized in this
identity.

#### `TCPDirection`

String enum: `a_to_b`, `b_to_a`, `unknown`. `unknown` is permitted only for
report-level or role evidence, never for a packet assigned to a conversation.

#### `TCPRole`

String enum: `client`, `server`, `unknown`, `ambiguous`.

#### `TCPRoleEvidence`

| Field | Type | Requirement |
|---|---|---|
| `observed_initiator` | `Literal["a", "b"] \| None` | Null unless a qualifying SYN establishes it. |
| `inferred_client` | `Literal["a", "b"] \| None` | Null when unknown/ambiguous. |
| `inferred_server` | `Literal["a", "b"] \| None` | Null when unknown/ambiguous. |
| `endpoint_a_role` | `TCPRole` | Required. |
| `endpoint_b_role` | `TCPRole` | Required. |
| `strength` | `TCPRoleEvidenceStrength` | `observed`, `supported`, `suggested`, or `unknown`. |
| `basis` | tuple of `TCPRoleEvidenceBasis` | Ordered stable values such as `syn_without_ack`, `syn_ack_response`, `system_to_dynamic_port`, `simultaneous_open`, `midstream`. |
| `observation` | non-empty string | Human-readable evidence statement. |

### 8.2 Statistics and state assessments

#### `TCPDirectionalStatistics`

Fields: `direction`, `packets`, `captured_bytes`, `original_frame_bytes`,
`payload_bytes`, `first_frame`, `last_frame`, `first_time`, `last_time`,
`first_payload_frame`, `first_payload_time`, `minimum_window_value`,
`maximum_window_value`, `minimum_effective_window`, and
`maximum_effective_window`. Optional boundary fields are all present as JSON
`null` when unavailable. Byte counters are observed sums and must not be called
application throughput.

#### `TCPConversationStatistics`

Fields: `first_frame`, `last_frame`, `first_time`, `last_time`,
`duration_seconds`, `a_to_b`, `b_to_a`, `interfaces`, and
`rows_with_optional_parse_errors`. Duration is final observed timestamp minus
first observed timestamp, or `null` if boundaries are unavailable. Interface
IDs are deterministically sorted strings.

#### `TCPHandshakeAssessment`

Fields:

- `state`: `complete`, `incomplete`, `midstream`, `simultaneous_open`,
  `not_observed`, or `ambiguous`;
- `syn_frame`, `syn_ack_frame`, `final_ack_frame`: optional positive integers;
- `syn_time`, `syn_ack_time`, `final_ack_time`: optional aware datetimes;
- `syn_retries`, `syn_ack_retries`: non-negative integers;
- `syn_to_syn_ack_seconds`, `syn_ack_to_ack_seconds`: optional finite
  non-negative floats;
- `sequence_matching_available`: boolean;
- `evidence_strength`: deterministic enum; and
- `limitations`: stable code tuple.

`complete` means an ordered three-stage pattern was observed and, when raw
sequence capability exists, acknowledgment values match modulo 2^32. It does
not prove no packet was missing.

Exact matching requires:

- SYN/ACK acknowledgment equals `(SYN sequence + 1) mod 2^32`; and
- final ACK acknowledgment equals `(SYN/ACK sequence + 1) mod 2^32`.

The final ACK may carry payload. A repeated matching stage updates retry
counters without replacing the first stage frame or timestamp.

#### `TCPClosureAssessment`

Fields:

- `state`: `orderly`, `reset`, `fin_incomplete`, `not_observed`, or
  `ambiguous`;
- first FIN frame/time by direction;
- FIN-acknowledgment frame by direction when sequence matching is available;
- first reset frame/time/direction;
- `reset_count`; and
- stable limitation codes.

`orderly` requires FIN in both directions and acknowledgment of both FIN
sequence spaces when raw matching is available. Otherwise an ordered
bidirectional FIN pattern may be recorded but remains `ambiguous`.

#### `TCPSymptomCounters`

Non-negative strict counters:

- `retransmission_indicator_frames`;
- `fast_retransmission_indicator_frames`;
- `spurious_retransmission_indicator_frames`;
- `lost_segment_indicator_frames`;
- `ack_lost_segment_indicator_frames`;
- `duplicate_ack_indicator_frames`;
- `out_of_order_indicator_frames`;
- `zero_window_indicator_frames`;
- `window_full_indicator_frames`;
- `keepalive_indicator_frames`; and
- `keepalive_ack_indicator_frames`.

A packet carrying multiple retransmission subtype fields increments aggregate
retransmission once and each applicable subtype once.

#### `TCPConversationTiming`

Fields: `conversation_duration_seconds`, `syn_to_syn_ack_seconds`,
`syn_ack_to_final_ack_seconds`, `tshark_initial_rtt_seconds`,
`time_to_first_payload_a_to_b_seconds`,
`time_to_first_payload_b_to_a_seconds`, and `availability`.
`availability` is a tuple of stable labels:
`timing_observed`, `timing_not_available`,
`timing_limited_by_midstream_capture`,
`timing_limited_by_missing_direction`,
`timing_limited_by_timestamp_quality`, and
`timing_tshark_derived`.

### 8.3 Evidence, findings, limitations, and actions

#### `TCPConversationEvidence`

Fields: `provenance`, `values` as an immutable scalar mapping, and
`representative_frames` as a sorted unique tuple of at most eight positive
integers. Serialization produces a normal JSON object and array.

#### `TCPConversationFinding`

Fields:

- `code`: stable uppercase string;
- `category`: `handshake`, `termination`, `delivery`, `flow_control`, or
  `activity`;
- `severity`: `informational` or `warning`;
- `observation`: required factual text;
- `interpretation`: optional cautious text, serialized as `null`;
- `evidence_strength`: `observed`, `supported`, `suggested`, or `unknown`;
- `evidence`: `TCPConversationEvidence`;
- `limitations`: tuple of stable limitation codes; and
- `recommendation_codes`: tuple of stable recommendation codes.

Severity describes investigative relevance, not outage impact.

#### `TCPConversationLimitation`

Fields: `code`, `description`, and `affected_capabilities`. Codes are stable;
human wording may improve within schema 1.x.

#### `TCPConversationRecommendation`

Fields: `code`, positive `priority`, `action`, and `rationale`.
Recommendations are deduplicated by code at conversation and report levels.

### 8.4 Assessment and report

#### `TCPConversationStatus`

String enum: `complete`, `complete_with_findings`, `partial`, `limited`,
`insufficient`. Section 12 defines reduction.

#### `TCPAnalysisStatus`

String enum: `analyzed`, `analyzed_with_findings`, `limited`, and
`insufficient`. It describes report completeness and the presence of notable
evidence, never TCP or application health.

#### `TCPConversationAssessment`

Fields: `identity`, `roles`, `statistics`, `handshake`, `closure`, `symptoms`,
`timings`, `status`, `status_summary`, `findings`, `limitations`, and
`recommendation_codes`. It contains no source path, packet rows, or payload.

#### `TCPAnalysisStatistics`

Fields:

- `rows_processed`, `usable_tcp_rows`, `unusable_tcp_rows`,
  `malformed_optional_fields`;
- `tcp_conversations`, `tracked_conversation_limit`,
  `conversation_tracking_complete`, `untracked_conversation_rows`;
- `stream_tuple_conflicts`, `ambiguous_encapsulation_rows`;
- counts per conversation status;
- counts per stable finding code in a defensively copied mapping;
- `retained_parser_warnings`, `total_parser_warnings`;
- supported and unsupported derived capability names using Packet Investigator
  capability identifiers, not TShark field names; and
- interface IDs observed.

#### `TCPAnalysisReport`

| Field | Type | Requirement |
|---|---|---|
| `schema_version` | `Literal["1.0"]` | Required TCP report contract version. |
| `tool_version` | non-empty string | Required canonical package version. |
| `capture` | existing privacy-safe `CaptureQualityCapture` | Required; `path` absent by default. |
| `capture_quality_status` | existing quality enum | Required prerequisite result. |
| `capture_quality_limitation_codes` | tuple of strings | Required, filtered to TCP-relevant limitations. |
| `status` | `TCPAnalysisStatus` | Required overall result. |
| `summary` | non-empty string | Deterministic human-readable summary. |
| `analysis_statistics` | `TCPAnalysisStatistics` | Required. |
| `limitations` | tuple | Deduplicated deterministic report-wide limitations. |
| `conversations` | tuple of assessments | All tracked conversations in canonical order. |
| `recommendations` | tuple | Deduplicated deterministic report recommendations. |

Reusing the privacy-safe capture projection avoids duplicating metadata logic.
If a future generic capture projection replaces it, TCP schema 1.x output must
remain byte-for-byte compatible for equal values.

## 9. Deterministic finding taxonomy

### 9.1 Accepted initial findings

Rules run in the order below. A trigger of `count > 0` applies only after the
required capability and minimum evidence checks.

#### 1. `TCP_SYN_RETRY_OBSERVED`

- **Trigger:** At least two SYN-without-ACK packets from the observed initiator
  with the same raw initial sequence before SYN/ACK or terminal state.
- **Evidence:** Retry count and up to eight SYN frames.
- **Interpretation:** The initiator repeated an observed connection attempt; a
  response may have been delayed, absent, or invisible.
- **Limitations:** Capture duplication and missing opposite direction.
- **Action:** Capture both directions and compare endpoint TCP counters.
- **Severity:** Warning.

#### 2. `TCP_SYN_ACK_RETRY_OBSERVED`

- **Trigger:** Repeated matching SYN/ACK from the responder before final ACK.
- **Interpretation:** The responder repeated its observed handshake response;
  the final ACK may have been delayed, absent, or invisible.
- **Action:** Capture both endpoints or compare observation points.
- **Severity:** Warning.

#### 3. `TCP_HANDSHAKE_INCOMPLETE`

- **Trigger:** An opening SYN is visible, the ordered handshake is not complete,
  and the epoch is neither classified midstream nor completed by simultaneous
  open rules.
- **Evidence:** Which stages and directions were observed.
- **Interpretation:** The handshake did not complete within visible evidence.
- **Limitations:** Missing packets may be a real symptom, outside the capture
  window, filtered, or invisible at this point.
- **Action:** Begin capture before reproduction and observe both directions.
- **Severity:** Warning.
- **Suppression:** Suppressed by `TCP_MIDSTREAM_CONVERSATION`.

#### 4. `TCP_MIDSTREAM_CONVERSATION`

- **Trigger:** Payload, non-SYN ACK behavior, or FIN is observed before an
  opening SYN for the epoch.
- **Interpretation:** The connection may have been established before capture,
  or opening packets may be absent.
- **Action:** Begin capture earlier.
- **Severity:** Informational.
- **Precedence:** Suppresses incomplete-handshake and role assertions based only
  on port convention.

#### 5. `TCP_SIMULTANEOUS_OPEN_OBSERVED`

- **Trigger:** SYN without ACK appears from both directions before SYN/ACK.
- **Interpretation:** The observed flags are consistent with TCP simultaneous
  open.
- **Limitations:** Duplicate capture paths or tuple ambiguity can imitate the
  pattern.
- **Action:** Confirm behavior at both endpoints when relevant.
- **Severity:** Informational.

#### 6–8. Reset findings

- `TCP_RESET_AFTER_SYN`: RST occurs after opening SYN but before completed
  establishment.
- `TCP_RESET_AFTER_ESTABLISHMENT`: RST occurs after complete handshake or
  established midstream behavior.
- `TCP_RESET_OBSERVED`: RST occurs when stage cannot be classified.

Only the most specific reset code is emitted per conversation. Evidence records
reset direction, count, first reset frame/time, and stage. Wording states that
the endpoint sent a packet with RST; it does not identify the process, device,
or reason. Recommended action is to review endpoint/application logs at the
observed time and compare capture points. Severity is warning.

#### 9. `TCP_CLOSE_STATE_INCOMPLETE`

- **Trigger:** FIN is observed in only one direction, or both FINs are visible
  but required acknowledgments cannot be observed or matched; no RST
  supersedes closure.
- **Interpretation:** Only part of an orderly close was visible.
- **Limitations:** Capture may have stopped, a direction may be absent, or the
  connection may have remained half-closed.
- **Action:** Continue capture through closure and capture both directions.
- **Severity:** Informational.
- **Suppression:** Complete orderly closure or any RST suppresses it.

#### 10. `TCP_RETRANSMISSION_INDICATORS_OBSERVED`

- **Trigger:** TShark marks any tracked frame as retransmission, fast
  retransmission, or spurious retransmission.
- **Evidence:** Unique aggregate marked-frame count, subtype counters, and
  representative frames.
- **Interpretation:** TShark identified sequence behavior consistent with
  retransmission at this observation point.
- **Limitations:** Capture duplication, reordering, offload, missing earlier
  packets, and observation placement can affect classification.
- **Action:** Compare indicator timing at another capture point and check
  endpoint TCP statistics.
- **Severity:** Warning.

Fast and spurious variants are counters inside this finding, not separate
findings, preventing redundant conclusions.

#### 11. `TCP_DUPLICATE_ACKS_OBSERVED`

- **Trigger:** TShark duplicate-ACK indicator count is positive.
- **Interpretation:** Repeated acknowledgments were indicated; causes can
  include reordering, missing visible sequence space, receiver behavior, or
  capture artifacts.
- **Action:** Compare sequence behavior at both endpoints.
- **Severity:** Warning.

#### 12. `TCP_OUT_OF_ORDER_INDICATORS_OBSERVED`

- **Trigger:** TShark out-of-order indicator count is positive.
- **Interpretation:** Arrival order at this capture point differed from
  TShark's expected sequence order.
- **Action:** Compare observation points before attributing path reordering.
- **Severity:** Informational.

#### 13. `TCP_LOST_SEGMENT_INDICATORS_OBSERVED`

- **Trigger:** `lost_segment` or `ack_lost_segment` indicator count is positive.
- **Observation:** TShark indicated missing prior sequence context.
- **Interpretation:** A segment may be absent from this capture or from the
  observed path.
- **Forbidden wording:** “Packet loss was proven.”
- **Action:** Compare client and server captures.
- **Severity:** Warning.

#### 14. `TCP_ZERO_WINDOW_OBSERVED`

- **Trigger:** TShark zero-window indicator, corroborated by raw advertised
  window zero when that field is available.
- **Interpretation:** The advertising endpoint reported no receive-window space
  in the observed packet.
- **Limitations:** It does not identify why buffer space was unavailable or
  prove application slowness.
- **Action:** Check receiving endpoint TCP/application metrics.
- **Severity:** Warning.

#### 15. `TCP_WINDOW_FULL_OBSERVED`

- **Trigger:** TShark window-full indicator count is positive.
- **Interpretation:** TShark calculated that outstanding data reached the
  advertised receive-window boundary.
- **Limitations:** Depends on TShark state and visibility of both directions.
- **Action:** Investigate receiver pressure and compare endpoint statistics.
- **Severity:** Warning.

#### 16. `TCP_ONE_WAY_PAYLOAD_OBSERVED`

- **Trigger:** Both directions contain at least one usable TCP packet, exactly
  one direction has positive payload bytes, and conversation evidence is not
  limited by known direction loss.
- **Interpretation:** TCP payload was observed in one direction only during the
  capture window.
- **Limitations:** Request/response semantics are unknown; one-way application
  transfer may be expected.
- **Action:** Correlate with application timing and capture through the expected
  response.
- **Severity:** Informational.

#### 17. `TCP_KEEPALIVE_ACTIVITY_OBSERVED`

- **Trigger:** TShark keepalive or keepalive-ACK count is positive.
- **Interpretation:** TShark classified observed packets as keepalive activity.
- **Limitations:** This is not a failure and depends on sequence context.
- **Action:** None by default; it supplies context to other findings.
- **Severity:** Informational.

### 9.2 Normal state stored outside findings

`TCP_HANDSHAKE_COMPLETE` and `TCP_ORDERLY_CLOSE_OBSERVED` are not findings in
the initial release. They are explicit handshake and closure model states and
summary-table facts. Emitting a finding for every normal conversation would
inflate reports and obscure notable evidence.

### 9.3 Deferred findings

- Standalone `TCP_FAST_RETRANSMISSION_INDICATORS_OBSERVED` and
  `TCP_SPURIOUS_RETRANSMISSION_INDICATORS_OBSERVED`: consolidated into the
  retransmission finding.
- `TCP_CONNECTION_OPEN_AT_CAPTURE_END`: absence of FIN/RST is too weak to call
  an abnormal condition; closure remains `not_observed`.
- `TCP_ROLE_AMBIGUOUS`: represented as role evidence and a limitation, not a
  repetitive finding.
- `TCP_NO_PAYLOAD_OBSERVED`: normal for failed attempts, probes, and control
  connections; retain statistics.
- `TCP_SMALL_ADVERTISED_WINDOW_OBSERVED`: no universal defensible threshold.
- `TCP_DELAY_BEFORE_FIRST_RESPONSE_OBSERVED`: requires a transport-safe
  request/response definition or user context.
- `TCP_SHORT_LIVED_CONNECTION`: no universal duration threshold.
- `TCP_LOW_EVIDENCE_CONVERSATION`: represented by status and limitations.

## 10. Rule precedence, consolidation, and ordering

Rule order is the accepted-finding order in section 9.

- Midstream suppresses incomplete handshake.
- Simultaneous open sets role ambiguity; incomplete handshake may coexist only
  when the simultaneous-open pattern itself lacks later establishment.
- Exactly one reset finding is selected using stage-specific precedence.
- RST suppresses open/FIN-incomplete closure interpretation.
- Complete FIN closure suppresses `TCP_CLOSE_STATE_INCOMPLETE`.
- Fast/spurious retransmission flags contribute to the single aggregate
  retransmission finding.
- Retransmission, duplicate ACK, out-of-order, and lost-segment findings may
  coexist because they are distinct observations, but interpretations and
  recommendations are deduplicated.
- A missing derived capability suppresses only dependent rules and creates a
  limitation.
- Empty and TCP-free captures create no conversations or conversation
  findings.
- Report-wide direction loss limits handshake, role, ACK, flow-control, and
  timing conclusions.

Ordering:

- conversations use section 4.5 ordering;
- findings preserve section 9 rule order;
- finding frame references are ascending unique integers;
- limitations use a fixed catalog order, then conversation order;
- recommendations use positive catalog priority, then catalog order;
- capability names and interface IDs use deterministic normalized ordering.

No unordered set iteration may affect public output.

## 11. Timing analysis

Supportable observed intervals:

- conversation duration: last observed timestamp minus first;
- SYN to matching SYN/ACK interval when both are visible;
- SYN/ACK to matching final ACK interval;
- TShark `initial_rtt`, labeled TShark-derived;
- time from first observed conversation packet to first payload in each
  direction; and
- time between first payload observations as two separate facts, not automatic
  request/response latency.

All timestamps must be timezone-aware UTC in models and RFC 3339/ISO 8601
strings in JSON. Decimal epoch values should be used during collection to avoid
premature binary floating-point loss; public durations are finite seconds with
documented microsecond precision.

Do not infer:

- path RTT from one-direction visibility;
- server, client, network, or application slowness;
- request-to-response time without a defined request boundary;
- causal delay from a capture-point interval;
- synchronized timing across interfaces or captures; or
- a universal “high latency” threshold.

No timing finding is emitted in the initial release. The report presents
intervals with availability labels. Timestamp regression, multiple interfaces,
midstream start, missing direction, or capture-quality timing limitations add
`TCP_TIMING_INTERPRETATION_LIMITED`.

## 12. Status models

### 12.1 Per-conversation status

From least to most constrained:

- `complete`: establishment and terminal state are sufficiently observed, no
  warning finding exists, and no material conversation limitation applies.
- `complete_with_findings`: establishment and terminal state are sufficiently
  observed, but one or more warning/notable findings exist.
- `partial`: meaningful conversation evidence exists, but start or closure is
  not visible; ordinary partial capture context is explicit.
- `limited`: identity conflict, known direction loss, unusable relevant rows,
  severe capture-quality constraint, or unavailable required capability
  prevents reliable answers to material TCP questions.
- `insufficient`: too little usable evidence remains to characterize the
  conversation beyond its tuple. Such groups should normally be omitted and
  counted rather than emitted.

Reduction precedence is `insufficient > limited > partial >
complete_with_findings > complete`. A midstream conversation is at least
`partial`. Missing closure alone makes a handshake-complete conversation
`partial`, not faulty. A warning finding changes otherwise complete to
`complete_with_findings`.

### 12.2 Overall TCP status

- `analyzed`: at least one conversation was analyzed, collection completed, no
  notable findings exist, and material report limitations are absent.
- `analyzed_with_findings`: analysis completed and findings or ordinary partial
  visibility exist, while useful TCP conclusions remain.
- `limited`: tracking was incomplete, capture quality was `limited`, required
  TCP identity/state capabilities were materially unavailable, report-wide
  direction visibility was missing, or all conversations are limited.
- `insufficient`: capture quality has no packet evidence, no usable TCP
  conversations exist, or the capture contains no TCP.

Precedence is `insufficient > limited > analyzed_with_findings > analyzed`.
Individual limited conversations do not force the entire report to `limited`
when other conversations are analyzable; they force
`analyzed_with_findings` and remain individually limited. Report-wide
limitations do force `limited`.

No numeric health, performance, or confidence score is permitted.

## 13. Limitations and recommendations

### 13.1 Stable report/conversation limitation codes

Initial catalog order:

1. `TCP_FLOW_TRACKING_LIMIT_REACHED`
2. `TCP_STREAM_IDENTITY_CONFLICT`
3. `TCP_TUPLE_REUSE_AMBIGUOUS`
4. `TCP_ENCAPSULATED_IDENTITY_UNSUPPORTED`
5. `TCP_UNUSABLE_ROWS_SKIPPED`
6. `TCP_HANDSHAKE_NOT_VISIBLE`
7. `TCP_CLOSE_NOT_VISIBLE`
8. `TCP_DIRECTION_NOT_VISIBLE`
9. `TCP_ROLE_INFERENCE_LIMITED`
10. `TCP_RAW_SEQUENCE_FIELDS_UNAVAILABLE`
11. `TCP_TSHARK_ANALYSIS_FIELDS_UNAVAILABLE`
12. `TCP_TSHARK_ANALYSIS_FIELDS_PARTIAL`
13. `TCP_TSHARK_ANALYSIS_DEPENDENCY`
14. `TCP_TIMING_INTERPRETATION_LIMITED`

`TCP_TSHARK_ANALYSIS_DEPENDENCY` accompanies findings based on TShark analysis
indicators and does not alone set report status to `limited`. Complete absence
of all requested delivery/flow-control indicator capabilities does.

### 13.2 Recommendation catalog

Stable initial recommendations:

1. `CAPTURE_BOTH_DIRECTIONS` — capture both directions at the same observation
   point.
2. `START_CAPTURE_BEFORE_REPRODUCTION` — begin before connection establishment.
3. `CONTINUE_CAPTURE_THROUGH_CLOSURE` — retain the window through expected
   termination.
4. `COMPARE_ENDPOINT_CAPTURES` — compare client-side and server-side captures.
5. `CHECK_ENDPOINT_TCP_STATISTICS` — inspect endpoint TCP counters at the
   observed time.
6. `REVIEW_LOGS_AT_RESET_TIME` — review endpoint and application logs aligned
   to the observed reset.
7. `INVESTIGATE_RECEIVER_PRESSURE` — correlate zero-window/window-full evidence
   with receiver metrics.
8. `COMPARE_DELIVERY_INDICATORS_ACROSS_CAPTURE_POINTS` — determine where
   sequence indicators first appear.
9. `VALIDATE_MTU_SEPARATELY` — collect ICMP/PMTUD and path evidence only when
   independent symptoms justify it.

The MTU recommendation is not linked merely because retransmission indicators
exist. Recommendations are emitted only when referenced by a finding or
limitation, deduplicated by code, and sorted by catalog priority.

## 14. Rich terminal report

Section order:

1. `Packet Investigator — TCP Conversation Analysis`
2. capture filename; path only if already present in the report
3. overall textual status and exact stored summary
4. report-wide limitations
5. conversation summary table
6. selected conversation detail sections
7. findings and timing observations within each selected detail
8. aggregate statistics
9. deduplicated recommendations
10. scope statement: TCP evidence only; no root-cause or ownership conclusion

Summary columns:

- conversation ID;
- endpoint A ↔ endpoint B;
- observed initiator;
- packets A→B / B→A;
- payload bytes A→B / B→A;
- duration;
- handshake state;
- closure state;
- resets;
- retransmission-indicator frames; and
- conversation status.

Bounds:

- Show at most 20 summary conversations by default.
- Show detail for at most 5 conversations.
- Rank terminal selection by `limited`, `partial`,
  `complete_with_findings`, `complete`, then first frame and conversation ID.
- Print “Showing N of M conversations” whenever any are omitted.
- JSON always retains every tracked conversation; terminal bounds do not alter
  the model.

Use restrained semantic Rich styles and textual labels; color is never the only
indicator. Endpoints may wrap, but values must not be silently truncated.
At constrained widths, render one conversation summary per compact block
instead of dropping columns. Width changes layout only, never selection,
ordering, values, or analysis.

The renderer receives `TCPAnalysisReport` and contains no thresholds, status
reduction, role inference, or finding generation.

## 15. JSON schema

TCP JSON schema begins at `"1.0"` independently of capture-quality schema.
Equal reports produce identical JSON text. Collections preserve model order.
Enums serialize as lowercase strings. Large counters remain JSON integers;
consumers must support integers beyond 32-bit range. Timestamps are timezone-
aware ISO 8601 strings. Optional measurement fields serialize as `null`;
privacy-excluded `capture.path` is omitted entirely.

Representative compact example:

```json
{
  "schema_version": "1.0",
  "tool_version": "0.5.0",
  "capture": {
    "filename": "synthetic-handshake-close.pcapng",
    "capture_format": "PCAPNG",
    "size_bytes": 2048,
    "packet_count": 10,
    "start_time": "2026-08-01T14:00:00+00:00",
    "end_time": "2026-08-01T14:00:01+00:00",
    "duration_seconds": 1.0,
    "interface_ids": ["0"],
    "tshark_version": "4.6.6",
    "inspection_status": "Inspection complete"
  },
  "capture_quality_status": "usable",
  "capture_quality_limitation_codes": [],
  "status": "analyzed",
  "summary": "One TCP conversation was analyzed with no notable TCP findings.",
  "analysis_statistics": {
    "rows_processed": 9,
    "usable_tcp_rows": 9,
    "unusable_tcp_rows": 0,
    "tcp_conversations": 1,
    "tracked_conversation_limit": 50000,
    "conversation_tracking_complete": true
  },
  "limitations": [],
  "conversations": [
    {
      "identity": {
        "conversation_id": "tcp-000001",
        "endpoint_a": {
          "ip_version": 4,
          "address": "192.0.2.10",
          "port": 443
        },
        "endpoint_b": {
          "ip_version": 4,
          "address": "198.51.100.20",
          "port": 49152
        },
        "protocol": "tcp",
        "epoch": 1,
        "grouping_basis": "stream_and_tuple"
      },
      "roles": {
        "observed_initiator": "b",
        "inferred_client": "b",
        "inferred_server": "a",
        "endpoint_a_role": "server",
        "endpoint_b_role": "client",
        "strength": "supported",
        "basis": ["syn_without_ack", "syn_ack_response"],
        "observation": "Endpoint B sent the first observed SYN without ACK."
      },
      "status": "complete",
      "handshake": {
        "state": "complete",
        "syn_frame": 1,
        "syn_ack_frame": 2,
        "final_ack_frame": 3
      },
      "closure": {
        "state": "orderly",
        "reset_count": 0
      },
      "findings": [],
      "limitations": [],
      "recommendation_codes": []
    }
  ],
  "recommendations": []
}
```

The example is representative, not permission to omit required model fields in
actual schema output. A complete contract test must serialize every required
field.

Schema rules:

- additive optional fields are allowed within 1.x;
- removing fields, changing enum/code meaning, or changing null/omission
  behavior requires schema 2.0;
- unknown finding and limitation codes must be preserved by generic consumers;
- unknown enum values fail strict model validation;
- conversation IDs are report-local and must not be used for cross-report
  joins; and
- IP addresses and ports are stable automation fields but sensitive metadata.

## 16. CLI and exit codes

### 16.1 Command shape

Use:

```bash
packet-investigator tcp CAPTURE_PATH
packet-investigator tcp CAPTURE_PATH --json
```

The flat command matches existing `inspect` and `quality`. `packet-investigator
analyze tcp` is rejected initially because it introduces a command group for
one analyzer and redesigns established navigation. Future protocol commands
may revisit grouping in a separately reviewed compatibility decision.

Initial inputs:

- required capture path;
- `--json`.

Do not initially expose `--top`, `--conversation`, `--include-complete`,
`--no-color`, flow limits, evidence limits, or analysis thresholds. Rich output
uses fixed documented bounds, JSON contains all tracked conversations, and Rich
respects normal terminal color behavior. Filtering a stored report can be added
later without changing analysis.

The CLI reuses existing validation and typed TShark operational exceptions. It
prints expected errors concisely without tracebacks. JSON success emits JSON
only on stdout. No protocol logic or formatting is duplicated in `cli.py`.

### 16.2 Exit codes

| Outcome | Exit |
|---|---:|
| `analyzed` | 0 |
| `analyzed_with_findings` | 0 |
| `limited` | 1 |
| expected non-validation TShark/processing failure | 1 |
| `insufficient` | 2 |
| invalid path/argument | 2 |

Ordinary TCP symptoms—including resets, retransmission indicators, duplicate
ACKs, zero windows, and incomplete observed handshakes—do not by themselves
produce a nonzero exit. Automation must inspect JSON status and finding codes.
Although status and operational errors share numeric values for compatibility,
successful JSON contains a report; operational errors write concise stderr and
leave stdout empty.

## 17. Synthetic test strategy

Use documentation addresses (`192.0.2.0/24`, `198.51.100.0/24`,
`2001:db8::/32`), locally administered MAC addresses, fixed UTC timestamps, and
payload lengths/bytes containing no sensitive data. Generate captures into
pytest temporary directories. No production capture is committed.

Unless a scenario intentionally tests capture-quality propagation, an
analyzable fixture must contain at least 10 frames over at least 1.0 second so
Phase 4's short-capture heuristic does not change the expected TCP status.
Additional frames must preserve the TCP behavior under test.

| Scenario | Required packet pattern | Expected evidence/findings | Must not appear | Conversation/report status; CLI |
|---|---|---|---|---|
| Complete handshake and orderly close | SYN, SYN/ACK, ACK, optional data, FIN/ACK both ways | handshake `complete`, closure `orderly` | incomplete, midstream, reset | `complete` / `analyzed`; 0 |
| Handshake/data, capture ends | Complete handshake, bidirectional packets, no FIN/RST | close `not_observed` and close limitation | reset, incomplete close finding | `partial` / `analyzed_with_findings`; 0 |
| SYN retries, no response | Same SYN/ISN repeated | SYN retry and incomplete handshake | reset, established reset | `partial` / `analyzed_with_findings`; 0 |
| SYN/SYN-ACK/ACK then RST | Complete handshake, RST | reset after establishment | generic reset, orderly close | `complete_with_findings` / `analyzed_with_findings`; 0 |
| Immediate RST after SYN | SYN then opposite RST | reset after SYN | reset after establishment | `partial` / `analyzed_with_findings`; 0 |
| Midstream bidirectional payload | ACK/payload both directions, no SYN | midstream; role unknown | incomplete handshake, definitive roles | `partial` / `analyzed_with_findings`; 0 |
| One-direction visibility | SYN and later ACK/data-like packets in one direction, no opposite rows | direction/handshake/timing limitations | client/server certainty, one-way payload finding | `limited` / `limited`; 1 |
| Retransmission indicator | Complete/closed conversation plus sequence/ACK pattern verified to trigger TShark | aggregate retransmission indicator | wire-loss claim | `complete_with_findings` / `analyzed_with_findings`; 0 |
| Duplicate ACK | Complete/closed conversation with repeated ACK sequence verified in TShark | duplicate-ACK indicator | proven packet loss | `complete_with_findings` / `analyzed_with_findings`; 0 |
| Out of order | Complete/closed conversation with deliberately reordered sequence frames | out-of-order indicator | path-reordering conclusion | `complete_with_findings` / `analyzed_with_findings`; 0 |
| Zero window | Complete/closed conversation with ACK window zero and context | zero-window finding | endpoint-health cause | `complete_with_findings` / `analyzed_with_findings`; 0 |
| Window full | Complete/closed ACK/data sequence producing TShark indicator | window-full finding | application-slowness conclusion | `complete_with_findings` / `analyzed_with_findings`; 0 |
| Keepalive | Complete/closed conversation containing a sequence pattern TShark recognizes | keepalive activity | failure severity | `complete_with_findings` / `analyzed_with_findings`; 0 |
| IPv6 | IPv6 TCP handshake/data/orderly close | canonical IPv6 endpoints | IPv4 fallback | `complete` / `analyzed`; 0 |
| Multiple conversations | Interleaved complete/closed distinct tuples | deterministic IDs/order | input-set ordering effects | all `complete` / `analyzed`; 0 |
| Four-tuple reuse | Complete close then new complete/closed SYN epoch with a new ISN | epochs 1 and 2 | merged statistics | both `complete` / `analyzed`; 0 |
| Empty capture | Valid PCAPNG, no packets | no conversations | per-conversation findings | `insufficient`; 2 |
| No TCP | Synthetic non-TCP frames | zero TCP conversations | TCP findings | `insufficient`; 2 |
| Malformed structural row | Missing column/invalid frame/time | typed operational error | partial report | operational; 1 |
| Optional malformed fields | Otherwise complete conversation with one malformed optional indicator | warning counter and limitation | crash or truthy coercion | `complete_with_findings` / `analyzed_with_findings`; 0 |
| Tracking exhaustion | 50,001 distinct synthetic row identities | cap limitation, no eviction, continued globals | tracked count above 50,000 | `limited`; 1 |

### 17.1 Reliability of TShark-derived fixtures

Handcrafted captures reliably validate raw flags, endpoints, lengths, windows,
handshakes, resets, FIN, IPv4/IPv6, and tuple reuse. Retransmission,
fast/spurious retransmission, duplicate ACK, lost-segment, out-of-order,
window-full, and keepalive indicators depend on TShark sequence analysis.

For those indicators:

1. define analyzer rule tests using synthetic normalized collector results;
2. define parser tests using synthetic field rows;
3. add a binary-generation scenario only after its TShark output is verified
   on the supported development version;
4. assert normalized indicator semantics, not every incidental field or expert
   message; and
5. capability-skip a specific integration assertion when the field is absent,
   without skipping unrelated tests.

Do not rely entirely on mocked rows, and do not make all unit tests require
TShark.

### 17.2 Test layers

- Model tests: immutability, strict types, address/port validation, enum values,
  timestamp awareness, bounds, null/omission, deterministic round-trip.
- Collector tests: field capability combinations, identity verification,
  streaming, epoch fallback, bounds, counters, malformed policy, timeout, and
  cleanup.
- Analyzer tests: every trigger, exclusion, suppression, precedence, wording,
  status, ordering, and recommendation reference.
- Renderer tests: targeted plain-text ordering and complete JSON contract;
  avoid brittle full-screen snapshots.
- CLI tests: mocked public orchestration, renderer exclusivity, errors, and exit
  mapping.
- End-to-end tests: generated PCAPNG through real inspection, quality, TCP
  collection, analysis, rendering, and CLI; skip precisely when TShark is not
  on `PATH`.

## 18. Performance and operational requirements

- Memory grows with tracked conversations and fixed queues, not packet count.
- The 50,000-conversation cap and per-finding/per-warning bounds are mandatory.
- Counters use Python integers; serialization must preserve exact values.
- Epoch timestamps must be finite and convertible to supported aware datetimes.
  Out-of-range timestamps are structural parser errors.
- Output ordering must not require retaining packets or sorting rows. Only the
  bounded conversation collection is sorted after streaming.
- TShark stdout is continuously drained through the bounded queue; stderr is
  continuously drained with bounded retention to prevent deadlock.
- Timeout covers capability queries, streaming, and child completion.
- Cancellation terminates then kills the child after the existing grace period
  and does not emit a traceback.
- No arbitrary capture-size guarantee is made. Large captures may exceed the
  timeout or conversation cap, both of which are reported explicitly.
- Progress reporting is deferred. If added, it must use stderr/terminal only
  and remain absent from JSON stdout.

Acceptance performance tests include a lazy million-row synthetic iterator
that cannot be iterated twice, cap boundaries at 49,999/50,000/50,001
conversations, evidence sampling beyond eight frames, warnings beyond 100, and
child cleanup on parser failure.

## 19. Privacy and security

- Treat capture paths, contents, and TShark output as untrusted.
- Validate `.pcap`/`.pcapng`, resolve safely, and pass the path as one argument.
- Never use a shell, command string interpolation, live capture, or external
  network access.
- TShark reads the source capture only; Packet Investigator does not modify,
  copy, upload, or delete it.
- Do not request, retain, log, serialize, or render payload bytes.
- Disable network, DNS, and service-name resolution.
- Bound diagnostic stderr and never include raw rows in errors.
- Do not expose environment variables, command environments, or credentials.
- Default terminal and JSON output omit the absolute source path. The Phase 5
  initial CLI has no path-disclosure option.
- Endpoint addresses and ports are necessary conversation metadata and are
  sensitive. Reports must be handled with the same care as captures.
- Models should permit future deterministic address redaction without changing
  finding codes; redaction behavior itself is deferred.
- Tests use only documentation addresses, locally administered MAC addresses,
  fixed synthetic payload bytes, and generated temporary captures.
- Production captures and generated PCAP/PCAPNG files must remain outside Git.

## 20. Implementation milestones

### 5.0 — Engineering specification

- **Scope:** This document and architecture decisions.
- **Expected files:** `docs/specs/phase-5-tcp-conversation-analysis.md`.
- **Tests:** Existing suite unchanged.
- **Acceptance:** Architect approves identity, models, findings, bounds,
  statuses, CLI, JSON, and milestones.
- **Non-goals:** All production implementation.

### 5.1 — TCP domain models

- **Scope:** Frozen strict enums/models and exports only.
- **Expected files:** `models/tcp_conversations.py`, model tests.
- **Tests:** Validation, immutability, serialization, path privacy, bounds,
  unknown finding codes, complete schema example.
- **Acceptance:** Schema 1.0 round-trips deterministically; no analyzer policy in
  validators.
- **Non-goals:** TShark, collection, findings, rendering, CLI.

### 5.2 — Streaming TCP evidence collector

- **Scope:** Capability detection, selected fields, streamed normalization,
  hybrid grouping, epoch fallback, bounded state and immutable result.
- **Expected files:** `parsers/tcp_conversations.py`, parser tests; reuse existing
  TShark wrapper.
- **Tests:** Field rows, stream conflicts, tuple reuse, IPv4/IPv6, all bounds,
  malformed behavior, derived capabilities, timeout/cancellation/cleanup.
- **Acceptance:** One-pass streaming, no payload, no eviction, deterministic
  aggregates.
- **Non-goals:** Findings, status, roles beyond collected facts, renderer, CLI.

### 5.3 — Deterministic TCP analyzer

- **Scope:** Identity projection, role inference, handshake/closure/timing
  assessments, accepted findings, limitations, recommendations, and status.
- **Expected files:** `analyzers/tcp_conversations.py`, analyzer tests.
- **Tests:** Table-driven rules, suppressions, boundary states, ordering,
  purity, unchanged inputs, deterministic equality.
- **Acceptance:** Every finding matches section 9 and no unsupported causal
  language appears.
- **Non-goals:** File I/O, subprocess, Rich/JSON text, CLI.

### 5.4 — Rich and JSON renderers

- **Scope:** Pure presentation of existing reports.
- **Expected files:** `renderers/tcp_conversations.py`, renderer tests.
- **Tests:** Section/order bounds, omitted notice, narrow console, path privacy,
  JSON schema and determinism.
- **Acceptance:** Rich remains readable without color; JSON contains the full
  model and no extra prose.
- **Non-goals:** Analysis, selection thresholds beyond fixed display bounds,
  files, HTML/Markdown/CSV/PDF.

### 5.5 — CLI integration

- **Scope:** `tcp CAPTURE_PATH [--json]` orchestration and exit mapping.
- **Expected files:** `cli.py`, CLI-focused tests.
- **Tests:** Each public boundary called once as designed, chosen renderer only,
  expected errors, all statuses, existing commands unchanged.
- **Acceptance:** No parser/analyzer/renderer logic in CLI; JSON stdout clean.
- **Non-goals:** Additional options or commands.

### 5.6 — End-to-end validation and documentation

- **Scope:** Generated fixtures, real TShark pipeline, README/development
  documentation, compact output examples.
- **Expected files:** fixture generator additions, fixture README, end-to-end
  tests, README and possibly development docs.
- **Tests:** Raw stable scenarios plus capability-aware derived scenarios;
  precise TShark skip behavior.
- **Acceptance:** Real Rich/JSON CLI results and exit codes match this contract;
  no sensitive binary fixture is committed.
- **Non-goals:** Production captures, broad protocol diagnosis.

### 5.7 — v0.5.0 release preparation

- **Scope:** Changelog, canonical version, clean wheel/sdist, fresh-wheel smoke
  tests, distribution/privacy inspection.
- **Expected files:** release documentation and version source only.
- **Tests:** Full quality gates, installed CLI and generated captures.
- **Acceptance:** Tagged only after separate authorization and complete release
  validation.
- **Non-goals:** Phase 6 work, publishing without authorization.

Every milestone must keep Ruff, formatting, strict mypy, pytest, existing
`inspect`/`quality` contracts, and version behavior passing.

## 21. Explicitly deferred capabilities

Phase 5 excludes:

- IP, UDP, ICMP, DNS, TLS, HTTP, SMB, QUIC, RDP, and firewall-policy analysis;
- packet or TCP stream reassembly;
- application payload extraction or storage;
- application transaction/request-response inference;
- cross-capture comparison and multi-point correlation;
- NAT/tunnel correlation and separate inner/outer conversation reports;
- causal packet-loss, latency, endpoint, firewall, or ownership conclusions;
- checksum diagnosis;
- MTU/PMTUD diagnosis;
- live capture;
- machine learning, probabilistic scores, or health scores;
- service-name/DNS resolution;
- automatic report upload or external calls;
- configurable finding thresholds without an architect-approved evidence basis;
- address/port redaction implementation;
- HTML, Markdown, CSV, or PDF reports; and
- support for arbitrarily many conversations without deterministic limits.

## 22. Architecture Decision Records

### ADR-5.1 — Conversation identity is hybrid

**Decision:** Verify TShark `tcp.stream` against a canonical bidirectional tuple
and use it for primary within-run segmentation; use deterministic tuple epochs
as fallback. Public IDs are assigned independently.

**Rationale:** This handles common tuple reuse without treating an unstable
tool-local index as a durable identity.

**Rejected:** `tcp.stream` alone, due to instability and conflict risk; tuple
alone, due to unsafe reuse merging; full internal TCP reconstruction, due to
scope and memory complexity.

### ADR-5.2 — Tracking is bounded without eviction

**Decision:** Track at most 50,000 conversations, eight representative frames
per finding, and 100 warning summaries. Stop new registration only after an
over-cap conversation appears; continue global/existing state and report the
limitation.

**Rejected:** LRU eviction, sampling, and unbounded maps because they silently
change or exhaust analysis.

### ADR-5.3 — Raw and TShark-derived evidence remain distinct

**Decision:** Normalize provenance at the parser boundary. Derived indicators
can trigger cautious findings only when supported; missing fields disable only
dependent rules.

**Rejected:** TShark expert text as authoritative findings and hardcoded version
allowlists.

### ADR-5.4 — Roles are evidence classifications, not guesses

**Decision:** Separate observed initiator from inferred application roles. Use
handshake evidence first and system/dynamic port convention only as a weak
secondary suggestion.

**Rejected:** Lower-port-equals-server and probabilistic role scores.

### ADR-5.5 — Retransmission language describes indicators

**Decision:** Say TShark indicated retransmission-like sequence behavior at the
capture point. Never convert counts to proven wire loss.

**Rejected:** “Packets were lost” and ownership attribution from a single
capture.

### ADR-5.6 — Timing remains factual and threshold-free

**Decision:** Report observed intervals and provenance with limitation labels.
No initial delay finding or universal latency threshold.

**Rejected:** Server/network slowness labels and transport-unsafe
request/response timing.

### ADR-5.7 — Status expresses completeness, not health

**Decision:** Use conversation statuses `complete`,
`complete_with_findings`, `partial`, `limited`, `insufficient` and report
statuses `analyzed`, `analyzed_with_findings`, `limited`, `insufficient`.

**Rejected:** Reusing capture-quality names without semantic review and numeric
health/confidence scores.

### ADR-5.8 — Findings do not make successful analysis fail

**Decision:** Exit 0 for `analyzed` and `analyzed_with_findings`, 1 for
`limited` or expected execution failures, and 2 for `insufficient` or invalid
input. JSON distinguishes status from errors.

**Rejected:** Nonzero exit for every reset/retransmission symptom and a new
elaborate exit-code namespace.

### ADR-5.9 — CLI remains flat

**Decision:** Add `packet-investigator tcp CAPTURE_PATH [--json]` in milestone
5.5.

**Rejected:** `analyze tcp` until multiple analyzers justify a command-group
migration, and option proliferation in the first increment.

### ADR-5.10 — TCP JSON starts at schema 1.0

**Decision:** Serialize immutable models directly with deterministic ordering,
explicit null measurement fields, and omitted private path.

**Rejected:** Ad hoc renderer dictionaries and using tool version as schema
version.

### ADR-5.11 — Payload is never retained

**Decision:** Collect only TCP payload length. No payload bytes enter collector,
models, logs, evidence, or reports.

**Rejected:** Reassembly, samples, and debug payload retention.

### ADR-5.12 — Tuple reuse and midstream ambiguity remain visible

**Decision:** Prefer verified stream segmentation, use conservative fallback
epochs, and expose ambiguous reuse or missing starts as limitations.

**Rejected:** Merging all four-tuple reuse, inventing unseen handshakes, or
discarding midstream conversations.

## 23. Phase 5 acceptance criteria

Phase 5 is complete only when:

- all milestones 5.1 through 5.6 conform to this contract;
- the Phase 4 quality and inspect contracts remain backward compatible;
- public models are immutable, strict, typed, and schema-versioned;
- TShark execution remains direct, read-only, bounded, and cancellable;
- collection is streaming and memory is bounded by documented state limits;
- hybrid identity verifies stream/tuple consistency and handles reuse visibly;
- role inference follows deterministic evidence precedence;
- accepted findings use exact triggers, suppressions, provenance, cautious
  wording, and linked recommendations;
- raw facts, TShark indicators, and Packet Investigator interpretations are
  distinguishable;
- statuses communicate analytical completeness rather than health;
- findings do not cause unsuccessful CLI exits;
- JSON ordering, null/omission behavior, enum values, and path privacy match
  schema 1.0;
- Rich output is bounded and deterministic;
- generated tests cover raw and capability-aware derived evidence without
  private captures;
- no payload, production capture, internal identity, credential, or absolute
  source path is committed or exposed by default;
- Ruff, formatting, strict mypy, and pytest pass; and
- README and release documentation describe only implemented Phase 5 behavior
  at the milestone where it exists.
