# TCP header comparison: first implementation milestone

The human-reviewed design is in PR #20, `docs/specs/two-capture-comparison.md`.
This increment implements immutable models and a pure, typed matcher. It does
not read capture files, invoke TShark, register a CLI command, or provide a UI.
Collector and generated two-file acceptance remain the next milestone.

## API

`compare_tcp_headers(left, right, alignment=..., record_limit=100_000)` accepts
two `CaptureHeaders` instances and a `ClockAlignment`. Each input contains
typed raw TCP header records, observation label, tracking completeness/omitted
counts, and a capture-quality limitation flag. Callers must supply actual
collection and quality context; the matcher does not verify the clocks or the
correctness of caller-provided records. Payloads and filesystem paths are not
accepted model fields.

Timestamps and tolerances use integer nanoseconds. The right clock is aligned
as `right.timestamp_ns + right_offset_ns`. The basis must be explicitly
`synchronized` or `user_offset` to enable matching; the default is `unverified`.
A nonzero offset requires user-offset provenance. Tolerances are inclusive at
both boundaries. Drift is not corrected, and intervals are not called latency.

## What the result establishes

Candidate keys contain the directional IPv4/IPv6 endpoint tuple, raw TCP
sequence/acknowledgment, flags, and payload length. Local stream IDs, link
addresses, TTL, and checksums do not participate. Candidate lookup uses indexed
groups and binary search within aligned time windows. Matching keys are header
correspondences only; no payload equality, packet identity, or causal inference
is claimed.

An anchor is unique only when it has one eligible opposite-point candidate
and that candidate has exactly one eligible anchor in reverse. Otherwise the
result is ambiguous. No arrival-order or nearest-time tie-breaking is used.
Repeated headers can therefore remain ambiguous even when they are genuine
retransmissions or duplicate observations. NAT/proxy translations and
segmentation/coalescing differences are not normalized.

Output anchors every retained left frame, plus right frames having no eligible
left candidate. Unique and ambiguous left records include opposite-point header
evidence with frame numbers, timestamps, and interface IDs. Ambiguous groups
retain at most eight candidate records and report the complete candidate count;
the omitted count is their difference. A single forward candidate can remain
ambiguous because it has multiple reverse candidates, recorded separately.
Rows and samples use deterministic frame/time ordering regardless of input
ordering. Source-record bounds are counted separately for both points.

## Conservative limits

Retain at most 100,000 records per point, selecting the lowest frame numbers;
smaller explicit limits are supported. The input tuples are already materialized
by the caller: this API does not claim bounded capture collection. Processing
avoids enumerating a many-to-many candidate cross product; candidate samples
are bounded to eight per output anchor.

Unknown clock assurance, incomplete tracking at either point, or any retained
truncated record disables all matching and one-sided conclusions in this first
milestone. Records are marked `not_comparable`. This deliberately conservative
truncation rule can be refined only with evidence and tests in later increments.
Timestamp regressions and quality flags remain explicit report limitations.
One-sided results mean no eligible header was observed within the supplied
window and matching rules; they never prove loss or identify a responsible
device. Recommendations ask for simultaneous untruncated captures, independent
clock verification, and NAT/proxy/offload/capture-drop telemetry.

## Verification

Synthetic normalized-record tests cover both-sided uniqueness, repeated-header
ambiguity, reverse multiplicity, bounded samples, deterministic reordering,
IPv4/IPv6, direction, sequence wrap, NAT/header/length differences, offset sign,
inclusive tolerance, missing clocks, drift, timestamp regressions, tracking
limits, truncation, empty evidence, malformed input, privacy fields, and immutable
JSON model round trips. These are pure model/matcher tests, not real-TShark or
two-capture end-to-end coverage. Existing analyzer contracts remain unchanged.
