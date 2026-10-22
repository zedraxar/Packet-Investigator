# Two-capture comparison — proposed contract

Status: design for human review; no comparison implementation is delivered by
this document. This follows the repository requirement to define an explicit
evidence-correlation contract before endpoint comparison is implemented.

## User outcome and sequence

An engineer supplies two unchanged local captures with labels such as client
and server. The result shows quality at each observation point, candidate TCP
header correspondences, evidence observed only at one point, uncertainty, and
the next useful collection step. Labels describe observation points; they are
not proof of topology, traffic direction, or device responsibility.

The first implementation milestone is a typed report model and pure matcher
over synthetic normalized header records. Then add a bounded TShark collector,
generated real-capture acceptance, CLI orchestration, and terminal/JSON reports
as separate reviewable changes. This avoids starting with UI or network access.

## Initial scope

- Two local PCAP/PCAPNG files, offline; TCP over IPv4/IPv6.
- Explicit observation labels; existing quality assessment for each capture.
- Header-level candidate matching and frame references at both points.
- Preserve existing single-capture commands, schemas, exit codes, and privacy.
- No live capture, upload, payload storage, TLS decryption, inferred topology,
  automatic NAT discovery, proxy-leg matching, loss diagnosis, or blame.

DNS correlation, multi-point comparison, and UI are later designs. Summary
reports from the current TCP command are not sufficient input: they retain
sampled evidence and aggregates, not a complete per-frame comparison stream.

## Input and time contract

Proposed CLI shape (not implemented):

```text
packet-investigator compare LEFT RIGHT --left-label client --right-label server
```

The first increment accepts only untranslated flows and requires either
documented synchronized clocks or an explicit user-supplied clock offset and
tolerance. It must never silently assume that equal timestamps imply
synchronization. Normalized right time is `right_timestamp + offset`; show the
offset, tolerance, and their user-supplied provenance in the report.

Without usable time information, show independent capture evidence and a
`TIME_ALIGNMENT_UNVERIFIED` limitation; do not issue unique correspondence
claims. A fixed offset does not correct drift. Retain timestamp regressions and
overlap limitations. No cross-point timing interval is called network latency.

NAT translation requires a separately reviewed explicit endpoint mapping
extension. Until then, translated or proxy-terminated flows may remain unmatched;
tuple differences are not evidence of dropped traffic. IP identifiers, TTL,
checksums, Ethernet addresses, and local TShark stream numbers are not identities
shared between observation points.

## Evidence and candidate matching

Retain the minimum necessary fields: observation ID, frame number, timestamp,
interface ID when available, address family, source/destination IP/port,
raw TCP sequence and acknowledgment numbers, TCP flags, TCP payload length,
and truncation/quality context. Never collect application payload bytes or a
payload hash. Raw sequence values, rather than TShark relative sequences,
avoid independently chosen sequence origins.

1. Group by the directional endpoint tuple and address family. Do not infer
   client/server role solely from port numbers.
2. Build candidate keys from the directional tuple, raw sequence/acknowledgment,
   relevant TCP flags, and TCP payload length, subject to aligned time tolerance.
3. A one-to-one candidate is a **header correspondence**, not proof that payload
   bytes are identical or that the two frames are the same packet.
4. Repeated/retransmitted headers, duplicate captures, tuple reuse, multiple
   interfaces, and many-to-many candidate sets remain explicitly ambiguous.
   Deterministic ordering must never become an arbitrary tie-breaking match.
5. A frame with no eligible counterpart is **observed only at LEFT/RIGHT within
   the compared evidence and configured window**. It is not a proven loss or
   failure at an intervening firewall.
6. Segmentation/coalescing and truncation can make equal traffic produce unequal
   frame lengths or sequences. Do not invent packet correspondences to compensate.

Report statuses per record: `unique_header_correspondence`, `ambiguous`,
`left_only`, `right_only`, or `not_comparable`. Include both frame references
for candidate correspondences, key fields, time-alignment provenance, reasons,
and limitations. Ambiguous lists must have explicit sample/omission counts.

## Capacity, determinism, and errors

Proposed initial bound: 100,000 retained TCP header records per capture and at
most 8 representative candidate frames per ambiguous group. These are review
parameters, not established performance guarantees. Use indexed bounded groups;
do not enumerate a cross product of repeated headers. Expose records observed,
retained, omitted, and every capacity limit reached. Once tracking is incomplete,
avoid unique/absence conclusions involving omitted evidence.

Use stable IDs derived from observation order/frame order, sorted report output,
strict immutable models, and a new versioned schema. Reject nonfinite/invalid
offsets and tolerances; validate untrusted paths; invoke TShark with argument
lists; use existing timeout/cancellation cleanup. Do not overwrite input files.
For the first CLI increment, operational errors produce stderr and no partial
success JSON. Paths remain absent from reports; endpoint metadata remains
sensitive. Labels must be bounded and rendered as literal text.

## Acceptance before comparison is called implemented

- Pure matcher tests: unique headers, sequence wraparound, directional symmetry,
  identical retransmissions, duplicate records, tuple reuse, ambiguous many-to-many
  groups, offset sign, tolerance boundaries, missing clock assurance, drift,
  timestamp regression, and tracking/sample limits.
- Negative cases: NAT/proxy differences without mapping, missing direction,
  nonoverlapping time windows, offload segmentation, truncation, empty captures,
  missing fields, malformed rows, and subprocess failure/timeout.
- Reordering input must not silently change ambiguity into a unique match.
- Generated two-point PCAPNGs exercised through real TShark on the collector,
  matcher, JSON, and CLI path, with frame assertions and exact pass/skip counts.
- Privacy tests: no source paths or payloads; untrusted label/field text cannot
  inject terminal formatting or executable content.
- Full Ruff, strict typing, pytest, and required CI. Agree exit-code semantics
  and finalize the schema in the model milestone before CLI implementation.
- Human architecture/privacy review, followed by explicit implementation scope
  approval. No automatic merge.

## Following milestones

After two-point comparison proves useful, propose multi-point correlation using
pairwise candidate relationships with explicit observation IDs. Do not infer a
unique transit path from a chain of ambiguous header correspondences.

Additional protocol analysis should follow concrete user investigations. A
possible first candidate is visible TLS handshake evidence, with a separate
field/privacy contract; no decrypted contents or inferred certificate failures
from incomplete visibility. A local desktop selector and shareable report export
follow once their packaging, safe rendering, and metadata/redaction behavior
have approved designs. These remain proposals, not feature commitments.
