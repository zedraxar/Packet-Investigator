# Compare two local capture files

`compare` connects the approved TCP header matcher to PCAP/PCAPNG files. It
assesses quality independently at both observation points and provides terminal
or JSON reports. Python 3.12+ and TShark on PATH are required.

```bash
packet-investigator compare client.pcapng server.pcapng \
  --left-label client --right-label server --assume-synchronized

packet-investigator compare client.pcapng server.pcapng \
  --clock-offset-ms=-200 --tolerance-ms=2 --json
```

Only supply `--assume-synchronized` after independently checking the clocks.
Alternatively, supply `--clock-offset-ms`: the value is **added to RIGHT
timestamps**. A right clock 200 ms ahead needs `-200`. The inclusive tolerance
defaults to 1 ms. Millisecond values must be finite, within signed 64-bit
nanosecond range, and have whole-nanosecond precision. Synchronization and an
explicit offset are mutually exclusive. Neither option corrects clock drift.

Without either assurance, the command reports `limited` evidence and
`TIME_ALIGNMENT_UNVERIFIED`; it does not silently match timestamps. Observation
labels are user descriptions, not inferred topology or client/server roles.
Provide two distinct, stable local files. Private captures stay local.

## Collection and matching

The command validates paths, inspects metadata, assesses quality, and streams
only frame identity/time/interface/length, IP endpoints, TCP ports, raw
sequence/acknowledgment, flags, and TCP payload **length**. It does not collect
payload bytes, hashes, decrypted content, names, or a full packet dump.
IPv4 and IPv6 are supported. Repeated/encapsulated IP/TCP field occurrences
are omitted as ambiguous instead of selecting a layer. Missing required TShark
field capabilities are operational failures.

`--record-limit N` retains at most N headers per capture (1–100,000; default
100,000). Malformed/oversized rows, duplicate frame records, and capacity
omissions are counted separately. Any omission makes tracking incomplete and
disables correspondence/one-sided conclusions. Raw malformed output is not
retained. A retained truncated frame also disables matching conservatively.
The shared TShark streaming boundary and its timeout behavior are reused;
record bounds are not a guarantee of a hard TShark process-memory ceiling.

Header correspondences require raw directional tuple, sequence, acknowledgment,
flags, length and aligned time eligibility. A unique candidate must be unique
in both directions. Retransmissions and duplicate headers remain ambiguous;
the matcher never chooses a nearest-time tie. Candidate samples contain at
most eight opposite-point frame/header records, with exact omitted counts.
JSON contains all tracked comparison rows and those bounded candidate samples.
Terminal comparison rows are limited to 50 with an explicit omitted count.

No TCP evidence on either side, or insufficient capture quality, prevents a
comparison. Nonoverlapping observed TCP time windows after clock adjustment
also prevent matching. Independent quality and collection summaries are still
reported. There are no one-sided packet claims for those skipped comparisons.

## Reports, errors, and exit codes

The new JSON envelope has `schema_version`, `tool_version`, `status`, labels,
clock `alignment`, `left_quality`, `right_quality`, collection accounting,
optional `comparison`, `limitations`, and recommended next verification steps.
Embedded quality/matcher reports keep their existing schemas. Absolute source
paths are omitted; filenames, endpoint addresses, ports, and timestamps remain
sensitive metadata. Treat output accordingly. Existing single-capture commands
and their exit codes are unchanged.

- `0`: comparison ran with adequate evidence and explicit clock assurance.
  Ambiguous candidates and one-sided observations are findings, not failures.
- `1`: a completed report has material limitations (unverified clocks,
  nonoverlap, incomplete tracking, truncation, or limited capture quality), or
  an operational error prevented a report.
- `2`: insufficient quality/TCP evidence, invalid input paths, or invalid
  options. The presence of JSON distinguishes an analytical result from an
  operational or option error.

Operational errors produce stderr and no partial JSON. Both source paths are
sanitized from expected error messages. File identity/size/modification time
are checked before and after the passes; detected changes fail the command.
This is a metadata stability check, not an atomic content snapshot.

## Interpretation and next steps

A correspondence is header similarity, not proof of payload identity or the
same packet. `left_only`/`right_only` means no eligible header was observed in
the compared evidence/window. It does not prove loss or identify a firewall,
network, endpoint, application, or team as responsible. NAT, proxies, tuple
reuse, segmentation/coalescing, capture drops, asymmetry, and clock drift can
affect results. No network-latency calculation or topology inference is added.

Collect simultaneous untruncated captures, verify clocks/filters independently,
and consult NAT/proxy/offload/capture-drop telemetry before causal conclusions.
The generated acceptance matrix covers identical and offset captures, IPv6,
one-sided evidence, repeated-header ambiguity, truncation, unknown clocks,
nonoverlap, empty captures, and non-TCP captures. These are synthetic offline
tests; compatibility still depends on tested Python/TShark environments.
