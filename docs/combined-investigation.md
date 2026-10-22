# One capture, one investigation

The combined workflow runs the existing offline quality, TCP, and classic DNS
analyzers in one command:

```bash
packet-investigator investigate path/to/capture.pcapng
packet-investigator investigate path/to/capture.pcapng --json
```

Python 3.12+ and TShark on PATH are required. Run against an unchanged local
PCAP/PCAPNG file. This command does not snapshot the file or detect all changes
made by another process while its sequential passes execute.

## Report contract

The terminal starts with quality, TCP, and DNS statuses, then shows the existing
component reports: observations, interpretations, limitations, frame evidence
where available, and next capture recommendations. Each component retains its
scope. Co-occurring DNS and TCP findings do not establish that a name lookup
caused a particular connection failure.

JSON is one document with `schema_version: "1.0"` and `quality`, `tcp`, `dns`
objects. These are the unchanged component schemas. The envelope verifies
matching capture metadata and quality context; it never includes the absolute
source path. Sensitive filenames, endpoint addresses, ports, and DNS names
remain in the report. No upload, payload inspection, decryption, or automatic
redaction is added.

Metadata inspection and quality collection run once, followed by TCP and DNS
collection. Existing record bounds and timeout behavior still apply; the
command makes multiple passes and may take longer than a single analyzer.
JSON retains all tracked component records. Terminal truncation behavior is
the existing component behavior.

## Exit codes and operational errors

- `0`: all stages executed, quality is usable or usable with limitations, and
  no protocol stage reports material analytical limits. Findings alone do not
  mean failure. A capture with no TCP or no in-scope classic DNS can still
  succeed; its empty component retains its insufficient-evidence status.
- `1`: quality is limited, a protocol stage is limited, or protocol rows were
  observed but the corresponding stage reports insufficient evidence.
- `2`: quality is insufficient (for example an empty capture), or the input
  path fails validation.

A capture/TShark execution error exits `1`; a path validation error exits `2`.
Errors go to stderr. A failed stage produces no partial JSON or success report.
An absent classic DNS section does not imply DNS was unused: encrypted DNS,
cached answers, other protocols, and unobserved exchanges remain possible.

There is no desktop file selector, HTML export, packet matching between
captures, technical ownership assignment, or root-cause conclusion in this
increment. Select the file by supplying its local path.
