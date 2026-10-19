# DNS troubleshooting quickstart

Packet Investigator analyzes **visible classic unicast DNS** transactions in a
local PCAP/PCAPNG using TShark. It reports observations, not root causes.

## Run the analysis

```bash
packet-investigator dns capture.pcapng
packet-investigator dns capture.pcapng --json
```

Use the terminal report to triage a capture; use JSON when you need stable,
structured evidence for a local investigation. A normal analyzed report exits
with code `0` (including reports with findings), a limited report with `1`,
and an insufficient-evidence report with `2`. Do **not** interpret exit code
`0` as proof that DNS or the application worked.

## Evidence-first interpretation

| Observed finding | What it establishes | Sensible next check |
| --- | --- | --- |
| Query without response | No matching response was visible in **this capture**. | Verify capture direction, timing, and resolver-side telemetry. |
| Response without query | A response was visible without its matching request. | Capture earlier or at another observation point. |
| SERVFAIL, NXDOMAIN, or REFUSED | A DNS response contained that response code. | Review the resolver's configuration and logs; the code alone does not identify the cause. |
| Repeated query / retry indicator | Repeated matching observations or a TShark retry indicator occurred. | Compare resolver telemetry and capture points; this does not prove packet loss. |
| Truncated response | The DNS truncation bit was set. | Look for a later TCP exchange; truncation alone does not prove a fallback occurred. |
| Ambiguous transaction match | Multiple compatible candidates prevented a unique linkage. | Narrow the capture or compare observation points; do not assign one response to a particular query. |

Inspect the report's **representative frame numbers**, evidence provenance,
limitations, and capture-quality status before drawing conclusions. The
analyzer does not inspect encrypted DNS contents or prove endpoint ownership,
fault, packet loss, or application intent.

## Privacy and scope

Processing is local; there is no automatic capture upload. However, **report
output is still potentially sensitive**: query names, endpoint IP addresses
and ports, and retained A/AAAA/CNAME answer summaries can identify systems or
users. Keep JSON reports and terminal transcripts in approved locations, and
review/redact them before sharing. Capture paths are omitted from DNS reports,
but that does not make the reports anonymous.

For implementation scope and known validation gaps, see
[the DNS implementation audit](dns-implementation-audit.md) and
[the roadmap](../ROADMAP.md). Real-TShark generated acceptance covers the
documented scenarios; cross-version compatibility and independent security
review remain separate gates.
