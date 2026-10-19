# First local PCAP investigation

This walkthrough uses the implemented **offline** CLI to inspect one authorized
PCAP/PCAPNG capture, assess its quality, and examine TCP or classic DNS evidence.
It does not perform live capture, upload packets, or establish root cause.

## Prerequisites

From an authorized local repository checkout, use Python 3.12 or newer and
install TShark so `tshark` is on your `PATH`:

```bash
tshark --version
python -m pip install .
packet-investigator --help
```

The project is not published to a package index. Installation from a local
checkout is not a release or a guarantee of compatibility across TShark versions.
Use a capture you are authorized to inspect; the repository does not bundle a
customer capture for this walkthrough.

## Four-command workflow

Replace `capture.pcapng` with the path to your local PCAP or PCAPNG file.
Run each command separately; an assessment can return a nonzero exit status
because evidence is limited, even when the capture was processed.

```bash
packet-investigator inspect capture.pcapng
packet-investigator quality capture.pcapng
packet-investigator tcp capture.pcapng
packet-investigator dns capture.pcapng
```

1. **Inspect** reports file/capture metadata and packet boundaries, not a
   protocol diagnosis. Its terminal output includes the resolved local file
   path, so do not share an unreviewed terminal transcript.
2. **Quality** checks whether visible capture evidence is suitable for
   interpretation. Review truncation, midstream, checksum, and visibility
   limitations before interpreting protocol findings.
3. **TCP** reports observed conversation, handshake, reset, retry, and
   flow-control indicators. A retransmission indicator alone does not prove
   packet loss or identify which device is responsible.
4. **DNS** reports visible *classic* DNS query/response evidence, response
   codes, retries, and ambiguous or unmatched transactions. A missing visible
   response does not prove the resolver failed. Encrypted DNS contents are not
   decoded.

Use only the relevant analyzer if your capture has no traffic of the other
protocol. An empty or insufficient report is not evidence that the protocol
was absent everywhere; it describes this capture point and time window.

## Machine-readable reports

To save a local structured report, use the implemented `--json` option:

```bash
packet-investigator quality capture.pcapng --json
packet-investigator tcp capture.pcapng --json
packet-investigator dns capture.pcapng --json
```

These commands write JSON to standard output, so you can redirect it to an
**approved local location** using your shell if needed. Do not automatically
upload or commit reports. IP addresses, ports, DNS names, and answer summaries
can be sensitive even when absolute capture paths are omitted. Inspect JSON
also contains capture metadata, including the resolved path.

For quality, TCP, and DNS, exit code `0` indicates a completed assessment
or analysis (possibly with findings); `1` indicates a limited result or
an execution error; `2` indicates insufficient evidence or input-validation
failure. Read the report status and error text rather than treating an exit
code as proof of network health.

## Next investigation step

For each finding, record the representative frame(s), observation point,
capture time window, explicit limitations, and the next capture or telemetry
needed to test an explanation. A single capture cannot reliably assign
root cause or device/team ownership. Two-point capture comparison and desktop
UI are not implemented.

See [DNS troubleshooting quickstart](dns-troubleshooting-quickstart.md) for
DNS-specific interpretation and [README](../README.md) for command details.
