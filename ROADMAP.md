# Packet Investigator Roadmap

Packet Investigator is an evidence-driven, offline packet-capture investigation tool designed to help network engineers move from raw captures to defensible conclusions.

The project should advance in small, testable phases. Each phase must preserve these principles:

- Evidence before conclusions
- Clear separation between observation, interpretation, and recommendation
- Safe handling of untrusted capture files
- Deterministic, testable analysis
- Constant or bounded memory use where practical
- No unsupported ownership or root-cause claims
- Accurate documentation of implemented versus planned functionality
- Ruff, formatting, strict mypy, and pytest must pass before each phase is committed

---

## Current Status

### Phase 1 — Development Environment ✅

Completed:

- Python virtual environment
- Git repository
- Ruff
- mypy
- pytest
- TShark
- Editable package installation
- Codex-assisted development workflow

### Phase 2 — Professional Project Scaffold ✅

Completed:

- Modern `src/` layout
- `pyproject.toml`
- Typer CLI
- Rich terminal output
- Package version and information commands
- Initial tests
- Architecture documentation
- Development workflow documentation
- Private-capture exclusions
- Initial Git commit

### Phase 3 — Capture Metadata Inspection ✅

Implemented:

```bash
packet-investigator inspect capture.pcapng
packet-investigator inspect capture.pcapng --json
```

Current capabilities:

- Validate `.pcap` and `.pcapng` paths
- Resolve and safely inspect capture files
- Report exact and human-readable file size
- Count packets
- Report first and final packet timestamps
- Calculate capture duration
- Report observed interface IDs when available
- Report TShark version
- Stream TShark field output without retaining all packet rows
- Produce terminal and JSON output
- Return concise expected-error messages without tracebacks

Current limitations:

- Metadata inspection only
- No packet diagnosis
- No conversation reconstruction
- No protocol analysis
- No ownership or root-cause conclusions

---

# Planned Phases

## Phase 4 — Capture Quality Assessment

### Goal

Determine whether a capture is suitable for investigation before attempting deeper analysis.

### Planned capabilities

- Detect empty captures
- Detect extremely short captures
- Identify whether the capture begins mid-conversation
- Identify whether the capture ends before observed conversations complete
- Detect missing TCP handshakes
- Detect suspicious timestamp ordering
- Detect malformed packet rows
- Detect likely packet truncation or limited snap length
- Identify checksum-offload artifacts without automatically treating them as network faults
- Report interface-count and capture-source limitations
- Provide a clearly worded capture-quality assessment
- Recommend whether another capture is needed

### Planned models

```text
CaptureQualityAssessment
CaptureLimitation
CaptureWarning
CaptureRecommendation
```

### Example output

```text
Capture Quality: Limited

Observed:
- 18,442 packets
- Capture duration: 324.531 seconds
- 6 TCP conversations begin without an observed SYN
- 14 packets appear truncated
- TCP checksum errors may be caused by local checksum offload

Interpretation:
The capture appears usable for partial analysis, but it may not contain the
beginning of several conversations.

Recommended next capture:
Capture simultaneously at the client and firewall beginning before reproduction.
```

### Exit criteria

- Capture-quality models implemented
- CLI output and JSON serialization implemented
- Tests cover empty, short, partial, truncated, and offload-like cases
- No unsupported diagnostic conclusions
- Documentation updated
- Ruff, formatting, mypy, and pytest pass

---

## Phase 5 — Normalized Packet Model

### Goal

Create the minimum packet representation needed for conversation building without retaining raw payloads by default.

### Planned models

```text
Packet
Endpoint
TransportProtocol
TcpFlags
PacketDirection
InterfaceObservation
```

### Minimum packet fields

- Frame number
- Timestamp
- Capture interface ID
- Source and destination IP
- Source and destination port
- IP protocol
- TCP flags
- TCP sequence and acknowledgment numbers
- TCP payload length
- Frame length
- IP length
- ICMP type and code where applicable
- Relevant TShark analysis flags
- Optional VLAN identifiers

### Design requirements

- Immutable typed models
- No raw packet payloads by default
- IPv4 and IPv6 support
- Missing fields represented explicitly
- Streaming parser boundary
- Stable JSON serialization
- No protocol-specific conclusions at this layer

### Exit criteria

- Packet model implemented
- TShark packet-field parser implemented
- Unit tests cover IPv4, IPv6, TCP, UDP, ICMP, and missing fields
- Large-output parsing does not retain unnecessary rows
- Existing metadata inspection remains functional

---

## Phase 6 — Conversation Builder

### Goal

Group normalized packets into meaningful transport conversations.

### Planned conversation types

```text
TcpConversation
UdpConversation
IcmpExchange
```

### Planned TCP conversation fields

- Initiator and responder
- First and last timestamps
- Duration
- Packet and byte count by direction
- SYN, SYN/ACK, and final ACK observations
- FIN and RST observations by side
- First and last payload direction
- Retransmission count
- Duplicate ACK count
- Out-of-order count
- Zero-window indicators
- Conversation completeness
- Capture limitations

### Important constraints

- Do not assume the lower port is always the server
- Do not claim client/server roles unless supported
- Distinguish observed initiator from inferred application role
- Allow partial conversations
- Avoid merging unrelated reused five-tuples
- Plan for connection epochs and tuple reuse

### Exit criteria

- TCP, UDP, and ICMP grouping implemented
- Tuple reuse handled safely
- Partial conversations supported
- Deterministic tests cover normal, reset, partial, and reused flows
- Conversation-summary CLI command implemented

---

## Phase 7 — Evidence Model and Finding Engine

### Goal

Create the core structure that separates facts from interpretation.

### Planned models

```text
Evidence
Observation
Finding
Interpretation
Confidence
Recommendation
RecommendedCapture
```

Every finding should distinguish:

1. Observed evidence
2. Interpretation
3. Confidence
4. Limitations
5. Recommended next action
6. Recommended next capture point

### Planned confidence levels

```text
Confirmed
High
Moderate
Low
Insufficient evidence
```

### Exit criteria

- Immutable evidence and finding models implemented
- Findings include limitations and confidence
- No bare root-cause strings
- JSON and Rich output supported
- Tests prove observation and interpretation remain separate

---

## Phase 8 — TCP Analyzer

### Goal

Provide deterministic TCP transport analysis for each conversation.

### Planned detections

- Complete and incomplete three-way handshakes
- SYN retransmissions
- Connection refusals
- Client- and server-originated resets
- Midstream resets
- Normal FIN closure
- Half-closed conversations
- Retransmissions and duplicate ACKs
- Out-of-order delivery
- Zero-window and window-update events
- Keepalive patterns
- Stalled data transfer
- One-way payload
- Possible MTU or PMTUD symptoms
- MSS and window-scale observations
- Abnormally small advertised windows
- Capture-offload caveats

### Important restrictions

- Do not label all retransmissions as packet loss
- Do not label checksum errors as real wire corruption without evidence
- Do not label a reset as firewall-generated unless captures support that claim
- Do not diagnose MTU from one symptom alone
- Use cautious wording for inferred causes

---

## Phase 9 — DNS Analyzer

### Planned detections

- Query without observed response
- NXDOMAIN, SERVFAIL, and REFUSED
- Truncated UDP response and TCP fallback
- Retransmitted queries
- Multiple-resolver behavior
- Long response time
- CNAME chain
- Observed answer records
- Name-to-IP timeline
- DNS response arriving after an application connection attempt

---

## Phase 10 — TLS Analyzer

### Planned detections

- TCP established but no ClientHello observed
- ClientHello and ServerHello observations
- TLS version, SNI, and ALPN
- Certificate metadata
- TLS alerts
- Handshake timeout
- Server close after ClientHello
- Client close after ServerHello
- Reset before TLS negotiation
- Session-resumption indicators when visible

### Important restrictions

- Do not claim certificate trust failure from packet evidence alone unless an alert supports it
- Distinguish malformed, incomplete, encrypted, and absent handshake evidence
- Avoid unnecessary certificate or hostname disclosure in reports

---

## Phase 11 — HTTP Analyzer

### Planned detections

- Request and response pairing
- Method, host, and privacy-controlled URI path
- Response status and redirects
- Server and client errors
- Content length
- Time to first byte
- Transfer duration
- Premature close
- Reset during transfer
- Repeated-request behavior

### Privacy requirements

- Redact authorization headers
- Redact cookies
- Avoid storing request bodies by default
- Support hostname and URI sanitization

---

## Phase 12 — SMB Analyzer

### Goal

Provide targeted SMB troubleshooting for enterprise file-transfer cases.

### Planned detections

- SMB dialect negotiation
- Session setup and tree connect
- File open, read, and write activity
- SMB status codes
- Request/response delay
- Credit-exhaustion indicators
- Signing and encryption observations
- Large-transfer stalls
- TCP retransmissions during SMB activity
- Reset or close ownership as observed

### Important restrictions

- Do not extract file contents
- Do not expose filenames unless explicitly requested and authorized
- Do not claim firewall inspection as the cause without comparative evidence

---

## Phase 13 — RDP and Interactive Session Analyzer

### Planned detections

- TCP reachability
- TLS or CredSSP negotiation state
- Server refusal
- Reset direction
- Long setup delay
- Session establishment followed by immediate closure
- Packet-loss or retransmission patterns during interactivity
- One-way traffic patterns

---

## Phase 14 — Endpoint Comparison

### Goal

Compare two captures from different observation points.

### Planned capabilities

- Align captures by timestamp
- Normalize clock offsets
- Match conversations
- Compare packet presence and sequence ranges
- Identify where retransmissions first appear
- Identify packets seen at one point but not another
- Compare resets and FINs
- Detect probable drops between observation points
- Detect probable packet modification
- Quantify latency added between points

Output should prefer:

```text
Observed at point A
Not observed at point B
```

rather than immediately claiming a specific device dropped traffic.

---

## Phase 15 — Multi-Point Correlation

### Goal

Correlate a flow across three or more capture locations.

### Example topology

```text
Client
  ↓
VPN adapter
  ↓
Internet edge
  ↓
Firewall
  ↓
Proxy or load balancer
  ↓
Server
```

### Planned capabilities

- Build observation-point timelines
- Identify the last point where a packet is observed
- Identify the first point where behavior changes
- Compare sequence translation and NAT
- Compare TCP resets across points
- Compare latency at each segment
- Produce a path-oriented evidence report

This is the phase most likely to distinguish Packet Investigator from general-purpose packet viewers.

---

## Phase 16 — Ownership Guidance

### Goal

Provide cautious technical ownership guidance based on evidence.

### Planned ownership categories

```text
Client endpoint
Server endpoint
Application
Name resolution
Network path
Firewall or security inspection
VPN transport
Proxy or load balancer
Capture insufficient
Multiple contributing factors
```

Prefer:

```text
Evidence currently points toward the server-side application path.
```

Avoid:

```text
The server team caused the issue.
```

Ownership guidance must include confidence, supporting findings, contradicting evidence, missing evidence, and a recommended next team or capture point.

---

## Phase 17 — Reporting

### Planned formats

- Rich terminal output
- JSON
- Markdown
- HTML
- Optional PDF later

### Planned report sections

1. Case summary
2. Capture inventory
3. Capture quality
4. Endpoint summary
5. Conversation summary
6. Timeline
7. Findings
8. Evidence
9. Confidence and limitations
10. Recommended next actions
11. Recommended next captures
12. Technical ownership guidance

### Privacy controls

- IP-address redaction
- Hostname redaction
- Username redaction
- URL redaction
- Filename redaction
- Payload exclusion
- Configurable report sanitization

---

## Phase 18 — Investigation Workspace

### Goal

Allow users to organize captures and findings into a local case.

### Planned structure

```text
case/
├── case.yaml
├── captures/
├── metadata/
├── findings/
├── reports/
└── logs/
```

### Security requirements

- Local-only by default
- No automatic cloud upload
- Clear warnings before exporting captures
- Hash captures for integrity tracking
- Never modify original capture files

---

## Phase 19 — Extensibility and Plugin Architecture

### Planned interfaces

```text
Analyzer
FindingProvider
ConversationEnricher
ReportSectionProvider
```

Potential future analyzers:

- SIP and RTP
- QUIC and HTTP/3
- Kerberos
- LDAP
- SQL protocols
- GlobalProtect-specific observations
- IPsec tunnel comparisons
- Vendor-specific firewall metadata imports

Do not design the plugin system prematurely. Implement it only after multiple analyzers demonstrate a stable shared interface.

---

## Phase 20 — Public Release Readiness

### Planned repository additions

- `LICENSE`
- `CONTRIBUTING.md`
- `CODE_OF_CONDUCT.md`
- `CHANGELOG.md`
- Security policy
- Issue templates
- Pull-request template
- Public synthetic capture fixtures
- User and installation documentation
- Supported-platform matrix
- Release workflow

### Release criteria

- No sensitive captures or internal identifiers
- Reproducible installation
- Complete test suite
- Stable CLI behavior
- Accurate limitations
- Sanitized examples
- Versioned releases
- Public documentation reviewed

---

# Suggested Version Milestones

## v0.1.x — Foundation

- Project scaffold
- Capture metadata inspection
- Capture quality assessment
- Initial packet model

## v0.2.x — Conversations

- TCP conversation builder
- UDP conversation builder
- ICMP exchanges
- Conversation summaries

## v0.3.x — Evidence and TCP Analysis

- Evidence model
- Finding engine
- TCP analyzer
- Confidence and limitations

## v0.4.x — Application Protocols

- DNS
- TLS
- HTTP
- SMB
- RDP

## v0.5.x — Capture Comparison

- Endpoint comparison
- Clock alignment
- Packet-presence comparison
- Path findings

## v0.6.x — Multi-Point Correlation

- Three-or-more capture correlation
- NAT-aware matching
- Path timeline
- Observation-point comparison

## v0.7.x — Reporting and Cases

- Markdown and HTML reports
- Investigation workspace
- Privacy and sanitization controls

## v0.8.x — Ownership Guidance

- Evidence-based technical ownership
- Contradicting evidence
- Recommended next team
- Recommended next capture

## v0.9.x — Public Beta

- Documentation
- Synthetic examples
- Packaging
- Contributor workflow
- Cross-platform validation

## v1.0.0 — Stable Initial Release

A stable release should include:

- Safe capture ingestion
- Capture-quality assessment
- TCP, UDP, and ICMP conversation reconstruction
- Evidence-based TCP, DNS, TLS, HTTP, SMB, and RDP findings
- Two-point and multi-point comparison
- Professional reports
- Privacy controls
- Stable CLI and JSON schema
- Complete documentation
- Public synthetic test data
- No claims that exceed available evidence

---

# Development Rules for Every Phase

Before implementation:

1. Review `ARCHITECTURE.md`.
2. Define the model and evidence boundary.
3. Define what is explicitly out of scope.
4. Create tests for normal, abnormal, partial, and malformed input.
5. Avoid using private captures in automated tests.

Before committing:

```bash
python -m pip install --editable '.[dev]'
ruff check .
ruff format --check .
mypy src
pytest
git diff --check
git diff --stat
git status
```

Each phase should end with:

- Clean validation
- Updated documentation
- Clear known limitations
- A focused Git commit
- No sensitive capture data
- No unsupported conclusions
- A recommended next step

---

# Immediate Next Step

Implement **Phase 4 — Capture Quality Assessment**.

The first increment should remain narrow and answer:

- Is the capture empty?
- Is the capture long enough to be useful?
- Does it appear to begin midstream?
- Are packets likely truncated?
- Are checksum warnings potentially caused by local offload?
- What limitations should the investigator know before deeper analysis?
- What capture should be collected next if evidence is insufficient?
