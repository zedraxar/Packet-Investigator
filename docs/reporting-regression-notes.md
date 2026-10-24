# Reporting consistency regression checks

The single-capture reports retain their schema 1.0 field names, status enums,
and CLI exit codes. The following details clarify how to interpret them:

- A complete TCP conversation without findings can coexist with an overall
  `analyzed_with_findings` status. Capture-quality warnings or limitations
  contribute to that overall status; the TCP summary now explains this explicitly.
  Individual conversation statuses and findings remain based on TCP evidence.
- Capture quality does not perform full handshake matching. Its terminal
  `Incomplete handshake flows` row says `Not assessed (use TCP analysis)`.
  The legacy JSON `statistics.incomplete_handshake_flows` field remains the
  integer zero for compatibility; zero here means **not measured**, not that
  all handshakes completed. Use the dedicated TCP analysis for handshake state.
- DNS retry evidence counts raw repeated queries and TShark-marked messages
  separately by provenance. Each message with one or more TShark retry flags
  contributes one derived indicator, not one indicator per flag. This corrects
  inflated transaction counts while retaining the existing JSON structure.
  For three repeated queries with TShark retry evidence on two messages, the
  summary and transaction finding now both report 4 indicators: 2 raw repeats
  plus 2 derived observations. Those sources can overlap; 4 is not a count of
  unique retransmissions or application retries. Capture-wide totals also cover
  messages outside retained transactions, so they need not equal displayed
  transaction totals when collection is incomplete or matching is ambiguous.

The project includes regression coverage in the TCP analyzer, capture-quality
renderer, DNS collector, DNS analyzer, and DNS renderer tests. Collector tests
exercise multiple simultaneous flags on queries and responses, and unflagged
raw repeats. The generated real-TShark DNS acceptance test exercises three
unanswered repeated queries, checks consistent counts across analysis and CLI
JSON, and preserves capture-bounded wording. Captures are generated temporarily;
no private traffic or committed PCAP files are required.

Run the full validation with Python 3.12+ and TShark on PATH:

```powershell
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\ruff.exe format --check .
.\.venv\Scripts\mypy.exe src
.\.venv\Scripts\python.exe -m pytest -q -ra
```

The external six-capture checker can additionally be run with
`--strict-reporting`; it should pass its core checks and clear all three
reporting audits. This is a focused smoke check, not cross-version validation.
