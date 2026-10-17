# DNS implementation audit — issue #2

Audited branch: `feature/phase-6-planning` at
`ba60004aafe78eef01cd734a9b63b807471799dc`.
Reference contract: [Phase 6 DNS specification](specs/phase-6-dns-transaction-analysis.md).

This is a **source-and-test inventory**, not a claim of runtime acceptance.
No private captures, external capture uploads, or live traffic were used.

## Implemented in the reviewed source

| Layer | Evidence | Current scope |
| --- | --- | --- |
| CLI | `src/packet_investigator/cli.py`, `tests/test_cli.py` | `packet-investigator dns CAPTURE_PATH [--json]` runs inspection, capture-quality assessment, DNS collection/analysis, and Rich or JSON rendering. Status-based exit mapping is present. |
| Collector | `src/packet_investigator/parsers/dns_transactions.py`, `tests/test_dns_transaction_collector.py` | TShark field projection and one-pass normalized-row collection for classic DNS over UDP/TCP. Excludes mDNS, LLMNR, and NBNS; missing required fields fail, while optional capabilities are reported. |
| Models | `src/packet_investigator/models/dns_transactions.py`, `tests/test_dns_transaction_models.py` | Immutable schema `1.0` evidence, finding, limitation, recommendation, and report models with explicit privacy and ordering validation. |
| Analyzer | `src/packet_investigator/analyzers/dns_transactions.py`, `tests/test_dns_transaction_analyzer.py` | Deterministic matching assessments, ambiguity and one-sided observations, response-code and retry indicators, evidence provenance, capture limitations, and noncausal recommendations. |
| Presentation | `src/packet_investigator/renderers/dns_transactions.py`, `tests/test_dns_transaction_renderers.py`, `tests/test_dns_pipeline.py` | Bounded Rich summaries and full tracked JSON report. Normalized-row pipeline tests exercise collector → analyzer → renderers. |

The collector limits tracking to **50,000 transactions**, retained answer
summaries to **100,000**, representative frames to **8** per sampled set,
and parser warnings to **100**. Per-message answer summaries are also bounded.
Only A, AAAA, and CNAME answer values are approved for retention; unsupported
RDATA is counted without retaining its value. Query names and endpoint
addresses remain potentially sensitive metadata, even without payload bytes.

## Remaining verification and deviations from the completion contract

- [ ] **Phase 6.6 real-TShark DNS acceptance is not present.** The
  specification requires 14 generated scenarios, but the reviewed tree has no
  `tests/test_dns_end_to_end.py` or DNS scenario generator in
  `tests/fixtures/captures.py`. Existing DNS pipeline tests use synthetic
  projected rows; CLI tests use mocks. Do not equate these with real-TShark
  capture acceptance.
- [ ] **Installed-TShark compatibility is not established by this audit.**
  Required/optional field handling has unit tests, but the complete DNS path
  still needs validation against supported installed TShark versions and
  deterministic, non-sensitive generated PCAP/PCAPNG fixtures.
- [ ] **Phase 6.5 architecture/security review and full release gates are
  not established here.** The reviewed source shows bounded state, sanitized
  errors, and privacy-oriented tests, but that is not equivalent to completed
  independent review, packaging smoke tests, or release approval.
- [x] **Documentation drift identified.** The roadmap and specification
  describe DNS as not implemented, and README/architecture status text omits
  the existing DNS code. This documentation-only change updates the current
  status while preserving the original specification as a historical contract.

## Interpretation boundaries

A missing response means none was **observed in this capture**, not that DNS
failed on the network. A nonzero response code, retry indicator, truncation,
or ambiguous match is evidence to investigate, not a root-cause finding.
Encrypted DNS, payload inspection, cross-capture correlation, ownership
assignment, and arbitrary DNS record-value extraction are not claimed.

## Next steps

1. Add the 14-scenario generated DNS real-TShark acceptance suite in a
   separate, reviewable issue/PR; do not commit private or binary captures.
2. Verify CLI and package behavior across the supported TShark/Python matrix
   and record the actual validation results.
3. Complete the remaining architecture/privacy review before marking Phase 6
   fully accepted or preparing a release.
