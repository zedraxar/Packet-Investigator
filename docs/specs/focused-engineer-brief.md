# Focused engineer investigation and graphical PDF brief

Status: implementation proposal for manual review, stacked on desktop preview PR #28.
This increment is authorized by the user's request to develop investigation context
and a clearer graphical report. It does not change the packet-analysis engine.

## Product direction

Make the workflow: describe the issue, select evidence, investigate, read a short
engineer brief, inspect technical detail, and export a shareable PDF. Keep user
statements separate from observed facts. Evidence coverage is not network health.

## First increment

- Optional symptom, target hostname/IP, client IP and capture-point inputs.
- Default engineer summary; existing technical/DNS-detail view remains accessible.
- Scope using exact IPs or boundary-matched DNS names/subdomains.
- Domain-to-TCP selection is candidate relevance only, based on retained A/AAAA
  answer addresses. Shared addresses, cached/encrypted DNS, aliases and missing
  evidence limit it. Never claim URL/application identity or causal linkage.
- Cap candidate IPs at 256 and disclose incomplete candidate tracking.
- Symptom changes finding priority, not thresholds, observations or diagnosis.
- A local graphical PDF with capture metrics, reported context, scope, DNS
  exchange coverage, prioritized findings, source/frame references, uncertainty,
  and next capture actions. No invented health score or causal timing waterfall.
- PDF uses a separate derived brief; existing raw JSON schemas and exit codes stay
  unchanged. JSON continues to export the full original evidence, without context.
- Render to memory, then use the existing no-overwrite publisher for binary export.
- ReportLab is optional for source installations and included in the desktop build.
  No remote fonts, web requests, LLM calls or capture uploads.
- Changing context clears the result and disables exports until analysis reruns.

## Acceptance

Test exact/subdomain boundary selection, IP/client intersection, no matching DNS,
unanswered/negative DNS, shared-address limitations, bounded findings/candidates,
deterministic output, unchanged input/JSON, escaping, empty/limited reports,
controller stale-result prevention, PDF text/parsing and no-overwrite behavior.
Visually render/inspect the example PDF. Run project checks and required CI.

A design preview based on the user's pasted report must explicitly say it is not
capture re-analysis. Private report text, endpoint names and IPs must never enter
shared fixtures or repository changes; use synthetic examples for tests.

## Follow-on work

Time-window scoping, application process identity, TLS/HTTP evidence, multi-point
correlation, richer on-screen charts, redaction controls, accessible navigation and
PDF branding need their own scoped review. Clean-machine installer, scaling,
independent review and signing gates remain open. Do not merge automatically.
