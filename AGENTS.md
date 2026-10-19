# Codex project instructions — Packet Investigator

These instructions apply to the entire repository. Read this file, `ROADMAP.md`, `README.md`, `docs/development.md`, and any relevant specifications before planning or editing. Repository state and current tests take precedence over stale descriptions. Do not assume planned features are implemented.

## Mission and users

Build a practical, trustworthy, local-first network packet investigation tool for network/security engineers. Given PCAP or PCAPNG evidence, help an engineer understand **what the capture proves**, what it **suggests but cannot prove**, what visibility is missing, and **where/what to capture next**. The product should eventually help correlate captures taken at client, firewall, VPN, proxy, server, and other network observation points, without pretending to know a root cause from one vantage point.

Prefer useful, understandable engineering reports over speculative diagnosis or feature volume. Think of the long-term experience as a network troubleshooting diagnostic assistant, not a packet viewer that merely restates protocol fields.

## Current implementation and boundaries

- Python >=3.12, TShark, Typer CLI, Rich output, typed models, Ruff, strict mypy, pytest.
- Existing single-capture CLI commands: `packet-investigator inspect`, `quality`, `tcp`, and `dns`; check the actual CLI and tests for current flags and behavior.
- Capture metadata, quality, TCP conversations, and classic DNS transaction analysis are implemented. Preserve their public schemas, exit codes, deterministic ordering, and privacy behavior.
- DNS generated real-TShark acceptance coverage was merged in PR #8. Acceptance on one CI image is not a claim of cross-version compatibility.
- Two-point comparison, multi-point correlation, desktop UI, wider protocol coverage, packaging/release, and MCP integration are **future proposals**, not current product capabilities. They require scoped design/review and should not be silently represented as complete.
- Consult `ROADMAP.md` and `docs/dns-implementation-audit.md` for current status and unresolved review gates. Do not unilaterally declare release readiness.

## Evidence and reporting contract

Every diagnostic claim must be traceable to observed packet/header/capture evidence. Keep distinct:
1. Observed facts (packet-level evidence and scope).
2. Cautious technical interpretation (possible explanations, not unsupported certainty).
3. Ownership guidance only where warranted; never assign blame from incomplete visibility.
4. Limitations (capture point, timing, offloads, missing packets, asymmetric paths, truncation, ambiguous matches).
5. Actionable next capture or verification steps.

Examples: retransmission indicators do not independently prove network packet loss; a DNS timeout in one capture does not prove the resolver failed; missing SYNs do not prove no handshake occurred; a reset does not prove a firewall caused it. Avoid language that overstates causality, responsibility, or security conclusions.

## Engineering principles

- Keep processing offline by default. Never upload captures, packets, payloads, credentials, DNS queries, or endpoint identifiers to external services without explicit approval.
- Treat all captures, paths, packet fields, and subprocess output as untrusted input. Avoid shell injection, unsafe path handling, unbounded parsing, or arbitrary execution.
- Collect the minimum TShark fields necessary. Prefer streaming and bounded memory; explicitly report dropped/omitted tracking when limits apply.
- Do not retain, print, log, or export application payloads or secrets. Preserve existing path privacy. Treat IPs, ports, hostnames, and DNS names in reports as sensitive metadata.
- Favor deterministic, typed, testable analysis and stable machine-readable JSON. Keep collection, models, analysis, presentation, and CLI orchestration reasonably separated.
- Preserve backwards compatibility unless a separately reviewed change authorizes breaking a contract. No unrelated refactoring.
- Include clear negative/ambiguous cases and limitations in tests. Prefer synthetic/generated fixtures; never commit private customer or government captures.
- Keep documentation accurate about what works **today**, with copy-pastable commands and examples validated against the actual CLI.

## Incremental autonomous workflow

For each task, work on **one small, reviewable, independently testable improvement**. Before editing:
1. Inspect current target branch `feature/phase-6-planning`, recent commits, open PRs/issues, CI, and the relevant code/docs.
2. Check whether the proposed work is already underway or merged; do not create duplicate branches or PRs.
3. Choose a narrow objective that advances a usable local CLI preview, evidence-backed DNS/TCP troubleshooting, onboarding, deterministic acceptance tests, or approved future architecture.
4. State acceptance criteria and risks. If scope is unclear or requires architectural/security decisions, draft a proposal or report the blocker instead of guessing.

Implement on a **new branch**, never directly on `feature/phase-6-planning` or `main`. Add/update focused tests and documentation. Keep diffs small and self-contained. Stop gracefully and report what remains if a task cannot fit in one run. Do not alter, pause, disable, or create ChatGPT scheduled tasks or notification settings.

## Local validation

When available, use Python >=3.12 and TShark installed on PATH:

```bash
python -m pip install -e ".[dev]"
tshark --version
ruff check .
ruff format --check .
mypy src
python -m pytest -q
```

For capture-facing changes, exercise relevant generated real-TShark acceptance tests and report **passed/skipped** counts; do not treat skipped tests as executed. If the environment lacks TShark or required tools, say so and rely on required CI without inventing results. Fix routine lint/format/test failures before seeking merge. Never bypass required checks.

## Pull requests, reviews, and auto-merge

Target PRs at `feature/phase-6-planning` unless the repository's approved workflow changes. Follow branch protection and the existing guarded GitHub auto-merge workflow.

- **Eligible low-risk PRs:** a nondraft same-repository `automation/*` branch changing only `src/`, `tests/`, `docs/`, `README.md`, or `ROADMAP.md`, with passing required `validate` CI. Let the existing workflow decide eligibility and perform any merge.
- **Manual-review PRs:** CI/workflows, `AGENTS.md` or other agent/governance instructions, dependency/build config, security/privacy controls, releases/packaging, broad architecture, breaking schemas/contracts, and work explicitly requiring human review (notably issue #3). Use a **non-`automation/*` branch**, request human review, and never attempt to auto-merge.
- Never manually merge, invoke a direct merge command, independently enable auto-merge, weaken rulesets, change workflow permissions, alter secrets, deploy, release, or publish packages without explicit user authorization.
- If CI fails, investigate and make a bounded correction on the PR branch. If checks or review block progress, report the exact blocker instead of bypassing it.

## Completion report

For meaningful work, report the PR URL/number, branch and commit SHA, changed files, user-facing behavior, tests actually executed (including skipped counts and TShark version when relevant), GitHub Actions outcome, and whether auto-merge is queued, merged, or blocked. Do not claim success before checking GitHub. If no useful work was completed, briefly explain the blocker or next step without inventing progress.

## Priority and approval

Favor a trustworthy, installable, useful local troubleshooting CLI before speculative expansion. Improve actual diagnostic value and first-run experience. Plan endpoint/two-point comparison with an explicit evidence-correlation contract before implementation; then consider multi-point comparison and a desktop UX. Keep privacy, correctness, reproducibility, and clear human oversight ahead of development speed.
