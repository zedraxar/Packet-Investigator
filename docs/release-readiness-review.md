# Release readiness review — October 22, 2026

Baseline: `feature/phase-6-planning` at `e7c036b` (version 0.5.0).
This is a development readiness assessment, not release approval or an
independent security certification. No private captures or live interfaces were
used. PR #17 already updates CI documentation; this review does not duplicate it.

## Verified locally

- Windows, Python 3.12.14: the original test suite produced 623 passed,
  6 failed, 88 skipped. The failures came from POSIX-only path fixtures or a
  hard-coded POSIX serialization expectation.
- After correcting those six assumptions without changing product behavior:
  **629 passed, 88 skipped**. Fixtures now supply resolved native absolute paths
  where the existing model requires them. Privacy rejection remains tested.
- Ruff lint, Ruff formatting, and `mypy src` passed on the corrected source.
- A wheel built successfully with the existing configuration. A combined
  sdist-to-wheel build hit a Windows sandbox extraction permission error; that
  route is not yet verified here.
- TShark is absent locally. The 88 skipped tests are explicitly unexecuted
  integration coverage, not successful packet-analysis checks. Previous PR #17
  CI recorded 717 passed on Linux/Python 3.12 with TShark; new CI must verify
  the current revision separately.

## Source review observations

- Capture commands use offline `-r` field extraction with argument lists,
  numeric address resolution (`-n`), timeouts, bounded row queues, bounded
  retained stderr, and subprocess cleanup.
- DNS and TCP collection cap tracked records and sampled frame evidence.
  DNS retains only the approved answer-value subset. Addresses, names, and
  ports remain sensitive report metadata.
- Protocol reports omit source paths; `inspect` intentionally retains its
  existing metadata/path contract. This behavior was not weakened.
- Bounded retained records do not establish a hard process-memory ceiling:
  line reads and the field-capability subprocess output still need adversarial
  resource review. Running TShark is not a parser sandbox.

## Remaining gates

1. Required Linux/TShark CI on each proposed change, with exact pass/skip counts.
2. Installed-wheel synthetic capture testing on a machine with TShark. The
   wheel installed into a second clean virtual environment locally; installed
   command smoke checks are recorded in the PR validation results.
3. Reproduce sdist-to-wheel installation outside this sandbox restriction and
   inspect both archives for unintended captures, reports, and development files.
4. Validate the advertised Python 3.13/3.14 versions and additional TShark
   versions. One Windows/Python version and one Linux CI image are not a matrix.
5. Independent architecture/privacy/resource review, including malformed
   captures, oversized field rows, subprocess stderr, and cancellation.
6. Human approval of release contents, version, and distribution method.

## Sequence after readiness checks

First deliver a combined single-capture CLI workflow using the existing
quality, TCP, and DNS reports. Keep their schemas and evidence boundaries.
Next review an explicit two-capture matching contract before implementing
comparison. Multi-point correlation, additional protocols, desktop UI, and
file-report export remain separate later milestones.
