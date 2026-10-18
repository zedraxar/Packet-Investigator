# Automated pull request merge policy

Routine development pull requests can opt into guarded auto-merge when they meet
all of these conditions:

- The pull request targets `feature/phase-6-planning`.
- Its branch belongs to this repository and starts with `automation/`.
- It is ready for review, not a draft.
- All changed files are limited to `src/`, `tests/`, `docs/`,
  `README.md`, or `ROADMAP.md`.
- The required `validate` GitHub Actions check succeeds and branch protection
  permits merging.

The auto-merge workflow requests GitHub auto-merge; it does not bypass branch
protection. Workflow files, dependency or packaging configuration, secrets,
releases, and other changes outside the allowed paths require manual review.

An automation branch name is not proof of trust: repository contributors and
automation operators must use this mechanism only for appropriately scoped,
reviewable changes. If checks fail, auto-merge must not proceed.
