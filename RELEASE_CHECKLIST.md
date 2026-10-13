# RenGuard v2.0.0 Release Checklist

This checklist distinguishes the locally validated release candidate from external
publication. `PASS` below records repository-local evidence only; it does not imply that
a tag or GitHub release exists.

## Local and repository gates

| Gate | Status | Evidence |
|---|---|---|
| Repository validator | PASS | `python scripts/validate_repo.py` |
| Unit tests | PASS | `python -m unittest discover -s tests -v` |
| Python compilation | PASS | `python -m compileall -q scripts tests` |
| Schema and JSON contracts | PASS | `python scripts/schema_tools.py check-repository` |
| Public-suite validation | PASS | `python scripts/run_benchmark.py validate` |
| Shared quality gate | PASS | `python scripts/check.py` |
| Documentation-relative links | PASS | Offline documentation regression test |
| Secret and repository-hygiene scan | PASS | Phase 12 local review |
| Historical and protected-file provenance | PASS | Phase 12 hash/diff checks |
| Release notes and metadata consistency | PASS | Phase 12 release-readiness tests |

## Branding assets

| Gate | Status | Evidence |
|---|---|---|
| Approved icon present | PASS | `assets/branding/renguard-icon.png` |
| Approved wordmark present | PASS | `assets/branding/renguard-wordmark.png` |
| Approved social-preview asset present | PASS | `assets/branding/renguard-social-preview.png` |
| PNG signatures and dimensions | PASS | Standard-library branding regression test |
| README hero uses approved local branding | PASS | Accessible local banner with live project text |
| Relative branding paths | PASS | Offline documentation-link regression test |

## GitHub presentation

| Gate | Status | Requirement |
|---|---|---|
| About description prepared | PREPARED | See `release/GITHUB_PUBLISHING.md` |
| Repository topics prepared | PREPARED | See `release/GITHUB_PUBLISHING.md` |
| Social Preview asset prepared | PREPARED | Use `assets/branding/renguard-social-preview.png` |
| Social Preview configuration | PENDING | Manual GitHub repository configuration required after push |

The prepared Social Preview file is not evidence that the GitHub repository setting has
already been configured.

## External and publication gates

| Gate | Status | Requirement |
|---|---|---|
| Push release-candidate commit | NOT_PERFORMED | Owner approval after Phase 12 review |
| GitHub-hosted CI | PENDING | Push candidate and obtain a passing Python 3.10–3.13 matrix |
| Review final hosted diff and checks | PENDING | Confirm the pushed commit matches the reviewed candidate |
| Create `v2.0.0` tag | NOT_PERFORMED | Only after hosted CI and release approval |
| Create GitHub release | NOT_PERFORMED | Publish approved notes from the tagged commit |
| Rename repository | NOT_PERFORMED | Optional naming decision; not technically required |
| Official live-model benchmark | NOT_REQUIRED | Required only before making quantitative live-performance claims |

Before publication, replace the pending `source_commit` in
[`release/release-manifest.json`](release/release-manifest.json) with the final committed
release-candidate SHA and rerun all local gates. Do not mark hosted CI, a tag, or a
GitHub release complete without external evidence.
