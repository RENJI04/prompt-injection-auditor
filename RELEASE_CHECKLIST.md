# RenGuard v2.0.0 Release Checklist

This checklist records local validation and observed GitHub evidence for the release
candidate. Completed CI and merge gates do not imply that a public tag or GitHub
Release exists. The follow-up metadata preparation still requires review.

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
| GitHub About application | PENDING | Apply the prepared description only with approval |
| Topics application | PENDING | Apply the prepared topics only with approval |
| Social Preview configuration | PENDING | Manual GitHub repository configuration and crop verification required |

The prepared Social Preview file is not evidence that the GitHub repository setting has
already been configured.

## External and publication gates

| Gate | Status | Requirement |
|---|---|---|
| Final branded RC | PASS | `9141879401019e6172aec27748dff216cb63370d` |
| RC pushed | PASS | Approved RC on remote `work` |
| RC push hosted CI | PASS | [Run 38337787172](https://github.com/RENJI04/prompt-injection-auditor/actions/runs/38337787172) |
| Release PR | PASS | [PR #1](https://github.com/RENJI04/prompt-injection-auditor/pull/1) |
| PR CI | PASS | [Run 38338406336](https://github.com/RENJI04/prompt-injection-auditor/actions/runs/38338406336) |
| Merge to main | PASS | Normal merge `d8ec26b9b19f79f9a134f838ba2f4b3d34211963`; full checkpoint history retained |
| Main hosted CI | PASS | [Run 38338862797](https://github.com/RENJI04/prompt-injection-auditor/actions/runs/38338862797) |
| Python 3.10 | PASS | Main hosted CI matrix |
| Python 3.11 | PASS | Main hosted CI matrix |
| Python 3.12 | PASS | Main hosted CI matrix |
| Python 3.13 | PASS | Main hosted CI matrix |
| Final metadata change reviewed/merged | PENDING | Review this documentation-only preparation |
| `v2.0.0` public tag | NOT_PERFORMED | Separate explicit approval required |
| GitHub Release | NOT_PERFORMED | Separate explicit approval required |
| Repository rename | NOT_REQUIRED / NOT_PERFORMED | Optional naming decision |
| Official live benchmark | NOT_REQUIRED / NOT_PERFORMED | Required only before quantitative live-performance claims |

The `source_commit` in [`release/release-manifest.json`](release/release-manifest.json)
identifies the validated main merge commit containing the release product content,
not the later metadata commit. This avoids self-reference. Keep `RELEASE_CANDIDATE`
until public publication is separately approved and completed.
