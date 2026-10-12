# Contributing to RenGuard

RenGuard is a security-auditing skill with provenance-protected historical artifacts,
stable taxonomy IDs, a public evaluation corpus, and an offline benchmark runner.
Changes should preserve those boundaries and remain reviewable.

## Development setup

The repository has no runtime or development package dependency. CI is configured to
target Python 3.10, 3.11, 3.12, and 3.13. During Phase 10, local verification was
performed on Python 3.12.14 only; the other target versions remain unverified pending a
successful GitHub-hosted matrix run. From the repository root, run the complete offline
quality gate:

```sh
python scripts/check.py
```

Focused commands remain available:

```sh
python scripts/validate_repo.py
python scripts/schema_tools.py check-repository
python -m unittest discover -s tests -v
python -m compileall -q scripts tests
```

Standard validation and tests must not contact model providers, require credentials,
or pass `--execute-live`. Fixture and replay adapters are the only adapters permitted
in CI.

## Schemas and versions

Draft 2020-12 contracts live under `schemas/`; `schemas/versions.json` is their version
registry. Schema versions are independent from the product, suite, runner, scoring, and
artifact versions. Preserve valid artifacts for PATCH/MINOR schema updates, and use a
MAJOR update for breaking changes. Pre-1.0 benchmark artifact versions are supported
only when explicitly registered. Do not change serialized scoring or artifact semantics
under an unchanged Phase 9 version.

## Evaluation cases

- Treat `evals/v2/` as a public corpus, never as a hidden holdout.
- Use stable `RG-EVAL-V2-...` and `RG-MUT-...` IDs; never silently reuse an ID.
- Use synthetic placeholders such as `<TEST_SECRET>` and reserved domains.
- Never add real credentials, malware, destructive commands, live exfiltration endpoints,
  or runnable production exploits.
- Keep output-sink fixtures declarative and normalized multimodal fixtures explicit about
  not testing native perception.
- Update the manifest and schema version only when their respective contracts require it.

The schema validates storage shape. `scripts/validate_repo.py` separately validates
taxonomy references, risk arithmetic, counts, provenance, and ground-truth consistency.
Both layers must pass.

## Benchmark changes

Keep adapters model-agnostic, network-gated, credential-safe, path-safe, and replayable.
Treat model output as untrusted. Tests must use deterministic synthetic fixtures or
captured replay data and must never publish fixture percentages as RenGuard performance.
Raw private holdout content and generated `benchmark-runs/` artifacts do not belong in
Git.

## Pull requests and commits

Keep commits scoped, explain version/compatibility effects, add regression coverage, and
run `python scripts/check.py`. Pull requests should identify changed contracts, preserved
invariants, and any intentionally deferred validation. Do not include caches, generated
benchmark runs, local paths, credentials, or editor backups.
