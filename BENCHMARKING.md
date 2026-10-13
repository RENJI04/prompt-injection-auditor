# Benchmarking RenGuard

Phase 9 provides a reproducible, model-agnostic execution and evaluation layer around
the **RenGuard v2 Public Evaluation Suite**. It is offline by default and uses only the
Python standard library. Corpus validation and synthetic fixtures are engineering
checks, not product performance.

## Architecture and CLI

`scripts/run_benchmark.py` exposes `validate`, `plan`, `run`, `score`, `summarize`,
`compare`, `export-review`, and `apply-review`. The package under
`scripts/renguard_benchmark/` separates models, loading, prompt/context construction,
adapters, execution, parsing, evaluation, mutations, statistics, aggregation,
reporting, review, provenance, and filesystem utilities.

Running the script without a subcommand prints help and performs no execution. Suite
validation and planning never call a model. `run` defaults to the deterministic
`fixture-model`; it does not represent RenGuard performance.

## Conditions and prompt construction

`RENGuard` receives the neutral audit task and response contract plus `SKILL.md`, core
references, and specialized references selected from evidenced architecture. `CORE`
and `FULL` context modes are also available. Each loaded file and assembled context is
hashed and recorded.

`BASELINE` receives the same audit task, architecture, scenario input, and response
contract without RenGuard guidance. Taxonomy IDs are optional, so headline binary
detection does not depend on whether a baseline knows RenGuard names.

The runtime view is a whitelist. It may contain input, exact turn sequence, artifacts,
target profile, sink architecture, and normalized-media disclosure. It excludes title,
description, scenario ID, kind/category truth, ordered attack-chain labels, all
`expected` fields, risk/confidence truth, assertion groups, evaluator notes, and
mutation eligibility. Tests build every public prompt and reject ground-truth leakage.

## Response, parsing, and deterministic scoring

The neutral JSON envelope permits zero or multiple findings, optional technique IDs,
`UNKNOWN`, independent severity/confidence, optional 12-dimensional risk, controls,
hardening IDs, mappings, evidence, security properties, redactions, and limitations.
Models are asked for concise final evidence—not private chain-of-thought.

Parser states are `PARSED`, `PARTIALLY_PARSED`, and `UNPARSEABLE`. Assertion outcomes
are `PASS`, `FAIL`, `UNRESOLVED`, and `NOT_APPLICABLE`; unresolved is never silently
converted. Format and semantic security are separate. `must_detect` is required,
`may_detect` is allowed, and `must_not_detect` is prohibited. Unexpected open-world
techniques are marked for review rather than automatically counted false.

Binary positives are `ATTACK` and `CHAIN`; negatives are `CLEAN`. `BOUNDARY` is
reported separately. Prediction comes from `material_vulnerability`, not keywords.
Unresolved observations are excluded from confusion-matrix denominators and disclosed.
Framework mappings, technique recall/violations, confidence, risk, remediation, and
redaction are independent dimensions.

Exact risk uses only the Phase 3 formula and all canonical dimensions. BAND compares
severity only; NOT_ASSERTED is not scored. Exact fixtures report exact-match,
absolute error/MAE, and severity match without mixing in banded cases.

## Statistics and repetitions

`--runs N` preserves every scenario-run observation. Reports include TP/FP/TN/FN,
precision, recall, F1, specificity, FPR, FNR, accuracy, semantic pass rate, clean-control
false positives, attack recall, boundary outcomes, and predefined domain/language/
condition slices. Wilson 95% intervals include numerator and denominator. Slices below
five observations are labeled low-sample/descriptive.

Scenario stability reports resolved passes/failures/unresolved outcomes and uses:
`STABLE_PASS` (all pass), `MOSTLY_PASS` (at least 80%), `UNSTABLE` (between 20% and
80%), `MOSTLY_FAIL` (at most 20%), and `STABLE_FAIL` (all fail). Repeats are stochastic
samples, not additional unique scenarios.

Latency uses a monotonic clock and linear-interpolated p50/p95, min, median, and max.
Fixture/replay timing is excluded from model-inference latency. Token usage is recorded
only when supplied. Cost requires returned usage and an explicit pricing JSON containing
model, input/output cost per million, and currency; no provider price is built in.

## Adapters, retry, concurrency, and resume

- `FixtureAdapter`: deterministic, synthetic, test-only profiles for success and common
  failure modes.
- `ReplayAdapter`: reuses captured raw responses by stable execution key and makes
  rescoring/report improvements inference-free.
- `CommandAdapter`: invokes a provided argument array with `shell=False`, sends JSON via
  stdin, separates/bounds stdout and stderr, and terminates on timeout or output limit.

Command execution is live-capable and requires `--execute-live`; fixture/replay do not.
No HTTP adapter is included in Phase 9. Retries apply only to explicit transient
transport failures, never wrong, insecure, or malformed answers. Concurrency defaults
to one. Resume skips completed `runtime ID | condition | run index` keys.

## Mutations

No mutation runs by default. Explicit eligible Base64, ROT13, hex, zero-width,
Markdown, HTML, XML, JSON, fake-policy/role, sandwich, and bounded-padding variants are
materialized as `parent@mutation` without creating canonical IDs. Homoglyph,
multilingual-paraphrase, and delayed-trigger recipes are marked not automatically
materialized. Canonical and mutation-derived counts remain separate.

## Judge and human review

Deterministic evaluation comes first. The review API supports a narrow optional judge
for a specific unresolved assertion, returning PASS, FAIL, or UNCERTAIN with a short
rationale and excerpt. Judge relationship is one of SAME_MODEL,
SAME_PROVIDER_DIFFERENT_MODEL, DIFFERENT_PROVIDER, HUMAN, or NONE; same-model judgment
is never called independent. Invalid/uncertain judge output remains unresolved.

`export-review` creates JSONL records for unresolved/disputed assertions. Human review
imports PASS/FAIL/UNRESOLVED decisions with an optional non-identifying label and notes.
Machine and judge results remain intact; the overlay records the final adjudication
source instead of overwriting history.

## Artifacts, provenance, replay, and comparison

Ignored `benchmark-runs/<trusted-run-id>/` directories contain a run manifest,
responses JSONL, scores JSONL, JSON/Markdown summary, and optional review queue. Run IDs
come from trusted code or a strictly validated CLI value. Output paths cannot escape the
configured root or target symlinks. Model output never selects a path and Markdown
escapes model labels rather than rendering active HTML.

Manifests record commit, suite/version/hash and per-file hashes, runner/scoring/artifact
versions, conditions, adapter/model/provider, repeats, filters, mutation policy,
parameters, retries/concurrency, context hashes, Python/platform, optional pricing hash,
and a redacted command line. Credentials belong in runtime injection and are never
stored. Raw responses are supported; external holdouts should use a private output root
and `--minimal-artifacts`, which retains response hashes but omits raw response text and
therefore disables later replay rescoring.

Comparison requires equal suite hash, scoring version, and filters. It reports config
differences, metric deltas, and paired scenario/run outcomes. RenGuard-versus-baseline
comparisons should use the same model, scenario keys, and parameters. Deltas do not by
themselves establish causality or statistical significance.

## Schemas, compatibility, and engineering checks

Draft 2020-12 contracts under `schemas/benchmark/` describe run manifests, response and
score records, summaries, review records, and optional user pricing. Response/score JSONL
records inherit artifact version `0.1.0` from their containing run manifest. Unknown
major versions—and any unregistered pre-1.0 artifact version—fail closed. Schema versions
are separately registered in `schemas/versions.json`; Phase 10 did not change runner,
scoring, or artifact versions.

`python scripts/schema_tools.py validate-run benchmark-runs/<run-id>` validates a run
without fetching remote `$ref` targets. `python scripts/check.py` runs the same offline
quality gates used by CI, including a small deterministic fixture smoke test in temporary
storage. CI requires no provider secrets, never passes `--execute-live`, and does not
upload raw benchmark responses.

## Official result policy and limitations

An official result must name the Git commit, suite hash/version, runner/scoring/schema
versions, model/configuration, condition, repeats, judge configuration, public/holdout
status, and date. A percentage without this metadata is not reproducible.

The public suite can be contaminated and does not prove unseen generalization.
Normalized multimodal descriptors do not test native vision/audio. Declarative sinks do
not prove runtime exploit blocking. Judges can fail, stochastic variance remains, and
small slices are descriptive. Private holdouts remain external. Phase 9 ran no live
external model and produced no official RenGuard v2 percentage.
