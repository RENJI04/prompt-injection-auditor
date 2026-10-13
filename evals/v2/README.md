# RenGuard v2 Public Evaluation Suite

This directory contains the public, pre-release RenGuard v2 evaluation corpus created
for Phase 8. It defines security-reasoning scenarios and expected concepts; it contains
no model responses, judge decisions, pass rates, or performance claims. Corpus
validation proves only that these definitions are internally consistent. It does not
prove that RenGuard or any model passes them.

The legacy v2-alpha definitions in `evals/evals.json` and `evals/files/` remain
unchanged. They are not the source corpus for the provenance-preserved 40/41 v1 result;
that exact historical corpus is tied to source commit `c2e8de4`. Neither the historical
result nor the legacy definitions are RenGuard v2 Phase 8 results. The Phase 9 runner
now consumes this corpus, but implementation validation produced no official live model
result.

## Layout

- `manifest.json` is the canonical suite index and records recomputable aggregate data.
- Eleven domain files contain 72 public scenarios grouped by security area.
- `mutations.json` defines safe, declarative mutation recipes; it contains no opaque or
  operational payload bank.
- `HOLDOUT_POLICY.md` describes future private evaluation without pretending that a
  committed file is secret.

## Scenario contract

Every scenario has a stable `RG-EVAL-V2-NNN` ID, title, category, kind, description,
language metadata, explicit target profile, safe synthetic input, structured expected
result, tags, public visibility, mutation eligibility, and relevant references. Missing
runtime facts are represented as `UNKNOWN`, not silently converted to `false` or zero.

The controlled kinds are:

- `ATTACK`: a material security weakness should be detected.
- `CLEAN`: no material vulnerability finding should be created.
- `BOUNDARY`: the case tests a nuanced safe/unsafe distinction.
- `CHAIN`: ordered cross-component reasoning is required; chain risk is not summed.

Multi-turn cases retain an explicit `turns` array. Multimodal cases use normalized
artifact descriptors and set `native_media_required_for_full_benchmark` to `true`.
They test trust, provenance, identity, and architecture reasoning—not native image or
audio perception. Output-sink cases describe sinks declaratively and execute nothing.

## Expected-result model

`must_detect`, `may_detect`, and `must_not_detect` reference stable RenGuard technique
IDs. Primary and secondary techniques remain separate so one root cause is not inflated
into many required findings. OWASP LLM 2026 and conditional Agentic 2026 mappings are
separate assertions rather than substitutes for technique detection.

Assertions are independently grouped as `SECURITY_DETECTION`, `TECHNIQUE_MAPPING`,
`FRAMEWORK_MAPPING`, `RISK`, `CONFIDENCE`, `REMEDIATION`, `REDACTION`, and `FORMAT`.
Security correctness therefore does not fail merely because prose or Markdown differs.
Formatting has no elevated security importance in this corpus.

Risk uses the unchanged Phase 3 model in three modes:

- `EXACT` includes all 12 dimensions and a deterministically recomputable score.
- `BAND` asserts only a defensible severity band.
- `NOT_ASSERTED` avoids inventing facts where risk precision is not meaningful.

Confidence is independent from risk. The suite includes HIGH, MEDIUM, and LOW
confidence, including high-consequence cases with incomplete runtime evidence.

## Coverage and languages

The suite covers all 38 RenGuard techniques across direct authority, RAG/retrieval,
hidden context, tools, MCP, memory, agentic systems, multimodal inputs, output sinks,
cross-cutting risks, and clean/boundary controls. The manifest's coverage matrix is
corpus coverage, not empirical detection performance.

Language metadata uses `en`, `ar`, `fr`, `zh-CN`, `es`, `ja`, and `ru`; a list denotes
meaningfully mixed-language content. Multilingual cases include attacks, boundaries,
and benign controls rather than literal translations of one template.

## Mutations and safety

Mutation recipes cover encoding, Unicode, wrappers, fake authority labels, contextual
sandwiching, multilingual paraphrase, delayed triggers, and bounded context padding.
Phase 9 can materialize explicitly selected eligible variants using harmless synthetic
markers only. It never creates combinations by default; multilingual paraphrase,
homoglyph substitution, and delayed triggers are not automatically materialized.
The public corpus uses placeholders such as `<TEST_SECRET>`, `<TEST_COMMAND>`, and
`<ATTACKER_DESTINATION>`, plus `example.invalid`; it includes no live credentials,
destructive commands, malware, or real exfiltration infrastructure.

## Stable IDs and case mutability

Published IDs are never silently reused or renumbered. A material change to security
semantics requires a new ID or a documented corpus-version migration. Minor typo or
non-semantic metadata corrections may keep the ID. Scenario IDs are distinct from
finding (`RG-F-*`), technique (`RG-PI-*`, etc.), hardening (`RG-HARD-*`), and mutation
(`RG-MUT-*`) IDs.

## Contributions

A new case must represent a meaningful distinct scenario, use a new stable ID, reference
valid techniques, define semantic expected behavior, supply required architecture and
language metadata, and avoid real secrets or destructive payloads. Contributors must not
silently rewrite an existing case, add a supposed hidden case to this public directory,
or add benchmark-result fields. Run the repository validator and unit tests after every
corpus change.

The storage contract is documented by `schemas/eval/scenario.schema.json`, with suite
and mutation contracts beside it and independent versions in `schemas/versions.json`.
Schema validity does not replace semantic validation: stable IDs, recomputed counts,
technique mappings, exact risk arithmetic, and ground-truth consistency remain enforced
by `scripts/validate_repo.py`. Contributors should run `python scripts/check.py`.

## Phase 9 runner contract

`scripts/run_benchmark.py` loads the scenario files in manifest order, validates stable
IDs, then sorts IDs deterministically. Its prompt builder exposes only runtime facts
such as input, turns, artifacts, architecture, and target profile. It excludes scenario
ID, kind, expected results, technique mappings, risk/confidence truth, notes, assertion
groups, and mutation eligibility. Multi-turn role and order are preserved.

The `RENGuard` condition loads `SKILL.md`, core references, and architecture-selected
specialized references. The `BASELINE` condition receives the same generic audit task,
scenario input, architecture, and neutral output contract without RenGuard guidance.
Technique IDs are optional for baseline responses; binary detection is scored from the
material-vulnerability classification rather than taxonomy vocabulary.

Fixture runs are explicitly synthetic engineering tests. Replay rescoring contacts no
model. Generated manifests hash the suite, context files, assembled contexts, pricing
configuration when supplied, and record runner/scoring/artifact versions. Runtime
artifacts belong under ignored `benchmark-runs/`, not in this corpus.

## Limitations

This is a public regression corpus, so systems can eventually see and overfit it. It
does not measure unseen-case generalization, native media perception, live tool or sink
behavior, or universal provider behavior. The Phase 9 runner can measure repeated-run
behavior, latency/usage when an adapter exposes it, deterministic assertions, optional
narrow judging, human review, and statistical summaries. Those capabilities do not
turn corpus coverage into empirical performance; no official live result exists.
