# RenGuard v2.0.0 Release Candidate Notes

RenGuard is a model-agnostic security auditing Skill and framework for AI systems and
agents. This repository state is a locally validated release candidate targeting
v2.0.0; it has not been tagged or published as a GitHub release.

## Major capabilities

- A provider-neutral catalog of 38 RenGuard techniques with an honest implementation
  posture of 33 CORE, 5 PARTIAL, and 0 PLANNED.
- A reproducible twelve-dimension RenGuard Risk Score that keeps severity independent
  from evidence confidence and never treats unknown evidence as zero.
- Twenty-seven defense-in-depth hardening patterns spanning prevention, containment,
  detection, and recovery across prompt, application, identity, authorization, data,
  tool, memory, runtime, network, approval, monitoring, and recovery layers.
- Conditional security analysis for RAG, persistent memory, tools, MCP, agentic
  workflows, multimodal inputs, and downstream output sinks.
- A public 72-scenario evaluation corpus covering all 38 techniques, with 15 safe
  mutation recipes, multilingual cases, boundary cases, and attack chains.
- A model-agnostic, offline-first benchmark runner with fixture, replay, and explicitly
  gated command adapters; deterministic scoring; repeated-run analysis; Wilson
  intervals; optional judge disclosure; and auditable human-review overlays.
- Nine Draft 2020-12 JSON schemas, a version registry, model-offline CI configuration,
  repository validation, examples, and reader-oriented documentation.

## Evaluation and benchmark status

No official RenGuard v2 live-model benchmark result is included in this release
candidate. The 72 scenarios are public evaluation definitions, not 72 live-model
passes. FixtureAdapter results are synthetic engineering validation and must not be
reported as product performance. Public-suite results alone cannot establish unseen-case
generalization; private holdouts remain external to public Git.

The absence of a live-model result does not block release of the core auditing
framework because no quantitative live-performance claim is made. Any later official
result must identify its source commit, suite hash and versions, configuration, repeats,
review policy, and public/holdout split.

## Compatibility and publication state

CI is configured to target Python 3.10–3.13. Phase 10 local verification covered Python
3.12.14; the hosted matrix remains pending and the full range is targeted compatibility,
not hosted-verified support.

The product version in `SKILL.md` is prepared as `2.0.0`, while the public suite,
runner, scoring, artifact, and schema contracts retain their independent versions. No
tag, GitHub release, push, repository rename, package publication, or source archive is
part of this release-candidate preparation.

## Limitations

- RenGuard assists security review; it is not runtime enforcement or a substitute for
  deterministic authorization, isolation, network controls, monitoring, recovery, or
  professional testing where those controls are required.
- Five techniques remain PARTIAL where comprehensive analysis requires specialized
  runtime, forensic, vector/embedding, truth-verification, or native-media evidence.
- Current public multimodal cases use normalized descriptors and do not measure native
  vision/audio perception, steganalysis, deepfake detection, biometric verification,
  certified OCR, malware analysis, or exhaustive media forensics.
- Output-sink cases are declarative and do not execute production shell, SQL, network,
  filesystem, browser, or deployment effects.
- No numerical RenGuard v2 performance claim is made by this release candidate.

See [README.md](README.md), [BENCHMARKING.md](BENCHMARKING.md), and the
[release checklist](RELEASE_CHECKLIST.md) for usage, methodology, and remaining public
release gates.
