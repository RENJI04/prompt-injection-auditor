# RenGuard v2.0.0

**Model-Agnostic Security for AI Systems & Agents**

Release status: **locally validated release candidate**. This repository state targets
v2.0.0; it has not been tagged or published as a GitHub release.

## Overview

RenGuard is a model-agnostic security auditing Skill and framework for AI systems and
agents. It helps reviewers identify trust-boundary failures, map findings consistently,
assess evidence-bounded risk, and recommend defense in depth across prompts, retrieval,
memory, tools, MCP, agents, multimodal inputs, and output sinks.

## Security coverage

- A provider-neutral catalog of 38 RenGuard techniques.
- Honest implementation posture: 33 CORE, 5 PARTIAL, and 0 PLANNED.
- Cross-references for the OWASP LLM and OWASP Agentic 2026 taxonomies.
- Explicit separation of attack technique, enabling weakness, consequence, finding ID,
  evidence confidence, and control status.

## Risk and hardening

- A reproducible twelve-dimension RenGuard Risk Score that keeps severity independent
  from evidence confidence and never treats unknown evidence as zero.
- Twenty-seven defense-in-depth patterns spanning prevention, containment, detection,
  and recovery across prompt, application, identity, authorization, data, tool, memory,
  runtime, network, approval, monitoring, and recovery layers.
- Proposed controls remain distinct from implemented controls; residual risk requires
  evidence-based reassessment and is not automatically reduced to zero.

## RAG, memory, tools, MCP, and agents

Conditional guidance covers retrieval provenance and authorization, persistent-memory
scope and lifecycle, tool capability and parameter controls, current MCP trust
boundaries, and agent delegation, handoffs, termination, and recovery. Retrieved data,
memory entries, tool output, and agent assertions do not become policy or authorization
merely because a model can observe them.

## Multimodal and output security

RenGuard analyzes normalized evidence from images, screenshots, OCR, audio,
transcripts, video, captions, and metadata without claiming native-media forensics.
Generated output remains untrusted until it is validated for the exact downstream sink,
including commands, SQL, HTML, Markdown, URLs, paths, code, and messages.

## Evaluation framework

- A public 72-scenario corpus covering all 38 techniques.
- Fifteen safe mutation recipes plus multilingual, boundary, multi-turn, exact-risk,
  and attack-chain cases.
- Nine Draft 2020-12 repository schemas and semantic validation beyond structural JSON
  validity.

Public-suite coverage is regression evidence, not proof of unseen-case generalization.
Private holdouts remain external to public Git.

## Benchmark runner

The model-agnostic, offline-first runner provides fixture, replay, and explicitly gated
command adapters; deterministic scoring; repeated-run analysis; Wilson intervals;
optional judge disclosure; and auditable human-review overlays. Live-capable execution
requires an explicit gate and is not used by standard validation or CI.

## Repository engineering

- Dependency-free validation and benchmark tooling using the Python standard library.
- Model-offline quality gate and CI configuration targeting Python 3.10–3.13.
- Phase 10 local verification on Python 3.12.14; the hosted matrix remains pending and
  is targeted compatibility rather than hosted-verified support.
- Versioned suite, runner, scoring, artifact, and schema contracts independent from the
  RenGuard product release target.

## Documentation and examples

Reader-oriented architecture, threat-model, usage, benchmark, schema, contribution,
security, and evaluation documentation is included with six educational audit examples.
Approved RenGuard branding and a manual GitHub publication runbook are prepared in the
repository; their presence does not imply publication or Social Preview configuration.

## Known limitations

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

## Benchmark status

No official RenGuard v2 live-model benchmark result is included in this release
candidate. The 72 scenarios are public evaluation definitions, not 72 live-model
passes. FixtureAdapter results are synthetic engineering validation and must not be
reported as product performance. No numerical RenGuard v2 performance claim is made by
this release candidate.

The absence of a live-model result does not block release of the core auditing
framework because no quantitative live-performance claim is made. Any later official
result must identify its source commit, suite hash and versions, configuration, repeats,
review policy, and public/holdout split.

## Adoption notes

Start with [`SKILL.md`](SKILL.md), then use the [usage guide](docs/usage.md) and
[examples](examples/) for the audit workflow. Review [BENCHMARKING.md](BENCHMARKING.md)
before interpreting evaluation artifacts. Publication owners should follow the
[release checklist](RELEASE_CHECKLIST.md) and
[GitHub publication guide](release/GITHUB_PUBLISHING.md); hosted CI, tagging, Social
Preview configuration, and GitHub Release creation remain separate external actions.
