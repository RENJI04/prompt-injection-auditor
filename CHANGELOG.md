# Changelog

All notable project changes are documented here. RenGuard v2 remains in development;
no final v2.0.0 release is declared by this file.

## Unreleased — RenGuard 2.0.0-alpha.1

### Phase 11 examples and documentation

- Rebuilt the README as an external-reader technical landing page with accurate product
  boundaries, quick start, audit workflow, domain coverage, risk/hardening summaries,
  evaluation status, limitations, and repository navigation.
- Added focused architecture, threat-model, and usage documentation that links to the
  normative Skill and reference sources rather than duplicating their specifications.
- Reviewed the four existing worked audits and added safe educational examples for
  persistent-memory poisoning and MCP multi-agent delegation/approval boundaries.
- Clarified that public corpus size and synthetic fixture runs are not performance,
  historical v1 evidence is not a v2 result, multimodal cases use normalized
  descriptors, and output-sink cases do not execute production effects.
- Added offline documentation link and claim regression checks without introducing a
  documentation framework, network dependency, release claim, or hosted-CI claim.

### Phase 10 CI, schemas, and repository engineering

- Added Draft 2020-12 structural contracts for Phase 8 scenario, suite-manifest, and
  mutation formats and Phase 9 run, response, score, summary, review, and pricing formats.
- Added an independent semantic-version registry, compatibility policy, and safe local
  `$ref` validation with no remote fetching or claim of complete JSON Schema support.
- Added a dependency-free quality gate covering validation, tests, compilation,
  schema/JSON checks, and a deterministic temporary FixtureAdapter smoke run.
- Configured read-only, secret-free GitHub Actions CI with a Python 3.10–3.13 target
  matrix on pushes and pull requests, with no live model execution or artifact upload.
  Phase 10 local verification used Python 3.12.14; the hosted matrix has not yet run.
- Added contributor/security guidance, editor normalization, artifact hygiene, version
  checks, and schema/CI/repository regression coverage.
- Preserved Phase 3–9 security and benchmark semantics, protected historical artifacts,
  and all Phase 9 versions. No official v2 live benchmark result was produced.

### Phase 9 benchmark runner and statistical evaluation

- Added an offline-first, standard-library benchmark runner with validate, plan, run,
  score, summarize, compare, review-export, and review-apply commands.
- Added immutable scenario loading/filtering, strict evaluator-ground-truth isolation,
  deterministic RenGuard context routing/hashing, and fair RenGuard/baseline conditions.
- Added fixture, replay, and bounded argument-array command adapters with explicit live
  execution gating, transport-only retries, conservative concurrency, and resume keys.
- Added explicit parser and assertion states, deterministic security/technique/framework/
  risk/confidence/remediation/redaction scoring, and immutable machine/judge/human trails.
- Added confusion matrices, precision/recall/F1/specificity/FPR/FNR, Wilson intervals,
  clean and boundary reports, risk MAE, subgroup sample warnings, and run stability.
- Added safe deterministic mutation materialization, public/private suite handling,
  provenance manifests, JSONL replay artifacts, Markdown/JSON reports, and paired run
  comparison without causal-significance claims.
- Added optional user-supplied pricing support without embedded provider prices; token
  and cost fields remain unavailable when adapters do not return usage.
- Added focused benchmark documentation, deterministic synthetic fixtures, runner
  validation, and substantive offline unit/workflow tests.
- Preserved Phase 3–8 security architecture and the historical v1 corpus/result. No
  official RenGuard v2 performance result was produced, and no live external model was
  contacted.

### Phase 8 advanced evaluation suite

- Added a separate `evals/v2/` public corpus with 72 stable-ID security-reasoning
  scenarios grouped across direct authority, retrieval, hidden context, tools, MCP,
  memory, agentic, multimodal, output-sink, cross-cutting, and clean-control domains.
- Covered all 38 RenGuard techniques without changing their 33 CORE / 5 PARTIAL /
  0 PLANNED implementation posture; corpus coverage is not detection performance.
- Added clean and nuanced boundary controls, 12 explicit multi-turn scenarios,
  19 ordered cross-component chains, and 22 non-English or mixed-language scenarios
  across English, Arabic, French, Chinese, Spanish, Japanese, and Russian.
- Added 15 safe declarative mutation recipes without opaque credential, malware, or
  destructive-command payloads.
- Added 12 deterministic Phase 3 scoring fixtures spanning INFORMATIONAL through
  CRITICAL, plus independent risk, confidence, remediation, redaction, framework,
  technique, security, and formatting assertion groups.
- Added normalized multimodal descriptors, declarative non-executed output sinks, and
  five synthetic-secret redaction/rotation cases with explicit capability limitations.
- Added public suite documentation, stable-ID and case-mutability rules, contribution
  guidance, a private holdout policy with no fake hidden cases, and a recomputable
  manifest/technique coverage matrix.
- Extended the network-independent validator and standard-library tests for corpus
  contracts, counts, mappings, exact scores, languages, mutations, holdout honesty,
  historical hashes, and Phase 3–7 integrity.
- Preserved the historical benchmark and legacy eval paths exactly, kept the 40/41
  result tied to original source commit `c2e8de4`, and produced no model calls, v2 model
  results, detection percentages, runner, or Phase 9 implementation.

### Phase 7 multimodal and output security engine

- Added conditional specialized audit domains for images/screenshots, OCR, audio/
  transcription, video/captions, mixed-modality documents, metadata, and model output
  consumed by automated downstream sinks.
- Added canonical `references/multimodal-security.md` guidance for modality/source
  profiling, provenance through transformations, content-versus-authority separation,
  appearance/voice identity claims, media-to-tool chains, RAG/memory/tool composition,
  safe verification, and explicit forensic limitations.
- Added canonical `references/output-security.md` guidance and `OS0`–`OS4` sink classes
  for shell, SQL, HTML/DOM, Markdown, URL, path, template, generated code,
  serialization, JSON/XML, spreadsheet, log/header, and outbound-message boundaries.
  Sink class remains distinct from and does not determine the Phase 3 score.
- Formalized four independent output questions: structural validity, semantic validity,
  authorization, and exact-sink safety, with destination-specific encoding,
  canonicalization, quarantine, provenance, and recovery guidance.
- Integrated multimodal-to-tool, output-to-tool, and output-to-agent paths with the
  unchanged Phase 3 attack-chain model and evidence-bounded scoring.
- Reused the existing 27 hardening patterns, expanded `RG-HARD-P-001` and
  `RG-HARD-OUT-001`, and added Multimodal Agent and Output-Processing Pipeline bundles;
  no new hardening ID was necessary.
- Promoted `RG-MM-001` from PLANNED to PARTIAL for architecture/content-aware analysis
  that explicitly excludes dedicated forensics. Promoted `RG-OU-001` from PARTIAL to
  CORE for comprehensive operational sink analysis. The resulting posture is 33 CORE,
  5 PARTIAL, and 0 PLANNED techniques.
- Added a worked multimodal field-service example with inert screenshot content, URL/
  command sinks, a single scored attack chain, and deterministic boundary controls.
- Extended offline validation and standard-library regression tests for Phase 7 files,
  conditional routing, technique references, trust and identity boundaries, output sink
  classes, unsafe consumption guidance, coverage transitions, and Phase 3 integrity.
- Left the historical benchmark and current eval corpus unchanged; no live model,
  forensic engine, sink exploit, or Phase 8 evaluation was run.

### Phase 6 tool, MCP, and agentic security engine

- Added conditional specialized audit domains for generic AI tools/functions, MCP
  deployments, autonomous agents, and multi-agent architectures.
- Added canonical tool guidance for `TC0`–`TC4` capability classification, origin and
  name collisions, description/output/error injection, schema and semantic validation,
  deterministic authorization, credentials, composition, code execution, retries, and
  budgets. Capability class does not replace the Phase 3 score.
- Verified the final stable MCP `2026-07-28` specification on 2026-10-10 from official
  project sources and documented its stateless lifecycle, JSON Schema 2020-12 behavior,
  authorization and token isolation, confused-deputy and conditional discovery/SSRF
  analysis, metadata trust, dynamic capabilities, MRTR, deprecated sampling, and
  extension maturity. Native modern deployments are not checked against obsolete
  `initialize` or `Mcp-Session-Id` requirements.
- Added architecture-aware agent analysis for goals, identity and privilege, scoped
  delegation, no default sub-agent privilege inheritance, structured handoffs, loops,
  cascading failures, human trust, unexpected code execution, supply chain,
  long-running/rogue execution, and independently enforced termination and recovery.
- Expanded the existing Tool-Using Agent bundle and added MCP Deployment and
  Multi-Agent System bundles by reusing the 27 canonical hardening patterns; no
  duplicate pattern was added.
- Promoted `RG-TL-004`, `RG-AG-003`, `RG-AG-004`, `RG-AG-005`, `RG-SC-001`,
  `RG-EX-001`, and `RG-RC-001` from PARTIAL to CORE because the core skill now routes
  to specialized profiling, checks, chain analysis, verification, and controls. The
  resulting posture is 32 CORE, 5 PARTIAL, and 1 PLANNED technique.
- Upgraded the autonomous coding-agent example with a tool inventory, capability
  classes, origin/authority boundaries, composition and attack-chain analysis,
  parameter-bound approval, monitoring, containment, and recovery.
- Extended offline validation and standard-library regression tests for all Phase 6
  references, routing, MCP provenance/version rules, tool and agent authority
  boundaries, approval binding, token handling, coverage transitions, and unchanged
  Phase 3 scoring.
- Left the historical benchmark and current eval corpus unchanged; no MCP server was
  contacted, no live penetration test was performed, and no model benchmark was run.

### Phase 5 RAG and memory security engine

- Added conditional, architecture-aware RAG and persistent/shared-memory audit domains
  without turning RenGuard into a standalone scanner.
- Added canonical RAG guidance for trust, provenance, ingestion, pre-retrieval
  authorization, tenant isolation, chunk metadata, query rewriting, corpus/index
  poisoning exposure, caches, citations, and retrieval-to-action chains.
- Added canonical memory guidance for authority separation, read/write authorization,
  provenance, typed schemas, persistence/TTL, cross-session/user/tenant isolation,
  shared-agent state, conflict policy, monitoring, deletion, and rollback.
- Promoted `RG-RA-001`, `RG-RA-002`, `RG-ME-001`, and `RG-ME-002` from PARTIAL to CORE
  because the core skill now routes to specialized profiles, checks, scoring guidance,
  and mitigations. Promoted `RG-RA-003` from PLANNED to PARTIAL for architectural
  vector/index controls while explicitly excluding empirical vector-space analysis.
- Expanded the existing RAG and Memory-Enabled Assistant hardening bundles without
  adding duplicate hardening patterns; the catalog remains at 27 patterns.
- Updated the RAG worked example with conditional subsystem detection, trust,
  provenance, retrieval-authorization, memory-scope, and unknown-fact analysis.
- Extended offline validation and standard-library regression tests for Phase 5 files,
  checklists, technique references, authority boundaries, tenant identity, evidence
  handling, coverage status, and Phase 3 formula integrity.
- Left the historical benchmark and current eval corpus unchanged; no live model,
  vector-database, or memory-backend benchmark was run.

### Phase 4 defense-in-depth hardening

- Rebuilt the remediation catalog around 12 control layers and stable, non-renumbering
  `RG-HARD-...` pattern IDs rather than prompt snippets alone.
- Added explicit control-strength, implementation-status, and PREVENT / CONTAIN /
  DETECT / RECOVER classifications with verification and residual-risk guidance.
- Formalized trusted identity, deny-by-default authorization, least privilege, tool
  schemas, secret isolation, sandboxing, egress restrictions, and secure failure.
- Distinguished chat confirmation from authenticated, parameter-bound approval and
  documented approval TOCTOU defenses.
- Added generic memory and inter-agent boundaries, privacy-aware monitoring, rollback,
  revocation, resource limits, safe output handling, and compensating controls.
- Added reusable defense-in-depth bundles and an anti-pattern catalog for controls that
  look strong but are not deterministic security boundaries.
- Updated the core skill, README, and three examples to separate prompt mitigations from
  proposed deterministic controls and to cite verifiable hardening patterns.
- Extended offline validation and standard-library tests for the Phase 4 hardening
  schema, references, labels, status honesty, prompt-only enforcement claims, approval
  wording, and zero-residual-risk claims.
- Left the current eval corpus and historical v1 benchmark unchanged; no live model
  benchmark was run for Phase 4.

### Phase 3 audit engine and risk scoring

- Added the project-specific, non-CVSS RenGuard Risk Score with 12 explicit 0–4
  dimensions, documented weights, one-decimal scoring, and fixed severity bands.
- Distinguished known-zero and not-applicable values from unknown evidence, made the
  40% Exploitability / Exposure and 60% Impact / Consequence groups explicit, and added
  sensitivity notes for material runtime gaps without speculative score inflation.
- Separated numeric risk from HIGH / MEDIUM / LOW confidence and formalized TRIVIAL,
  EASY, MODERATE, HARD, and CONDITIONAL exploitability labels.
- Added per-report `RG-F-` finding IDs, architecture-aware blast radius, persistence,
  reversibility, external reach, attack-chain, cascading-risk, and overall-risk rules.
- Added conservative projected residual-risk and before/after remediation comparisons
  using the same deterministic formula.
- Classified recommendations across prompt, application, authorization, tool, runtime,
  network, human-approval, and monitoring controls; clarified that chat confirmation is
  not robust authorization.
- Extended the core skill and three worked examples with score vectors, confidence,
  attack/weakness/impact separation, control tags, and verification guidance.
- Extended offline validation and unit tests for the risk specification, severity
  consistency, finding IDs, formula fixtures, labels, and example secret handling.
- Left current eval scenarios and the historical v1 benchmark artifact unchanged;
  Phase 3 has not been measured by a new live model benchmark.

### Phase 2 taxonomy modernization

- Added a stable 38-technique RenGuard taxonomy across 13 provider-neutral families.
- Migrated current framework mappings to OWASP Top 10 for LLM Applications 2026.
- Added conditional mappings for OWASP Top 10 for Agentic Applications 2026.
- Added an explicit v1→v2 crosswalk separating attack mechanism, enabling weakness,
  and impact while preserving the value of the original eight broad categories.
- Updated the core skill report format and worked examples with RenGuard technique IDs
  and applicable 2026 framework mappings.
- Extended offline validation and standard-library tests for framework names, unique
  technique IDs, cross-references, required files, and unsupported coverage claims.
- Left the current eval scenarios unchanged and preserved the historical v1 benchmark
  source commit and methodology.

### Phase 1 foundation

- Began the internal rebrand from Prompt Injection Auditor to RenGuard.
- Kept `SKILL.md` as the core product and clarified the boundary between the
  provider-neutral audit methodology and host-specific skill compatibility.
- Replaced Claude-exclusive positioning while retaining truthful Claude model metadata
  in the historical benchmark artifact.
- Corrected the historical benchmark summary and notes, explicitly separating the
  40/41 (97.56%) assertion-weighted result from the 97.92% mean eval result.
- Bound the historical benchmark corpus to source commit
  `c2e8de497b7550ca3ca4df081efae27ddd28d582` and explicitly distinguished it from
  the current RenGuard v2-alpha eval corpus. Eval prompts and assertions were unchanged;
  defensive fixture wording changed for evals 3 and 8.
- Added dependency-free repository validation and standard-library regression tests.
- Replaced overly broad “all user input is data” guidance with authority-aware handling
  of legitimate requests and untrusted embedded instructions.
- Clarified that the original v1 OWASP mappings are approximate cross-references and
  that prompt hardening is one part of a defense-in-depth program.

## 1.0.0 — Prompt Injection Auditor

- Established the original skill-first prompt injection audit workflow.
- Added the eight-category v1 taxonomy, hardening patterns, worked examples, eight
  declarative eval scenarios, and the historical with-skill/without-skill benchmark.
