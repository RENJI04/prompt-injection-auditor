# Changelog

All notable project changes are documented here. RenGuard v2 remains in development;
no final v2.0.0 release is declared by this file.

## Unreleased — RenGuard 2.0.0-alpha.1

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
