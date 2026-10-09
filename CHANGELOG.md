# Changelog

All notable project changes are documented here. RenGuard v2 remains in development;
no final v2.0.0 release is declared by this file.

## Unreleased — RenGuard 2.0.0-alpha.1

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
