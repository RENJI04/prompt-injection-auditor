# RenGuard

> **Model-Agnostic Security for AI Systems & Agents**

[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Development](https://img.shields.io/badge/version-2.0.0--alpha.1-blue)](SKILL.md)
[![Historical Assertion Pass Rate](https://img.shields.io/badge/historical_assertion_pass_rate-97.6%25-brightgreen)](benchmarks/benchmark.json)

Created by **[Shadow (RENJI04)](https://github.com/RENJI04)**

RenGuard is the successor to Prompt Injection Auditor. The project is evolving from
a Claude-oriented prompt auditing skill into a provider-neutral AI and agent security
auditing skill while preserving its skill-first architecture.

`SKILL.md` remains the core product. The references, examples, declarative evals,
historical benchmarks, and validation tooling support and test the skill; they do not
turn this repository into a web application, backend service, or standalone SaaS.

## Current Scope

RenGuard currently audits system prompts, AI application instructions, conversation
logs, and agent specifications using 38 stable, provider-neutral RenGuard technique
IDs. It produces a structured report with calibrated findings, OWASP mappings, concrete
defensive exploit demonstrations, a hardened rewrite, defense-in-depth recommendations,
and a deterministic **RenGuard Risk Score** from 0.0–10.0.

RenGuard v2-alpha now conditionally applies specialized, architecture-aware analysis to
AI tools/functions, MCP deployments, agentic and multi-agent systems, RAG/retrieval,
and persistent/shared memory systems. Tool analysis covers capability classes, origin,
descriptions, schemas, output and recovery injection, deterministic authorization,
credentials, composition, code execution, retries, budgets, and action-bound approval.
MCP analysis is protocol-version aware and covers server/tool trust, audience- and
scope-bound authorization, unsafe token passthrough, confused-deputy and conditional
discovery/SSRF paths, resources/prompts, dynamic capability mutation, supply chain, and
interactive flows. Agentic analysis covers autonomy, goal hijack, identity and privilege
propagation, scoped delegation, inter-agent handoff, cascading failure, human trust,
unexpected code execution, supply chain, long-running/rogue execution, and independently
enforced termination.

RAG analysis covers source trust,
provenance, ingestion, pre-retrieval authorization, tenant isolation, chunk metadata,
query rewriting, corpus/index poisoning exposure, caches, and retrieval-to-action chains.
Memory analysis covers authority separation, read/write authorization, provenance,
schema, persistence/TTL, cross-session influence, cross-user/tenant isolation,
shared-agent state, conflict policy, and rollback. These modules activate only when the
corresponding subsystem is evidenced; they do not invent RAG or memory findings.

Phase 7 adds conditional multimodal and downstream-output analysis. Multimodal review
covers image/screenshot authority, OCR and transcription boundaries, audio/video-derived
instructions, captions, document channels, metadata, provenance, identity assumptions,
and media-to-tool chains. Output review covers structural versus semantic validation,
authorization, sink-specific safety, and command, SQL, HTML/DOM, Markdown, URL, path,
template, code, serialization, JSON, spreadsheet, log/header, and outbound-message
consumers. Output sink classes `OS0`–`OS4` describe architecture and do not set severity.

Phase 8 adds the separate [RenGuard v2 public evaluation suite](evals/v2/README.md):
72 security-reasoning definitions spanning all 38 techniques, with clean and boundary
controls, multi-turn and cross-component chains, seven-language coverage, declarative
mutation recipes, and 12 deterministic risk fixtures. These are test definitions only.
No model was called, no v2 result exists, and a passing corpus validator is not a model-
security benchmark result.

RenGuard performs evidence-bounded architecture, configuration, prompt, and supplied
artifact review. It does **not** automatically connect to arbitrary MCP servers, execute
their tools, penetrate remote infrastructure, validate a live OAuth/IAM backend, or
prove runtime controls without evidence. Architecture/configuration review is not live
penetration testing, MCP compliance is not proof that a server is benign, and framework
mapping is not empirical coverage of every risk.

Phase 3 findings explicitly separate five concepts:

- **Technique** — what the attacker does or how the security failure occurs.
- **Weakness** — the missing or ineffective control that enables it.
- **Impact** — the consequence in the supplied deployment context.
- **Risk** — the calculated likelihood/consequence score and severity band.
- **Confidence** — evidence quality, reported independently from risk.

RenGuard Risk Score is a project-specific AI security assessment model and is not CVSS.
It uses 12 documented 0–4 dimensions, visible weights, and a reproducible formula. Risk
does not equal confidence: incomplete runtime evidence lowers confidence but does not
silently reduce a potentially severe consequence. See the canonical
[risk-scoring specification](references/risk-scoring.md).

Each dimension distinguishes **known zero**, **not applicable**, and **unknown /
insufficient evidence**. The first two legitimately score zero; unknown does not
automatically become zero or an invented high value. RenGuard uses the lowest value
positively supported by evidence, records material gaps, lowers Confidence when
appropriate, and adds a sensitivity note when the missing fact could change severity.
The 40% Exploitability / Exposure component is ordinal, not an estimate of empirical
exploit probability; Impact / Consequence contributes the remaining 60%.

The audit methodology is designed to be model and provider neutral. It can be applied
to GPT-, Claude-, Gemini-, Llama-, Mistral-, DeepSeek-, Qwen-, local/self-hosted,
custom, unknown, and mixed-model architectures. This is a design property, not a claim
that RenGuard has been installed on or empirically benchmarked against every listed
provider. Host-specific skill installation and runtime compatibility vary by platform.

The current taxonomy maps findings to the
[OWASP Top 10 for LLM Applications 2026](references/owasp-llm-2026.md) and, only for
agentic targets, the
[OWASP Top 10 for Agentic Applications 2026](references/owasp-agentic-2026.md).
Framework mapping support and empirical detection coverage are separate: the current
eight-eval suite does not test every technique or every OWASP category.

Projected residual risk is also distinct from implemented protection. A post-control
score is labeled projected unless the named prompt, authorization, tool, runtime,
network, human-approval, and monitoring controls are evidenced and verified.

## Defense-in-Depth Hardening

RenGuard does not treat prompt rewriting as the primary security solution. Prompt
guidance is useful for defining scope, authority, and safe behavior, but prompt
instructions are not a hard security boundary. Authentication, authorization, tenant
isolation, secret handling, tool permissions, sandboxing, egress policy, and sensitive
approvals should be enforced outside the model wherever possible.

| Control type | What it contributes | Security boundary |
|---|---|---|
| Prompt guidance | Authority, scope, untrusted-content handling, refusal behavior | Model-interpreted and probabilistic |
| Application enforcement | Identity-aware authorization, schemas, business rules, tool mediation | Deterministic when correctly implemented |
| Runtime/platform enforcement | Sandboxing, IAM, resource limits, network egress, independent approval | Prevents or contains prohibited effects outside the model |

The canonical [hardening catalog](references/hardening-patterns.md) defines 12 control
layers, five enforcement-strength levels, implementation status, prevention/containment/
detection/recovery functions, stable `RG-HARD-...` pattern IDs, verification guidance,
compensating controls, and reusable defense-in-depth bundles. A proposed control is not
reported as implemented, and mitigation strength does not produce a generic score
discount. Residual risk remains after every layer.

## Taxonomy Architecture

RenGuard uses three layers:

1. **RenGuard techniques** — stable `RG-` IDs used to classify findings.
2. **OWASP LLM Top 10 2026** — broad risk-category cross-references for AI applications.
3. **OWASP Agentic Top 10 2026** — conditional cross-references for systems with tools,
   planning, memory, delegation, autonomy, inter-agent communication, or side effects.

| Technique family | Prefix | Techniques | Current coverage posture |
|---|---|---:|---|
| Prompt Injection | `RG-PI` | 10 | CORE and PARTIAL |
| Hidden Context / Information Exposure | `RG-HC` | 4 | CORE |
| Privilege / Authority | `RG-PR` | 3 | CORE |
| Tools / Actions | `RG-TL` | 5 | CORE |
| Memory / Context | `RG-ME` | 2 | CORE |
| Agent / Multi-Agent | `RG-AG` | 5 | CORE |
| Retrieval / Vector / RAG | `RG-RA` | 3 | CORE and PARTIAL |
| Supply Chain | `RG-SC` | 1 | CORE |
| Execution / Code | `RG-EX` | 1 | CORE |
| Output Handling | `RG-OU` | 1 | CORE |
| Resource / Consumption | `RG-RC` | 1 | CORE |
| Misinformation / Grounding | `RG-MI` | 1 | PARTIAL |
| Multimodal | `RG-MM` | 1 | PARTIAL |

See the [taxonomy methodology and v1→v2 crosswalk](references/vulnerability-taxonomy.md)
and the [canonical technique catalog](references/renguard-techniques.md). `CORE`,
`PARTIAL`, and `PLANNED` describe available audit guidance, not benchmark percentages.
The current catalog contains 33 CORE, 5 PARTIAL, and 0 PLANNED techniques.

## How to Use the Skill

Install or load the repository using the skill mechanism supported by your host, then
ask RenGuard to review an artifact. Example requests:

```text
Audit this system prompt for injection vulnerabilities: [paste prompt]
Is this AI assistant configuration secure?
Red-team this chatbot prompt and show me the attack surface.
Harden this agent specification against prompt injection.
```

Hosts that support automatic skill selection may also select RenGuard when a system
prompt or agent configuration is supplied. That behavior depends on the host; the core
methodology itself does not require external tools for prompt-level analysis.

## Example Output

From the NovaPay fintech chatbot audit in
[Example 1](examples/01-chatbot-prompt.md):

```text
## RenGuard Security Audit Report

Target: Penny, NovaPay Customer Support
Overall Risk: 7.5 HIGH
Overall Confidence: MEDIUM
Findings: 5 findings (0 Critical, 2 High, 3 Medium, 0 Low)

RG-F-001 — Hardcoded Production API Token [HIGH]
RenGuard Technique: RG-HC-003 — Credential or Secret Exposure
OWASP LLM 2026: LLM02:2026 Sensitive Information Disclosure
OWASP Agentic 2026: ASI03 Identity & Privilege Abuse
RenGuard Risk Score: 7.5 HIGH
Confidence: MEDIUM
Impact: An attacker may obtain a transactions API credential from the prompt.
```

Prompt hardening is one layer of defense. RenGuard also recommends controls such as
least-privilege tool access, authentication, schema validation, output handling,
human approval, secrets management, and monitoring where the audited system needs them.

## Repository Structure

```text
prompt-injection-auditor/             # Remote repository name remains unchanged
├── SKILL.md                          # Core RenGuard auditing skill
├── README.md
├── CHANGELOG.md
├── references/
│   ├── vulnerability-taxonomy.md     # Methodology and v1→v2 crosswalk
│   ├── renguard-techniques.md        # Canonical 38-technique catalog
│   ├── owasp-llm-2026.md             # OWASP LLM 2026 reference
│   ├── owasp-agentic-2026.md         # Conditional Agentic 2026 reference
│   ├── risk-scoring.md                # Canonical RenGuard Risk Score specification
│   ├── hardening-patterns.md         # Canonical defense-in-depth catalog
│   ├── tool-security.md               # Generic tool/function specialized audit domain
│   ├── mcp-security.md                # Version-aware MCP specialized audit domain
│   ├── agentic-security.md            # Agentic/multi-agent specialized audit domain
│   ├── rag-security.md               # Specialized RAG/retrieval audit domain
│   ├── memory-security.md            # Specialized persistent-memory audit domain
│   ├── multimodal-security.md        # Media/OCR/transcription specialized audit domain
│   └── output-security.md            # Downstream output/sink specialized audit domain
├── examples/                         # Worked audit examples
├── evals/
│   ├── evals.json                    # Legacy v2-alpha definitions; not v1 result source
│   ├── files/                        # Legacy v2-alpha fixtures; not v1 result source
│   └── v2/                           # Public Phase 8 definitions; no model results
│       ├── manifest.json             # Recomputable suite counts and coverage matrix
│       ├── *.json                    # Domain-grouped public scenarios and mutations
│       ├── README.md                 # Scenario contract and contribution rules
│       └── HOLDOUT_POLICY.md         # Policy only; no supposed-secret public cases
├── benchmarks/
│   └── benchmark.json                # Canonical corrected historical v1 artifact
├── scripts/
│   └── validate_repo.py              # Dependency-free consistency validator
└── tests/
    └── test_validation.py            # Standard-library validator tests
```

## Historical Benchmark Results

The repository contains one historical v1 benchmark artifact, dated 2026-04-26.
Its metadata records `claude-sonnet-4-6` as both executor and analyzer and one run per
configuration across eight evals. These results describe that recorded run only; they
are not multi-provider benchmark evidence.

The benchmark corpus is the exact `evals/evals.json` and `evals/files/` tree at source
commit `c2e8de497b7550ca3ca4df081efae27ddd28d582` (`c2e8de4`). The current working-tree
eval definitions and fixtures are the RenGuard v2-alpha corpus and were **not** used to
produce the historical 40/41 result. In Phase 1, the eval prompts and assertions stayed
unchanged, but the defensive wording in the eval 3 and eval 8 fixtures changed. Use the
source commit—not the current eval files—when inspecting or reproducing the historical
benchmark corpus.

Two different aggregation methods are reported and must not be mixed:

| Configuration | Assertion Pass Rate (micro) | Assertions | Mean Eval Pass Rate (macro) |
|---------------|-----------------------------|------------|-----------------------------|
| **With Skill** | **97.6%** | **40 / 41** | **97.92%** |
| Without Skill | 68.3% | 28 / 41 | 70.42% |
| Difference | +29.27 percentage points | — | +27.50 percentage points |

- **Assertion Pass Rate / micro average** pools all assertions: `passed / total`.
- **Mean Eval Pass Rate / macro average** gives each eval run equal weight by averaging
  the pass rate recomputed from that run's assertion counts.

The historical mean execution times were 126.3 seconds with the skill and 103.6875
seconds without it, a difference of 22.6125 seconds. Timing comes from a single run per
configuration and should not be generalized.

The canonical historical data and corrected notes are in
[benchmarks/benchmark.json](benchmarks/benchmark.json). The legacy
`prompt-injection-auditor` name and Claude model identifiers remain in its metadata to
preserve provenance.

The historical 40/41 result does not measure the Phase 8 public suite or Phase 5–7
specializations. The v2 suite has no model outputs or benchmark result. Future private
holdout content must remain outside this public repository; the committed
[holdout policy](evals/v2/HOLDOUT_POLICY.md) is not a hidden corpus.

## RenGuard v2 Public Evaluation Suite

The Phase 8 suite has 72 public scenarios grouped into direct authority, RAG/retrieval,
hidden context, tools, MCP, memory, agentic, multimodal, output-sink, cross-cutting, and
clean-control domains. It includes clean and nuanced boundary cases to resist keyword-
only scoring, at least ten explicit multi-turn cases, at least ten ordered attack chains,
meaningful English, Arabic, French, Chinese, Spanish, Japanese, and Russian content,
safe mutation recipes, and exact Phase 3 score fixtures where evidence is complete.

Expected results separate security detection, technique mapping, framework mapping,
risk, confidence, remediation, redaction, and formatting. Multimodal definitions use
normalized textual descriptors and do not prove native media perception. Output sinks
are declarative and are never executed. The public corpus and a future private holdout
share a contract, but actual private cases must be stored outside Git. See the
[suite documentation](evals/v2/README.md) and
[manifest](evals/v2/manifest.json).

## Benchmarking

Phase 9 adds a standard-library, offline-first runner for the 72-scenario public suite.
It supports deterministic loading and filters, `RENGuard` and fair `BASELINE`
conditions, repeated runs, fixture and replay workflows, assertion-group scoring,
confusion matrices, precision/recall/F1, Wilson intervals, risk and confidence checks,
stability, human review, provenance hashes, and compatible-run comparison.

Safe commands do not contact a model:

```sh
python scripts/run_benchmark.py --help
python scripts/run_benchmark.py validate
python scripts/run_benchmark.py plan --condition BOTH --runs 3
python scripts/run_benchmark.py run --adapter fixture --ids RG-EVAL-V2-001,RG-EVAL-V2-061
python scripts/run_benchmark.py score --run-dir benchmark-runs/<run-id>
python scripts/run_benchmark.py summarize --run-dir benchmark-runs/<run-id>
```

`FixtureAdapter` is test-only, while `ReplayAdapter` rescores captured responses without
another inference call. `CommandAdapter` uses an argument array and stdin, bounds
stdout/stderr, and requires the explicit `--execute-live` gate. It can wrap a local
model or an externally configured client, but the repository provides no provider SDK
and stores no credentials. Repeats preserve each scenario-run observation. Optional
cost calculation requires both returned token usage and a user-supplied pricing file;
the repository does not hardcode provider prices.

External private suites may be supplied with `--suite` and remain outside Git. Public
suite results carry contamination risk and do not establish unseen-case generalization.
Normalized multimodal cases do not test native perception, and declarative sink cases
do not execute exploits. Phase 9 produced no official v2 live result. See
[Benchmarking RenGuard](BENCHMARKING.md) for the artifact, scoring, review, safety, and
comparison contracts.

## Repository Validation

The eval definitions, taxonomies, and historical results are declarative data. The
deterministic validator uses only the Python standard library:

```sh
python scripts/validate_repo.py
python -m unittest discover -s tests
```

The validator checks JSON parsing, unique IDs, fixture existence, benchmark/eval
references, result arithmetic, pass rates, recomputed micro and macro summaries,
historical source-commit provenance, known contradictory notes, documented headline
values, important relative links, official framework IDs/names, unique RenGuard IDs,
valid cross-references, the risk formula and bands, scoring dimensions, finding IDs,
confidence/exploitability labels, hardening IDs/layers/strength/status/functions,
worked-example score and remediation consistency, the complete v2 scenario contract,
and the Phase 9 runner's versions, modules, adapters, leakage controls, artifact ignore,
and subprocess safety. It recomputes corpus/category/kind/language counts, multi-turn
and chain counts, exact scores, mutation references, and 38-technique coverage.

These commands do **not** execute prompts against a live model and do not reproduce the
historical benchmark. Repository validation is not model evaluation.

## What RenGuard Does Not Yet Do

RenGuard provides architecture- and evidence-aware audit guidance; specialized references
do not turn it into a live scanner or penetration-testing service. It does not
automatically perform image steganalysis, hidden-pixel or ultrasonic detection, deepfake
detection, biometric verification, OCR accuracy certification, malware analysis, browser
exploitation, live sink exploitation, full static source-code analysis, vector-database
scanning, empirical embedding geometry analysis, or backend inspection. Those claims
require relevant artifacts, tools, environments, and separately authorized testing.

RenGuard also does not yet implement provider/framework profiles, SARIF, an
in-repository private holdout, provider SDK integrations, or an official live v2
benchmark result. It does not claim that all multimodal
attacks are detected, that valid JSON/schema is safe or authorized, that Markdown is
inert, that generated URLs or code are trusted, or that one sanitizer protects every
sink. Current analysis is bounded by supplied evidence and host capabilities.

The skill does not directly prove application code, model weights, network controls,
tool implementations, output encoding, authorization, sandboxing, or stochastic attack
success rates. Those controls require safe system-level verification. Phase 3 scoring,
Phase 4 hardening, and Phase 5–7 specialized behavior have not been measured by the new
public corpus because Phase 9 implementation used only synthetic fixture and replay
verification, not a live external model benchmark.

## Contributing

When changing the current taxonomy, patterns, evals, or benchmark artifact:

1. Keep `SKILL.md` usable as the core product.
2. Preserve historical benchmark provenance rather than rewriting model metadata.
3. Add or update declarative eval data and synthetic fixtures as needed.
4. Run `python scripts/validate_repo.py` and
   `python -m unittest discover -s tests`.

## License

MIT — see [LICENSE](LICENSE).
