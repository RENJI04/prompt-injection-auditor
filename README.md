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
RAG/retrieval and persistent/shared memory systems. RAG analysis covers source trust,
provenance, ingestion, pre-retrieval authorization, tenant isolation, chunk metadata,
query rewriting, corpus/index poisoning exposure, caches, and retrieval-to-action chains.
Memory analysis covers authority separation, read/write authorization, provenance,
schema, persistence/TTL, cross-session influence, cross-user/tenant isolation,
shared-agent state, conflict policy, and rollback. These modules activate only when the
corresponding subsystem is evidenced; they do not invent RAG or memory findings.

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
| Tools / Actions | `RG-TL` | 5 | CORE and PARTIAL |
| Memory / Context | `RG-ME` | 2 | PARTIAL |
| Agent / Multi-Agent | `RG-AG` | 5 | CORE and PARTIAL |
| Retrieval / Vector / RAG | `RG-RA` | 3 | PARTIAL and PLANNED |
| Supply Chain | `RG-SC` | 1 | PARTIAL |
| Execution / Code | `RG-EX` | 1 | PARTIAL |
| Output Handling | `RG-OU` | 1 | PARTIAL |
| Resource / Consumption | `RG-RC` | 1 | PARTIAL |
| Misinformation / Grounding | `RG-MI` | 1 | PARTIAL |
| Multimodal | `RG-MM` | 1 | PLANNED |

See the [taxonomy methodology and v1→v2 crosswalk](references/vulnerability-taxonomy.md)
and the [canonical technique catalog](references/renguard-techniques.md). `CORE`,
`PARTIAL`, and `PLANNED` describe available audit guidance, not benchmark percentages.

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
│   ├── rag-security.md               # Specialized RAG/retrieval audit domain
│   └── memory-security.md            # Specialized persistent-memory audit domain
├── examples/                         # Worked audit examples
├── evals/
│   ├── evals.json                    # Current RenGuard v2-alpha eval definitions
│   └── files/                        # Current synthetic security test fixtures
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
confidence/exploitability labels, hardening IDs/layers/strength/status/functions, and
worked-example score and remediation consistency.

These commands do **not** execute prompts against a live model and do not reproduce the
historical benchmark. A live model evaluation and benchmark runner is deferred to a
later phase.

## What RenGuard Does Not Yet Do

Phase 5 implements classification, formal audit reasoning, deterministic risk
assessment, defense-in-depth remediation, and specialized RAG/memory audit logic.
This does not mean RenGuard performs live vector-database scanning, empirical embedding
geometry analysis, memory-backend inspection, or backend penetration testing. It audits
the architecture and evidence supplied by the user.

RenGuard does not yet implement dedicated MCP, multimodal, output-security,
or supply-chain scanners; provider/framework profiles; SARIF;
large eval expansion; mutation testing; holdout suites; live multi-model execution; or
statistical confidence intervals. Future work is described as planned work, not current
functionality.

The current prompt-level skill also does not directly test application code, model
weights, network controls, tool implementations, UI output encoding, or stochastic
attack success rates. Those controls require system-level testing beyond prompt review.
Phase 3 scoring, Phase 4 hardening, and Phase 5 RAG/memory behavior have not been measured
by a new live model benchmark.

## Contributing

When changing the current taxonomy, patterns, evals, or benchmark artifact:

1. Keep `SKILL.md` usable as the core product.
2. Preserve historical benchmark provenance rather than rewriting model metadata.
3. Add or update declarative eval data and synthetic fixtures as needed.
4. Run `python scripts/validate_repo.py` and
   `python -m unittest discover -s tests`.

## License

MIT — see [LICENSE](LICENSE).
