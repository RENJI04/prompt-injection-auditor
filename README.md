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
logs, and agent specifications for the original project's eight prompt-security
categories. It produces a structured report with calibrated findings, concrete exploit
demonstrations, a hardened rewrite, and defense-in-depth recommendations.

The audit methodology is designed to be model and provider neutral. It can be applied
to GPT-, Claude-, Gemini-, Llama-, Mistral-, DeepSeek-, Qwen-, local/self-hosted,
custom, unknown, and mixed-model architectures. This is a design property, not a claim
that RenGuard has been installed on or empirically benchmarked against every listed
provider. Host-specific skill installation and runtime compatibility vary by platform.

The current v1 taxonomy includes mappings to the OWASP LLM Top 10 taxonomy used by the
original project. These are approximate audit cross-references, not proof of complete
technical coverage. Taxonomy modernization is deferred to Phase 2.

## What It Detects

| # | Vulnerability Category | Original v1 OWASP Mapping | Severity Range |
|---|------------------------|---------------------------|----------------|
| 1 | Direct Prompt Injection | LLM01 | CRITICAL–HIGH |
| 2 | Indirect / Environmental Injection | LLM01, LLM03 | CRITICAL–HIGH |
| 3 | Role Confusion & Persona Hijacking | LLM01 | CRITICAL–HIGH |
| 4 | Instruction Leakage | LLM02, LLM07 | CRITICAL–MEDIUM |
| 5 | Goal Hijacking | LLM01, LLM09 | CRITICAL–HIGH |
| 6 | Context Overflow & Memory Poisoning | LLM04, LLM10 | HIGH–MEDIUM |
| 7 | Delimiter & Format Escaping | LLM05 | HIGH–MEDIUM |
| 8 | Multi-Agent & Tool-Call Injection | LLM06, LLM08 | CRITICAL–HIGH |

See the [v1 vulnerability taxonomy](references/vulnerability-taxonomy.md) for the
definitions and original cross-reference table.

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
Overall Risk: CRITICAL
Findings: 5 vulnerabilities (3 Critical, 2 High, 0 Medium, 0 Low)

Finding #1 -- Hardcoded Production API Token [CRITICAL]
Impact: An attacker may obtain a transactions API credential from the prompt.
```

Prompt hardening is one layer of defense. RenGuard also recommends controls such as
least-privilege tool access, authentication, schema validation, output handling,
human approval, secrets management, and monitoring where the audited system needs them.

## Repository Structure

```text
prompt-injection-auditor/             # Remote repository name remains unchanged in Phase 1
├── SKILL.md                          # Core RenGuard auditing skill
├── README.md
├── CHANGELOG.md
├── references/
│   ├── vulnerability-taxonomy.md     # Original v1 categories and mappings
│   └── hardening-patterns.md         # Defensive prompt patterns
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

The eval definitions and historical results are declarative data. Phase 1 adds a
deterministic, Python-standard-library validator for their internal consistency:

```sh
python scripts/validate_repo.py
python -m unittest discover -s tests
```

The validator checks JSON parsing, unique IDs, fixture existence, benchmark/eval
references, result arithmetic, pass rates, recomputed micro and macro summaries,
historical source-commit provenance, known contradictory notes, documented headline
values, and important relative links.

These commands do **not** execute prompts against a live model and do not reproduce the
historical benchmark. A live model evaluation and benchmark runner is deferred to a
later phase.

## What RenGuard Does Not Yet Do

Phase 1 does not implement the planned OWASP 2026 taxonomy migration, agentic taxonomy,
MCP/RAG/memory/multimodal engines, provider-specific profiles, advanced scoring, SARIF,
large eval expansion, mutation testing, holdout suites, live multi-model execution, or
statistical confidence intervals. Future work is described as planned work, not current
functionality.

The current prompt-level skill also does not directly test application code, model
weights, network controls, tool implementations, UI output encoding, or stochastic
attack success rates. Those controls require system-level testing beyond prompt review.

## Contributing

When changing the current taxonomy, patterns, evals, or benchmark artifact:

1. Keep `SKILL.md` usable as the core product.
2. Preserve historical benchmark provenance rather than rewriting model metadata.
3. Add or update declarative eval data and synthetic fixtures as needed.
4. Run `python scripts/validate_repo.py` and
   `python -m unittest discover -s tests`.

## License

MIT — see [LICENSE](LICENSE).
