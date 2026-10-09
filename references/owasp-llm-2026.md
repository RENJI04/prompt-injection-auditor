# OWASP Top 10 for LLM Applications 2026

This reference records the current framework names used by RenGuard. OWASP categories
are broad risk classes; RenGuard technique IDs remain the operational classification
used in findings.

## Sources and attribution

- [OWASP GenAI LLM Top 10 2026 publication](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/)
- [Canonical OWASP 2026 source files](https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/tree/9253e38ade58e959b531c0c5c9a4842272c9cd0e/2026/final)

Names were verified against canonical source commit
`9253e38ade58e959b531c0c5c9a4842272c9cd0e` on 2026-10-10. The summaries below are
RenGuard-authored descriptions, not reproductions of OWASP text.

## LLM01:2026 — Prompt Injection

Attacker-controlled instructions alter model interpretation or behavior, directly or
through content the application supplies to the model. RenGuard mappings include
`RG-PI-001` through `RG-PI-010`, `RG-PR-001`, `RG-TL-002`, `RG-TL-003`, `RG-AG-001`,
`RG-AG-002`, and `RG-MM-001`.

## LLM02:2026 — Sensitive Information Disclosure

The system exposes secrets, personal data, proprietary content, or other protected
information through model output or model-accessible context. RenGuard mappings include
`RG-HC-003`, `RG-HC-004`, and contextual mappings from `RG-TL-005`.

## LLM03:2026 — Excessive Agency

Functionality, permissions, or autonomy allow manipulated or erroneous model behavior
to cause actions beyond the intended task. RenGuard mappings include `RG-PR-002`,
`RG-PR-003`, `RG-TL-001`, `RG-TL-004`, `RG-TL-005`, `RG-AG-003`, and `RG-EX-001`.

## LLM04:2026 — Supply Chain

Compromised or untrustworthy models, data, tools, packages, services, or other AI
components undermine the application. The primary RenGuard mapping is `RG-SC-001`;
delivery through untrusted content can also combine with `RG-PI-002`.

## LLM05:2026 — Data and Model Poisoning

Adversarial changes to training, fine-tuning, retrieval, memory, or operational data
corrupt model behavior or decisions. RenGuard mappings include `RG-ME-001`,
`RG-ME-002`, `RG-RA-001`, and `RG-RA-003`.

## LLM06:2026 — Unbounded Consumption

Uncontrolled inference, context, tool, or workflow use creates denial of service,
unexpected cost, or capacity exhaustion. The primary RenGuard mapping is `RG-RC-001`,
with `RG-PI-010` as a contextual input-driven mechanism.

## LLM07:2026 — Misinformation

Ungrounded, false, or misleading output creates security, safety, legal, or operational
harm when it is trusted or acted upon. The primary RenGuard mapping is `RG-MI-001`;
`RG-AG-005` applies when deceptive output exploits human oversight in an agentic flow.

## LLM08:2026 — Hidden Context Exposure

Users infer, reconstruct, or extract hidden instructions, configuration, tools, roles,
or operational context. RenGuard mappings include `RG-HC-001`, `RG-HC-002`, and
contextually `RG-HC-003`.

## LLM09:2026 — Vector and Embedding Weaknesses

Weak isolation, authorization, integrity, or lifecycle controls around embeddings and
vector retrieval enable leakage or manipulation. RenGuard mappings include
`RG-RA-002`, `RG-RA-003`, and contextually `RG-RA-001`.

## LLM10:2026 — Improper Output Handling

Downstream components consume model output without appropriate validation, encoding,
or execution boundaries. RenGuard mappings include `RG-OU-001` and contextually
`RG-EX-001`.

## 2025 to 2026 identifier migration

This table is for identifier migration only. Historical benchmark metadata and v1
documentation remain historical evidence and must not be relabeled as 2026 results.

| 2025 identifier/name | 2026 identifier/name |
|---|---|
| LLM01 Prompt Injection | LLM01:2026 Prompt Injection |
| LLM02 Sensitive Information Disclosure | LLM02:2026 Sensitive Information Disclosure |
| LLM06 Excessive Agency | LLM03:2026 Excessive Agency |
| LLM03 Supply Chain Vulnerabilities | LLM04:2026 Supply Chain |
| LLM04 Data and Model Poisoning | LLM05:2026 Data and Model Poisoning |
| LLM10 Unbounded Consumption | LLM06:2026 Unbounded Consumption |
| LLM09 Misinformation | LLM07:2026 Misinformation |
| LLM07 System Prompt Leakage | LLM08:2026 Hidden Context Exposure |
| LLM08 Vector and Embedding Weaknesses | LLM09:2026 Vector and Embedding Weaknesses |
| LLM05 Improper Output Handling | LLM10:2026 Improper Output Handling |

Framework mapping support means RenGuard can classify findings against these entries.
It does not mean every entry has dedicated empirical coverage in the current eight-eval
suite.
