# OWASP Top 10 for Agentic Applications 2026

This reference records the current Agentic Security Initiative (ASI) category names
used by RenGuard. ASI mappings are conditional: apply them only when the target has
agentic properties such as tools, planning, persistent state, autonomous execution,
delegation, inter-agent communication, or external side effects.

## Sources and attribution

- [OWASP Top 10 for Agentic Applications 2026 publication](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [OWASP announcement of the Agentic Top 10](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/)
- [Canonical OWASP ASI 2026 mapping](https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/blob/9253e38ade58e959b531c0c5c9a4842272c9cd0e/2026/final/mappings/asi-2026.json)

Names were verified against these OWASP sources and canonical mapping commit
`9253e38ade58e959b531c0c5c9a4842272c9cd0e` on 2026-10-10. The summaries below are
RenGuard-authored descriptions, not reproductions of OWASP text.

## ASI01 — Agent Goal Hijack

An attacker redirects an agent's objectives, plan, or task execution toward an
attacker-chosen outcome. Relevant RenGuard mappings include the `RG-PI` family,
`RG-PR-001`, `RG-TL-002`, `RG-TL-003`, `RG-AG-001`, and `RG-MM-001` when those
techniques affect an agent.

## ASI02 — Tool Misuse & Exploitation

An agent invokes a legitimate tool in an unsafe, unintended, or attacker-controlled
way. RenGuard mappings include `RG-PR-003` and `RG-TL-001` through `RG-TL-005`.

## ASI03 — Identity & Privilege Abuse

Weak identity, authorization, or credential boundaries let an agent or attacker act
with inappropriate privilege. RenGuard mappings include `RG-HC-003`, `RG-HC-004`,
`RG-PR-001`, `RG-PR-002`, and `RG-TL-005`.

## ASI04 — Agentic Supply Chain Vulnerabilities

Compromised agents, tools, models, registries, plugins, or protocol components corrupt
an agentic workflow. The primary RenGuard mapping is `RG-SC-001`.

## ASI05 — Unexpected Code Execution

Agent decisions or manipulated inputs cause unauthorized code or command execution.
RenGuard mappings include `RG-EX-001` and, where downstream model output is executed,
`RG-OU-001`.

## ASI06 — Memory & Context Poisoning

Adversarial state persists in or corrupts memory and context used for later decisions.
RenGuard mappings include `RG-ME-001`, `RG-ME-002`, `RG-RA-001`, and `RG-RA-003`.

## ASI07 — Insecure Inter-Agent Communication

Untrusted messages, weak peer identity, or unsafe protocols allow one agent or relay to
manipulate another. RenGuard mappings include `RG-AG-001` and `RG-AG-002`.

## ASI08 — Cascading Failures

Errors, compromised decisions, or unsafe actions propagate through a workflow and
amplify across agents or tools. RenGuard mappings include `RG-AG-003`, `RG-PR-003`,
`RG-RC-001`, and contextually `RG-PI-010`.

## ASI09 — Human-Agent Trust Exploitation

Attackers exploit human over-trust, approval fatigue, deceptive presentation, or weak
oversight of agent output. The primary RenGuard mapping is `RG-AG-005`; `RG-MI-001`
applies when false or ungrounded information is the mechanism.

## ASI10 — Rogue Agents

A malicious, compromised, or materially misaligned agent operates against the intended
workflow or other participants. The primary RenGuard mapping is `RG-AG-004`.

## Applicability rule

A text-only chatbot with no tools, planning, persistent state, delegation, autonomous
execution, or external side effects does not receive an ASI mapping merely because it
uses a language model. Report `Not applicable — target is non-agentic` instead. Mapping
support across ASI01–ASI10 is not a claim that the current eval suite empirically tests
all ten categories.
