# RenGuard Risk Scoring

This document is the canonical specification for the **RenGuard Risk Score**, a
project-specific method for assessing AI-system security findings. The score ranges
from **0.0 to 10.0**. It is not CVSS, CVSS-compatible, CVSS-equivalent, or endorsed by
OWASP, NIST, MITRE, or any other external organization.

The model is provider-neutral and architecture-aware. It scores a finding in its
documented deployment context, not a technique name in isolation. The same technique
can therefore be low risk in a text-only demonstration and critical in an agent with
production write access.

## Required evidence and inputs

Before scoring, record the attack technique, enabling security weakness, material
impact, known preconditions, affected assets, privileges, tools, trust boundaries, and
evidence. Do not invent missing architecture. State assumptions and lower confidence,
but do not automatically lower the risk score merely because confidence is low.

Before assigning a number, classify the evidence state:

- **KNOWN ZERO — numeric value 0:** Evidence confirms that the dimension has no
  material contribution to this finding.
- **NOT APPLICABLE — numeric value 0:** The dimension genuinely does not apply to the
  finding.
- **UNKNOWN / INSUFFICIENT EVIDENCE — no automatic numeric value:** Required
  architecture or runtime evidence is unavailable. UNKNOWN must never be silently
  recorded as 0.

For an unknown dimension, use the lowest value positively supported by available
evidence, state the evidence gap or assumption, and lower Confidence when the gap is
material. Never invent a high value because missing information might conceal danger.
If no numeric level can be positively supported, do not present the finding as fully
scored; obtain the missing evidence or mark the numeric assessment incomplete.

When an unknown dimension could change the severity band, add a sensitivity note, for
example: “External reach is unknown. The current score reflects only verified
capabilities; actual risk may be higher if unrestricted egress exists.” This is a
disclosure of uncertainty, not a score range or probabilistic adjustment.

Every assigned numeric dimension uses this common ordinal scale:

- **0 — Known zero or not applicable:** evidence supports no material contribution.
- **1 — Low:** limited contribution under restrictive conditions.
- **2 — Moderate:** meaningful but bounded contribution.
- **3 — High:** substantial contribution or broad capability.
- **4 — Severe:** maximum credible contribution in the supplied context.

A zero must identify either KNOWN ZERO or NOT APPLICABLE; it is never shorthand for
UNKNOWN. Each dimension also has specific criteria below. When evidence falls between
two levels, use the lower supported value and document what evidence would justify the
higher one.

## Exploitability / Exposure Component (40%)

This component is an ordinal assessment of attack accessibility and operational
exposure. RenGuard does not estimate empirical exploit probability.

### E — Exploitability (weight 14%)

| Value | Criteria |
|---:|---|
| 0 | No credible exploitation path is established, or the dimension is not applicable. |
| 1 | HARD: unusual access, timing, expertise, or environmental control is required. |
| 2 | MODERATE: multiple steps or specific attacker-controllable conditions are required. |
| 3 | EASY: a short sequence or common setup is sufficient. |
| 4 | TRIVIAL: one straightforward input works without special access or technique. |

### P — Preconditions / Required Access (weight 10%)

| Value | Criteria |
|---:|---|
| 0 | A required condition is absent, so no demonstrated path exists. |
| 1 | Privileged administrative, internal-system, or equivalent rare access is required. |
| 2 | Authenticated/restricted access or compromise of a bounded downstream component is required. |
| 3 | Ordinary user access or influence over one routinely consumed untrusted source is required. |
| 4 | Public/unauthenticated input is sufficient, or no special attacker access is required. |

### H — Human Interaction / Dependency (weight 8%)

| Value | Criteria |
|---:|---|
| 0 | Not applicable, or multiple independent authenticated approvals block the demonstrated path. |
| 1 | A deliberate privileged human action is required after a clear, specific warning. |
| 2 | An ordinary user must knowingly perform or approve a consequential step. |
| 3 | A routine, low-friction, ambiguous, or approval-fatigue-prone interaction is required. |
| 4 | Exploitation completes without human interaction or approval. |

### X — Detection Difficulty (weight 8%)

| Value | Criteria |
|---:|---|
| 0 | The effect is immediately obvious, or this dimension is not applicable. |
| 1 | The event is strongly logged, alerted, or otherwise highly visible. |
| 2 | Routine review is likely to detect it. |
| 3 | It is subtle and requires focused investigation. |
| 4 | It is stealthy, persistent, or poorly observable with the supplied controls. |

Detection difficulty contributes only 8% and cannot dominate the score. Its placement
in the Exposure component does not mean that a hard-to-detect attack is more
technically exploitable. Poor observability increases operational exposure because an
attack may persist longer or evade response.

## Impact / Consequence Component (60%)

### V — Privilege / Authority (weight 9%)

| Value | Criteria |
|---:|---|
| 0 | No privilege change or privileged access. |
| 1 | Read-only access to restricted or sensitive resources. |
| 2 | Restricted write capability or bounded delegated authority. |
| 3 | Privileged external action or significant state-changing authority. |
| 4 | Administrative, arbitrary execution, security-control, or production control. |

Conversation text claiming “I am an administrator” is not authenticated administrator
context. Score authority actually obtainable through the system, not the attacker's
self-asserted role.

### T — Tool / Action Capability (weight 9%)

| Value | Criteria |
|---:|---|
| 0 | No tools or external actions. |
| 1 | Low-risk, read-only tools over non-sensitive resources. |
| 2 | Sensitive reads or bounded, readily reversible writes. |
| 3 | Significant external actions or state modification. |
| 4 | Destructive, financial, privileged, deployment, arbitrary-execution, or production capabilities. |

This is a contextual scoring classification, not a specialized tool or MCP scanner.

### D — Sensitive Data Exposure (weight 9%)

| Value | Criteria |
|---:|---|
| 0 | No protected data is exposed. |
| 1 | Non-sensitive internal information. |
| 2 | Limited personal, customer, or internal information. |
| 3 | Sensitive personal, business, legal, or security data. |
| 4 | Credentials, secrets enabling further access, regulated/high-impact data, or large-scale confidential data. |

Do not claim a legal or regulatory classification unless the supplied context proves it.

### A — Autonomy (weight 6%)

| Value | Criteria |
|---:|---|
| 0 | Text response only; no independent action. |
| 1 | Recommendations only; a human separately executes actions. |
| 2 | Constrained, bounded actions under direct supervision. |
| 3 | Autonomous multi-step actions with limited stopping points. |
| 4 | Autonomous privileged, long-running, or self-directed execution. |

An “agent” is not automatically severe; score the authority it can exercise without
human intervention.

### S — Persistence (weight 6%)

| Value | Criteria |
|---:|---|
| 0 | NONE: no state or continuing effect. |
| 1 | SESSION: one response or current-session transient effect. |
| 2 | CROSS-SESSION: user-scoped memory or recurring state survives the session. |
| 3 | SHARED PERSISTENT STATE: multiple users or workflows consume the modified state. |
| 4 | PERSISTENT SYSTEM STATE: durable configuration, code, credential, or backdoor changes. |

This rubric assesses context only; it is not a specialized memory scanner.

### B — Blast Radius (weight 8%)

| Value | Criteria |
|---:|---|
| 0 | LOCAL/NONE: no external effect or informational observation only. |
| 1 | ISOLATED: one response or isolated transient effect. |
| 2 | SINGLE USER/RESOURCE: one user, session, record, or bounded resource. |
| 3 | MULTI-USER/TENANT: multiple users/resources or one tenant. |
| 4 | ORGANIZATION/CROSS-TENANT/EXTERNAL: production-wide, organization-wide, cross-tenant, or significant external systems. |

Every HIGH or CRITICAL finding must state the blast radius and its supporting evidence.

### R — Reversibility (weight 6%)

| Value | Criteria |
|---:|---|
| 0 | No material effect, or automatic recovery leaves no meaningful harm. |
| 1 | FULLY REVERSIBLE with a routine rollback and no durable disclosure. |
| 2 | MOSTLY REVERSIBLE with bounded recovery cost. |
| 3 | PARTIAL/DIFFICULT: meaningful effects remain or recovery is costly. |
| 4 | IRREVERSIBLE in practice, such as external secret disclosure, completed transfer, unrecoverable deletion, public publication, or privileged deployment. |

Do not assume irreversibility without evidence.

### G — External Reach (weight 7%)

| Value | Criteria |
|---:|---|
| 0 | No action or transmission outside the local trust boundary. |
| 1 | Internal, controlled destination only. |
| 2 | Constrained external destination. |
| 3 | Broad external connectivity or several external destinations. |
| 4 | Arbitrary external egress, publication, or an exfiltration path. |

## Formula and weights

The weights deliberately allocate **40% to Exploitability / Exposure** and **60% to
Impact / Consequence**. AI-system findings often combine uncertain attack paths with
high-consequence authority, so consequence receives moderately greater influence while
exposure remains large enough to keep harmless prompt manipulation below severe
findings. This is an ordinal contextual security-risk assessment; RenGuard does not
estimate empirical exploit probability.

### Exploitability / Exposure weights

| Symbol | Dimension | Weight |
|---|---|---:|
| E | Exploitability | 14 |
| P | Preconditions / Required Access | 10 |
| H | Human Interaction / Dependency | 8 |
| X | Detection Difficulty | 8 |
| **Total** | **Exploitability / Exposure Component** | **40** |

### Impact / Consequence weights

| Symbol | Dimension | Weight |
|---|---|---:|
| V | Privilege / Authority | 9 |
| T | Tool / Action Capability | 9 |
| D | Sensitive Data Exposure | 9 |
| A | Autonomy | 6 |
| S | Persistence | 6 |
| B | Blast Radius | 8 |
| R | Reversibility | 6 |
| G | External Reach | 7 |
| **Total** | **Impact / Consequence Component** | **60** |

The component totals are 40 and 60; all weights total 100. For assigned ordinal values
`E` through `G`:

```text
weighted_total = 14E + 10P + 8H + 9V + 9T + 9D
               + 6A + 6S + 8B + 6R + 8X + 7G

RenGuard Risk Score = round_half_up(weighted_total / 40, 1)
```

Division by 40 maps the maximum weighted total (`100 × 4 = 400`) to 10.0.
Round once, at the end, to one decimal place using ordinary half-up rounding. Bound the
result to 0.0–10.0. Do not insert undocumented multipliers or model intuition into the
formula. If the result appears wrong, correct an unsupported dimension assignment and
document the evidence; do not override the severity label manually.

## Severity bands

The numeric score is the reproducible measurement; severity is its communication label.
They are related but not interchangeable.

| Severity | Minimum | Maximum |
|---|---:|---:|
| INFORMATIONAL | 0.0 | 0.0 |
| LOW | 0.1 | 3.9 |
| MEDIUM | 4.0 | 6.9 |
| HIGH | 7.0 | 8.9 |
| CRITICAL | 9.0 | 10.0 |

Manual severity overrides are not permitted. A report with no findings may use
`CLEAN`; an informational observation still has score 0.0 and severity INFORMATIONAL.

## Confidence model

The Risk Score is based on supported security context. Confidence represents certainty
in the evidence used to assign that score. Confidence does not change the formula, and
an unknown value is never replaced with an invented zero or high value merely to
produce a preferred score.

### Confidence: HIGH

The vulnerable instruction/configuration, relevant permission, and material trust
boundary are directly visible or verified.

### Confidence: MEDIUM

The weakness is strongly supported, but one or more runtime details, enforcement
points, or asset scopes are missing.

### Confidence: LOW

Material architecture assumptions are required, runtime enforcement cannot be
inspected, or relevant authorization/tool behavior is unknown. State each assumption.

A finding may therefore be `8.1 HIGH / LOW confidence` when outbound-network
restrictions cannot be verified. The score reflects only confirmed capabilities; a
sensitivity note explains that actual risk may be higher if unrestricted egress exists.
Unknown material facts generally reduce Confidence, not Risk through invented zeros or
speculative inflation.

## Exploitability labels

Exploitability is human-readable shorthand for `E`, not the entire risk score.

| Label | E value | Meaning |
|---|---:|---|
| TRIVIAL | 4 | One straightforward input; no special technique. |
| EASY | 3 | Short sequence or common setup. |
| MODERATE | 2 | Specific conditions or multiple steps. |
| HARD | 1 | Unusual access, timing, expertise, or environment. |
| CONDITIONAL | Evidence-supported 0–4 | Missing runtime facts prevent an unconditional label. State the assigned E value, evidence, and assumptions; normally assign LOW confidence. |

`CONDITIONAL` does not silently map to zero. The report must state the evidence-supported
`E` value used so the formula remains reproducible.

## Finding IDs and classification

Per-report finding IDs use `RG-F-001`, `RG-F-002`, and so on. They preserve references
within one audit and may restart in another audit. They are not taxonomy identifiers.
Stable technique IDs such as `RG-PI-003` classify what the attacker does or how the
security failure occurs.

Every significant finding separates:

- **Attack Technique:** attacker action or failure mechanism, with a stable technique ID.
- **Security Weakness:** missing or ineffective control that enables the technique.
- **Impact:** material consequence if exploitation succeeds.

Preconditions must come from supplied evidence. Do not fabricate attacker access,
authorization state, tools, or enforcement behavior.

## Attack chains and cascading risk

Represent a real chain as an ordered list of finding IDs:

```text
RG-F-001 Retrieved-document injection
  → RG-F-004 Persistent memory poisoning
  → RG-F-003 Sensitive data disclosure
```

For each chain, identify the initial entry point, final material consequence, trust
boundaries crossed, affected components, and supporting evidence. Do not create a chain
for independent findings.

Do not add or average member scores. Assess the chain once with the same 12 dimensions:
use the credible entry path for Exploitability / Exposure dimensions and the final end-to-end
consequence for impact dimensions. The chain score can exceed an individual member only
when documented propagation or authority increases the supported consequence.

## Overall system risk

Overall risk is not an average. Use this deterministic rule:

1. Calculate every material finding score.
2. Calculate each supported end-to-end attack-chain score once.
3. The overall numeric score is the maximum of those finding and chain scores.
4. Derive the overall severity from the standard bands.
5. Report `CLEAN` only when there are no findings; use 0.0 INFORMATIONAL for a
   non-material observation.

Many independent low findings do not automatically become critical. If a systemic
weakness produces a consequence not represented by an existing finding or chain, add a
separately evidenced finding rather than applying an arbitrary escalation bonus.

## Residual risk and remediation comparison

Residual risk is the risk expected after a named control set. Reassign all 12 dimensions
under that explicit control scenario and use the same formula. Do not subtract a generic
mitigation percentage.

Use a comparison such as:

| State | Score | Severity | Status |
|---|---:|---|---|
| Before remediation | 9.3 | CRITICAL | Observed |
| After prompt-only hardening | 7.1 | HIGH | Projected if listed prompt controls are implemented |
| After runtime enforcement | 3.2 | LOW | Projected if listed runtime controls are implemented and verified |

Unless controls are already evidenced, label the result **Projected residual risk if
controls are implemented**. Prompt defenses are probabilistic guidance, not hard
enforcement. They do not remove the need for authorization, least privilege, isolation,
egress controls, monitoring, and human governance.

## Control classification

Tag each recommendation with one or more control classes:

- `[PROMPT]` — instruction hierarchy, scope, and untrusted-content handling.
- `[APPLICATION]` — application logic, parsing, validation, or data flow.
- `[AUTHORIZATION]` — authenticated identity and resource/action authorization.
- `[TOOL]` — capability scoping and parameter/destination constraints.
- `[RUNTIME]` — sandboxing, isolation, policy enforcement, budgets, or circuit breakers.
- `[NETWORK]` — ingress/egress and destination controls.
- `[HUMAN APPROVAL]` — authenticated platform or out-of-band approval.
- `[MONITORING]` — logs, alerts, anomaly detection, and review.

A chat message such as “type CONFIRM” is only an interaction safeguard, not strong
authorization. Consequential actions should use authenticated platform confirmation,
scoped or signed approval, out-of-band verification, or two-person approval when the
risk justifies it.

## Defensive demonstrations and secret handling

Use the minimum non-destructive proof needed to demonstrate a weakness. Redact exposed
secrets in reports, for example `sk_live_ab…REDACTED` or `Bearer eyJ…REDACTED`. Identify
the secret type and location, recommend revocation/rotation when applicable, and never
copy it into a hardened rewrite.

## Deterministic worked cases

The vector order is `E,P,H,V,T,D,A,S,B,R,X,G`.

| Case | Vector | Expected score | Severity |
|---|---|---:|---|
| A — benign/informational | `0,0,0,0,0,0,0,0,0,0,0,0` | 0.0 | INFORMATIONAL |
| B — isolated low-impact prompt manipulation | `4,4,4,0,0,0,0,0,1,1,0,0` | 3.6 | LOW |
| C — sensitive read exposure | `3,3,4,1,2,3,1,1,2,4,2,2` | 6.0 | MEDIUM |
| D — privileged external action | `3,3,4,3,3,3,3,2,3,4,3,4` | 7.9 | HIGH |
| E — production/destructive agent compromise | `4,4,4,4,4,3,4,4,4,4,3,4` | 9.6 | CRITICAL |

These are formula fixtures, not live-model evals or benchmark results.

## Limitations

- Scores depend on the accuracy of supplied architecture and assigned evidence.
- The rubric does not estimate exploit frequency or stochastic model success rates.
- It does not replace application testing, code review, runtime enforcement, or legal
  and business impact analysis.
- Phase 3 provides reasoning and reporting, not specialized MCP, RAG, memory,
  multimodal, provider-specific, secret, code, or runtime scanners.
- Phase 3 functionality has not been measured by a new live model benchmark.
