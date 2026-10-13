# RenGuard Threat Model

This threat model describes the systems RenGuard is designed to audit and the boundary
of RenGuard's own claims. It is a practical review model, not formal verification.

## Terms

- **Threat:** malicious or untrusted activity that could affect the system.
- **Vulnerability:** a system weakness that permits the threat to cause impact.
- **Risk:** the evidence-based combination of exploitability/exposure and consequence.
- **Control:** an architectural or operational measure that changes likelihood, scope,
  detectability, recovery, or impact.

These terms are related but not interchangeable.

## Assets

Common assets include system instructions, user and tenant data, credentials, retrieved
content, memory, tool capabilities, MCP sessions, agent identities, approval decisions,
model outputs, downstream resources, logs, and service availability.

## Threat actors and influence sources

- Untrusted or compromised users, content authors, data suppliers, tool providers, MCP
  servers, agents, integrations, and software dependencies.
- Insiders or operators acting beyond intended scope.
- Non-malicious users whose ambiguous content or approvals trigger unsafe behavior.
- Compromised content or components that launder instructions through otherwise trusted
  workflows.

RenGuard does not assume that every failure is adversarial. Misconfiguration, stale
state, ambiguous authority, and ordinary model error can produce the same security
impact.

## Primary trust boundaries

| Boundary | Untrusted side | Trusted decision that must remain separate |
|---|---|---|
| User/conversation | User prose and self-asserted role | Authenticated principal and session |
| Retrieval | Documents, chunks, metadata, query rewrites | Access decision, tenant scope, provenance policy |
| Memory | Recalled text, summaries, preferences | Write/read authorization, lifecycle, policy |
| Tool | Descriptions, arguments, outputs, errors | Capability grant, parameter authorization, execution policy |
| MCP | Server claims, names, resources, prompts, annotations | Server origin, workload identity, token audience/scope |
| Agent | Peer messages, delegated output, self-reported identity | Authenticated identity, delegation scope, privilege grant |
| Multimodal | Images, OCR, audio, transcripts, captions, metadata | Identity, approval, instruction authority |
| Output sink | Model-generated text or structured output | Semantic validity, authorization, sink-specific safety |

Content may cross several boundaries in one chain. Each downstream consumer must make
its own authorized decision rather than inheriting trust transitively.

## Threats in scope

- Direct and indirect instruction injection, authority impersonation, hidden-context
  disclosure, and multi-turn goal drift.
- Retrieval poisoning, unauthorized retrieval, tenant leakage, and retrieval-to-action
  chains.
- Persistent or cross-session memory poisoning and lifecycle failures.
- Excessive tool capability, parameter manipulation, output/recovery injection, unsafe
  external action, and unexpected code execution.
- MCP origin confusion, token passthrough, scope/audience failure, dynamic capability
  mutation, and untrusted prompts/resources.
- Cross-agent injection, spoofed messages, privilege propagation, cascade, rogue
  behavior, and approval manipulation.
- Multimodal instruction injection and false identity/approval cues.
- Unsafe use of model output in rendered, structured, network, filesystem, command,
  query, code, or messaging sinks.
- Resource exhaustion, compromised AI components, and weak monitoring or recovery.

## Security properties under review

RenGuard evaluates confidentiality, integrity, availability, authorization, isolation,
accountability, reversibility, and recovery using the evidence available. It looks for
deterministic boundaries around sensitive data and effects, including least privilege,
tenant separation, action-bound approval, sandboxing, egress controls, budgets, audit
trails, circuit breakers, revocation, and rollback.

## Model and human roles

The model is not a trusted authorization mechanism. It may classify, propose, summarize,
or request an action, but deterministic controls should decide whether a principal may
perform that exact action on that exact resource.

Human approval is useful only when the reviewer sees sufficient context and the approval
is authenticated and bound to immutable action parameters. A chat response such as
`CONFIRM` alone is not strong authorization. Agent or tool self-identification likewise
does not establish identity.

## Assumptions and evidence handling

RenGuard assumes only what supplied evidence supports. `UNKNOWN` is not zero. A missing
network policy, tenant boundary, runtime sandbox, or approval mechanism lowers confidence
and may require sensitivity analysis; it is not silently treated as absent or maximally
unsafe.

Controls named in designs are `PROPOSED` until implementation evidence is supplied.
Projected residual risk must be reassessed after controls are implemented and tested.

## Non-goals and limitations

RenGuard does not by itself:

- enforce authorization, isolate runtimes, filter networks, or operate a SOC;
- guarantee vulnerability absence or identical behavior across models;
- perform unrestricted penetration testing or execute destructive payloads;
- verify a live OAuth/IAM backend without evidence;
- perform malware analysis, steganalysis, deepfake detection, biometric verification,
  OCR certification, or exhaustive media forensics;
- inspect raw vector geometry or empirically measure embedding behavior;
- prove native image/audio perception through normalized public descriptors; or
- establish unseen-case generalization from a public evaluation suite.

See [`SKILL.md`](../SKILL.md), the
[technique catalog](../references/renguard-techniques.md), and the
[hardening catalog](../references/hardening-patterns.md) for normative audit behavior.
