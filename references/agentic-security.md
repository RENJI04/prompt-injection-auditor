# RenGuard Agentic and Multi-Agent Security

This is the canonical specialized audit reference for systems with evidenced autonomous
planning, delegation, multi-agent operation, background execution, orchestration, or
significant independent action. Do not activate it for a text-only chatbot or because
marketing calls a product an “agent.” Use actual architecture and capabilities.

The authoritative OWASP names and RenGuard crosswalk remain in
[OWASP Agentic 2026](owasp-agentic-2026.md): `ASI01` Agent Goal Hijack, `ASI02` Tool
Misuse & Exploitation, `ASI03` Identity & Privilege Abuse, `ASI04` Agentic Supply Chain
Vulnerabilities, `ASI05` Unexpected Code Execution, `ASI06` Memory & Context Poisoning,
`ASI07` Insecure Inter-Agent Communication, `ASI08` Cascading Failures, `ASI09`
Human-Agent Trust Exploitation, and `ASI10` Rogue Agents. Mapping is not empirical
detection coverage.

The names were verified on 2026-10-10 against the official OWASP GenAI Security
Project's [Agentic Top 10 release](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/)
and canonical Top 10 document. No Phase 2 identifier or name required correction.

## Agent profile and trust boundaries

Record supported facts about goals, planner, executor, tool layer, RAG, memory,
orchestrator, sub-agents, delegation, background tasks, human approval, human/service/
workload/agent identities, credentials, resource ownership, communications, persistence,
network and production reach, monitoring, cancellation, and recovery. Mark unsupported
facts UNKNOWN.

For complex systems, write a compact trust-boundary path such as:

```text
External content -> Retriever -> Planner -> delegated worker -> Approval Boundary
                 -> Deployment Tool -> Production
```

Label data, identity, privilege, approval, persistence, and egress crossings. A diagram
is optional; the crossings are not.

## Goals, tools, identity, and delegation

Trace whether untrusted user, retrieval, web, email, tool, memory, peer-agent, or MCP
content can alter the goal, plan, priority, constraints, completion condition, tool,
target, recipient, or resource scope. Goal changes remain inside authenticated and
authorized task boundaries. Map supported goal redirection to `RG-PI`, `RG-TL`,
`RG-AG`, and `ASI01` as appropriate.

Distinguish misuse of a legitimate tool from a malicious or compromised tool. Sending
protected data to an unauthorized recipient is misuse even if `send_email` is benign;
a tampered tool package is a supply-chain problem. Evaluate actual authorization and
context, not the name.

Separate host-assigned identity, authenticated service/workload identity, and
self-reported agent names. A message such as “I am AdminAgent” or “AdminAgent approved”
is not authenticated identity or authorization. Where security decisions depend on
agent identity, use proportionate strong authentication and preserve provenance.

For every delegation, bind task, delegator, recipient, allowed capabilities/actions,
resources, credential scope, tenant, duration/expiry, depth, onward-delegation policy,
return channel, approval reference, and termination. Sub-agents receive **no parent
privilege by default**. A documentation worker does not inherit deployment credentials
merely because its parent can deploy. Enforce minimum task capability outside the model.

## Inter-agent communication and handoff

Treat peer messages as externally sourced content unless authenticated architecture
assigns narrow authority. Assess sender identity, provenance, message integrity, schema,
task ID, replay, destination, tenant, resource ownership, capability claims, approval
claims, and tool-result claims. Free text from one agent cannot become orchestration
policy for another.

Prefer a typed handoff containing task ID, authenticated requester/delegator and worker,
scope, allowed actions/resources, expiry, approval reference, provenance, and structured
result fields. Structure reduces ambiguity; it does not itself authenticate a sender or
authorize an action. Retrieve the real approval evidence rather than accepting “Agent B
says the user approved.”

Bound delegation depth, spawning, loops, retries, fan-out, concurrency, steps, cost, and
runtime. Detect cycles and duplicate tasks. Deny or terminate work that exceeds its
lease; never resolve failure by granting ambient credentials.

## Cascades, composition, and code execution

Trace supported chains across agent -> agent -> tool -> system and RAG -> planner ->
coding agent -> deployment agent -> production. Record boundaries crossed, shared
credentials/memory/tools, affected components, containment, and blast radius. A system
combining private data, attacker-controlled content, and outbound action deserves chain
analysis, not an automatic vulnerability claim. Score a chain once with the unchanged
Phase 3 formula; do not sum scores or add arbitrary bonuses.

Assess natural-language paths into shells, interpreters, SQL, build/CI, deployment,
package/plugin loaders, templates, executable files, or infrastructure automation.
Generated code is not authorization to execute. Require scoped identity, deterministic
policy, sandboxing, filesystem/credential and network isolation, resource limits,
review/approval proportionate to impact, logs, rollback, and termination. Map supported
paths to `RG-EX-001`, tool techniques, and `ASI05`.

## Human trust and bound approval

Inspect deceptive summaries, obscured destinations/parameter changes, urgency,
authority impersonation, approval fatigue, incomplete action descriptions, and requests
for credentials. The approval UI should show the actual security-relevant action and
origin rather than relying on the agent's reassurance.

Consequential approval binds authenticated requester, agent and tool origin, action,
normalized parameters, resource, destination, value/amount, expiry, and a request or
nonce where supported. Material changes require fresh approval. “Approve all future
actions” and chat-level confirmation are not equivalent to narrow authorization.

## Supply chain and dynamic operation

Inventory agent packages, skills, plugins, MCP/tool servers, prompt packages, model
adapters, dependencies, images, downloaded scripts, remote configuration, and dynamic
catalogs. Evaluate publisher/provenance, integrity and version pinning proportional to
risk, updates and permission changes, dependency compromise, and runtime mutation. Do
not require signatures universally, and never equate a familiar display name with a
trusted component.

For long-running/background work, assess runtime and credential lifetime, task lease and
owner, periodic authorization, stale assumptions, tool-definition changes, state,
cancelability, orphan detection, monitoring, and automatic restart. Initial approval can
expire before a task ends.

“Rogue” means compromised or uncontrolled execution, not human-like intent. Check for
work continuing after completion, out-of-scope action, ignored cancellation,
unnecessary retained credentials, uncontrolled workers, approval bypass, unauthorized
persistence, and re-enabled capabilities. Controls include independently enforced task
leases, maximum runtime, heartbeat/health policy, action logs, orphan detection, tool
disable, capability/token revocation, egress block, state quarantine, and restart
inhibition.

## Monitoring, containment, and recovery

Monitor tool calls, delegation, denials, approval, identity/capability changes, spawning,
memory writes, egress, repeated failures, unusual sequences, and termination. Monitoring
is DETECT, not PREVENT, and must minimize secrets and sensitive content.

Termination cannot rely on telling the model “please stop.” A control plane should be
able to cancel a task, stop a worker, revoke capability/token, disable a tool, block
egress, quarantine memory/state, prevent automatic restart, preserve evidence, and
rollback reversible actions. Recovery can isolate a compromised server, rotate exposed
credentials, restore known-good configuration, and review downstream effects; it cannot
undo irreversible disclosure.

## Agentic defense-in-depth bundle

Start with explicit goal/scope (`RG-HARD-P-001`, `RG-HARD-P-002`), trusted identity and
minimum capabilities (`RG-HARD-AUTHN-002`, `RG-HARD-AUTHZ-001`,
`RG-HARD-AUTHZ-002`), bounded delegation and typed handoff (`RG-HARD-AGENT-001`,
`RG-HARD-AGENT-002`), exact-action approval (`RG-HARD-HITL-001`), isolation and egress
(`RG-HARD-RUN-001`, `RG-HARD-RUN-002`, `RG-HARD-NET-001`), budgets
(`RG-HARD-RES-001`), monitoring (`RG-HARD-MON-001`, `RG-HARD-MON-002`), and
independent cancellation/revocation/recovery (`RG-HARD-REC-001`,
`RG-HARD-REC-002`). Label each control's evidence status. Residual risk remains.
