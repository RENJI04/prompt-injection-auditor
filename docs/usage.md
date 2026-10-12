# Using RenGuard

RenGuard is a Skill/framework for structured security review. It is not installed as a
published package and is not a hosted scanner. Use `SKILL.md` through the Skill mechanism
available in your host, or read it directly as the audit methodology.

## Evidence to provide

Supply what is available and label what is not:

- system/developer prompts and policy documents;
- architecture and trust-boundary diagrams;
- identity, session, tenant, and authorization context;
- retrieval sources, ingestion rules, metadata, query flow, and access enforcement;
- memory read/write schemas, scope, provenance, TTL, deletion, and rollback;
- tool/MCP inventories, origin, schemas, credentials, token audience/scope, and retries;
- agent identities, delegation rules, message contracts, budgets, and termination;
- multimodal preprocessing, provenance, OCR/transcription, and identity assumptions;
- downstream sinks and their structural, semantic, authorization, and execution checks;
- monitoring, incident response, revocation, and recovery evidence.

Do not replace missing facts with conversational claims. Mark them `UNKNOWN` so risk and
confidence remain evidence-bounded.

## Request an audit

A useful request names the target and desired depth:

```text
Audit this tool-using RAG assistant with RenGuard. Profile the architecture and trust
boundaries, identify findings and attack chains, map RenGuard and OWASP techniques,
score risk and confidence, and propose layered hardening. Distinguish observed controls
from proposed controls and call out unknown evidence.
```

The report should distinguish technique, weakness, impact, risk, and confidence. Finding
IDs (`RG-F-*`) identify report observations; technique IDs (`RG-*`) classify attack or
failure mechanisms and are not interchangeable.

## Common workflows

### Chatbot

Provide the system prompt, identity/session model, sensitive data in context, allowed
tasks, escalation paths, and any actions. Review authority impersonation, disclosure,
scope, and whether self-reported roles can affect privilege. Start with
[`examples/01-chatbot-prompt.md`](../examples/01-chatbot-prompt.md).

### RAG assistant

Provide ingestion and retrieval architecture, tenant identity source, authorization
point, provenance, query rewriting, caches, and downstream actions. Retrieved content is
evidence, never privileged policy. Review poisoning separately from unauthorized
retrieval. See [`examples/02-rag-agent-prompt.md`](../examples/02-rag-agent-prompt.md).

### Memory-enabled assistant

Provide memory schemas, write/read authorization, scope, provenance, conflict policy,
TTL, revocation, and rollback. A legitimate preference may be stored, but free text must
not become standing policy. See
[`examples/05-memory-poisoning-agent.md`](../examples/05-memory-poisoning-agent.md).

### Tool-using or coding agent

Provide tool origin, capability, parameter schemas, credentials, runtime privilege,
network access, budgets, retries, approval, and recovery. Availability does not grant
authorization. See
[`examples/03-tool-using-agent-prompt.md`](../examples/03-tool-using-agent-prompt.md).

### MCP and multi-agent workflow

Provide server provenance, negotiated version, transport, workload identity, token
audience/scope, tool/resource/prompt inventory, agent message contracts, delegation
limits, and termination. Names and annotations are hints, not trust anchors. See
[`examples/06-mcp-multi-agent-workflow.md`](../examples/06-mcp-multi-agent-workflow.md).

### Multimodal and output flow

Provide media source/provenance, preprocessing, OCR/transcription, identity assumptions,
and every consumer of model output. Validate each output for its exact sink; valid JSON
does not authorize an action. See
[`examples/04-multimodal-output-agent.md`](../examples/04-multimodal-output-agent.md).

## Interpreting results

- **Severity** reflects the RenGuard Risk Score; **confidence** reflects evidence quality.
- `UNKNOWN` facts are explicit and may change severity when resolved.
- OWASP entries are crosswalks, not certification.
- Hardening patterns identify control architecture. `PROPOSED` is not `IMPLEMENTED`.
- Monitoring detects; it does not prevent. Recovery contains aftermath; it does not make
  the original weakness disappear.
- Residual risk is projected until implementation and verification evidence exists, and
  it is not assumed to be zero.

## Repository and benchmark commands

Run the model-offline repository quality gate:

```bash
python scripts/check.py
```

Inspect the benchmark CLI and validate the public suite without calling a model:

```bash
python scripts/run_benchmark.py --help
python scripts/run_benchmark.py validate
```

`FixtureAdapter` is synthetic test infrastructure and must not be reported as RenGuard
performance. Live-capable command execution requires an explicit gate and external
configuration; no official v2 live result currently exists.

For the artifact and scoring contract, read [`BENCHMARKING.md`](../BENCHMARKING.md) and
[`evals/v2/README.md`](../evals/v2/README.md).
