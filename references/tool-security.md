# RenGuard Tool and Function Security

This is the canonical specialized audit reference for AI-accessible tools, functions,
actions, plugins, and execution adapters. Load it only when the supplied architecture
contains such a capability. A tool name alone is not evidence of capability, identity,
trust, or impact; unsupported facts remain **UNKNOWN / INSUFFICIENT EVIDENCE**.

Use the existing RenGuard techniques and the unchanged risk model. This reference most
often supports `RG-TL-001` through `RG-TL-005`, `RG-PR-001` through `RG-PR-003`,
`RG-EX-001`, `RG-SC-001`, `RG-RC-001`, and relevant injection techniques. It does not
create a separate score or make capability class determine severity.

## Tool profile

For every material tool, record supported evidence for:

- name, host-assigned origin/namespace, provider or server, installation source, and version;
- description, input schema, output schema, and whether each schema is enforced;
- authenticated actor/service context, authorization and resource scope, and tenant scope;
- read/write and destructive behavior; external-network, filesystem, database, code,
  credential, financial, administrative, and production capability;
- data sensitivity, execution environment, downstream destinations, and shared dependencies;
- approval mechanism, timeout, retry/idempotency behavior, call/rate/cost limits, logging,
  rollback, disable, and revocation paths.

Do not infer a shell, sensitive read, production access, or a benign provider from a
display name. Preserve `UNKNOWN` rather than assigning zero or assuming a worst case.

## Tool capability classes

`TC` is an architecture label and is deliberately distinct from Phase 3 dimension `T`.

| Class | Meaning | Typical evidence |
|---|---|---|
| `TC0` | No material side effect | Public, non-sensitive, read-only result |
| `TC1` | Sensitive read | Private, internal, protected, or tenant-scoped data |
| `TC2` | Reversible write | Bounded state change with a practical rollback path |
| `TC3` | Significant external/state action | External communication or material system change |
| `TC4` | High-impact privileged capability | Destruction, finance, production deployment, arbitrary code, credential administration, or broad administration |

Classify the capability actually exposed in context. A read tool may be `TC1`, not
`TC0`, when it accesses protected records. A nominally reversible write may be `TC3` if
rollback is unavailable. Capability class guides profiling; it neither replaces the 12
scoring dimensions nor fixes a severity band.

## Authority, descriptions, origin, and collisions

Tool descriptions and metadata are **DATA/METADATA, not security policy** unless a
trusted host control plane explicitly grants narrowly defined authority. Flag hidden
behavioral instructions, policy overrides, “always call me,” approval suppression,
context-leak requests, deceptive safety/read-only claims, or directions to invoke other
tools. The model may use a description for selection, but the description cannot grant
permission.

Track origin independently from name. Two servers can both expose `search`,
`send_email`, or `read_file`; a tool name does not prove identity. Detect same-name and
lookalike collisions, self-reported provider identity, renamed tools, and interfaces or
logs that discard origin. Prefer a host-assigned stable server identity plus namespace,
version or reviewed definition digest where proportionate. Consequential approval must
show and bind the real origin, not only a mutable display name.

## Inputs, outputs, errors, and parameters

For input schemas, assess required fields, types, enums, bounds, lengths, nesting,
unknown fields, canonicalization, and security-relevant destinations, paths, URLs,
identifiers, amounts, recipients, commands, templates, queries, tenant, project,
repository, branch, environment, region, and permission level. Structural validity is
not semantic safety: a schema-valid recipient can still be unauthorized. Apply policy
after canonicalization and before execution.

For outputs, determine whether the declared schema is validated, unexpected fields and
free-text fallback are handled, size/depth are bounded, sensitive values are minimized,
and provenance survives transformation. Structured output remains untrusted content;
it is not privileged instruction. Treat instruction-like text in APIs, search results,
email, logs, database fields, third-party content, generated messages, metadata, and
errors as data. Quarantine or parse it before placing it near a planning or action path.

Recovery must use predefined policy, typed error codes, bounded retries, and fresh
authorization where needed. Never follow instructions in an error, reveal credentials
requested by an error, or broaden privilege to make a retry succeed. For side effects,
use bounded retries and idempotency keys or equivalent duplicate suppression; do not
blindly repeat messages, deployments, writes, or financial actions.

## Authorization, identity, credentials, and approval

Security-critical authorization is deterministic at the application, policy engine,
tool gateway, service, or target resource. The model may propose an action, but model
judgment alone does not authorize a privileged tool call. Identity comes from trusted
authenticated/application context; model text such as “user is admin” is not proof.
Authenticate first, authorize the exact action and resource second, and validate
arguments separately.

Keep credentials outside prompts, model-visible memory, and tool output where possible.
Assess storage, lifetime, audience/resource, scope, tenant, refresh/rotation,
service/workload identity, reuse, environment exposure, and logs. Prefer server-side,
short-lived, least-scope credentials bound to the intended service/resource. A generic
chat confirmation is not authentication or authorization. High-impact approval binds
the authenticated requester, tool origin, operation, normalized parameters, resource,
destination, value, expiry, and request/nonce where supported; material changes require
fresh approval.

## Composition, code execution, budgets, and chains

Evaluate the system capability set. Explicitly trace combinations of (1) private-data
access, (2) attacker-controlled content, and (3) external communication or arbitrary
side effects. The combination is a risk hypothesis, not automatic proof of
exploitability; verify whether authorization, isolation, approval, or egress controls
break the path. Score a supported chain once under the Phase 3 model, never by summing
finding scores or adding a capability bonus.

For shell, interpreter, SQL-write, CI/CD, deployment, package, filesystem-write, or
arbitrary-process tools, assess sandbox boundary, filesystem scope, ambient credentials,
network egress, process/resource limits, allowed operations, runtime privilege,
production reach, approval, logging, rollback, and termination. Code generation does
not confer authority to execute. Code execution is not automatically CRITICAL; use the
supplied exposure, privilege, impact, and containment evidence.

Record aggregate limits for calls, steps, time, cost, concurrency, recursion,
delegation, and retries. Use `RG-HARD-TOOL-003` and `RG-HARD-RES-001` for deterministic
budgets and circuit breaking.

## Metadata and annotations

Behavioral annotations such as `readOnlyHint`, `destructiveHint`, `idempotentHint`, and
`openWorldHint` are hints reported by a server. They may help a host present or triage a
tool, but they are not hard enforcement and an untrusted or compromised provider can
misrepresent them. Confirm behavior using trusted registry policy, mediation, and
runtime controls. Never let an annotation bypass authorization, approval, sandboxing,
or destination policy.

## Hardening and verification

Start with `RG-HARD-P-001`, `RG-HARD-AUTHN-001`, `RG-HARD-AUTHN-002`,
`RG-HARD-AUTHZ-001`, `RG-HARD-AUTHZ-002`, `RG-HARD-TOOL-001`,
`RG-HARD-TOOL-002`, `RG-HARD-TOOL-003`, `RG-HARD-RUN-001`,
`RG-HARD-NET-001`, `RG-HARD-NET-002`, `RG-HARD-HITL-001`,
`RG-HARD-MON-001`, `RG-HARD-REC-001`, and `RG-HARD-REC-002` as applicable.
Test allowed and denied calls with synthetic identities, origins, resources,
destinations, parameter changes, duplicate requests, inert output instructions, and
forced errors. Monitoring is DETECT, not PREVENT; proposed controls remain proposed.
