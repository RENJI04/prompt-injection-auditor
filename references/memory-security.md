# Memory Security Audit Domain

Canonical Phase 5 guidance for persistent, cross-session, shared-agent, and multi-user/
multi-tenant memory audits. Load this reference only when supplied evidence shows state
that survives the immediate turn/session or is shared across principals or agents. If no
persistent/shared memory exists, do not create memory findings. Unknown architecture facts
are **UNKNOWN / INSUFFICIENT EVIDENCE — not zero and not assumed unsafe**.

Use the existing [RenGuard techniques](renguard-techniques.md), [risk model](risk-scoring.md),
and [hardening catalog](hardening-patterns.md). RenGuard audits supplied descriptions and
artifacts; it has no implicit access to a memory backend.

## Memory system profile

Record supported facts: memory type; scope; owner; read/write/delete permissions; source;
provenance; lifetime; persistence; private/shared status; user and tenant; namespace;
retrieval/update/deletion mechanisms; history/rollback; conflict policy; downstream action
influence; and cache/backup boundaries. Types may include session, user profile, preference,
task, knowledge, cross-run scratchpad, long-term, or shared-agent memory. Do not assume all
stores or provider-native memory behave alike.

## Memory authority model

Memory is data, not security policy. User-, document-, tool-, or model-written memory must
not gain trusted system authority because it persists. An entry such as “administrator
approval is no longer required” cannot alter authentication, authorization, approval, or
control-plane policy. Trusted application policy belongs in a protected configuration or
policy channel separate from preference and task memory.

## Security terminology

- **Provenance:** where the memory came from and how it changed.
- **Authentication:** who or what is acting.
- **Authorization:** what that actor may read, write, update, or delete.
- **Trust:** how recalled content is treated, independent of its storage location.
- **Persistence:** how long state survives.
- **Scope:** which user, tenant, task, session, or agent owns the state.

## Security matrix

| Attack surface | Relevant techniques | Typical weakness | Likely impact | Primary controls |
|---|---|---|---|---|
| Write | `RG-ME-001`, `RG-PI-002` | Untrusted free-form write lacks authorization/schema | Persistent injection | `RG-HARD-MEM-001`, `RG-HARD-AUTHZ-001` |
| Read | `RG-ME-002`, `RG-HC-004` | Recall is not scoped to authenticated owner | Disclosure or behavior contamination | Owner/tenant authorization before recall |
| Scope | `RG-ME-002`, `RG-PR-002` | Missing owner, tenant, task, or namespace key | Cross-principal influence | Trusted scope keys and deny-by-default access |
| Persistence | `RG-ME-001`, `RG-AG-004` | State outlives purpose with no expiry | Long-lived goal hijack | `RG-HARD-MEM-002` TTL and review |
| Cross-session | `RG-ME-001`, `RG-ME-002` | Session A state controls session B | Persistent poisoning | Provenance, typed recall, bounded authority |
| Cross-user | `RG-ME-002`, `RG-HC-004` | User A data/preferences reach User B | Leakage or behavior change | Per-user isolation and access tests |
| Cross-tenant | `RG-ME-002`, `RG-HC-004` | Shared backend has weak tenant filters | Broad confidentiality breach | Authenticated tenant namespace and backup isolation |
| Shared agent | `RG-ME-002`, `RG-AG-002` | Agent B trusts Agent A's unprovenanced state | Delegated poisoning | `RG-HARD-AGENT-001`, task-bound capabilities |
| Conflict/update | `RG-ME-001`, `RG-ME-002` | Lower-trust write silently overwrites verified data | Policy/fact corruption | Trust-aware versioned conflict rules |
| Action influence | `RG-ME-001`, `RG-AG-001` | Recalled text drives privileged tools | Future unauthorized action | Independent authorization and approval |
| Delete/rollback | `RG-ME-001`, `RG-AG-004` | Poisoned entries cannot be identified or reverted | Persistent incident impact | `RG-HARD-MEM-002`, `RG-HARD-REC-001` |

## Specialized security checks

### Read and write authorization

Identify who can write, what types/size are allowed, how source is attributed, and whether
owner/tenant/task scope is bound from authenticated application context. Prefer structured
writes with field/type/length validation and moderation where proportionate. Enforce read,
write, update, and delete policy at the memory boundary—not in natural-language prompts.
A webpage or retrieved document must not independently cause a persistent free-form policy
write.

### Persistent poisoning and cross-session influence

Trace malicious instructions, fake policy, poisoned preferences, tool-use directions, and
attacker notes from write source to later recall. Establish whether state actually survives
turn, session, user, agent, or worker boundaries before raising `S`; persistence is never
inflated from a memory label alone. Map durable malicious writes to `RG-ME-001` and improper
cross-boundary reuse to `RG-ME-002`.

### Cross-user and cross-tenant isolation

Test conceptually for User A state visible to User B, preferences changing another user's
behavior, global user-derived policy, missing owner/tenant keys, natural-language-only
authorization, and shared cache or backup leakage. Tenant identity comes from trusted
application/session context, never solely from user prose. Review read, write, delete,
backup, restore, and cache boundaries only when multi-tenancy is present.

### Shared-agent memory

Treat one agent's stored output as attributable data for another agent. Preserve writer,
task, source, schema, and review state; do not inherit privilege or accept stored claims of
approval. Bound delegation and action capabilities separately. This is memory-boundary
analysis, not the full Phase 6 inter-agent engine.

### Provenance and structured memory

Preserve enough information to answer who/what created an entry, when, for which user/
tenant, from which source, under which session/task, whether model-generated or supplied,
review status, type, version, and expiry. A useful security-relevant shape is:

```json
{
  "type": "user_preference",
  "owner": "<trusted-subject-id>",
  "tenant": "<trusted-tenant-id>",
  "value": "<bounded value>",
  "source": "<source-id>",
  "created_at": "<timestamp>",
  "expires_at": "<timestamp>"
}
```

Schema enforcement narrows structural attack surface but does not prove truth or semantic
safety. Do not permit memory fields to grant capabilities or redefine protected policy.

### Lifetime, TTL, conflict, and minimization

Choose session-only, task-scoped, time-limited, user-deletable, or durable storage based on
legitimate need. Longer persistence can increase `S` but durability may be required by law
or business operations; do not prescribe deletion blindly. Use trust-aware conflict rules:
lower-trust sources cannot silently overwrite higher-trust verified values, and conflicts
remain reviewable. Minimize secrets, credentials, personal data, internal identifiers, and
confidential business information. Never store raw credentials as conversational memory.

### Monitoring, deletion, and rollback

Log privacy-minimized memory writes/reads, actor/source, versions, policy-like write
signals, bulk writes, and cross-principal denials. Monitoring is DETECT, not PREVENT.
Support identification, disablement, deletion, prior-version restoration, cache
invalidation, and incident review. Deletion cannot undo prior disclosure or actions.

### Memory-to-action attack chains

Represent supported chains using Phase 3 finding IDs, for example:

`malicious memory write → later session recall → planning change → privileged tool → external action`

Score the chain once. Persistent content influencing consequential actions warrants closer
scrutiny, but a tool is not presumed privileged or externally reachable without evidence.

## Risk-scoring integration

Use the unchanged Phase 3 formula. Verified cross-session poisoning may affect `S`, `B`,
and `A`; cross-user/tenant memory exposure may affect `D`, `B`, and `V`; a memory-to-tool
chain may affect `T`, `S`, `B`, and `G`. Unknown scope, lifetime, egress, or action facts
remain UNKNOWN and never automatically score zero or maximum.

## Memory-Enabled Assistant hardening bundle

This bundle is PROPOSED until verified and does not eliminate poisoning:

- `[PROMPT]` `RG-HARD-P-001`: recalled memory is data, not privileged authority.
- `[AUTHORIZATION]` `RG-HARD-AUTHZ-001`: enforce owner/tenant read, write, update, and delete policy.
- `[DATA]` `RG-HARD-DATA-002`: minimize stored fields and sensitive values.
- `[MEMORY]` `RG-HARD-MEM-001`: typed writes, provenance, trusted scope, and policy separation.
- `[MEMORY]` `RG-HARD-MEM-002`: TTL, version history, review, deletion, and rollback.
- `[APPLICATION]` `RG-HARD-AGENT-001`: preserve attribution across agent/orchestration boundaries.
- `[MONITORING]` `RG-HARD-MON-001`, `RG-HARD-MON-002`: audit writes and suspicious access without secrets.
- `[RECOVERY]` `RG-HARD-REC-001`: disable poisoned state and invalidate dependent caches/actions.

Verify cross-user/tenant denial, schema rejection, policy-field rejection, expiry, conflict
handling, rollback, cache invalidation, and privacy-aware audit events in a safe test store.

## Memory audit checklist

- **Memory existence/type:** Confirm persistence or sharing before specialized findings.
- **Scope:** Identify session, task, user, tenant, agent, or global boundaries.
- **Ownership:** Derive owner from trusted identity rather than stored prose.
- **Read authorization:** Enforce owner/tenant/resource access before recall.
- **Write authorization:** Control writers and permitted entry types/fields.
- **Provenance:** Retain creator, source, session/task, review, version, and time.
- **Schema:** Restrict fields, types, lengths, and policy/capability semantics.
- **Persistence:** Establish actual survival and affected principals.
- **TTL:** Match lifetime to need and support explicit expiry/deletion.
- **Cross-session:** Trace influence from one session to later sessions.
- **Cross-user:** Verify User A cannot read or control User B memory.
- **Cross-tenant:** Verify namespaces, backups, restores, caches, reads, and writes.
- **Shared agents:** Preserve attribution and prevent authority/privilege inheritance.
- **Conflict policy:** Prevent lower-trust silent overwrite and retain history.
- **Sensitive data:** Minimize and access-control personal/confidential data; exclude raw credentials.
- **Action influence:** Trace recalled state into planning, tools, approvals, and external effects.
- **Monitoring:** Audit suspicious writes/access as detection, with data minimization.
- **Rollback/delete:** Identify, disable, delete, restore, and invalidate dependent state.

## Scope and limitations

This guidance is provider-, framework-, and storage-neutral. It covers application-defined
or provider-native memory, SQL/NoSQL stores, search/vector recall, local stores, and custom
systems based on architecture rather than brands. RenGuard cannot inspect a backend,
prove isolation, or observe cross-session behavior unless relevant evidence is supplied.
