# RAG Security Audit Domain

Canonical Phase 5 guidance for architecture-aware retrieval-augmented generation (RAG)
audits. Load this reference only when supplied evidence shows retrieval, search, an
embedding/vector index, or retrieved context. If no RAG subsystem exists, do not create
RAG findings. Unknown architecture facts are **UNKNOWN / INSUFFICIENT EVIDENCE — not
zero and not assumed unsafe**.

Use the existing [RenGuard techniques](renguard-techniques.md), [risk model](risk-scoring.md),
and [hardening catalog](hardening-patterns.md). This is an architectural audit of supplied
evidence, not live vector-database scanning, backend penetration testing, or empirical
measurement of embedding geometry.

## Architecture profile

Record only components supported by evidence: ingestion source; owner; provenance and
trust; ingestion authorization; parser/extractor; chunking; embedding generation; vector
and metadata stores; index; retriever; reranker; query rewriting; retrieved context;
prompt assembly; model; caches; downstream tools/actions; authenticated user/tenant; and
the access-control boundary. Mark absent evidence UNKNOWN instead of inventing a design.

## Trust and authority model

| Trust classification | Treatment |
|---|---|
| TRUSTED CONTROL CONTENT | Authenticated system/application policy delivered through a protected control path |
| INTERNAL MANAGED CONTENT | Organization-controlled data; not automatically privileged instructions |
| USER-CONTROLLED CONTENT | Uploads, tickets, forms, comments, messages, and notes; untrusted data |
| EXTERNAL CONTENT | Web pages, third-party documents, public feeds, email, or repositories; untrusted data |
| UNKNOWN-PROVENANCE CONTENT | Source cannot be established; do not promote its authority |

Content authority and instruction authority are different. A policy document may be
evidence about a policy, but arbitrary text inside it cannot reconfigure the agent.
Retrieved content remains data unless trusted architecture explicitly establishes a
control-plane source and authorized semantics. Internal location alone does not do so.

## Provenance model

Where proportionate, preserve source ID, owner, tenant, ingestion time, document type,
trust classification, authentication context, authorization metadata, integrity/version,
and the relationship between a document and its chunks. Flag security decisions that
depend on content with no establishable provenance. Cryptographic signing is appropriate
for some high-assurance control sources, not a universal requirement.

## Security matrix

| Attack surface | Relevant techniques | Typical weakness | Likely impact | Primary controls |
|---|---|---|---|---|
| Ingestion | `RG-RA-001`, `RG-PI-002` | Untrusted writer enters a managed corpus | Persistent injection or misinformation | Authorized writes, review, provenance, rollback |
| Retrieval authorization | `RG-RA-002`, `RG-HC-004` | Missing or post-retrieval ACL/tenant filter | Cross-tenant disclosure | `RG-HARD-AUTHZ-001`, `RG-HARD-DATA-002` |
| Chunking | `RG-RA-001`, `RG-RA-002` | ACL, tenant, or source metadata is lost | Unauthorized or misleading context | Metadata inheritance and integrity checks |
| Vector/index | `RG-RA-003`, `RG-RA-001` | Untrusted index writes or ranking influence | Retrieval steering and leakage | Integrity, isolation, controlled rebuild, monitoring |
| Query rewriting | `RG-RA-002`, `RG-PI-001` | Model-generated query drops security filters | Broadened or cross-tenant search | Server-bound filters and authorization |
| Retrieved context | `RG-PI-002`, `RG-PI-003` | Retrieved prose gains instruction authority | Goal hijack | `RG-HARD-P-001`, `RG-HARD-TOOL-002` |
| Cache | `RG-ME-002`, `RG-RA-002` | Shared key or stale authorization state | Cross-user leakage or poisoned reuse | Identity/tenant-bound keys, invalidation |
| Citation/source | `RG-RA-001`, `RG-MI-001` | Source IDs lost or conflicts hidden | Untraceable security decisions | Source preservation and conflict display |
| Tool escalation | `RG-PI-003`, `RG-TL-001`, `RG-AG-001` | Retrieved data triggers privileged action | Exfiltration or destructive effects | Tool authorization, sandbox, egress, approval |

## Specialized security checks

### Indirect retrieved-content injection

Inspect PDFs, pages, knowledge articles, tickets, email, records, code/comments,
metadata, extracted text, and recalled memory for pathways that give embedded directives
control authority. Map the execution of retrieved instructions primarily to applicable
`RG-PI` techniques and `LLM01:2026`; use agentic mappings only when tools, autonomy, or
actions exist. Do not classify every indirect injection as supply-chain compromise.

### Ingestion and corpus integrity

Identify who may add, update, delete, assign tenant metadata, or rebuild content. Review
source authentication, moderation, parser isolation, metadata validation, duplicates,
versioning, document disablement, and rollback. Untrusted contributors able to modify a
trusted corpus support `RG-RA-001`; do not infer malicious insertion without evidence.

### Chunk-level preservation

Verify each chunk retains document/owner/tenant/ACL/source/version metadata needed for
authorization and traceability. Consider whether boundaries isolate malicious directives,
hide context, or duplicate poisoned chunks. Chunking is not inherently insecure.

### Retrieval authorization and tenant isolation

Authorization should constrain retrieval **before** sensitive text enters model context.
Bind namespace, collection, document/row ACL, ownership, metadata filters, and cache keys
to authenticated application identity. Tenant identity comes from trusted session context,
never solely from conversational claims. Filtering after context assembly is too late for
confidentiality. Apply multi-tenant checks only when the architecture is multi-tenant.

### Query rewriting

Determine whether a model rewrite can broaden scope, introduce hidden identifiers, drop
filters, or enable cross-tenant search. Treat the rewrite as untrusted query input.
Security filters must be server-enforced and reattached from trusted identity, not copied
from model-generated text.

### Vector and embedding exposure

Audit permissions and provenance for corpus inserts, embedding imports, index writes,
metadata, duplicate handling, rebuilds, exports, and ranking changes. Consider malicious
corpus insertion, nearest-neighbor steering, adversarial metadata, and poisoned duplicates.
Without actual embeddings/index data and an empirical method, RenGuard does not claim to
measure geometry, similarity manipulation, or numerical nearest-neighbor behavior.
`RG-RA-003` therefore has PARTIAL coverage: architecture and poisoning controls are in
scope; empirical vector analysis is not.

### Result quarantine, source integrity, and caching

Preserve provenance, separate content from controls, label source trust, validate known
structured fields, and never execute retrieved free text automatically. Delimiters alone
are not a security boundary. Assess semantic/response/retrieval caches only when present;
bind keys and invalidation to identity, tenant, authorization version, source version,
and relevant policy. Preserve source IDs, surface conflicting/stale sources where security
decisions depend on them, and avoid turning this into a general hallucination assessment.

### Retrieval-to-action attack chains

Represent supported chains using Phase 3 finding IDs, for example:

`malicious document → retrieval → RG-PI injection → goal hijack → privileged tool → disclosure`

Score the chain once with the existing dimensions. Tools and downstream actions increase
contextual scrutiny but do not trigger a separate Phase 6 tool scan.

## Risk-scoring integration

Use the unchanged formula and evidence-bounded values. Cross-tenant retrieval may affect
`D`, `B`, and `V`; unrestricted ingestion may affect `P`, `B`, and `S`; a RAG-to-tool
exfiltration chain may affect `T`, `D`, `B`, and `G`. Unknown cache, egress, privilege, or
tenant facts remain UNKNOWN and never automatically score zero or maximum.

## RAG Assistant hardening bundle

This bundle is PROPOSED until verified and is not universally sufficient:

- `[PROMPT]` `RG-HARD-P-001`: retrieved content has no automatic privileged authority.
- `[AUTHORIZATION]` `RG-HARD-AUTHZ-001`: enforce owner/tenant/document access before retrieval.
- `[DATA]` `RG-HARD-DATA-002`: preserve provenance and minimize context.
- `[APPLICATION]` `RG-HARD-AGENT-001`: bind trusted identity and provenance through orchestration.
- `[TOOL]` `RG-HARD-TOOL-002`: validate structured retrieval fields and quarantine free text.
- `[NETWORK]` `RG-HARD-NET-001`: restrict external retrieval when applicable.
- `[MONITORING]` `RG-HARD-MON-001`, `RG-HARD-MON-002`: audit writes, retrieval anomalies, and denials.
- `[RECOVERY]` `RG-HARD-REC-001`: disable poisoned documents and rebuild/rollback indexes safely.

Verify cross-tenant denial, lost-metadata rejection, non-allowlisted external retrieval,
query-rewrite filter preservation, document disablement, and redacted audit events.

## RAG audit checklist

- **Architecture:** Profile supplied ingestion, parsing, chunking, index, retrieval, assembly, cache, and action components.
- **Trust:** Classify sources without treating internal content as instructions.
- **Provenance:** Preserve source, owner, tenant, time, type, authorization, and version where needed.
- **Ingestion:** Authorize writes/deletes and provide review, isolation, versioning, and rollback.
- **Authorization:** Apply authenticated resource policy before sensitive retrieval.
- **Tenant isolation:** Bind namespace, filters, context, and caches to trusted tenant identity.
- **Chunk metadata:** Retain document provenance and ACL/tenant fields on every chunk.
- **Retrieval:** Validate scope, reranking, result limits, and context assembly.
- **Query rewriting:** Prevent model rewrites from controlling authorization filters.
- **Vector/index poisoning:** Audit integrity and access; state the empirical-analysis limitation.
- **Result authority:** Keep retrieved data separate from control-plane instructions.
- **Caching:** Review identity/tenant keys, poisoning, invalidation, and stale policy.
- **Tool escalation:** Trace retrieval-to-action chains with existing tool scoring.
- **Monitoring:** Log ingestion, denials, anomalies, source changes, and high-risk chains without secrets.
- **Recovery:** Support document disablement, version rollback, cache invalidation, and controlled rebuild.

## Scope and limitations

This guidance is provider-, framework-, and storage-neutral. It applies to managed or
local vector stores, SQL/NoSQL retrieval, search engines, custom pipelines, and hybrid
systems. RenGuard audits only supplied configuration and evidence; it does not magically
access a vector database, inspect raw vectors, prove corpus integrity, or run a live attack.
