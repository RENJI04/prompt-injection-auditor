# RenGuard Model Context Protocol Security

This is the canonical specialized audit reference for evidenced Model Context Protocol
(MCP) deployments. Apply it together with [tool security](tool-security.md), and with
[agentic security](agentic-security.md) only when the architecture is actually agentic.
MCP compliance is not a trust decision, and RenGuard does not connect to or penetrate a
server without supplied evidence.

## Source provenance and scope

- **Verified stable MCP version:** `2026-07-28`
- **Verified on:** `2026-10-10`
- **Source type:** official Model Context Protocol specification/project
- **Canonical specification:** <https://modelcontextprotocol.io/specification/2026-07-28>
- **Stable changelog:** <https://modelcontextprotocol.io/specification/2026-07-28/changelog>
- **Normative authorization security considerations:** <https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations>
- **Official security guidance:** <https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices>
- **Stable tool specification:** <https://modelcontextprotocol.io/specification/2026-07-28/server/tools>

The stable specification and its normative authorization pages define requirements.
Official security guidance supplies implementation analysis and mitigations. A FINAL
SEP incorporated into `2026-07-28` explains a stable change; a proposal, draft, release
candidate, experimental feature, or independently versioned extension is not a
normative core requirement. Record extension maturity and version rather than silently
promoting it to stable core behavior. This source pin is refreshed deliberately;
offline repository validation does not fetch the web.

## Profile and version first

Record the protocol version, host/client, each actual server origin, local or remote
transport/deployment, tools, resources, prompts, extensions, authorization model,
server trust, credentials/scopes, network path, installation/update provenance,
approval model, and execution environment. Unknown facts remain UNKNOWN. Do not require
unused MCP capabilities merely because the protocol supports them.

For native `2026-07-28`, the core is stateless at protocol level. Every request carries
version, client identity, and capabilities; optional `server/discover` provides
up-front discovery. The stable revision removed the legacy `initialize` /
`notifications/initialized` exchange and `Mcp-Session-Id`. Do not require those legacy
mechanisms or report their absence as a modern vulnerability. Application state may use
explicit handles; validate authorization and ownership for every handle.

For `2025-11-25` and earlier deployments, apply the lifecycle and session rules for the
negotiated legacy version. Expected legacy behavior is not proof of security. Never mix
legacy requirements into a modern finding without labeling compatibility context.
Reject malformed or unsupported versions, record version mismatches, and analyze any
translation layer as an additional trust boundary.

## Server, tool, resource, and prompt trust

Classify each server independently as organization-managed, approved third party,
user-installed, unknown, or untrusted. Protocol compliance does not prove that a server
is benign. Preserve a host-assigned origin and namespace through catalogs, planning,
approvals, policy, and logs. Stable MCP tool names are unique only within a server; the
server-reported name is not guaranteed globally unique. A tool name does not prove
identity.

Apply every generic tool check. Tool descriptions and annotations are untrusted unless
they come from a trusted server, and even trusted metadata is not deterministic
authorization. `readOnlyHint`, `destructiveHint`, `idempotentHint`, and `openWorldHint`
remain behavioral hints, not guarantees. Bind high-risk approval to the actual server
origin, tool, normalized parameters, resource/destination/value, requester, and expiry.

Resources and tool results are content/data, not privileged instructions. Preserve
origin, URI, access-control, tenant, sensitivity, and provenance information; inspect
cross-server reads and context exposure. A server-supplied prompt or instruction is
content from that server. It cannot silently outrank host security policy or suppress
approval unless a trusted host architecture explicitly grants narrow authority.

## Schemas and dynamic capabilities

In stable `2026-07-28`, tool input/output schemas use JSON Schema 2020-12 semantics;
input schemas retain an object root while output schemas and structured content may
represent any conforming JSON value. Validate schemas and values with depth, size,
composition, reference, and resource limits. Reject unsafe unknown fields where policy
requires it, then perform semantic authorization. JSON Schema does not validate
permission, intent, ownership, or destination safety.

Track list/discovery changes, origin, cache freshness, version, description, schemas,
annotations, behavior, and permission changes. Review TOCTOU/rug-pull paths where a user
or policy approves definition A but execution reaches definition B. For consequential
tools, bind the decision to a stable host origin and reviewed definition/version or
equivalent integrity evidence; require fresh policy/approval after material mutation.
Map malicious packages, servers, registries, updates, or mutable definitions to
`RG-SC-001`, tool mechanisms, and `ASI04` where agentic.

## Authorization and token handling

MCP authorization is optional overall and transport-dependent; when a protected HTTP
deployment uses the stable authorization profile, assess protected resource metadata,
authorization-server discovery, validated issuer, client registration method, exact
redirect handling, PKCE, resource/audience binding, least scopes and step-up, consent,
access-token validation/expiry, and service-to-service identity. OAuth authentication
does not replace resource-, tenant-, or operation-level authorization.

Stable requirements include use of protected resource metadata and authorization-server
discovery, resource indicators in authorization/token requests, issuer checking when
specified, and server validation that an access token is intended for that MCP server.
Credentials are issuer-bound. Scope must be least privilege and the backend still
authorizes every action and resource using trusted identity.

Unsafe token passthrough is prohibited: an MCP server must not forward the client token
unchanged to a downstream API. Validate the inbound token for the MCP server; use a
separate downstream token or a deliberate delegation/token-exchange architecture bound
to the downstream audience, subject, scope, and policy. Keep tokens out of prompts,
memory, tool output, and logs. Assess token theft, reuse, refresh, rotation, revocation,
and cross-tenant scope.

For proxy/deputy architectures, model client identity, user identity, downstream
resource ownership, static client credentials, per-client consent, delegated authority,
approval scope, and external URLs. A privileged component can be a confused deputy even
without prompt injection.

## Discovery, network, and supply chain

Apply SSRF analysis only when an attacker can influence discovery or fetched endpoints.
Protected-resource metadata, authorization-server metadata, client metadata documents,
redirects, DNS changes, internal/reserved addresses, localhost, and cloud metadata paths
are relevant. Prefer validated HTTPS endpoints, safe URL parsing, per-hop redirect
validation, private/reserved route controls, DNS/TOCTOU defenses, network segmentation,
and an egress proxy where risk warrants them. HTTP alone is not proof of SSRF.

For local servers, record package/executable/script/container/source provenance,
publisher, pin/integrity, update path, dependencies, startup command, OS privilege,
filesystem/environment/secrets access, network access, sandbox, and disable path. Do not
recommend piping an untrusted remote script into a shell. For remote servers, assess
authenticated origin, transport, authorization, token destination, scope, egress,
privacy, updates, and tool/resource provenance. Local is not automatically safe; remote
is not automatically unsafe.

## Interactive flows and extensions

Stable `2026-07-28` uses Multi Round-Trip Requests (MRTR) instead of legacy in-flight
server-initiated requests: an operation can return `input_required`, and the client
retries with bound `inputResponses` and `requestState`. Audit request/origin binding,
replay/duplication, parameter changes, unexpected input requests, privilege expansion,
and approval. Server-requested input does not have host authority.

Elicitation can collect additional user input. Show the server origin in trusted UI,
limit sensitive requests, bind inputs to the operation, resist phishing, and never ask
for raw credentials merely because a server requested them. Elicitation is not
authorization. Sampling remains available but is deprecated in `2026-07-28`; if an
evidenced deployment exposes it, minimize supplied context and capabilities, reveal
origin, prevent secret/tool expansion, and bound loops/cost. New implementations should
follow the stable migration guidance rather than assuming sampling is a preferred core
design.

Inventory each enabled extension with identifier, version/maturity, origin, capability,
data flow, authorization, UI/action effect, and supply-chain path. Official extensions
are opt-in and independently scoped; draft and experimental extensions remain
non-normative. Phase 6 performs architecture-level review rather than a full engine for
Tasks, Apps, Skills, enterprise authorization, or other individual extensions.

## MCP defense-in-depth bundle

Use approved origin and installation provenance; minimum audience-bound scopes; token
isolation; server/resource authorization; origin-aware tool names; deterministic tool
authorization; schema and semantic validation; annotation distrust; exact-action
approval; sandboxing; egress policy; privacy-aware logs; and independent server/tool
disable and credential revocation. Reuse `RG-HARD-TOOL-001` through
`RG-HARD-TOOL-003`, `RG-HARD-AUTHZ-001`, `RG-HARD-AUTHZ-002`,
`RG-HARD-DATA-001`, `RG-HARD-DATA-002`, `RG-HARD-RUN-001`,
`RG-HARD-NET-001`, `RG-HARD-NET-002`, `RG-HARD-HITL-001`,
`RG-HARD-MON-001`, `RG-HARD-REC-001`, and `RG-HARD-REC-002`. Compliance alone
does not provide this bundle, and no bundle guarantees safety or zero residual risk.
