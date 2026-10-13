# RenGuard Output Security

This is the canonical Phase 7 audit reference for model or agent output consumed by
tools, databases, shells, interpreters, browsers, renderers, template engines,
filesystems, URL fetchers, APIs, build/deploy systems, serializers/deserializers,
spreadsheets, or other automated systems. Load it only when an evidenced downstream
consumer exists; ordinary display-only text does not require every sink check.

Use the existing [RenGuard techniques](renguard-techniques.md),
[risk model](risk-scoring.md), [hardening catalog](hardening-patterns.md), and the
[tool](tool-security.md) and [agentic](agentic-security.md) references when those
architectures are present.

## Core principle and output profile

Model output is untrusted data until validated for its specific downstream sink. A model
producing text, code, JSON, a URL, path, query, template, or control message does not make
that value safe to interpret or execute. Security is enforced at the consumer/sink
boundary, not by the model's claim that its output is safe.

Record supported facts about the output producer, task, format, parser, schema, consumer,
sink, privilege, destination, encoding, validation, authorization, execution environment,
human review, external reach, and rollback/recovery. Mark unsupported facts **UNKNOWN /
INSUFFICIENT EVIDENCE — not zero and not assumed unsafe**.

## Output sink classes

`OS` is an architecture label distinct from Phase 3 risk dimensions and severity.

| Class | Meaning | Typical examples |
|---|---|---|
| `OS0` | Display-only inert output | Escaped plain text with no active links, fetching, or execution |
| `OS1` | Structured non-executing application input | Validated enum or bounded record used without sensitive state change |
| `OS2` | Sensitive state or query input | Tenant-scoped lookup, protected record selection, or reversible state change |
| `OS3` | Active renderer, network, filesystem, or privileged-action input | HTML/webview, fetch URL, path, outbound message, significant tool action |
| `OS4` | Code, command, deployment, or high-impact execution input | Shell/process, interpreter, build/deploy, production code, privileged database mutation |

Classify the actual sink and deployed behavior. A Markdown field can be `OS0` in an
inert renderer or `OS3` when it auto-fetches resources or permits active HTML. An `OS4`
label does not automatically make a finding CRITICAL; score only supported exposure and
impact with the Phase 3 formula.

## Four-question validation model

Keep these decisions separate:

1. **Structural validity:** Is the output well-formed and within type, schema, size, and depth constraints?
2. **Semantic validity:** Is the value meaningful and allowed for this task, field, destination, and business rule?
3. **Authorization:** May this authenticated actor perform this action on this resource and tenant?
4. **Sink safety:** Is the value safely represented and constrained for this exact parser, interpreter, renderer, or execution context?

Passing one question does not answer the others. Valid JSON does not imply a safe action.
Schema validity does not grant authorization. A correctly encoded value may still name
an unauthorized recipient or dangerous operation.

## Shell, commands, and processes

Trace model output entering a shell, terminal, command runner, process launcher, or
script. Never concatenate model output into shell commands. Prefer a fixed executable,
structured process invocation, validated bounded arguments, narrow allowlists when the
task is naturally constrained, least privilege, sandboxing, and no shell when it is not
needed. Quoting alone does not solve every command, option, path, environment, or
interpreter risk. Generated command text is not authorization to run it.

## SQL and database sinks

Separate model-generated query content from database authorization. Never concatenate
model output into SQL queries. Prefer parameterized queries, constrained query builders,
read-only or least-privilege database identities, statement allowlists for narrow tasks,
row/tenant authorization, bounded results, and transaction boundaries. “Only generate
safe SQL” is prompt guidance, not the primary database control.

## HTML, DOM, Markdown, and rendering

For HTML, DOM, rich content, templates, or webviews, assess scripts, event handlers,
unsafe attributes, active links, embedded resources, style/URL contexts, and
HTML/Markdown transformations. Apply context-aware encoding or a sanitizer designed and
configured for the specific renderer and allowed feature set. One sanitizer is not
universal across HTML text, attributes, URLs, scripts, styles, templates, and other
contexts.

Markdown is not universally inert. Renderer behavior determines whether links, images,
embedded HTML, custom extensions, command/action links, local resources, or automatic
fetches create an active sink. Review the actual renderer configuration rather than
calling Markdown safe by format alone.

## URLs, network destinations, and redirects

A generated URL is not a trusted destination. For fetching, redirects, callbacks,
webhooks, navigation, image loading, and API calls, validate scheme, host, port,
canonical destination, allowlist where naturally bounded, DNS/IP behavior, internal and
reserved ranges, credentials, redirects at every hop, and data sent to the destination.
Apply SSRF and egress analysis only when an attacker-influenced URL can reach a fetch or
network path; not every displayed URL creates SSRF.

## Filesystem paths and archive entries

For filenames, paths, directories, upload/extraction targets, and archive entries,
canonicalize according to the real platform and enforce root, tenant, ownership,
extension/type, overwrite, and symlink policy before use. Consider traversal, absolute
paths, reserved names, aliases, links, and race conditions. String-prefix checks alone
are unsafe when path semantics can escape the intended root.

## Templates, configuration, and generated code

Treat server/client templates, infrastructure templates, and configuration as input to
their actual parser or evaluator. Check expression execution, interpolation, privilege-
bearing changes, secrets, destinations, and deployment authorization. Generated
template text is not automatically safe to render or apply.

Generated code does not gain execution authority. Separate generation, review,
dependency installation, testing, sandbox execution, filesystem/secret/network access,
production access, and deployment approval. Apply `RG-EX-001` when code reaches an
unexpected execution path and `RG-OU-001` to the unsafe downstream-consumption boundary.

## Serialization and structured output

Prefer simple data formats, safe parsers, explicit schemas, bounded size/depth, and no
arbitrary type or object instantiation. JSON being structured does not establish truth,
intent, tenant ownership, or permission. Validate required fields, types, enums, lengths,
numeric ranges, nesting, unknown fields, canonical identifiers, semantic constraints,
and authorization.

For XML, apply architecture-appropriate parser controls for entities, external
references, schema behavior, size, and depth. XML is not inherently vulnerable, but an
unsafe parser configuration can be. For other serializers, reject unsafe type metadata
or constructors where applicable rather than treating model-selected object types as
trusted.

## CSV and spreadsheet output

When output is opened or imported by spreadsheet software, assess formula-leading cells,
product-specific executable constructs, external links, delimiters, encodings, and
unsafe import behavior. Neutralize or encode for the actual destination without assuming
one rule covers every spreadsheet product. Preserve the intended cell value and test it
in a safe environment.

## Logs, headers, protocols, and messages

For logs, assess newline/log forging, terminal escape sequences, structured-log
corruption, sensitive-data leakage, and secret exposure. Prefer typed structured events,
length limits, destination-aware encoding, and redaction. Raw model context is not safe
for logs by default.

Where output enters HTTP, email, or other protocol fields, validate field syntax,
newlines/CRLF where applicable, recipient and destination, and protocol-specific limits.
Do not generalize header-splitting risk to architectures without such a sink.

For email or messages, keep generation separate from sending. Independently authorize
recipient, channel, subject/body fields, attachments, links, confidentiality, external
destination, impersonation-sensitive identity, and automatic-send behavior. Bind
consequential approval to the exact rendered action and parameters.

## Encoding, canonicalization, and allowlists

Encoding and escaping are destination-specific: HTML text, HTML attributes, URLs, SQL
parameters, shell arguments, JSON strings, CSV cells, and filesystem paths use different
rules. There is no universal “sanitize everything” operation. Sanitization can remove or
transform disallowed content for a defined sink, but it does not replace semantic
validation, authorization, or containment.

Canonicalize paths, URLs, domains, usernames, and resource IDs before policy checks when
their semantics require it. Account for alternate encodings, case rules, redirects,
aliases, and normalization without turning the model into the policy oracle. Use
allowlists for naturally bounded values such as enums, known domains, deployment
environments, or report formats; avoid giant brittle lists for open-ended tasks.

## Output-to-tool and agent chains

Trace supported chains such as:

```text
model URL -> fetch tool -> internal resource -> sensitive response
model command -> shell tool -> filesystem change
model SQL -> database tool -> cross-tenant read
model code -> build -> authenticated approval -> deployment
```

An upstream agent's output does not become authenticated identity, protected policy,
approval, trusted code, or privileged parameters for a downstream agent. Preserve
producer/task provenance and apply Phase 6 typed handoff, origin, authorization, and
approval rules. Score each supported chain once; never sum findings or add an `OS` bonus.

## Quarantine, provenance, and recovery

For high-risk generated code, scripts, infrastructure/configuration, migrations,
external messages, or active documents, consider a quarantine/review stage with
sink-specific static checks, tests, sandbox execution, diff review, authenticated
approval, and policy checks. Quarantine is one control layer, not a safety guarantee.

Preserve producing model/agent, task, relevant source inputs, timestamp, target sink,
validation results, approval reference, and artifact digest/version where proportionate.
This supports review, auditability, rollback, revocation, and incident response without
over-prescribing provenance for trivial `OS0` display output. Irreversible disclosure or
external action may not be recoverable.

## Risk and hardening integration

Use `RG-OU-001` and `LLM10:2026` for unsafe downstream consumption, not generic bad
formatting, prompt injection, or any incorrect answer. Add Agentic mappings only when an
agentic execution path exists. Output-to-shell can affect `T`, `V`, `B`, and `R`; a URL
fetch can affect `G`, `B`, and `D`; cross-tenant SQL can affect `V`, `D`, and `B`; and
production code can affect `T`, `V`, `R`, and `B`. Values remain evidence-bounded and
UNKNOWN is not zero. The Phase 3 formula is unchanged.

Reuse `RG-HARD-OUT-001` as the primary sink-specific pattern, with
`RG-HARD-TOOL-002`, `RG-HARD-AUTHZ-001`, `RG-HARD-AUTHZ-002`,
`RG-HARD-RUN-001`, `RG-HARD-NET-001`, `RG-HARD-NET-002`,
`RG-HARD-DATA-001`, `RG-HARD-HITL-001`, `RG-HARD-MON-001`,
`RG-HARD-REC-001`, and `RG-HARD-REC-002` as applicable. This output-processing bundle
uses existing patterns; it does not claim implementation or zero residual risk.

## Output security checklist

- **Output type:** What exact text, data, artifact, link, query, code, or control value is produced?
- **Parser:** Which parser, decoder, renderer, constructor, or interpreter reads it?
- **Sink:** What `OS0`–`OS4` destination and context receives it?
- **Execution potential:** Can it trigger active content, network, filesystem, code, command, or deployment behavior?
- **Privilege:** Which identity, credentials, tenant, and environment does the consumer use?
- **Schema:** Are types, fields, sizes, depths, enums, ranges, and unknown fields constrained?
- **Semantic validation:** Is the value allowed and sensible for the specific task and business rule?
- **Authorization:** May the authenticated actor perform the exact action on the resource?
- **Encoding:** Is representation correct for the exact sink context rather than a universal sanitizer?
- **Canonicalization:** Are path, URL, domain, and identifier semantics normalized before policy where needed?
- **Destination:** Are recipient, host, resource, environment, and amount bound and approved as applicable?
- **Network reach:** Can output reach internal, external, credentialed, or redirecting destinations?
- **Filesystem reach:** Can output read, write, overwrite, escape a root, or cross tenant boundaries?
- **Human approval:** Is high-impact approval authenticated, comprehensible, and bound to exact parameters?
- **Logging:** Are allow/deny/validation events attributable and redacted?
- **Rollback / recovery:** Can execution be stopped, credentials revoked, and reversible state restored?

## Limitations

RenGuard audits supplied architecture, configuration, prompts, examples, and artifacts.
It is not automatically a browser sandbox, live XSS/SQLi/SSRF tester, static source-code
analyzer, malware scanner, universal sanitizer, or penetration-testing service. It does
not claim guaranteed safe output, fully sanitized artifacts, injection-proof sinks, or
that a prompt can replace sink validation. Runtime controls require implementation and
safe system-level verification.
