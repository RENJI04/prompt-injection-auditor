# RenGuard Attack Technique Catalog

This is RenGuard's canonical operational taxonomy. A technique describes an attack or
security-failure mechanism. It is not interchangeable with the weakness that enables
the mechanism or the impact that follows.

Technique IDs are permanent identifiers. New techniques receive the next unused number
inside the appropriate family. Published IDs are never renumbered or reused; a retired
technique remains documented with a replacement pointer. Names may be clarified only
when the underlying semantics remain stable.

Coverage labels are conservative:

- **CORE** — the current skill directly guides prompt/configuration-level detection.
- **PARTIAL** — the taxonomy and general audit guidance apply, but specialized runtime
  inspection or a later-phase engine is still needed for comprehensive analysis.
- **PLANNED** — classified now for stable reporting; dedicated detection is deferred.

OWASP entries are cross-references. The primary mapping identifies the closest broad
risk class; secondary mappings apply only when the stated context exists. ASI mappings
apply only to agentic targets.

## RG-PI-001 — Direct Instruction Override

- **Category Family:** Prompt Injection (`RG-PI`)
- **Definition:** A user supplies instructions intended to replace, disable, or supersede higher-priority behavior.
- **Typical attack sources:** Chat messages, API input, form fields, support tickets.
- **Detection signals:** Override language, fake system markers, requests to ignore policy.
- **Preconditions:** Attacker input reaches the model as instruction-capable context.
- **Security impact:** Policy bypass, task redirection, disclosure, or unsafe action.
- **Example attack pattern:** A user declares a new system policy and requests restricted output.
- **Primary OWASP LLM 2026:** `LLM01:2026`
- **Secondary OWASP LLM 2026:** None.
- **OWASP Agentic 2026:** `ASI01` when the target can plan or act.
- **Commonly confused with:** `RG-PI-008` persona hijacking and `RG-PR-001` authority impersonation.
- **Boundary / non-example:** An authorized in-scope user request that does not attempt to override policy.
- **Prompt-level mitigations:** State authority, scope, and instruction precedence explicitly.
- **Application/runtime mitigations:** Enforce permissions outside the model and isolate untrusted input.
- **Current RenGuard Coverage Status:** CORE

## RG-PI-002 — Indirect Content Injection

- **Category Family:** Prompt Injection (`RG-PI`)
- **Definition:** Instructions embedded in data supplied by a third party or external system influence model behavior.
- **Typical attack sources:** Documents, messages, API responses, database fields, source code.
- **Detection signals:** Instruction-like text inside content expected to be data.
- **Preconditions:** External content enters model context without a reliable trust boundary.
- **Security impact:** Task hijack, unauthorized disclosure, or attacker-directed actions.
- **Example attack pattern:** An uploaded file tells the model to ignore the user's task and export data.
- **Primary OWASP LLM 2026:** `LLM01:2026`
- **Secondary OWASP LLM 2026:** `LLM04:2026` only when a compromised supplier or component delivers it.
- **OWASP Agentic 2026:** `ASI01` when the content redirects an agent.
- **Commonly confused with:** `RG-SC-001` supply-chain compromise.
- **Boundary / non-example:** Malicious content alone is not a supply-chain event without provenance or component compromise.
- **Prompt-level mitigations:** Declare external content untrusted and separate data from authorized instructions.
- **Application/runtime mitigations:** Track provenance, constrain tools, sanitize pipelines, and require authorization.
- **Current RenGuard Coverage Status:** CORE

## RG-PI-003 — Retrieved-Document Injection

- **Category Family:** Prompt Injection (`RG-PI`)
- **Definition:** Instruction-like content in a retrieved document redirects the model or agent.
- **Typical attack sources:** RAG chunks, indexed PDFs, knowledge bases, enterprise search.
- **Detection signals:** Retrieved text addresses the model, changes policy, or requests actions.
- **Preconditions:** Retrieved content is placed in context and treated as authoritative instructions.
- **Security impact:** Answer corruption, data exposure, tool misuse, or persistent compromise.
- **Example attack pattern:** A retrieved policy page instructs the assistant to disclose unrelated records.
- **Primary OWASP LLM 2026:** `LLM01:2026`
- **Secondary OWASP LLM 2026:** `LLM05:2026` when the retrieval corpus was deliberately poisoned.
- **OWASP Agentic 2026:** `ASI01` when retrieval redirects an agentic plan.
- **Commonly confused with:** `RG-RA-001` retrieval poisoning, which concerns corpus integrity.
- **Boundary / non-example:** Incorrect but non-instructional retrieved content is not prompt injection.
- **Prompt-level mitigations:** Define retrieved text as evidence, never privileged policy.
- **Application/runtime mitigations:** Preserve provenance, filter ingestion, authorize retrieval, and limit actions.
- **Current RenGuard Coverage Status:** CORE

## RG-PI-004 — Web-Content Injection

- **Category Family:** Prompt Injection (`RG-PI`)
- **Definition:** Instructions on a fetched web resource manipulate a browsing or web-enabled model.
- **Typical attack sources:** Web pages, comments, metadata, search snippets, advertisements.
- **Detection signals:** Hidden or visible directives addressed to an AI reader.
- **Preconditions:** The application fetches attacker-influenced web content into context.
- **Security impact:** Goal hijack, data exfiltration, unsafe navigation, or tool misuse.
- **Example attack pattern:** Invisible page text asks a browsing agent to upload session data.
- **Primary OWASP LLM 2026:** `LLM01:2026`
- **Secondary OWASP LLM 2026:** None by default.
- **OWASP Agentic 2026:** `ASI01` when a browsing agent changes goals or actions.
- **Commonly confused with:** `RG-PI-003`, which is specific to retrieval/document pipelines.
- **Boundary / non-example:** Ordinary page instructions shown to a human are not automatically an AI injection.
- **Prompt-level mitigations:** Mark web content untrusted and prohibit embedded policy changes.
- **Application/runtime mitigations:** Isolate browsing, restrict destinations, and mediate outbound actions.
- **Current RenGuard Coverage Status:** CORE

## RG-PI-005 — Structural or Delimiter Injection

- **Category Family:** Prompt Injection (`RG-PI`)
- **Definition:** Crafted delimiters or serialization structure blur instruction and data boundaries.
- **Typical attack sources:** XML, JSON, Markdown fences, templates, chat-role markers.
- **Detection signals:** User-controlled closing tags, role tokens, or boundary-like sequences.
- **Preconditions:** Prompt construction relies on delimiters the attacker can reproduce or escape.
- **Security impact:** Instruction reinterpretation, role confusion, or policy bypass.
- **Example attack pattern:** Input closes a data tag and opens a forged instruction block.
- **Primary OWASP LLM 2026:** `LLM01:2026`
- **Secondary OWASP LLM 2026:** None.
- **OWASP Agentic 2026:** `ASI01` only when it redirects an agent.
- **Commonly confused with:** `RG-OU-001` unsafe downstream output execution.
- **Boundary / non-example:** Output formatting is not improper output handling unless a downstream consumer trusts it unsafely.
- **Prompt-level mitigations:** Use explicit authority language and robust data framing.
- **Application/runtime mitigations:** Use typed interfaces, escaping, schemas, and separate instruction channels.
- **Current RenGuard Coverage Status:** CORE

## RG-PI-006 — Encoded or Obfuscated Instruction Injection

- **Category Family:** Prompt Injection (`RG-PI`)
- **Definition:** An attacker encodes or disguises instructions to evade inspection or policy cues.
- **Typical attack sources:** Base64, ciphers, token splitting, alternate languages, transformed text.
- **Detection signals:** Decode-and-follow requests or opaque payloads paired with execution directives.
- **Preconditions:** The model is asked or configured to decode content and treat the result as instructions.
- **Security impact:** Hidden policy bypass, exfiltration, or unsafe action.
- **Example attack pattern:** A message asks the model to decode a payload and obey it without review.
- **Primary OWASP LLM 2026:** `LLM01:2026`
- **Secondary OWASP LLM 2026:** None.
- **OWASP Agentic 2026:** `ASI01` when decoded content redirects an agent.
- **Commonly confused with:** `RG-PI-007` character-level concealment.
- **Boundary / non-example:** Decoding content for analysis without following it is not exploitation.
- **Prompt-level mitigations:** Separate transformation from authority and inspect decoded content as data.
- **Application/runtime mitigations:** Normalize inputs and gate actions independently of model interpretation.
- **Current RenGuard Coverage Status:** CORE

## RG-PI-007 — Unicode, Homoglyph, or Invisible-Character Injection

- **Category Family:** Prompt Injection (`RG-PI`)
- **Definition:** Character-level tricks conceal, split, or visually misrepresent malicious instructions.
- **Typical attack sources:** Zero-width characters, bidirectional controls, homoglyphs, invisible text.
- **Detection signals:** Suspicious normalization changes, hidden code points, visual/text mismatch.
- **Preconditions:** The ingestion or display layer preserves deceptive characters into model context.
- **Security impact:** Filter evasion, hidden goal redirection, or reviewer deception.
- **Example attack pattern:** Invisible Unicode text in source code instructs an agent to run a command.
- **Primary OWASP LLM 2026:** `LLM01:2026`
- **Secondary OWASP LLM 2026:** None.
- **OWASP Agentic 2026:** `ASI01` when concealed text hijacks an agent.
- **Commonly confused with:** `RG-PI-006` general encoding or obfuscation.
- **Boundary / non-example:** International text containing legitimate non-ASCII characters is not suspicious by itself.
- **Prompt-level mitigations:** Tell the auditor to consider concealed instruction channels.
- **Application/runtime mitigations:** Normalize safely, surface control characters, and compare rendered and raw text.
- **Current RenGuard Coverage Status:** PARTIAL

## RG-PI-008 — Persona or Role Hijacking

- **Category Family:** Prompt Injection (`RG-PI`)
- **Definition:** An attacker induces the model to adopt a role or persona that conflicts with its assigned behavior.
- **Typical attack sources:** Roleplay requests, fictional framing, alternate-persona prompts.
- **Detection signals:** Requests to become an unrestricted or differently governed identity.
- **Preconditions:** Role boundaries are weak or treated as user-selectable.
- **Security impact:** Policy bypass, scope expansion, or unsafe output.
- **Example attack pattern:** A user asks the assistant to become a persona with no restrictions.
- **Primary OWASP LLM 2026:** `LLM01:2026`
- **Secondary OWASP LLM 2026:** None.
- **OWASP Agentic 2026:** `ASI01` when the persona change alters agent goals.
- **Commonly confused with:** `RG-PR-001` false authority claims.
- **Boundary / non-example:** Benign roleplay within unchanged policy and permissions is not hijacking.
- **Prompt-level mitigations:** Anchor role boundaries while permitting safe in-scope roleplay.
- **Application/runtime mitigations:** Enforce capabilities and authorization outside persona text.
- **Current RenGuard Coverage Status:** CORE

## RG-PI-009 — Multi-Turn Goal Drift

- **Category Family:** Prompt Injection (`RG-PI`)
- **Definition:** Repeated interactions gradually redirect the system away from its authorized objective.
- **Typical attack sources:** Conversational pressure, incremental reframing, staged requests.
- **Detection signals:** Small accepted deviations accumulate into an out-of-scope task.
- **Preconditions:** State persists and goal adherence is not re-evaluated across turns.
- **Security impact:** Scope bypass, unsafe assistance, or agent goal hijack.
- **Example attack pattern:** Harmless subtasks are chained until the final task violates the original scope.
- **Primary OWASP LLM 2026:** `LLM01:2026`
- **Secondary OWASP LLM 2026:** `LLM03:2026` when drift reaches privileged actions.
- **OWASP Agentic 2026:** `ASI01` when an agent's plan is redirected.
- **Commonly confused with:** `RG-PI-001`, which is an overt single-step override.
- **Boundary / non-example:** Legitimate clarification that remains within scope is not goal drift.
- **Prompt-level mitigations:** Restate durable objectives and require scope checks before material transitions.
- **Application/runtime mitigations:** Track task state, authorize actions, and reset contaminated sessions.
- **Current RenGuard Coverage Status:** CORE

## RG-PI-010 — Context Dilution or Overflow Control Degradation

- **Category Family:** Prompt Injection (`RG-PI`)
- **Definition:** Large or strategically placed content weakens effective adherence to controlling instructions.
- **Typical attack sources:** Long conversations, oversized documents, repeated filler, context flooding.
- **Detection signals:** Critical controls are displaced, truncated, or ignored after large inputs.
- **Preconditions:** Context management does not preserve trusted policy or bound untrusted content.
- **Security impact:** Instruction loss, policy bypass, latency, or resource exhaustion.
- **Example attack pattern:** An attacker floods context and places a conflicting directive near the end.
- **Primary OWASP LLM 2026:** `LLM01:2026`
- **Secondary OWASP LLM 2026:** `LLM06:2026` when consumption or denial of service is part of the attack.
- **OWASP Agentic 2026:** Primary `ASI01`; secondary `ASI08` only when degradation propagates through a workflow.
- **Commonly confused with:** `RG-RC-001` resource consumption.
- **Boundary / non-example:** A long legitimate document is not an attack without control degradation or abusive consumption.
- **Prompt-level mitigations:** Keep critical controls concise and require priority preservation.
- **Application/runtime mitigations:** Budget context, isolate trusted policy, summarize safely, and reject abusive size.
- **Current RenGuard Coverage Status:** PARTIAL

## RG-HC-001 — System or Developer Instruction Extraction

- **Category Family:** Hidden Context / Information Exposure (`RG-HC`)
- **Definition:** An attacker elicits hidden system or developer instructions verbatim or in transformed form.
- **Typical attack sources:** Direct requests, translation, encoding, completion, or reconstruction prompts.
- **Detection signals:** Requests to reveal, repeat, summarize, or encode hidden instructions.
- **Preconditions:** Hidden instructions are present in model context and disclosure controls are weak.
- **Security impact:** Control disclosure, easier targeted attacks, or secret leakage.
- **Example attack pattern:** A user asks for the complete hidden prompt in a code block.
- **Primary OWASP LLM 2026:** `LLM08:2026`
- **Secondary OWASP LLM 2026:** `LLM02:2026` when protected information is disclosed.
- **OWASP Agentic 2026:** None by default.
- **Commonly confused with:** `RG-HC-002`, which includes non-instructional hidden context.
- **Boundary / non-example:** A documented public behavior summary is not hidden-instruction extraction.
- **Prompt-level mitigations:** Define appropriate confidentiality without claiming prompts are a security boundary.
- **Application/runtime mitigations:** Keep secrets out of prompts and minimize sensitive context.
- **Current RenGuard Coverage Status:** CORE

## RG-HC-002 — Hidden Context Extraction

- **Category Family:** Hidden Context / Information Exposure (`RG-HC`)
- **Definition:** An attacker infers or reconstructs concealed roles, tool descriptions, policies, reasoning artifacts, or configuration.
- **Typical attack sources:** Probing, differential prompts, reconstruction, repeated boundary testing.
- **Detection signals:** Queries designed to enumerate hidden configuration or internal state.
- **Preconditions:** Sensitive operational context is exposed to the model or inferable from behavior.
- **Security impact:** Attack-surface discovery, control bypass, privacy loss, or follow-on exploitation.
- **Example attack pattern:** Repeated probes reconstruct the tool allowlist and refusal conditions.
- **Primary OWASP LLM 2026:** `LLM08:2026`
- **Secondary OWASP LLM 2026:** `LLM02:2026` when the context contains sensitive data.
- **OWASP Agentic 2026:** None by default.
- **Commonly confused with:** `RG-HC-001` verbatim instruction extraction.
- **Boundary / non-example:** User-visible capability documentation is not hidden context.
- **Prompt-level mitigations:** Avoid unnecessary operational detail and resist configuration reconstruction requests.
- **Application/runtime mitigations:** Minimize context, partition tools, and avoid relying on obscurity.
- **Current RenGuard Coverage Status:** CORE

## RG-HC-003 — Credential or Secret Exposure

- **Category Family:** Hidden Context / Information Exposure (`RG-HC`)
- **Definition:** Credentials, tokens, private keys, or comparable secrets become available through AI context or output.
- **Typical attack sources:** Hardcoded prompts, tool output, logs, retrieved files, memory.
- **Detection signals:** Secret-like values in prompts or unrestricted model-accessible data.
- **Preconditions:** A secret enters context or a model-accessible store.
- **Security impact:** Account compromise, unauthorized access, or lateral movement.
- **Example attack pattern:** A prompt contains an API token that a user elicits conversationally.
- **Primary OWASP LLM 2026:** `LLM02:2026`
- **Secondary OWASP LLM 2026:** `LLM08:2026` when the secret resides in hidden context.
- **OWASP Agentic 2026:** `ASI03` when exposed credentials authorize agent actions.
- **Commonly confused with:** `RG-HC-001` prompt extraction; a secret may leak without the prompt.
- **Boundary / non-example:** Clearly synthetic test tokens in isolated fixtures are not live secret exposure.
- **Prompt-level mitigations:** Prohibit secret disclosure, while acknowledging this is not sufficient protection.
- **Application/runtime mitigations:** Remove secrets from context, use scoped credentials, vaults, and output filters.
- **Current RenGuard Coverage Status:** CORE

## RG-HC-004 — Sensitive Retrieved-Data Disclosure

- **Category Family:** Hidden Context / Information Exposure (`RG-HC`)
- **Definition:** The system reveals protected data obtained through retrieval beyond the requester's authorization.
- **Typical attack sources:** RAG stores, enterprise search, databases, cross-tenant indexes.
- **Detection signals:** Broad retrieval access, missing tenant filters, or output beyond user scope.
- **Preconditions:** The model can retrieve data not independently authorized for the requesting principal.
- **Security impact:** Privacy breach, tenant leakage, regulatory exposure, or intelligence disclosure.
- **Example attack pattern:** A user asks a support bot to list records belonging to other customers.
- **Primary OWASP LLM 2026:** `LLM02:2026`
- **Secondary OWASP LLM 2026:** `LLM09:2026` when vector-store isolation or authorization fails.
- **OWASP Agentic 2026:** `ASI03` when agent identity or privilege enables retrieval.
- **Commonly confused with:** `RG-RA-002`, which is the retrieval authorization weakness/mechanism.
- **Boundary / non-example:** Returning data the authenticated user is authorized to access is not disclosure.
- **Prompt-level mitigations:** State data-minimization and user-scope requirements.
- **Application/runtime mitigations:** Authorize before retrieval, enforce tenant isolation, and minimize output.
- **Current RenGuard Coverage Status:** CORE

## RG-PR-001 — Authority or Administrator Impersonation

- **Category Family:** Privilege / Authority (`RG-PR`)
- **Definition:** An attacker claims a privileged identity or role to obtain policy exceptions or expanded access.
- **Typical attack sources:** User messages, forged metadata, spoofed inter-agent identity.
- **Detection signals:** Self-asserted developer, administrator, auditor, or emergency authority.
- **Preconditions:** The system trusts unverified identity claims in model-visible content.
- **Security impact:** Privilege escalation, policy bypass, disclosure, or unsafe action.
- **Example attack pattern:** A user claims to be an administrator and requests unrestricted tool access.
- **Primary OWASP LLM 2026:** `LLM01:2026`
- **Secondary OWASP LLM 2026:** `LLM03:2026` when the claim unlocks capabilities.
- **OWASP Agentic 2026:** Primary `ASI03`; secondary `ASI01` when the claim redirects agent goals.
- **Commonly confused with:** `RG-PI-008` persona hijacking.
- **Boundary / non-example:** Identity supplied by a verified application authentication boundary is not self-assertion.
- **Prompt-level mitigations:** Reject conversational privilege grants and identify trusted authority channels.
- **Application/runtime mitigations:** Authenticate principals and enforce authorization outside the model.
- **Current RenGuard Coverage Status:** CORE

## RG-PR-002 — Excessive Permissions

- **Category Family:** Privilege / Authority (`RG-PR`)
- **Definition:** The AI system or its tools hold broader data or action privileges than the task requires.
- **Typical attack sources:** Over-scoped tokens, shared service accounts, broad database roles.
- **Detection signals:** Cross-tenant access, write privileges for read tasks, or global credentials.
- **Preconditions:** Application identity and authorization are not least-privileged.
- **Security impact:** Expanded blast radius for injection, error, or compromise.
- **Example attack pattern:** A read-only assistant uses a service account that can delete production records.
- **Primary OWASP LLM 2026:** `LLM03:2026`
- **Secondary OWASP LLM 2026:** None.
- **OWASP Agentic 2026:** `ASI03`.
- **Commonly confused with:** `RG-TL-001` excessive tool capability.
- **Boundary / non-example:** A necessary permission constrained to the authenticated task is not excessive.
- **Prompt-level mitigations:** Document allowed operations and prohibit privilege expansion.
- **Application/runtime mitigations:** Use user-scoped credentials, least privilege, and complete mediation.
- **Current RenGuard Coverage Status:** CORE

## RG-PR-003 — Excessive Autonomy

- **Category Family:** Privilege / Authority (`RG-PR`)
- **Definition:** The system can plan or execute consequential actions without proportionate approval or stopping conditions.
- **Typical attack sources:** Autonomous loops, proactive-action directives, automatic retries.
- **Detection signals:** Irreversible actions without confirmation, budgets, or escalation.
- **Preconditions:** The agent can create external side effects and controls do not constrain autonomy.
- **Security impact:** Unauthorized changes, cascading damage, financial loss, or exfiltration.
- **Example attack pattern:** An agent deploys changes automatically after an ambiguous request.
- **Primary OWASP LLM 2026:** `LLM03:2026`
- **Secondary OWASP LLM 2026:** None.
- **OWASP Agentic 2026:** Primary `ASI02`; secondary `ASI08` when autonomous actions propagate failures.
- **Commonly confused with:** `RG-PR-002` permissions and `RG-TL-001` capability breadth.
- **Boundary / non-example:** Bounded automation with authenticated approval and rollback is not inherently excessive.
- **Prompt-level mitigations:** Define approval gates, budgets, and halt conditions.
- **Application/runtime mitigations:** Enforce human approval, transaction limits, circuit breakers, and rollback.
- **Current RenGuard Coverage Status:** CORE

## RG-TL-001 — Excessive Tool Capability

- **Category Family:** Tools / Actions (`RG-TL`)
- **Definition:** A tool exposes functions broader or more dangerous than the agent's task requires.
- **Typical attack sources:** General shells, unrestricted APIs, combined read/write/delete tools.
- **Detection signals:** Open-ended commands or high-impact functions without narrow interfaces.
- **Preconditions:** The model can select or invoke the over-capable tool.
- **Security impact:** Destructive actions, lateral movement, exfiltration, or code execution.
- **Example attack pattern:** A support agent can invoke an unrestricted database administration tool.
- **Primary OWASP LLM 2026:** `LLM03:2026`
- **Secondary OWASP LLM 2026:** None.
- **OWASP Agentic 2026:** `ASI02`.
- **Commonly confused with:** `RG-PR-002` excessive identity permissions.
- **Boundary / non-example:** A narrow tool exposing only task-required operations is not excessive.
- **Prompt-level mitigations:** Declare tool purpose, allowed parameters, and prohibited operations.
- **Application/runtime mitigations:** Split tools by function, allowlist operations, sandbox, and minimize capabilities.
- **Current RenGuard Coverage Status:** CORE

## RG-TL-002 — Tool-Output Instruction Injection

- **Category Family:** Tools / Actions (`RG-TL`)
- **Definition:** Instruction-like text returned by a tool manipulates subsequent model or agent behavior.
- **Typical attack sources:** API responses, web fetches, command output, plugin metadata.
- **Detection signals:** Tool output addresses the model or requests unrelated actions.
- **Preconditions:** Free-form tool output is treated as trusted instruction-capable context.
- **Security impact:** Goal hijack, unsafe calls, disclosure, or exfiltration.
- **Example attack pattern:** An API response tells the agent to send records to an external address.
- **Primary OWASP LLM 2026:** `LLM01:2026`
- **Secondary OWASP LLM 2026:** `LLM03:2026` when injected text reaches privileged actions.
- **OWASP Agentic 2026:** Primary `ASI01`; secondary `ASI02` when it drives tool misuse.
- **Commonly confused with:** `RG-PI-002` generic indirect injection.
- **Boundary / non-example:** Structured status data parsed according to schema is not an instruction.
- **Prompt-level mitigations:** Quarantine tool output as untrusted data.
- **Application/runtime mitigations:** Enforce schemas, validate fields, and authorize each subsequent action.
- **Current RenGuard Coverage Status:** CORE

## RG-TL-003 — Error or Recovery-Message Injection

- **Category Family:** Tools / Actions (`RG-TL`)
- **Definition:** Attacker-controlled error text or recovery guidance directs the model to take unsafe action.
- **Typical attack sources:** Exception messages, HTTP errors, failed tool calls, deployment output.
- **Detection signals:** Error bodies contain commands, credential requests, or policy changes.
- **Preconditions:** The system follows free-form recovery instructions from untrusted errors.
- **Security impact:** Code execution, repeated unsafe actions, exfiltration, or workflow hijack.
- **Example attack pattern:** A failed deployment response asks the agent to run an external script.
- **Primary OWASP LLM 2026:** `LLM01:2026`
- **Secondary OWASP LLM 2026:** `LLM03:2026` when recovery invokes privileged tools.
- **OWASP Agentic 2026:** Primary `ASI01`; secondary `ASI02` when recovery misuses tools.
- **Commonly confused with:** `RG-TL-002`, which covers any tool output.
- **Boundary / non-example:** Recovery selected from trusted local logic is not error-message injection.
- **Prompt-level mitigations:** Prohibit following recovery directives embedded in error data.
- **Application/runtime mitigations:** Use typed error codes, local recovery logic, retry limits, and approval.
- **Current RenGuard Coverage Status:** CORE

## RG-TL-004 — Tool-Parameter Manipulation

- **Category Family:** Tools / Actions (`RG-TL`)
- **Definition:** Attacker input influences tool arguments beyond the authorized operation or data scope.
- **Typical attack sources:** User-controlled paths, queries, recipients, URLs, shell fragments.
- **Detection signals:** Raw input reaches sensitive parameters or crosses tenant and destination boundaries.
- **Preconditions:** Parameter construction lacks validation, binding, or independent authorization.
- **Security impact:** Injection, unauthorized access, data modification, or exfiltration.
- **Example attack pattern:** User text changes an email recipient to an attacker-controlled address.
- **Primary OWASP LLM 2026:** `LLM03:2026`
- **Secondary OWASP LLM 2026:** `LLM01:2026` when prompt injection drives the manipulation.
- **OWASP Agentic 2026:** `ASI02`.
- **Commonly confused with:** Conventional command or query injection in the tool implementation.
- **Boundary / non-example:** A validated parameter within an authorized schema is not manipulation.
- **Prompt-level mitigations:** State parameter constraints and require confirmation for sensitive values.
- **Application/runtime mitigations:** Bind parameters, validate destinations, authorize resources, and avoid shells.
- **Current RenGuard Coverage Status:** CORE

## RG-TL-005 — Untrusted External Action or Exfiltration

- **Category Family:** Tools / Actions (`RG-TL`)
- **Definition:** The system sends data or causes side effects at an untrusted or unauthorized destination.
- **Typical attack sources:** Email, webhooks, HTTP requests, file sharing, publishing tools.
- **Detection signals:** Attacker-chosen recipients, destinations, payloads, or external effects.
- **Preconditions:** The agent has outbound capability without destination and data controls.
- **Security impact:** Data exfiltration, fraud, unauthorized communication, or persistent change.
- **Example attack pattern:** Retrieved content directs an agent to email private records externally.
- **Primary OWASP LLM 2026:** `LLM03:2026`
- **Secondary OWASP LLM 2026:** `LLM02:2026` when protected data is disclosed.
- **OWASP Agentic 2026:** Primary `ASI02`; secondary `ASI03` when privilege enables the action.
- **Commonly confused with:** `RG-HC-004` disclosure without an external action channel.
- **Boundary / non-example:** An approved action to an authenticated destination is not exfiltration.
- **Prompt-level mitigations:** Define allowed destinations and require approval for outbound actions.
- **Application/runtime mitigations:** Apply egress controls, recipient allowlists, DLP, and audit logging.
- **Current RenGuard Coverage Status:** CORE

## RG-ME-001 — Persistent Memory Poisoning

- **Category Family:** Memory / Context (`RG-ME`)
- **Definition:** Adversarial content is written to durable memory and influences future behavior.
- **Typical attack sources:** User memory, agent notes, profiles, long-term stores, summaries.
- **Detection signals:** Free-text policy or instructions persist across otherwise separate tasks.
- **Preconditions:** Untrusted content can write memory that later enters authoritative context.
- **Security impact:** Persistent goal hijack, repeated disclosure, or cross-user compromise.
- **Example attack pattern:** A document causes an agent to store a malicious standing instruction.
- **Primary OWASP LLM 2026:** `LLM05:2026`
- **Secondary OWASP LLM 2026:** `LLM01:2026` when poisoned memory acts as an injection.
- **OWASP Agentic 2026:** `ASI06`.
- **Commonly confused with:** `RG-ME-002` contamination propagated across session context.
- **Boundary / non-example:** A validated structured preference stored with user consent is not poisoning.
- **Prompt-level mitigations:** Restrict what may become memory and treat recalled text as untrusted.
- **Application/runtime mitigations:** Validate writes, scope memory, preserve provenance, expire, and audit.
- **Current RenGuard Coverage Status:** CORE

## RG-ME-002 — Cross-Session Context Poisoning

- **Category Family:** Memory / Context (`RG-ME`)
- **Definition:** Contaminated state from one session or principal influences another session improperly.
- **Typical attack sources:** Shared summaries, caches, conversation stores, reused scratchpads.
- **Detection signals:** Instructions or data appear outside their originating session or tenant.
- **Preconditions:** Session boundaries are weak or stored context is reused without authorization.
- **Security impact:** Cross-user manipulation, data leakage, or persistent policy corruption.
- **Example attack pattern:** One user's injected summary is loaded into another user's conversation.
- **Primary OWASP LLM 2026:** `LLM05:2026`
- **Secondary OWASP LLM 2026:** `LLM01:2026` when the carried state contains instructions.
- **OWASP Agentic 2026:** `ASI06`.
- **Commonly confused with:** `RG-HC-004` cross-tenant data disclosure.
- **Boundary / non-example:** Deliberately shared, authorized organizational context is not poisoning.
- **Prompt-level mitigations:** Treat recalled context as scoped data rather than controlling policy.
- **Application/runtime mitigations:** Enforce tenant/session isolation, provenance, validation, and deletion.
- **Current RenGuard Coverage Status:** CORE

## RG-AG-001 — Cross-Agent Instruction Injection

- **Category Family:** Agent / Multi-Agent (`RG-AG`)
- **Definition:** One agent or its attacker-controlled output injects instructions into another agent.
- **Typical attack sources:** Delegation results, agent messages, shared task boards, orchestrator relays.
- **Detection signals:** Peer output includes directives outside the agreed message contract.
- **Preconditions:** Receiving agents treat peer free text as trusted instructions.
- **Security impact:** Goal hijack, privilege chaining, exfiltration, or code execution.
- **Example attack pattern:** A sub-agent response orders the orchestrator to invoke an unrelated tool.
- **Primary OWASP LLM 2026:** `LLM01:2026`
- **Secondary OWASP LLM 2026:** `LLM03:2026` when privileges amplify the injection.
- **OWASP Agentic 2026:** Primary `ASI07`; secondary `ASI01` when agent goals are redirected.
- **Commonly confused with:** `RG-AG-002` the insecure trust boundary that enables it.
- **Boundary / non-example:** A schema-valid task result without directive semantics is not injection.
- **Prompt-level mitigations:** Declare peer output untrusted and constrain accepted message semantics.
- **Application/runtime mitigations:** Authenticate peers, validate schemas, authorize actions, and isolate agents.
- **Current RenGuard Coverage Status:** CORE

## RG-AG-002 — Insecure Inter-Agent Message Trust

- **Category Family:** Agent / Multi-Agent (`RG-AG`)
- **Definition:** An agent accepts peer identity, content, or authority without adequate authentication and validation.
- **Typical attack sources:** Agent buses, A2A protocols, queues, callbacks, shared memory.
- **Detection signals:** Unauthenticated senders, free-form messages, implicit transitive trust.
- **Preconditions:** Multiple agents communicate across an insufficiently controlled boundary.
- **Security impact:** Spoofing, message tampering, privilege confusion, or workflow compromise.
- **Example attack pattern:** A forged agent message is accepted as an approved deployment result.
- **Primary OWASP LLM 2026:** `LLM01:2026`
- **Secondary OWASP LLM 2026:** `LLM03:2026` when trusted messages authorize actions.
- **OWASP Agentic 2026:** `ASI07`.
- **Commonly confused with:** `RG-AG-001` the injected message content itself.
- **Boundary / non-example:** Authenticated, authorized, schema-validated messages are not inherently insecure.
- **Prompt-level mitigations:** State that peer claims do not grant authority.
- **Application/runtime mitigations:** Authenticate agents, sign messages, enforce schemas, and minimize trust.
- **Current RenGuard Coverage Status:** CORE

## RG-AG-003 — Cascading Agent Failure

- **Category Family:** Agent / Multi-Agent (`RG-AG`)
- **Definition:** An error, compromise, or unsafe decision propagates and amplifies through dependent agents or tools.
- **Typical attack sources:** Orchestrator chains, automatic retries, shared outputs, recursive delegation.
- **Detection signals:** Unbounded fan-out, unchecked pass-through, missing circuit breakers.
- **Preconditions:** Workflow components consume upstream decisions without independent validation.
- **Security impact:** Widespread corruption, repeated actions, availability loss, or systemic compromise.
- **Example attack pattern:** One poisoned result triggers harmful actions across every downstream agent.
- **Primary OWASP LLM 2026:** `LLM03:2026`
- **Secondary OWASP LLM 2026:** None by default.
- **OWASP Agentic 2026:** `ASI08`.
- **Commonly confused with:** `RG-AG-001` the initial injection mechanism.
- **Boundary / non-example:** A contained component failure stopped by validation is not cascading.
- **Prompt-level mitigations:** Require downstream verification and explicit halt conditions.
- **Application/runtime mitigations:** Add circuit breakers, idempotency, budgets, isolation, and rollback.
- **Current RenGuard Coverage Status:** CORE

## RG-AG-004 — Rogue or Compromised Agent Behavior

- **Category Family:** Agent / Multi-Agent (`RG-AG`)
- **Definition:** A malicious, compromised, or materially misaligned agent acts against the intended workflow.
- **Typical attack sources:** Compromised agents, malicious peers, tampered agent packages, insider control.
- **Detection signals:** Deception, unauthorized tasks, hidden coordination, or persistent policy divergence.
- **Preconditions:** The workflow admits or fails to contain an untrusted agent participant.
- **Security impact:** Sabotage, exfiltration, deception, or compromise of peer agents.
- **Example attack pattern:** A compromised specialist agent falsifies results and recruits peers into unsafe actions.
- **Primary OWASP LLM 2026:** `LLM03:2026`
- **Secondary OWASP LLM 2026:** `LLM04:2026` when compromise originates in the agent supply chain.
- **OWASP Agentic 2026:** `ASI10`.
- **Commonly confused with:** `RG-SC-001` compromise of the supplied component itself.
- **Boundary / non-example:** A bounded agent error without adversarial or persistent divergence is not rogue behavior.
- **Prompt-level mitigations:** Require agents to expose provenance and reject peer authority escalation.
- **Application/runtime mitigations:** Attest agents, monitor behavior, isolate peers, revoke identity, and contain actions.
- **Current RenGuard Coverage Status:** CORE

## RG-AG-005 — Human-Agent Trust Exploitation

- **Category Family:** Agent / Multi-Agent (`RG-AG`)
- **Definition:** An attacker or unsafe agent exploits human trust, urgency, authority cues, or approval fatigue to obtain acceptance of a harmful action or claim.
- **Typical attack sources:** Deceptive agent output, repeated approval requests, fabricated evidence, urgency framing.
- **Detection signals:** Consequential requests rely on trust in the agent rather than verifiable evidence or informed consent.
- **Preconditions:** A human reviewer can authorize or act on agent output without adequate verification.
- **Security impact:** Unsafe approval, fraud, hidden failure, policy bypass, or destructive action.
- **Example attack pattern:** An agent falsely labels a high-impact action as routine until a fatigued operator approves it.
- **Primary OWASP LLM 2026:** `LLM07:2026`
- **Secondary OWASP LLM 2026:** `LLM03:2026` when human approval enables excessive agent action.
- **OWASP Agentic 2026:** `ASI09`.
- **Commonly confused with:** `RG-MI-001`, which classifies the false or ungrounded information itself.
- **Boundary / non-example:** An informed approval based on accurate, independently verifiable evidence is not trust exploitation.
- **Prompt-level mitigations:** Require clear uncertainty, evidence, and non-coercive approval language.
- **Application/runtime mitigations:** Use independent verification, meaningful approvals, rate limits, and anti-fatigue workflows.
- **Current RenGuard Coverage Status:** CORE

## RG-RA-001 — Retrieval Poisoning

- **Category Family:** Retrieval / Vector / RAG (`RG-RA`)
- **Definition:** Adversarial content is inserted or modified in a retrieval corpus to corrupt future outputs.
- **Typical attack sources:** Knowledge-base ingestion, user uploads, crawlers, synchronized repositories.
- **Detection signals:** Untrusted corpus writes, anomalous chunks, provenance loss, coordinated content changes.
- **Preconditions:** Attackers can influence indexed data that later informs model behavior.
- **Security impact:** Persistent misinformation, injection delivery, or targeted retrieval manipulation.
- **Example attack pattern:** A poisoned policy document is indexed to redirect future support answers.
- **Primary OWASP LLM 2026:** `LLM05:2026`
- **Secondary OWASP LLM 2026:** `LLM01:2026` for embedded instructions; `LLM09:2026` for vector-layer weaknesses.
- **OWASP Agentic 2026:** `ASI06` when poisoned retrieval corrupts agent context.
- **Commonly confused with:** `RG-PI-003`, the execution of instructions in a retrieved document.
- **Boundary / non-example:** A stale but non-adversarial document is a quality issue, not necessarily poisoning.
- **Prompt-level mitigations:** Require provenance-aware treatment of retrieved content.
- **Application/runtime mitigations:** Control ingestion, sign sources, review changes, and monitor retrieval anomalies.
- **Current RenGuard Coverage Status:** CORE

## RG-RA-002 — Unauthorized Retrieval or Tenant Leakage

- **Category Family:** Retrieval / Vector / RAG (`RG-RA`)
- **Definition:** Retrieval returns records outside the principal's authorization or tenant boundary.
- **Typical attack sources:** Vector queries, metadata filters, hybrid search, shared indexes.
- **Detection signals:** Post-retrieval authorization, missing tenant filters, global similarity search.
- **Preconditions:** Authorization is absent, late, or disconnected from retrieval identity.
- **Security impact:** Cross-tenant disclosure, privacy breach, or unauthorized intelligence access.
- **Example attack pattern:** Similarity search returns another customer's private support transcript.
- **Primary OWASP LLM 2026:** `LLM09:2026`
- **Secondary OWASP LLM 2026:** `LLM02:2026` for the resulting disclosure.
- **OWASP Agentic 2026:** `ASI03` when agent identity or privilege drives access.
- **Commonly confused with:** `RG-HC-004`, which describes the disclosure result.
- **Boundary / non-example:** Retrieval scoped and authorized before content reaches the model is not leakage.
- **Prompt-level mitigations:** Request only data authorized for the current principal.
- **Application/runtime mitigations:** Authorize before retrieval and enforce tenant-isolated indexes and filters.
- **Current RenGuard Coverage Status:** CORE

## RG-RA-003 — Vector or Embedding Manipulation

- **Category Family:** Retrieval / Vector / RAG (`RG-RA`)
- **Definition:** An attacker manipulates embeddings, vector indexes, or similarity behavior to alter retrieval or reconstruct data.
- **Typical attack sources:** Malicious embeddings, index writes, inversion attacks, crafted nearest neighbors.
- **Detection signals:** Untrusted vector imports, unexplained similarity shifts, exposed embedding exports.
- **Preconditions:** Vector artifacts lack integrity, confidentiality, or lifecycle controls.
- **Security impact:** Retrieval steering, source reconstruction, leakage, or poisoned decisions.
- **Example attack pattern:** Crafted vectors consistently outrank trusted policy content for targeted queries.
- **Primary OWASP LLM 2026:** `LLM09:2026`
- **Secondary OWASP LLM 2026:** `LLM05:2026` when the index is poisoned.
- **OWASP Agentic 2026:** `ASI06` when manipulated vectors poison agent context.
- **Commonly confused with:** `RG-RA-001` content-level retrieval poisoning.
- **Boundary / non-example:** Normal approximate-nearest-neighbor variance is not manipulation by itself.
- **Prompt-level mitigations:** No reliable prompt-only control; flag the architecture for specialized review.
- **Application/runtime mitigations:** Protect vector integrity, access, provenance, isolation, and monitoring.
- **Current RenGuard Coverage Status:** PARTIAL

## RG-SC-001 — AI Component or Tool Supply-Chain Compromise

- **Category Family:** Supply Chain (`RG-SC`)
- **Definition:** A compromised or malicious model, tool, package, registry, dataset, or service enters the AI system.
- **Typical attack sources:** Dependencies, model hubs, plugins, MCP servers, tool registries, build pipelines.
- **Detection signals:** Unpinned components, weak provenance, unsigned artifacts, unexpected capability changes.
- **Preconditions:** External components are trusted without sufficient verification and lifecycle control.
- **Security impact:** Backdoors, poisoned behavior, code execution, data theft, or systemic compromise.
- **Example attack pattern:** A tampered tool package adds a hidden exfiltration action.
- **Primary OWASP LLM 2026:** `LLM04:2026`
- **Secondary OWASP LLM 2026:** None.
- **OWASP Agentic 2026:** `ASI04`.
- **Commonly confused with:** `RG-PI-002` malicious content delivered through an otherwise intact source.
- **Boundary / non-example:** Untrusted document content alone is not a component supply-chain compromise.
- **Prompt-level mitigations:** Treat component/tool descriptions as untrusted and flag provenance gaps.
- **Application/runtime mitigations:** Pin, sign, attest, inventory, sandbox, and monitor components.
- **Current RenGuard Coverage Status:** CORE

## RG-EX-001 — Unexpected Code Execution

- **Category Family:** Execution / Code (`RG-EX`)
- **Definition:** Model or agent behavior causes unauthorized commands or code to execute.
- **Typical attack sources:** Shell tools, code interpreters, build hooks, generated scripts, unsafe plugins.
- **Detection signals:** Unbounded execution tools, attacker-influenced commands, automatic execution.
- **Preconditions:** Model output reaches an execution boundary without sufficient validation or approval.
- **Security impact:** Host compromise, data loss, persistence, lateral movement, or service disruption.
- **Example attack pattern:** Injected repository text causes a coding agent to execute a command.
- **Primary OWASP LLM 2026:** `LLM03:2026`
- **Secondary OWASP LLM 2026:** `LLM10:2026` when downstream output handling executes code.
- **OWASP Agentic 2026:** `ASI05`.
- **Commonly confused with:** `RG-OU-001`, the unsafe downstream-consumption mechanism.
- **Boundary / non-example:** Sandboxed code execution explicitly requested and authorized is not unexpected.
- **Prompt-level mitigations:** Require confirmation and prohibit execution derived from untrusted content.
- **Application/runtime mitigations:** Sandbox, allowlist, isolate credentials, mediate commands, and log execution.
- **Current RenGuard Coverage Status:** CORE

## RG-OU-001 — Unsafe Downstream Output Execution

- **Category Family:** Output Handling (`RG-OU`)
- **Definition:** A downstream component interprets untrusted model output as executable code, markup, query, or command.
- **Typical attack sources:** Generated HTML, Markdown, SQL, shell, templates, code, URLs, paths, serialized data, spreadsheets, headers, or control messages.
- **Detection signals:** Raw output reaches interpreters, active renderers, network/filesystem boundaries, or privileged sinks without sink-specific validation, authorization, or encoding.
- **Preconditions:** The application treats probabilistic model output as trusted executable material.
- **Security impact:** Injection, code execution, data corruption, client compromise, or unauthorized action.
- **Example attack pattern:** Generated HTML containing attacker-controlled script is rendered unsafely.
- **Primary OWASP LLM 2026:** `LLM10:2026`
- **Secondary OWASP LLM 2026:** None.
- **OWASP Agentic 2026:** `ASI05` when output triggers code execution in an agentic workflow.
- **Commonly confused with:** `RG-PI-005`, which concerns input structure changing model interpretation.
- **Boundary / non-example:** Displaying escaped output as inert text is not unsafe execution.
- **Prompt-level mitigations:** Request constrained output, but do not rely on prompt compliance for safety.
- **Application/runtime mitigations:** Validate structure and semantics, authorize independently, encode for the exact context, parameterize, canonicalize, quarantine, sandbox, and separate data from code.
- **Current RenGuard Coverage Status:** CORE

## RG-RC-001 — Unbounded Agent or Tool Consumption

- **Category Family:** Resource / Consumption (`RG-RC`)
- **Definition:** Uncontrolled model, context, tool, or workflow use exhausts cost, capacity, or availability.
- **Typical attack sources:** Recursive tasks, retry loops, oversized inputs, fan-out, expensive tools.
- **Detection signals:** Missing budgets, depth limits, rate limits, timeouts, or circuit breakers.
- **Preconditions:** Attackers or failures can trigger unbounded resource use.
- **Security impact:** Denial of service, financial loss, queue starvation, or cascading failure.
- **Example attack pattern:** An agent recursively delegates a task without a depth or cost limit.
- **Primary OWASP LLM 2026:** `LLM06:2026`
- **Secondary OWASP LLM 2026:** None.
- **OWASP Agentic 2026:** `ASI08` when consumption cascades through agents or tools.
- **Commonly confused with:** `RG-PI-010` context flooding used to degrade instruction control.
- **Boundary / non-example:** A large authorized workload inside enforced budgets is not unbounded.
- **Prompt-level mitigations:** Define iteration, retry, and delegation limits.
- **Application/runtime mitigations:** Enforce quotas, budgets, timeouts, depth limits, and circuit breakers.
- **Current RenGuard Coverage Status:** CORE

## RG-MI-001 — Security-Relevant Misinformation

- **Category Family:** Misinformation / Grounding (`RG-MI`)
- **Definition:** False or ungrounded output is trusted in a way that creates security, safety, legal, or operational harm.
- **Typical attack sources:** Hallucination, poisoned sources, missing grounding, deceptive agent output.
- **Detection signals:** Unsupported claims drive consequential decisions without verification.
- **Preconditions:** Users or systems rely on generated claims as authoritative evidence.
- **Security impact:** Unsafe decisions, fraud, misconfiguration, approval manipulation, or hidden failure.
- **Example attack pattern:** An agent falsely reports that a destructive migration passed all checks.
- **Primary OWASP LLM 2026:** `LLM07:2026`
- **Secondary OWASP LLM 2026:** None.
- **OWASP Agentic 2026:** `ASI09` when misinformation exploits human trust or oversight.
- **Commonly confused with:** Goal hijacking, which changes objectives rather than factual grounding.
- **Boundary / non-example:** A harmless factual error with no meaningful security consequence is outside this technique.
- **Prompt-level mitigations:** Require citations, uncertainty disclosure, and verification before consequential claims.
- **Application/runtime mitigations:** Ground outputs, verify evidence, require review, and monitor decision quality.
- **Current RenGuard Coverage Status:** PARTIAL

## RG-MM-001 — Multimodal Instruction Injection

- **Category Family:** Multimodal (`RG-MM`)
- **Definition:** Instructions embedded in images, audio, video, or mixed media manipulate model behavior.
- **Typical attack sources:** Image text, visual overlays, audio speech, metadata, cross-modal content.
- **Detection signals:** Visible or derived media content contains conflicting directives or security-sensitive parameter changes.
- **Preconditions:** Multimodal content is converted into instruction-capable context.
- **Security impact:** Goal hijack, hidden actions, disclosure, or filter evasion.
- **Example attack pattern:** Text concealed in an image directs an agent to upload private data.
- **Primary OWASP LLM 2026:** `LLM01:2026`
- **Secondary OWASP LLM 2026:** None.
- **OWASP Agentic 2026:** `ASI01` when media redirects an agentic plan.
- **Commonly confused with:** `RG-PI-007` character-level concealment in text.
- **Boundary / non-example:** Benign media content relevant to the user's task is not injection.
- **Prompt-level mitigations:** Treat extracted media instructions as untrusted content.
- **Application/runtime mitigations:** Preserve source/transformation provenance, separate identity and authority, validate derived parameters, and independently authorize resulting actions.
- **Current RenGuard Coverage Status:** PARTIAL
