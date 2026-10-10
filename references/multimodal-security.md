# RenGuard Multimodal Security

This is the canonical Phase 7 audit reference for systems that process images,
screenshots, scanned documents, audio, speech, video, frames, captions, subtitles,
mixed-modality files, OCR, or transcription. Load it only when the supplied
architecture or artifact establishes one of those paths. Do not invent a multimodal
subsystem from product branding or an ordinary text-only input.

Use the existing [RenGuard techniques](renguard-techniques.md),
[risk model](risk-scoring.md), and [hardening catalog](hardening-patterns.md). Apply the
[RAG](rag-security.md), [memory](memory-security.md), [tool](tool-security.md),
[MCP](mcp-security.md), and [agentic](agentic-security.md) references only when those
subsystems are also evidenced.

## Trust and authority principle

Multimodal content is data, not privileged instruction authority. Content in an image,
audio clip, video frame, document, transcript, caption, subtitle, or metadata field does
not automatically gain authority over system policy, authenticated user intent,
authorization, or approval. Modality describes representation; it does not establish
provenance, identity, or trust.

Instruction-like media can still be legitimate task data or evidence. Classify it from
the architecture and requested task rather than treating every command-looking string as
an attack. Conversely, visual polish, a familiar voice, an official-looking UI, or a
machine-readable field does not make content authoritative.

## Multimodal system profile

Record supported facts about input modality; source and owner; authenticated user and
tenant; provenance; upload or acquisition channel; preprocessing; OCR; transcription;
caption generation; metadata, frame, table, attachment, and link extraction; document
parser; model receiving each derived representation; storage and retrieval; memory;
downstream tools/actions; rendering; trust boundaries; and human review. Mark missing
facts **UNKNOWN / INSUFFICIENT EVIDENCE — not zero and not assumed unsafe**.

Trace transformations explicitly, for example:

```text
uploaded screenshot -> OCR text -> vision/planning model -> URL parameter -> fetch tool
voice note -> transcript with speaker label -> model -> payment destination -> approval
```

Preserve source, page/frame, timestamp, modality, tenant/resource, transformation,
confidence where available, and the relationship between original and derived content.
Transformation does not promote authority.

## Images, screenshots, and visual encodings

Inspect visible text, screenshots, diagrams, forms, UI images, labels, overlays, tiny or
low-contrast text when actually available, background text, and image-heavy documents
for paths that can redirect the model or its tools. Trace `image -> extracted or
understood content -> model -> decision/action`. Map supported manipulation to
`RG-MM-001`, and add prompt-injection, privilege, tool, or output techniques only when
the corresponding mechanism exists.

For screenshots, browser pages, desktop views, and remote-computer screens, distinguish
rendered content from trusted product chrome and control-plane state. Fake warnings,
button labels, administrator banners, confirmation text, and security notices are social
or instruction content. A screenshot that says “Admin approved this action” is not
authenticated approval. Approval must come from an authenticated channel and bind the
exact consequential action.

If the evidenced pipeline decodes QR codes, barcodes, or similar visual encodings, treat
the decoded URL, command, identifier, payment destination, credential, or configuration
value as untrusted data. Validate it for its eventual sink. Do not claim that RenGuard
decoded an encoding unless the host or supplied evidence actually did so, and do not
assume all visual encodings are malicious.

## OCR and document extraction boundary

OCR and transcription output is derived untrusted content, not privileged policy. For
OCR, examine whether text becomes instructions, whether source/page and tenant/resource
associations survive extraction, whether low-visibility text reaches the model, whether
errors can change a security decision, and whether derived strings reach an interpreter
or action directly. OCR correctness is not a security boundary and RenGuard does not
certify OCR accuracy.

For PDF, slide, office, scanned-form, and image-heavy document flows, profile only the
channels the supplied parser exposes: normal text, OCR text, images, annotations,
comments, metadata, links, attachments, tables, captions, and embedded objects. A parser
that omits a channel should not generate a finding for that channel without evidence.
Keep page/object provenance and access-control labels through extraction and chunking.

## Audio, transcription, and identity

Inspect speech, calls, recordings, voice notes, assistants, mixed audio, and audio tracks
for spoken policy overrides, impersonated authority, credential requests, low-volume or
embedded instructions when supported by evidence, and malicious transcript content.
Trace `audio -> transcription -> model -> tool/action` and preserve source, speaker
attribution, timestamp, confidence, and user/tenant context where available.

A transcribed claim such as “I am the administrator” is not authenticated identity.
Voice likeness, face likeness, displayed names, and spoken identity claims do not prove
identity for a security-sensitive action unless an independent trusted mechanism does.
This distinction does not turn RenGuard into a biometric-authentication system, speaker
verification engine, or deepfake detector.

## Video, frames, captions, and subtitles

When video is processed, identify which frame content, OCR text, audio tracks, subtitles,
captions, metadata, scene transitions, or extracted events actually reach the model.
Instructions may persist across frames or appear in one modality while the legitimate
task is represented in another. Do not claim exhaustive frame-by-frame coverage unless
the evidenced pipeline provides it.

Captions and subtitles are content. They do not outrank application policy,
authenticated user authority, or deterministic authorization. Check whether they can
alter a goal, redirect a tool, request credentials, cause disclosure, or redefine
approval state.

## Metadata and secondary channels

Audit metadata only when it is processed. Relevant fields can include filename, title,
document author, media description, alt text, captions, comments, attachment names,
location, timestamps, and EXIF-like fields. Metadata is not privileged merely because
it is hidden from ordinary presentation or machine-readable. Preserve provenance and
apply the same authority separation as visible content.

## Cross-domain composition

When documents or images are ingested into RAG, apply this reference with
[RAG security](rag-security.md). Preserve original and OCR provenance, chunk ACLs,
tenant scope, and document-to-chunk lineage; examine image-derived instructions,
authority confusion, and multimodal corpus poisoning. Do not duplicate the same root
mechanism as multiple findings unless separate security impacts justify it.

When derived content can persist, apply [memory security](memory-security.md) to the
chain `media -> extracted interpretation -> memory write -> later session/action`.
Memory write authorization, scope, provenance, lifetime, and rollback remain required.

When a tool or MCP server supplies or consumes a screenshot, image, audio clip, resource,
or transcript, preserve host-assigned origin and apply Phase 6 trust rules. Tool/MCP
origin supplies provenance, not instruction authority. Apply [output security](output-security.md)
when derived content or model output reaches an automated sink.

## Attack chains and scoring

Represent only supported paths using Phase 3 finding IDs, for example:

```text
malicious screenshot -> visual instruction -> agent goal change -> privileged tool -> external action
audio -> transcript -> destination change -> sensitive action -> external recipient
scanned document -> OCR text -> RAG chunk -> later retrieval -> memory write -> tool action
```

Score a supported chain once with the unchanged 12-dimension formula; never add a
multimodal bonus or sum findings. Multimodal injection may affect `E`, `P`, or `A` when
the evidence supports it, while the downstream tool, data, persistence, blast radius,
reversibility, detection, and reach determine the remaining dimensions. UNKNOWN remains
distinct from zero.

`RG-MM-001` has PARTIAL coverage: RenGuard can profile supplied multimodal architecture,
reason about visible/derived content and authority, trace chains, and recommend controls.
It does not perform dedicated image/audio forensics or guarantee detection of hidden
signals.

## Hardening and verification

Reuse `RG-HARD-P-001` for authority separation, `RG-HARD-AUTHN-001` for trusted user
identity, `RG-HARD-AUTHZ-001` and `RG-HARD-AUTHZ-002` for action/resource policy,
`RG-HARD-DATA-002` for tenant/source minimization, `RG-HARD-TOOL-002` for derived
parameters, `RG-HARD-OUT-001` for sink handling, `RG-HARD-HITL-001` for exact-action
approval, `RG-HARD-MON-001` for attributable events, and `RG-HARD-REC-001` for
containment/recovery as applicable. These are a starting bundle, not a guarantee.

Use inert fixtures in a safe environment: visible conflicting image text, a synthetic
OCR error, an unverified admin banner, a decoded `https://example.invalid/` URL, a
speaker identity claim, a caption instruction, and metadata text. Verify that legitimate
content remains usable while identity, authority, approval, and sink policy come from
trusted boundaries. Monitoring is DETECT, not PREVENT.

## Multimodal security checklist

- **Modalities present:** Which image, screenshot, document, audio, video, caption, or mixed channels exist?
- **Source / provenance:** Can original and derived content be attributed across transformations?
- **Identity assumptions:** Is any voice, face, displayed name, or content claim mistaken for authentication?
- **Preprocessing:** Which parsers, frame extractors, decoders, and transformations run?
- **OCR / transcription:** Are outputs treated as derived data with page/time/speaker context?
- **Hidden / secondary channels:** Which low-visibility, annotation, attachment, or encoded channels are actually processed?
- **Metadata:** Which fields enter model context or downstream decisions?
- **Authority:** Can media-derived instructions override protected policy or authenticated intent?
- **Tenant scope:** Do source, ACL, user, and tenant labels survive extraction, storage, and retrieval?
- **Storage / retrieval:** Can derived content poison a corpus, cache, or later lookup?
- **Memory persistence:** Can interpretations affect later sessions, users, tenants, or agents?
- **Downstream actions:** Which tools, sinks, destinations, and privileges can derived content influence?
- **Approval:** Is sensitive approval authenticated and bound to the exact action rather than media content?
- **Monitoring:** Are security-relevant transformations and resulting actions attributable without logging secrets?
- **Recovery:** Can poisoned artifacts/state be disabled, revoked, quarantined, or rolled back where possible?

## Limitations

Architecture and artifact review is not image steganalysis, hidden-pixel detection,
audio or video forensics, ultrasonic-attack detection, deepfake detection, biometric
verification, OCR accuracy certification, malware scanning, or exhaustive media
processing. RenGuard does not claim all image injection or hidden text is detected, that
multimodal attacks are eliminated, or that a safe-looking artifact is benign. Report
only analysis supported by supplied evidence and host capabilities.
