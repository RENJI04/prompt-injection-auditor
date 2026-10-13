# GitHub publication guide

This runbook records completed release-source prerequisites and prepares GitHub
presentation for RenGuard v2.0.0. Remaining settings and publication actions require
separate approval.

## Repository identity

- Current repository: `RENJI04/prompt-injection-auditor`
- Product: **RenGuard**
- Release target: **v2.0.0**
- Current state: **validated release candidate on main; not publicly released**
- Validated main source: `d8ec26b9b19f79f9a134f838ba2f4b3d34211963`

## Recommended GitHub About description

> Model-agnostic security auditing framework for AI systems, LLM applications, and
> autonomous agents.

Application status: **PENDING**. The current GitHub About metadata may still describe
the historical project; it is not the current product specification.

## Recommended GitHub topics

`ai-security`, `llm-security`, `agent-security`, `prompt-injection`, `rag-security`,
`mcp`, `ai-agents`, `security`, `security-audit`, `owasp`

Application status: **PENDING**.

## Social Preview

Use [`assets/branding/renguard-social-preview.png`](../assets/branding/renguard-social-preview.png).

Status: **PENDING — manual GitHub repository configuration required.** Committing the
asset does not configure the repository setting. An authorized repository owner must
select this file in the GitHub
Social Preview settings and verify the rendered crop.

## Release presentation

- Release title: **RenGuard v2.0.0**
- Release tag: `v2.0.0`
- Release notes source: [`RELEASE_NOTES.md`](../RELEASE_NOTES.md)

The release body must remain understandable without embedded images. Do not add a CI,
performance, certification, or release badge until the underlying external event has
actually occurred.

## Publication prerequisites

- [x] Final branded release-candidate commit approved
- [x] Release-candidate pushed to GitHub
- [x] GitHub-hosted Python 3.10–3.13 matrix passes
- [x] Release PR merged to main
- [x] Main Python 3.10–3.13 matrix passes
- [ ] GitHub About description applied
- [ ] Repository topics applied
- [ ] Social Preview configured and crop verified
- [ ] Final metadata change reviewed/merged
- [ ] `v2.0.0` tag explicitly approved
- [ ] GitHub Release explicitly approved

Observed CI evidence: [RC push 38337787172](https://github.com/RENJI04/prompt-injection-auditor/actions/runs/38337787172),
[release PR 38338406336](https://github.com/RENJI04/prompt-injection-auditor/actions/runs/38338406336),
and [main merge 38338862797](https://github.com/RENJI04/prompt-injection-auditor/actions/runs/38338862797)
all passed. The metadata preparation remains a follow-up review step.

## Optional repository rename

A future rename from `prompt-injection-auditor` to `renguard` is optional and is not
technically required for v2.0.0. Before any rename, check name availability, obtain
explicit owner approval, and review links, integrations, automation, and downstream
references. This guide does not claim that a rename has occurred.
