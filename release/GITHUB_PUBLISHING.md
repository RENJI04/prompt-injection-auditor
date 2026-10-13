# GitHub publication guide

This runbook prepares GitHub presentation for RenGuard v2.0.0. It does not authorize or
record a push, tag, repository rename, Social Preview configuration, or GitHub release.

## Repository identity

- Current repository: `RENJI04/prompt-injection-auditor`
- Product: **RenGuard**
- Release target: **v2.0.0**
- Current state: **locally validated release candidate; not publicly released**

## Recommended GitHub About description

> Model-agnostic security auditing framework for AI systems, LLM applications, and
> autonomous agents.

## Recommended GitHub topics

`ai-security`, `llm-security`, `agent-security`, `prompt-injection`, `rag-security`,
`mcp`, `ai-agents`, `security`, `security-audit`, `owasp`

## Social Preview

Use [`assets/branding/renguard-social-preview.png`](../assets/branding/renguard-social-preview.png).

Status: **PENDING — manual GitHub repository configuration required.** Committing the
asset does not configure the repository setting. After the final release-candidate
commit is pushed, an authorized repository owner must select this file in the GitHub
Social Preview settings and verify the rendered crop.

## Release presentation

- Release title: **RenGuard v2.0.0**
- Release tag: `v2.0.0`
- Release notes source: [`RELEASE_NOTES.md`](../RELEASE_NOTES.md)

The release body must remain understandable without embedded images. Do not add a CI,
performance, certification, or release badge until the underlying external event has
actually occurred.

## Publication prerequisites

- [ ] Final branded release-candidate commit approved
- [ ] Release-candidate commit pushed to GitHub
- [ ] GitHub-hosted Python 3.10–3.13 matrix passes
- [ ] Final pushed diff and checks reviewed
- [ ] Claims, links, provenance, and secret scan reconfirmed
- [ ] `v2.0.0` tag explicitly approved
- [ ] GitHub Release explicitly approved

## Optional repository rename

A future rename from `prompt-injection-auditor` to `renguard` is optional and is not
technically required for v2.0.0. Before any rename, check name availability, obtain
explicit owner approval, and review links, integrations, automation, and downstream
references. This guide does not claim that a rename has occurred.
