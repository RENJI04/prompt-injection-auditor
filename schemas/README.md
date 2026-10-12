# RenGuard JSON contracts

These files are the machine-readable structural contracts for the RenGuard v2 public
evaluation suite and Phase 9 benchmark artifacts. They use JSON Schema Draft 2020-12
and stable repository-owned URN identifiers. `versions.json` is the canonical registry
for schema identities and versions; schema versions are independent from the RenGuard
product, public suite, runner, scoring, and benchmark artifact versions.

The repository remains dependency-free. `scripts/schema_tools.py` validates the schema
documents, local references, version registry, canonical corpus, and benchmark artifacts
using only the documented keyword subset used by these files. It is deliberately **not**
a complete general-purpose Draft 2020-12 engine. `scripts/validate_repo.py` remains
normative for cross-file relationships, exact risk arithmetic, taxonomy mappings,
provenance, and other semantic or security invariants. Structural schema validity never
implies that an artifact is secure, authorized, or semantically correct.

## Registry and compatibility

All current schemas are version `1.0.0`. Version changes follow semantic versioning:

- PATCH clarifies or corrects constraints without invalidating existing valid artifacts.
- MINOR adds backward-compatible optional fields or extensions.
- MAJOR changes the contract incompatibly and requires explicit migration.

For pre-1.0 serialized benchmark artifacts, only versions explicitly listed by the
registry are supported. Unknown majors and unknown `0.x` versions fail closed instead
of being silently interpreted. Response and score JSONL records inherit the artifact
contract version from their containing `run-manifest.json`; they are not standalone
versioned envelopes.

Core stored records use `additionalProperties: false` so typos and accidental contract
drift fail visibly. Extensible maps—model parameters, filters, assertion details,
breakdowns, and architecture-specific facts—remain open deliberately.

## Offline reference policy

`$ref` values may point only to repository-local JSON schema files and JSON Pointer
fragments beneath `schemas/`. Absolute paths, URI schemes, path traversal, and network
fetches are rejected. The Draft dialect URI in `$schema` identifies the standard; the
validator does not dereference it.

## Validation

From the repository root:

```sh
python scripts/schema_tools.py check-repository
python scripts/schema_tools.py validate-run benchmark-runs/<run-id>
python scripts/check.py
```

The schemas cover individual public scenarios, the suite manifest, mutation recipes,
run manifests, response records, score records, summaries, human-review records, and
user-supplied pricing configuration. They do not schema-encode the Phase 3 scoring
formula or duplicate the repository's complete semantic validator.
