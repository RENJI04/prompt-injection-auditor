# Security policy

## Scope

Security reports about this repository may include unsafe benchmark execution, command
or path injection in tooling, credential exposure, schema-reference network access,
provenance bypass, or weaknesses in the RenGuard auditing instructions. A finding that
RenGuard reports in a separately audited system belongs to that system's owner and is
not automatically a vulnerability in this repository.

## Reporting

If this repository's GitHub **Security** tab offers private vulnerability reporting,
use that channel. No dedicated security email or guaranteed response-time commitment is
currently documented. If no private channel is available, open a minimal public issue
requesting a private contact path without including exploit details, credentials, or
sensitive user data.

Never publish real secrets to demonstrate a report. Use synthetic placeholders and
reserved domains. Benchmark fixtures in this repository are intentionally synthetic and
must not contain malware, destructive production commands, live exfiltration endpoints,
or real credential material.

## Validation boundary

Passing repository validation, schemas, or fixture benchmarks does not prove complete
protection, authorization correctness, or production security. Standard CI is offline
with respect to models and does not execute live tools, providers, or exploit sinks.
