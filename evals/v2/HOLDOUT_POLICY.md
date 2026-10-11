# Private Holdout Policy

A public Git repository cannot contain a genuinely hidden holdout. This directory
therefore contains policy only—no private scenario content and no file presented as
secret.

Future private evaluation should:

- store holdout cases outside the public repository with access limited to evaluation
  operators;
- keep cases unavailable to the system under evaluation before scoring;
- use the same scenario field contract and stable assertion semantics as the public
  suite;
- include both attack cases and clean/boundary controls across every major domain;
- use novel wording, architectures, and cross-component combinations rather than simple
  copies of public cases;
- include safe mutation variants, multilingual content, and multi-turn cases;
- use only synthetic secrets, inert payloads, and non-routable example destinations;
- preserve a versioned audit trail without exposing case content in public results; and
- rotate or replenish cases when evidence suggests benchmark gaming or contamination.

Aggregate target distributions and field-contract revisions may be public. Actual case
content, expected answers, and pre-scoring model outputs must remain outside Git. A
future Phase 9 runner may accept the same contract from an authorized private source,
but Phase 8 does not implement that runner or any private storage mechanism.
