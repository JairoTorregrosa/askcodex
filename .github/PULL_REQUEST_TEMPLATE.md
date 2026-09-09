<!--
Evidence package. See GOVERNANCE.md and agm.json.
Zone low: delete everything below and describe your change.
Delete the sections your zone does not require.
Redact every transcript you paste: no token values, no account_id, no
user_id, no email. Use acct_REDACTED / user_REDACTED / email_REDACTED.
-->

Risk zone: <!-- low | medium | high | critical -->

Provenance: <!-- tool and model, when an agent produced any part of this change -->

## Summary

<!-- What changes and why. -->

## Checks

<!-- State that fmt --check, clippy -D warnings, and test pass locally. -->

## Behavior evidence

<!-- Before/after command transcript (redacted), a new test, or equivalent
proof. -->

## External assumptions

<!-- Each belief about data askcodex does not control — the auth.json schema,
backend response shapes, OAuth refresh behavior, SSE event stream — and how
each was verified against real (redacted) calls. Declare what you could not
verify. -->

## Risk

<!-- What breaks if this is wrong, and the rollback. -->

## Second review

<!-- Adversarial pass by a second agent or human: findings, resolution. -->

## Merge authorization

<!-- Name the maintainer authorizing delivery and describe any delegation to
implement/merge. State whether independent human code review occurred; do not
conflate delegated execution or an agent's second review with human review.
GitHub permissions and configured review rules govern the actual merge. -->

Authorization: <granted only when explicitly authorized>
Maintainer: @<github-login>
Scope: <concrete delegated scope>

<!-- These self-declared fields do not authenticate identity or permission.
Use exactly one of each field; duplicates/conflicts fail the gate. -->
