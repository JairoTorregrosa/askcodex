# Refactor acceptance matrix

Baseline: commit `6ed721d`. This document specifies acceptance, not a claim that
the migration has passed. The release evidence must record the final commit,
commands run, outcomes, omitted checks, and any remaining compatibility changes.

## Product and regression gates

| Area | Required behavior | Independent evidence |
| --- | --- | --- |
| Command surface | Preserve `whoami`, `usage`, `models`, `transcribe`, `ask`, both image operations, `raw`, both auth operations and their existing flags | `tests/migration.rs` invokes every leaf's help and legacy arguments on the shipped binary; existing parser tests cover values/defaults |
| Machine output | Versioned final JSON; stable error code; exactly one document; no human prose mixed into machine payload | Black-box auth success and local-error tests, plus endpoint result tests |
| Events | NDJSON deltas and final result; structured failures on stderr; mutually exclusive output modes; incomplete stream fails | Black-box output-mode tests and injected SSE lifecycle tests |
| Raw | Preserve backend JSON and raw SSE wire escape hatch; no wrapper around raw payload | Existing raw dispatcher/mock tests; compare baseline examples |
| Input preparation | Missing/malformed WAV, references, JSON, unreadable stdin, invalid image output fail before credentials are loaded or refreshed | Migration tests use deliberately malformed auth as a competing failure; the local error must win |
| Credential reads | Status is read-only; errors never repair malformed auth; unknown keys survive writes | Migration byte comparisons and private auth safety tests |
| Refresh | Serialize cooperating askcodex refreshes; adopt a newer usable refresh token; preserve working credentials after failure | Sequential stale-snapshot adoption and refresh-failure tests; real subprocess lock exclusion and release after process death (not simultaneous HTTP refresh trials) |
| Persistence | Same-directory atomic replacement, 0600 before data, backups, symlink policy, failure leaves complete old/new document | Auth safety suite moved from `tests/auth_safety.rs` to private `src/auth/safety_tests.rs`, plus store tests |
| Secret boundary | No general runtime secret serialization; no secret in stdout/stderr; credentials only attached by transport | Type/API review and black-box synthetic sentinel sweep |
| Transport | Validated trusted origin, no redirects, no alternate credential origin, bounded retry | Existing HTTP/mock tests and shipped-binary hostile-origin tests |
| Ask | Deltas preserved, terminal completion required, cancellation/broken pipe fail without panic | SSE parser and dispatcher tests; independent fallible-sink tests and actual consumer early-stop test |
| Images | Read references before refresh; output checked before generation; invalid payload never replaces existing file | Migration ordering tests and image artifact tests |
| Transcribe | WAV structure and bounded input checked before refresh; absent text rejected; empty text valid | Migration ordering tests and existing transcription fixtures |
| Installer | Binary install without login; auth check and skill installs explicit; backups and modes preserved | Isolated fake HOME installer tests, shellcheck, shfmt, Bats |
| Live verification | Live tests visibly ignored by default and never access real credentials in CI | Default cargo test ignored count; explicit isolated opt-in report |
| Documentation | One command reference, documented machine schema/migration, dated backend evidence separate from product contract | Review README, DESIGN, PROTOCOL, TESTING, skills and generated help for agreement |
| Production | PR review findings resolved; required CI green; merged main builds; installed binary matches merged release | PR/check URLs, merge SHA, clean local main, installed binary comparison and offline help/status checks |

## Execution and evidence rules

Run `cargo test --test migration` first as the independently owned migration
gate. Run the full offline suite, `cargo clippy --all-targets -- -D warnings`,
`cargo fmt --check`, and installer checks before merge. Queue longer commands
through the local job runner. A failure or a skipped live test must not be
reported as successful live compatibility verification.

Migration tests isolate HOME and CODEX_HOME in temporary directories, clear
inherited environment, install dead proxies, and use only synthetic credentials.
They exercise the actual binary rather than importing private implementation
types. An intentionally malformed auth document proves failure ordering without
needing any network request or refresh. It must remain byte-identical afterwards.

The baseline binary is archived outside the repo at
`/tmp/askcodex/refactor-20260908/baseline-askcodex`. Set
`ASKCODEX_MIGRATION_BASELINE` to that path to run optional command/help parity.
The optional baseline test is explicitly ignored otherwise; absence is visible.
Exact human wording, internal module names and elapsed expiry countdowns are not
compatibility contracts. New versioned output intentionally supersedes the old
unversioned JSON; callers must use the documented migration mapping.

## Command reference acceptance

`askcodex reference` is a local operation. It must succeed with no credentials,
with malformed credentials, and without network access. Its inventory comes
from the same Clap command definition used by parsing and help. It must include
every command path and public option, including global `--json`, `--events` and
`--no-refresh`, nested image/auth operations, and its own invocation. Default
output is Markdown suitable for committing as the canonical command reference.

The independent verifier searches generated output for the preserved leaf
paths and representative legacy flags. Review must additionally confirm that
the generator walks Clap metadata rather than maintaining a second hard-coded
list. If the repo commits generated output, CI should compare a fresh generation
with that file; it must not update it silently. README and installed skills
should link to this reference and explain workflows, rather than duplicate a
full command/flag inventory. Backend protocol evidence remains dated and
separate; a generated product reference cannot verify server behavior.

## Stream verification obligations

The mock-backed dispatcher suite must prove `ask --events` emits text deltas in
order and exactly one final result only after a terminal success event. Empty
completed responses are distinct from streams that terminate before completion.
A failure after one or more deltas must leave those valid event lines intact,
emit a structured error on stderr, and exit nonzero without any result event.
Unknown SSE events must not fabricate completion. `raw --stream` remains a
verbatim wire stream; `raw --events` must fail locally. Closed stdout and read
failure must propagate rather than becoming a panic or a successful exit.

Successful backend streams require mock injection below the shipped binary's
trusted-origin boundary. The independent shipped-binary suite must not add an
endpoint override merely to test these paths. Existing parser/dispatcher tests
are the companion evidence for this acceptance row, not live-backend evidence.

## Verified local evidence and pending release gates

Snapshot recorded on 2026-09-08 during implementation, before the final PR
commit. Local logs are under `/tmp/askcodex/refactor-20260908/`. These results
describe the executions below; they do not certify later edits or deployment.

| Check | Observed result | Evidence log |
| --- | --- | --- |
| Final offline `cargo test --locked` | 366 passed, 0 failed, 11 ignored: 314 library tests, 35 CLI tests, 8 fixture tests, 9 migration tests | `final-tests.log` |
| Format, Clippy with warnings denied, private rustdoc with warnings denied, locked release build and generated-reference comparison | All passed on the 0.1.0 candidate | `final-fmt.log`, `final-clippy.log`, `final-rustdoc.log`, `final-build.log` |
| Governance and installer | 82 governance tests and 7 Bats tests passed; shellcheck and shfmt passed | `final-governance.log`; local shell checks |
| Explicit final archived-baseline parity | 1 passed against the archived 0.0.1 binary | `final-baseline.log` |
| Candidate installation | Installed 0.1.0 matches the release build; both skill directories match; generated reference matches; no-refresh auth check passed with unchanged credential bytes | `final-install.log` |
| Extended fixture redaction and provenance suite | 8 passed, 0 failed; retains the original 6 tests and adds 2 provenance tests after the full-suite snapshot | `provenance.log` |
| Independent shipped-binary migration suite with input bounds | 9 passed, 0 failed, 1 optional baseline test ignored | `migration-bounds.log` |
| Explicit archived-baseline help parity | 1 passed, 0 failed; successful help exit status for every legacy leaf | `migration-baseline.log` |
| Independent fallible streaming output suite | 5 passed, 0 failed; incremental flushed events, exactly one successful result, no result on failure, immediate callback failure on broken pipe | `migration-stream-fallible-final.log` |

The 11 ignored cases in the full offline run comprise 9 live-backend tests,
1 subprocess lock helper (invoked explicitly by its parent test), and
1 optional archived-baseline test. They are not 11 successful backend checks.
The historical capture is truncated and the executable SSE fixture contains
declared synthetic text substitutions; neither is fresh live verification.

Concurrency evidence has two distinct parts. The stale-snapshot tests execute
refresh/adoption sequentially against a mock backend. The lock test starts a
real subprocess, proves that its held kernel lock excludes the parent, kills
and reaps that child, and then proves the parent can acquire the same lock.
This establishes exclusion and process-death release, not an end-to-end trial
of simultaneous HTTP refreshes in multiple processes. Codex and older askcodex
versions using unlink-based locks do not participate in this coordination.
Same-token external metadata edits can still be overwritten; these tests do
not establish general lost-update prevention against unrelated writers.

Final acceptance still requires resolved PR review findings, final-head CI,
a merge SHA, and verification against the merged release. At this snapshot,
CI and production landing are pending. Record their actual outcome in the final
PR and delivery evidence; do not infer them from the local passes above.
