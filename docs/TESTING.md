# Testing askcodex

askcodex is a client of a backend nobody here controls, driven by credentials
that belong to the person running it. That shapes the test suite into three
tiers with very different costs, and one rule that applies to all of them:

> **A test that could not actually verify something must say so, loudly.**
> A suite that quietly does nothing and reports green is worse than no suite
> at all — it is a failure-masking default, and this project treats those as
> bugs.

## The three tiers at a glance

| Tier | What it proves | Network | Credentials | Quota cost | Gate | Command |
| --- | --- | --- | --- | --- | --- | --- |
| 1 — unit | Pure logic: JWT `exp` math, SSE framing, arg parsing, response decoding, every renderer | none | none | none | always on | `cargo test` |
| 2 — offline integration | Wiring: HTTP headers, status handling, the 401→refresh→retry policy, atomic auth writes, SSE over a real socket | loopback only (`httpmock`) | fake, in a temp `CODEX_HOME` | none | always on | `cargo test` |
| 3a — live, read-only | That the **real** backend still answers the shapes askcodex parses | `chatgpt.com` | **your real** `~/.codex/auth.json`, read-only | none | `ASKCODEX_LIVE=1` | `ASKCODEX_LIVE=1 cargo test --test live` |
| 3b — live, quota | The image size/opacity lock and real SSE streaming | `chatgpt.com` | **your real** `~/.codex/auth.json`, read-only | 2 images + 1 message | `ASKCODEX_LIVE=1 ASKCODEX_LIVE_QUOTA=1` | `ASKCODEX_LIVE=1 ASKCODEX_LIVE_QUOTA=1 cargo test --test live` |

CI runs tiers 1 and 2 only. See [Why CI stops at tier 2](#why-ci-stops-at-tier-2).

---

## Tiers 1 and 2 — `cargo test`

```sh
cargo test                      # everything offline (tier 3 skips, visibly)
cargo test --lib                # in-crate tests only
cargo test sse                  # filter by name
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

Both offline tiers run in one command; they are distinguished by what they
touch, not by where they live. Tier-1 tests are pure functions over
fixtures. Tier-2 tests stand up a `httpmock` server on `127.0.0.1` and/or
point `CODEX_HOME` at a fresh temp directory, then drive the real client
code against it.

Two rules from `DESIGN.md` govern both, and they are not negotiable:

- **No test, fixture, or CI job may read or write the real `~/.codex`.**
  Every test that touches auth sets `CODEX_HOME` to a temp directory it
  created. The one deliberate exception is the live suite, which is opt-in,
  read-only, and described below.
- **No offline test may reach the network.** The endpoint layer takes an
  origin parameter precisely so tests can point it at localhost; the OAuth
  token URL is likewise injectable for tests only (`Client::with_token_url`)
  and is never readable from the environment.

Fixtures captured from real calls live in `docs/samples/` and are
sanitized with the project's placeholders — `acct_REDACTED`,
`user_REDACTED`, `email_REDACTED`, with response, message and session ids
following the same `<kind>_REDACTED` shape — plus truncated base64 and no
tokens.

`tests/fixtures.rs` enforces that. It reads the directory at run time
rather than naming files, so a fixture added tomorrow is covered without
anyone remembering to add it, and it fails on anything shaped like a live
identifier: an `acct`/`user`/`org`/`resp`/`msg`/`session` id that is not
the declared placeholder, an email address, a UUID, a JWT, or an absolute
path under someone's home directory. Rewriting `acct_REDACTED` in
`usage.json` to any other spelling turns the suite red.

That gate is shape-matching, and it is worth being exact about what it
buys: it catches a capture committed as captured. It cannot tell a
fabricated id from a real one, so it is a backstop for the accident, not a
substitute for reading what you are about to publish. One of its own
tests, `the_gate_would_actually_fail`, runs every pattern against a
fabricated offender — a sanitization check that cannot go red is worse
than none, because it gets read as proof.

`cargo test` also compiles and runs `tests/live.rs`. Without the gate
variables every test in it is a no-op that prints why:

```text
running 9 tests
askcodex live: live_usage_decodes_into_the_typed_model_and_its_windows_parse: skipped — set ASKCODEX_LIVE=1 to run (real backend, real credentials, no quota spent)
askcodex live: live_quota_ask_streams_a_completed_answer: skipped — set ASKCODEX_LIVE=1 ASKCODEX_LIVE_QUOTA=1 to run (real backend; SPENDS your quota)
...
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

Those lines are written to the stdout **handle** rather than through
`println!`, because libtest captures macro output and shows it only for
failing tests — which would make a skipped tier invisible in exactly the
case that matters.

---

## Tier 3 — the live suite (`tests/live.rs`)

This is the only place askcodex is tested against the thing it actually talks
to. CI cannot run it, so a backend change that breaks askcodex passes CI and
fails in a user's terminal. Running this suite is how the project finds out
first.

### What it costs you

**`ASKCODEX_LIVE=1` — read-only tier**

- **Network:** currently 13 `GET`s to `chatgpt.com/backend-api` across the
  six tests (`auth status` contributes none — it only reads the local
  credential file).
- **Credentials:** reads `${CODEX_HOME:-~/.codex}/auth.json`. Never writes
  it. Never refreshes it. One test asserts its size and mtime are unchanged
  after the whole tier has run.
- **Quota:** none. `usage`, `models`, `whoami` and `raw GET /codex/usage`
  do not consume messages or images.
- **Time:** a few seconds.

**`ASKCODEX_LIVE=1 ASKCODEX_LIVE_QUOTA=1` — additionally the quota tier**

- **2 image generations** (one `image create`, one `image edit`) and
  **1 `ask` message**, charged to your ChatGPT/Codex subscription. That is
  the entire bill, per run; it does not scale with anything.
- **Time:** image generations take tens of seconds each.

`ASKCODEX_LIVE_QUOTA=1` without `ASKCODEX_LIVE=1` is a hard error, not a silent
skip: you asked for something that could not happen, so the suite says so.
The accepted value for both variables is exactly `1`; unset or empty means
skip; anything else (`true`, `yes`, `0`) panics rather than pretending you
did not mean it.

### The rules the live suite obeys

1. **It never refreshes a token.** Every invocation is spawned through a
   helper that injects `--no-refresh` and rejects an argv that could reach
   the OAuth endpoint (`auth refresh`, or a `raw` call at `auth.openai.com`).
   A refresh rotates the real refresh token; the old one dies immediately,
   and a crash or a failed write in that window can lock you out of codex
   until you run `codex login` again. That is not a risk a test suite gets
   to take on your behalf.
2. **An expired access token fails the run.** Because of rule 1 the suite
   cannot renew it, and it will not pretend otherwise: `auth status` asserts
   the token is still valid and the failure message tells you to run
   `askcodex auth refresh` yourself, deliberately, and re-run.
3. **Nothing personal is asserted or printed.** No email, account id, user
   id, plan name, or model slug is compared against a literal — those are
   personal and they change. Assertions check shape: `plan_type` is a
   non-empty string, the model array is non-empty and every entry has a
   slug, rate-limit windows parse as numbers. Payloads never appear in
   failure messages, and the text that does (child stderr, serde errors)
   passes through a redactor that replaces `$HOME`, `acct_…`, `user_…`,
   emails and JWT-shaped strings first — with `acct_REDACTED`,
   `user_REDACTED`, `email_REDACTED` and `token_REDACTED`, the project's
   placeholders, so redacted test output reads the same as a redacted
   transcript. That redactor is self-tested at every gate check against
   those exact four strings, so a broken one stops the suite instead of
   leaking.
4. **It never writes `~/.codex`.** Proved, not just intended:
   `live_read_only_suite_never_mutates_auth_json` fingerprints the file's
   size and mtime (it never opens it), runs every read-only command, and
   fingerprints again.
5. **Skipping is loud.** See the transcript above.

### Preconditions

- `codex login` has been run with **file** credential storage, so
  `${CODEX_HOME:-~/.codex}/auth.json` holds ChatGPT-subscription tokens. If
  codex kept your credentials in the system keyring, askcodex fails with
  instructions — it has no keyring support yet (see `ROADMAP.md`).
- The stored access token is not expired: check with
  `askcodex --no-refresh auth status`.
- `CODEX_HOME` is honored if set, exactly as the binary honors it.
- **There is no API key involved anywhere.** `OPENAI_API_KEY` is not read,
  not accepted, and not usable with this tool.

### Running it

```sh
# read-only tier: network + real credentials, zero quota
ASKCODEX_LIVE=1 cargo test --test live

# everything, including the tier that spends 2 images + 1 message
ASKCODEX_LIVE=1 ASKCODEX_LIVE_QUOTA=1 cargo test --test live

# one test at a time
ASKCODEX_LIVE=1 cargo test --test live -- live_models

# serialize (the default runs several backend calls concurrently)
ASKCODEX_LIVE=1 cargo test --test live -- --test-threads=1
```

There is **no wall-clock timeout**. The client sets a connect timeout and
nothing else, on purpose: an `ask` stream may legitimately run for minutes
and a read timeout would kill a healthy request. A hung live test is
visible and yours to Ctrl-C.

`ASKCODEX_LIVE_REF_IMAGE=/path/to.png` overrides the reference image used by the
`image edit` test. Unset, the test writes a small PNG that is embedded in
the test file (decoded and checked before any quota is spent). Set to a path
that is not a file, the test fails — an override that silently falls back
would hide your typo. It must be a real PNG: `image edit` checks the magic
bytes of every `--inputs` file and refuses anything else before it calls, so
a JPEG here fails locally rather than spending quota on a request the
backend was never told the truth about.

### What the live tests assert

| Test | Assertion |
| --- | --- |
| `live_auth_status_reports_claims_only_and_never_a_token` | Claim keys are present; the expiry parses as RFC3339 and agrees with the countdown; the token is still valid; nothing token-shaped appears in either output mode. |
| `live_whoami_reports_a_plan_without_this_test_learning_who_you_are` | All five identity keys exist (absence is `null`, never a missing key); `plan_type` and `account_id` are non-empty strings. Values are never read into a message. |
| `live_usage_decodes_into_the_typed_model_and_its_windows_parse` | The live document still decodes into `askcodex::models::UsageResponse`; at least one rate-limit window is present; percentages are finite and non-negative; the text renderer agrees with the JSON. |
| `live_models_lists_slugs_and_decodes_into_the_typed_catalog` | The catalog is a non-empty array; every entry decodes into `ModelInfo` and carries a non-empty `slug`; at least one model accepts text input; the human header counts what the array holds. |
| `live_raw_get_codex_usage_reaches_the_same_endpoint_as_the_usage_command` | `raw GET /codex/usage` returns a document with the same top-level key set as `askcodex usage` (keys only — values move between two calls). |
| `live_read_only_suite_never_mutates_auth_json` | `auth.json` is byte-size- and mtime-identical after the whole read-only tier. |
| `live_quota_image_create_writes_exactly_one_locked_size_png` | Exactly one file is written; PNG signature and IHDR are valid; the colour type is **2** (RGB, no alpha); the reported `size` matches the pixels; the reported byte count matches the file. The exact dimensions are deliberately not pinned — the size is a server-chosen value that changes over time. |
| `live_quota_image_edit_returns_one_locked_size_png_from_a_reference` | Same image contract, plus `ref_images == 1`. |
| `live_quota_ask_streams_a_completed_answer` | The SSE stream completes; askcodex reports the model it used; the answer is non-empty. |

The image assertions are the interesting ones. The backend locks image output
to a single opaque PNG at a size it chooses and ignores every knob askcodex could
send (size, quality, background, format, n, model). That lock is documented in
`README.md`, `docs/PROTOCOL.md` §5 and `skill/SKILL.md`; this test is how the
project learns if it changes. The exact dimensions are not asserted, because
the server picks them and has picked differently on different dates.

What is read back out of the file's IHDR rather than trusted from the
response envelope: the colour type must be **2** — truecolour RGB, with no
alpha channel, which is what "opaque" means in the pixels — and the envelope's
`size` string must agree with the actual pixel dimensions. A test may only
assert what has been verified.

### Adding a live test

- Gate it. `live("your_test_name")` for read-only, `live_quota(...)` for
  anything that spends quota. Both return the token that `run` needs, so a
  test that returned early at its gate cannot reach the network by accident.
- Assert shape, not values. If the assertion would break when the user's
  plan, email, or model catalog changes, it is the wrong assertion.
- Never put a payload, a parsed document, or a field value into a panic
  message. Key names and JSON type names only; run any external text
  through `scrub`.
- Never add a code path that can refresh. If you need one, that is a
  conversation, not a commit.
- If your test spends quota, update the cost line in this document. Someone
  decides whether to run the suite based on that number.

---

## Why CI stops at tier 2

`.github/workflows/ci.yml` says it plainly:

> CI runs the mocked test suite only. askcodex's live integration tests are
> opt-in behind `ASKCODEX_LIVE=1`: they call the real Codex backend and read the
> caller's `~/.codex/auth.json`. Never set `ASKCODEX_LIVE` here, and never add a
> credential secret to this workflow — askcodex has no API key, and CI has no
> account to use.

Three reasons, in order of importance:

1. **There is no credential CI could legitimately hold.** askcodex authenticates
   with one person's ChatGPT-subscription tokens. Putting them in a repo
   secret would mean handing a personal, rotating, account-wide credential to
   every workflow run — and a token that CI refreshed would be rotated out
   from under its owner.
2. **A green CI must not imply the backend was verified.** Live results are
   evidence about a system that can change without warning; CI runs on push,
   against no backend. Conflating the two would let a mocked-green build read
   as proof the wire contract still holds.
3. **CI must not spend a user's quota.** Ever, and least of all on a fork's
   pull request.

What CI does enforce, on Linux and macOS: `cargo fmt --check`,
`cargo clippy --all-targets -- -D warnings`, `cargo test`,
`cargo build --release`, plus a separate job that compiles at the declared
MSRV floor.

---

## If you paste output anywhere

Transcripts from this project are public by default. Before pasting:

- Replace account ids with `acct_REDACTED`, user ids with `user_REDACTED`,
  and emails with `email_REDACTED`.
- Never paste a token value — not an `access_token`, not an `id_token`, not
  a `refresh_token`, not a fragment of one. askcodex itself never prints them
  (`auth status` reports claim names, an expiry timestamp and a verdict), so
  if you are looking at a token you got it from somewhere else.
- Never `cat ~/.codex/auth.json`.
