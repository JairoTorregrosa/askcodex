# Design

This document records the architecture decisions for askcodex and the rules
that govern changes. It is a contract: code is written against it, reviews
enforce it.

## Purpose

askcodex drives the ChatGPT/Codex **subscription** backend
(`chatgpt.com/backend-api/codex/*`) with the tokens `codex login` already
stored in `~/.codex/auth.json`. Semantic verbs (`whoami`, `usage`,
`models`, `image`, `ask`), one escape hatch (`raw`). **No API key is used
or accepted, anywhere, ever.**

## Non-negotiable rules

- **Credential source is `auth.json` only.** No key flags, no key env
  vars, no alternative auth path.
- **Credentials are scoped to one origin.** The bearer token and
  `chatgpt-account-id` are attached ONLY to requests aimed at the origin
  askcodex is credentialed for — scheme + host + effective port, **derived from
  `config::BASE_URL`**, never spelled out a second time, so exactly one
  place in the crate decides which host askcodex talks to. `askcodex raw` is the
  only command that names a destination; it accepts a path beginning with
  `/` (which hangs off `config::BASE_URL`) or an absolute http(s) URL
  already on that origin, and refuses everything else. It refuses twice:
  in clap's `value_parser`, before the credential file is opened, and
  again as the first statement of `Client::send_once` — before the access
  token is read out of the loaded credentials, at the single point where
  the `Authorization` header is built, where `raw`, the endpoint modules
  and the streaming path all converge. The parse-time check is a courtesy;
  the one in `send_once` is the invariant.
  Scheme equality is part of the comparison, so an `http://`
  downgrade of the backend host is refused like any foreign host, and
  redirects are not followed at all (`max_redirects(0)`) because a followed
  redirect replays `chatgpt-account-id` at a host chosen by a `Location`
  header, inside the transport where this check cannot see it. Anything
  unparseable fails closed. **There is deliberately NO environment variable
  and NO flag that widens the trusted origin**: such a knob would be the
  same vulnerability with a supported name. The refresh endpoint obeys the
  identical rule from the other side — `config::TOKEN_URL` is a
  compile-time constant, and the injectable parameter beside it is reachable
  only from this crate's own offline tests. The one widening that exists is
  compile-time and disclosed rather than hidden: `origin_permitted`'s
  `allow_loopback` argument is true only under `cfg!(test)` in this crate's
  unit build, where the backend is an httpmock server on 127.0.0.1. The
  shipped binary and the integration tests compile without `cfg(test)`, so
  no build a user can run is affected.
- **No defaults that mask failure.** Missing auth, failed refresh,
  unexpected response shape, non-PNG payload: loud error on stderr,
  non-zero exit. Never placeholder output, never a silent fallback,
  never a retry loop that hides a root cause.
- **Secrets are unprintable.** Token values ride in the `Secret` newtype
  (`src/redact.rs`); `Debug`/`Display` redact; the only exposure path is
  `Secret::expose()` into HTTP headers/bodies. No `*_token: String` field
  may exist in this crate. Errors carry claim *names*, statuses, and
  bounded body snippets — never token values. Anything destined for the
  repo or evidence files additionally redacts `account_id`, `user_id`, and
  email, using one fixed spelling each — `acct_REDACTED`, `user_REDACTED`,
  `email_REDACTED` — so that fixtures, transcripts and the live suite's own
  scrubber all produce the same text. Other identifier kinds follow the
  same lowercase `<kind>_REDACTED` shape (`resp_REDACTED`, `msg_REDACTED`,
  `uuid_REDACTED`, `token_REDACTED`). A one-off spelling is a bug: it
  defeats grepping for what was redacted.
- **The image path has no knobs.** The backend returns one opaque PNG at
  a size it chooses and ignores size/quality/background/format/n
  (validated live). Exposing an ignored option would be a failure-masking
  default, so only the prompt (and edit reference images) exist.
- **`image edit` reference images must be PNG.** askcodex labels every
  reference `image/png` on the wire, unconditionally, so it verifies that
  label locally: each `-i/--inputs` file is checked for the PNG magic bytes
  (`\x89PNG`) before anything is sent, and a file that lacks them fails
  with `Error::InputImageNotPng` — naming the path and the magic bytes
  found — and a non-zero exit, with no call made. This is a **declared
  restriction**: PNG is the only reference type ever verified against the
  live backend, so askcodex states the limit instead of discovering it on the
  user's quota. Uploading other bytes under an `image/png` label would be a
  lie told to the backend on the user's behalf, and it comes back as an
  opaque server-side rejection; a local refusal that names the offending
  file is the loud failure this project prefers. It is the mirror of the
  existing rule on the way back: a response payload whose first four bytes
  are not PNG magic is never written to disk.

## Decision log (probe-backed)

Every dependency choice below was validated by a throwaway crate that
compiled and ran the exact APIs against the resolved versions. That probe
crate was scratch work and is **not** part of this repository, so each
finding it produced is restated here in full rather than cited — a probe
finding you cannot re-read is only as good as the sentence that survives
it. Where a finding is load-bearing at runtime it is also pinned by a test
in `src/http.rs` or `src/auth.rs`, which is the copy that cannot silently
go stale. The
dependency set is **frozen**: ureq 3.3, clap 4.6 (derive), serde/serde_json,
thiserror 2, base64 0.23, chrono 0.4 (no default features), httpmock 0.8
(dev only). Do not add or upgrade dependencies without re-probing.

### ureq (blocking) over reqwest (async)

A CLI performs one logical request at a time; an async runtime buys
nothing and costs a tokio tree, larger binaries, and `async` coloring
through every module. ureq v3 is blocking, small, rustls-native (the tree
contains **no openssl / native-tls** — verified with `cargo tree -i`), and
its streaming body reader is a plain `impl Read`, which makes the SSE path
a `BufReader::lines()` loop. reqwest+tokio remains the documented
alternative if askcodex ever needs concurrent requests; nothing in the module
layout precludes swapping the transport behind `http.rs`.

ureq v3 specifics the implementation MUST honor (probe findings):

- The agent is built with `http_status_as_error(false)`. ureq's default
  converts non-2xx into `Error::StatusCode(u16)` **losing the response
  body**; askcodex needs the status for the 401 policy and the body for loud
  error messages.
- ureq v3 sets **no timeouts by default**. The shared agent sets only
  `timeout_connect`; a global or recv-body timeout would kill long `ask`
  streams. Short calls may tighten per request via the request-scoped
  config override.
- Plain body readers are **unlimited**; every read goes through
  `into_with_config().limit(BODY_LIMIT_BYTES)`.
- `send_json` emits `Content-Type: application/json; charset=utf-8`.

### lib + bin split

`src/lib.rs` exposes every module; `src/main.rs` only parses argv,
calls `askcodex::run`, and maps `Error` to `askcodex: error: …` + exit 1. This
keeps the whole behavior surface testable in-process against httpmock and
temp dirs. No `anyhow`: a single closed `thiserror` enum already renders
every failure; a context-wrapping crate at the boundary would add a
dependency to do what one `eprintln!` does.

### Error strategy

One `#[non_exhaustive]` enum in `src/error.rs` with a variant per failure
*meaning* (auth missing vs unparseable vs keyring-case vs refresh vs HTTP
status vs shape vs stream …), each with a message that tells the user what
to do next. Exit code is uniformly 1 (clap owns usage errors at 2).
`Display` strings are part of the contract — tests may assert them.

### Secret handling: hand-rolled newtype (secrecy rejected on evidence)

The probe demonstrated `secrecy::SecretString` does not implement
`Serialize` (its `str` lacks `SerializableSecret`), and askcodex must write
rotated tokens back to `auth.json`. The 30-line `Secret` newtype provides
redacting `Debug`/`Display`, transparent serde in both directions, and a
single greppable exposure method — with zero added dependency. Memory
zeroing is a documented non-goal: the threat model is accidental
printing/logging/committing, not process-memory forensics.

### SSE approach

`sse.rs` implements line-based framing over any `BufRead` (transport
agnostic: live ureq reader in production, `Cursor` fixtures in tests) and
yields `data:` payload frames. Event *semantics* live in
`models::ResponsesSseEvent::classify` (frozen): delta / completed / error /
other. Multi-line `data:` coalescing is deliberately not implemented — the
backend emits one JSON document per `data:` line (a declared assumption:
[docs/PROTOCOL.md](docs/PROTOCOL.md) §4 records that multi-line `data:`
frames were never observed, and lists that as unverified). A stream that
ends without `response.completed` is an error, never a silently truncated
answer.

### Auth freshness and refresh (`auth.rs` — highest-stakes module)

- Refresh when the access token `exp` is within 300 s, or `last_refresh`
  is older than 8 days (codex parity).
- `jwt_exp` failure is **loud**: an undecodable token is an error, never a
  silent "refresh now" guess.
- Exactly **one** refresh attempt per trigger; the 401 path retries the
  original request exactly once after a successful refresh; `--no-refresh`
  disables both the pre-flight refresh and the 401 retry.
- `last_refresh` is written byte-compatible with codex's own format
  (`2026-08-07T23:32:41.615755Z`, 6-digit micros + `Z`) via an explicit
  chrono formatter; chrono's default serde emit is variable-precision and
  is banned for this field.

### Atomic persistence design

`persist_atomic` (contract in `src/auth.rs`):

1. serialize the full document — unknown keys ride along via serde
   flatten (round-trip verified, including null-valued legacy keys);
2. temp file **in the same directory** (same filesystem ⇒ atomic rename),
   `O_CREAT|O_EXCL`, **mode 0600 before any byte is written** — never a
   chmod after the fact, which would leave a readable window;
3. write, flush, fsync;
4. backup `auth.json` → `auth.json.bak` (0600) — best-effort forensics
   (its refresh token may already be rotated server-side) that preserves
   `account_id` and unknown keys; a backup failure aborts the persist;
5. atomic `rename`.

Postcondition on every path: `auth.json` is either the complete old or the
complete new document — never absent, truncated, or mode-loosened. A
refresh whose HTTP call fails leaves file *and* memory untouched (the old
refresh token is still valid). A persist failure after rotation is the one
unavoidable bad state; `Error::PersistFailed` says exactly that, names the
backup, and never prints a token.

### Module map

| Module | Role |
|---|---|
| `config.rs` | constants, `CODEX_HOME`/`$HOME` resolution (loud when unresolvable) |
| `redact.rs` | `Secret` newtype |
| `error.rs` | crate error enum |
| `models.rs` | wire + `auth.json` serde types, SSE event classifier, timestamp helpers |
| `cli.rs` | clap tree = the command-surface contract |
| `auth.rs` | load / jwt_exp / needs_refresh / refresh / persist_atomic |
| `http.rs` | agent, headers, error mapping, one-shot 401→refresh→retry |
| `sse.rs` | SSE framing over `BufRead` |
| `endpoints/` | account, images, responses wrappers |
| `run.rs` | dispatch + rendering (output contract in its header) |
| `main.rs` | thin shell: argv → `run` → exit code |

### Output contract

stdout carries payload only (text rendering or JSON); stderr carries
errors. `--json` prints the **raw** backend value for `usage`/`models`
(unknown fields never dropped), composed structs for `whoami`/`ask`.
Details per command live in `src/run.rs`'s header.

"The raw backend value" for `models` means the **whole wire document** —
the `{"models": [ … ]}` envelope — never just the inner array. Printing
only the array would silently drop every envelope-level sibling, so a
`default_model` or a paging cursor would never reach the user and a
truncated catalog would read as the whole catalog: a partial result
presented as success, which the rules above forbid. The array is one
`jq .models` away; losing a key the backend sent is not recoverable at
all. `usage` behaves identically: the whole body, always.

## Testing strategy

- **CODEX_HOME isolation rule: every test that touches auth sets
  `CODEX_HOME` to a fresh temp directory — NEVER the real `~/.codex`.**
  No test, mock, fixture, or CI job may read or write the user's real
  credential file. Tests that set env vars must not run concurrently with
  each other (serialize or set per-process).
- HTTP behavior is tested against `httpmock` (blocking) fixtures: status
  paths, 401-refresh-retry, SSE streams as `text/event-stream` bodies —
  the exact pattern was proven in the dependency probe described above
  (scratch work, not in this repository).
- Unit tests target the pure cores: JWT `exp` math, SSE framing edge
  cases (blank lines, `[DONE]`, `event:` lines, truncated stream), arg
  parsing (in `cli.rs`, frozen), response decoding, timestamp round-trip,
  auth atomic-write and failed-refresh safety (crash injection via
  read-only dirs / missing parents).
- Live integration tests exist but are opt-in (`ASKCODEX_LIVE=1`), never in
  CI, and never call the refresh endpoint implicitly.
- CI enforces `cargo fmt --check`, `cargo clippy --all-targets --
  -D warnings`, and `cargo test` on Linux and macOS (zero warnings).

## Toolchain

Edition 2024, `rust-version = 1.88` (MSRV; resolver v3 verified to pick
the probe-identical dependency set), toolchain pinned to 1.97.1 in
`rust-toolchain.toml`. Release profile: `opt-level=3, lto=true,
codegen-units=1, strip=true, panic="abort"` — one small static binary.
