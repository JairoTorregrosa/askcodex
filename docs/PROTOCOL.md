# askcodex wire protocol

Reverse-engineered protocol for the OpenAI **Codex ChatGPT-subscription** backend, as driven by the
`askcodex` CLI. No API key is used or accepted — the only credential source is the subscription tokens in
`~/.codex/auth.json` (`OPENAI_API_KEY` is **not used**; see auth schema below).

Every fact carries a provenance tag:
- `[verified-live 2026-08-07]` — confirmed by a real authenticated call on that date. The raw
  transcripts are **not** included in this repository: they contain live credentials, account ids and
  an email address. What is committed is the sanitized capture of each shape, in
  [`samples/`](samples) — `usage.json`, `models.json`, `whoami-fields.json`, `responses-sse.txt`,
  `image-response-meta.json`. Where a live fact has no committed artifact, this document says so
  instead of pointing at something you cannot open.
- `[verified-source <permalink>]` — confirmed against `openai/codex` source, commit-pinned to
  `2e3a1702c2e7adea5f2ae9ea2799c625024b4fda` (repo HEAD on 2026-08-07). A citation abbreviated as
  `.../codex-rs/…` hangs off
  `https://github.com/openai/codex/blob/2e3a1702c2e7adea5f2ae9ea2799c625024b4fda/`.
- `[UNVERIFIED: reason]` — not confirmed; the reason and the accepted limitation are stated.

**"RE report" / "RE-report" below** means the reverse-engineering log written *before* askcodex existed,
while the backend was first being mapped. It is a private working document and is **not part of this
repository**, so its section numbers (§1, §2, …) are a provenance note, not a citation a reader can
follow. Every fact resting on it alone is tagged `[UNVERIFIED]` where it appears and is listed again
in §9, each time saying what — if anything — askcodex actually does with it.

Source cross-check used the installed codex line `0.147.x`; the pinned commit is repo HEAD, which is
newer — noted where a path may have drifted.

---

## 1. Base URLs

| Purpose | URL | askcodex constant | Provenance |
|---|---|---|---|
| ChatGPT-subscription API root | `https://chatgpt.com/backend-api` | `config::BASE_URL` | `[verified-live 2026-08-07]` (all calls below) |
| Codex sub-tree | `https://chatgpt.com/backend-api/codex` | `config::CODEX_BASE_URL` | `[verified-source]` const `CHATGPT_CODEX_BASE_URL` |
| OAuth token refresh | `https://auth.openai.com/oauth/token` | `config::TOKEN_URL` | `[verified-source]` const `REFRESH_TOKEN_URL` |

All three are compile-time constants, and none of them is readable from an environment variable, a
config file, or a flag — see §2.1 for why that is a rule rather than an omission.

`[verified-source https://github.com/openai/codex/blob/2e3a1702c2e7adea5f2ae9ea2799c625024b4fda/codex-rs/model-provider-info/src/lib.rs#L37]`
`pub const CHATGPT_CODEX_BASE_URL: &str = "https://chatgpt.com/backend-api/codex";`

Note: `/me` and `/transcribe` live under `/backend-api` (**not** under `/codex`); the other endpoints below are under
`/codex`.

---

## 2. Headers (sent on every ChatGPT-subscription API call)

| Header | Value | Provenance |
|---|---|---|
| `Authorization` | `Bearer <tokens.access_token>` | `[verified-live 2026-08-07]` (401 without it, 200 with it) |
| `ChatGPT-Account-Id` | `<tokens.account_id>` | `[verified-live 2026-08-07]` |
| `originator` | `codex_cli_rs` | `[verified-source]` `DEFAULT_ORIGINATOR` |
| `User-Agent` | codex-style UA (see shape below) | `[verified-source]` + `[verified-live]` (any codex-style UA accepted) |
| `Content-Type` | `application/json` | `[verified-live]` (on POST bodies) |
| `Accept` | `application/json`, or `text/event-stream` for streaming | `[verified-live]` |

`originator` header + name:
`[verified-source .../codex-rs/login/src/auth/default_client.rs#L40]` `pub const DEFAULT_ORIGINATOR: &str = "codex_cli_rs";`
`[verified-source .../codex-rs/login/src/auth/default_client.rs#L330-L336]` `default_headers()` inserts
literal header key `"originator"` = `originator().header_value`, plus `USER_AGENT`.

**User-Agent shape** `[verified-source .../codex-rs/login/src/auth/default_client.rs#L159-L182]`
`get_codex_user_agent()`:
```
{originator}/{cargo_pkg_version} ({os_type} {os_version}; {arch}) {terminal_user_agent}[ (suffix)]
```
e.g. `codex_cli_rs/0.147.0 (Macintosh 26.0.0; arm64) <terminal-ua>`.
The backend does not validate the exact UA — any codex-style string works `[verified-live 2026-08-07]`
(askcodex sends `config::USER_AGENT`, currently `codex_cli_rs/0.147.0 (askcodex)`, and gets 200s). The CLI
sends a codex-style UA built from its own version; it must **not** claim to be a browser.

**Auth negative control:** unauthenticated `POST …/responses` → **401**; with the headers above,
`GET …/codex/usage` → **200** `[verified-live 2026-08-07]` (transcript not committed — see the
provenance legend; the same 401-then-200 behaviour is exercised offline by the 401 → refresh → retry
tests in `src/http.rs`). Earlier RE-report §1 agrees.

### 2.1 Those headers travel to exactly one origin

The two headers above that carry the user's identity — `Authorization: Bearer <access_token>` and
`ChatGPT-Account-Id` — are attached **only** to requests aimed at the origin askcodex is credentialed
for. That origin is scheme + host + effective port, and it is **derived from `config::BASE_URL`**
rather than written out a second time: `config.rs` is the one place that decides which host askcodex
talks to, and the origin check reads it rather than restating it, so the two cannot disagree.
Everything else fails closed — a relative target, a missing or unsupported scheme, a missing host, an
unparseable string.

`askcodex raw` is the reason this rule has to be enforced rather than assumed: it is the one command that
takes a destination from the command line. It accepts exactly two shapes — a path beginning with `/`,
which hangs off `config::BASE_URL`, or an absolute `http(s)` URL already on that origin — and refuses
anything else. The refusal happens **twice**:

1. in clap's `value_parser` for `raw <path>`, so the reason is printed at parse time, before the
   credential file is even opened; and
2. again inside `Client::send_once`, on the resolved URL, as the first statement of the function —
   before the access token is read out of the loaded credentials, at the single point where the
   `Authorization` header is built. Nothing routes around it: `request_json` and `request_stream`
   both call `send_once`, so `raw`, the endpoint modules and the SSE path all pass through the same
   gate.

The first layer is a courtesy. The second is the invariant.

Three consequences worth stating explicitly:

- **Scheme equality is part of the comparison.** `http://chatgpt.com/backend-api/…` is a different
  origin from `https://chatgpt.com/backend-api/…`, so a plaintext downgrade of the backend host is
  refused like any foreign host. Host and scheme are lowercased and the port is made explicit before
  comparison, so `https://CHATGPT.COM:443/x` matches and `https://chatgpt.com:8443/x` does not; a
  `user:pass@` prefix cannot spoof the host, because the userinfo is not part of it.
- **Redirects are not followed** (`max_redirects(0)`). A followed redirect would replay
  `ChatGPT-Account-Id` at whatever host a `Location` named, and would build that request inside the
  HTTP library where this check cannot see it. A 3xx therefore comes back as an ordinary response and
  is reported as the anomaly it is.
- **There is deliberately no environment variable and no flag that widens the trusted origin.** Such
  a knob was considered and rejected: it would be this exact vulnerability with a supported name, and
  anything able to plant a variable in the user's environment could then redirect a live credential.
  The same reasoning applies, separately, to the refresh endpoint in §6 — `config::TOKEN_URL` is a
  compile-time constant for the same reason, and the injectable parameter that exists beside it is
  reachable only from this crate's own offline tests, never from the environment, a config file, or
  argv.

There is exactly one widening of the origin check, and it is disclosed here rather than left to be
discovered: `origin_permitted` takes an `allow_loopback` flag whose only true caller is
`cfg!(test)` inside `Client::send_once`, where this crate's own unit tests point the "backend" at an
httpmock server on 127.0.0.1. It is a compile-time switch, not a runtime one — the shipped binary and
the integration tests compile `http.rs` without `cfg(test)`, so no build a user can run is affected,
and the refusal is separately tested by calling `origin_permitted` with the production setting.

The refresh token and the bearer token thus have one destination each, and neither is settable from
outside the binary: `config::TOKEN_URL` for the refresh, the `config::BASE_URL` origin for everything
else.

---

## 3. Endpoints

### 3.1 `GET /codex/usage` — plan + rate limits
`[verified-live 2026-08-07]`; sanitized body in [`samples/usage.json`](samples/usage.json), which is
also the fixture `src/run.rs` and `src/endpoints/account.rs` decode in their tests.

Response (observed keys):
```jsonc
{
  "user_id": "user_REDACTED",     // redact
  "account_id": "acct_REDACTED",  // redact (a UUID on the wire)
  "email": "email_REDACTED",      // redact
  "plan_type": "plus",
  "rate_limit": {
    "allowed": true, "limit_reached": false,
    "primary_window": { "used_percent": 20, "limit_window_seconds": 604800,
                        "reset_after_seconds": 16361, "reset_at": 1786176171 },
    "secondary_window": null
  },
  "code_review_rate_limit": null, "additional_rate_limits": null,
  "credits": { "has_credits": false, "unlimited": false, "overage_limit_reached": false,
               "balance": "0", "approx_local_messages": [0,0], "approx_cloud_messages": [0,0] },
  "spend_control": { "reached": false, "individual_limit": null },
  "rate_limit_reached_type": null, "promo": null,
  "rate_limit_reset_credits": { "available_count": 2, "applicable_available_count": 0 }
}
```

### 3.2 `GET /me` — profile  (under `/backend-api`, NOT `/codex`)
`[verified-live 2026-08-07]` (via `whoami`, which merges `/codex/usage` + `/me`; the sanitized merged
projection is [`samples/whoami-fields.json`](samples/whoami-fields.json)). The CLI reads at
least `name` from it; `email`/`plan`/ids come from `/codex/usage`. Full `/me` body not separately
captured `[UNVERIFIED: only the merged whoami projection was captured — /me raw body not
dumped, and no raw /me artifact exists in this repository; low risk, /me is a well-known ChatGPT
profile endpoint]`.

### 3.3 `GET /codex/models?client_version=<v>` — model catalog
`[verified-live 2026-08-07]`; sanitized in [`samples/models.json`](samples/models.json). The `client_version`
query param is required (askcodex defaults it to `0.147.0`). Response: `{ "models": [ … ] }`;
each model object has ~50 fields — the semantically relevant ones:
`slug`, `display_name`, `visibility` (`list`|`hide`), `input_modalities` (`["text","image"]` for all 8),
`context_window` (272000), `default_reasoning_level`, `supported_reasoning_levels[].effort`,
`supported_in_api`, `supports_search_tool`, `web_search_tool_type` (`text_and_image`).

Live catalog (8 models):

| slug | visibility | reasoning efforts | default | supported_in_api |
|---|---|---|---|---|
| gpt-5.6-sol | list | low→ultra | low | true |
| gpt-5.6-sol-wm | hide | low→ultra | low | false |
| gpt-5.6-terra | list | low→ultra | medium | true |
| gpt-5.6-luna | list | low→max | medium | true |
| gpt-5.5 | list | low→xhigh | medium | true |
| gpt-5.4 | list | low→xhigh | medium | true |
| gpt-5.4-mini | list | low→xhigh | medium | true |
| codex-auto-review | hide | low→max | medium | true |

(These are the coding/agent models; image generation is a *tool* layered on them, not a listed model.)

### 3.4 `POST /codex/images/generations` — text → image
`[verified-live 2026-08-07]` (one real `askcodex image create`; the returned PNG is not committed, its
envelope is summarized in [`samples/image-response-meta.json`](samples/image-response-meta.json)) ·
`[verified-source .../codex-rs/codex-api/src/endpoint/images.rs#L33-L45]` (`generate()` posts path `"images/generations"`).

Request body the CLI sends (only these two fields matter):
```json
{ "prompt": "<text>", "model": "gpt-image-2" }
```
Source request type `ImageGenerationRequest { prompt, model, background?, quality?, size?, n? }`
`[verified-source .../codex-rs/codex-api/src/images.rs#L5-L16]`. `model="gpt-image-2"` is hardcoded by
the codex tool `[verified-source .../codex-rs/ext/image-generation/src/tool.rs#L57]`
`const IMAGE_MODEL: &str = "gpt-image-2";`.

### 3.5 `POST /codex/images/edits` — edit / reference-guided
`[verified-live 2026-08-07]` (one real `askcodex image edit` with a single reference image) ·
`[verified-source .../codex-rs/codex-api/src/endpoint/images.rs#L47-L53]` (`edit()` posts path `"images/edits"`).

Request body:
```json
{ "prompt": "<text>", "model": "gpt-image-2",
  "images": [ { "image_url": "data:image/png;base64,…" } ] }
```
`ImageEditRequest { images: Vec<ImageUrl>, prompt, model, background?, quality?, size?, n? }`,
`ImageUrl { image_url: String }` `[verified-source .../codex-rs/codex-api/src/images.rs#L19-L36]`.
**≤5 reference images** `[verified-source .../codex-rs/ext/image-generation/src/tool.rs#L58]`
`const MAX_EDIT_IMAGES: usize = 5;` — the CLI enforces this client-side.

**Reference images must be PNG.** Look at the data URL above: askcodex labels every reference
`image/png` on the wire, unconditionally. So it verifies that label locally before sending. Each
`-i/--inputs` file is read and its first four bytes are compared against the PNG magic `89 50 4E 47`
(`\x89PNG`); a file that does not start with them is refused with `Error::InputImageNotPng`, naming
the path and the magic bytes actually found, and askcodex exits non-zero without making the call.

This is a **declared restriction**, not an inferred one. PNG is the only reference type ever verified
against the live subscription backend; nothing here establishes what the backend does with a JPEG or
a WebP labelled as PNG, and askcodex will not find out on the user's quota. Sending other bytes under an
`image/png` label would be a lie told to the backend on the user's behalf, and the answer would come
back as an opaque server-side rejection — a 4xx about an image the user believed was fine. A local
refusal that names the file is the loud, obvious failure this project prefers, and it is the same
rule already applied in the other direction: a *response* payload whose first four bytes are not PNG
magic is never written to disk either (§3.6).

### 3.6 Image response body (both endpoints)
`[verified-source .../codex-rs/codex-api/src/images.rs#L56-L70]`
`ImageResponse { created: u64, data: Vec<ImageData>, background?, quality?, size? }`,
`ImageData { b64_json: String }`. The earlier RE report §3 (private log, not in this repository) adds
`output_format` and a `usage` block (`input_tokens`/`output_tokens`, incl. `image_tokens`); askcodex does
not read either field, so nothing depends on that claim.

```jsonc
{ "created": <u64>,
  "data": [ { "b64_json": "<raw base64 PNG, no data: prefix>" } ],
  "background": "opaque", "quality": "low", "size": "1254x1254",
  "output_format": "png",
  "usage": { "input_tokens": <int>, "output_tokens": <int>, "image_tokens": <int> } }
```
`data[0].b64_json` decodes to a PNG (magic `89 50 4E 47`). See
[`samples/image-response-meta.json`](samples/image-response-meta.json) (b64 replaced with a
byte-count placeholder; its `_note` carries the same provenance split as this paragraph). The `size`
value is server-chosen and varies between dates — `[verified-live 2026-08-07: "1254x1254";
2026-08-20: "1402x1122"]` (returned in the envelope and printed by the CLI); see §5. The
`created`/`background`/`quality`/`output_format`/`usage` field VALUES are
`[UNVERIFIED: carried from the earlier RE report §3, which is not in this repository, so there is no
artifact here to check them against. askcodex reads none of them except `size`; re-dump the raw
envelope when the image path is next re-probed]`.

### 3.7 `POST /codex/responses` — streaming text completion (SSE)
`[verified-live 2026-08-07]` (one real `askcodex ask`, plus the same call through `askcodex raw --stream`;
an adapted fixture is [`samples/responses-sse.txt`](samples/responses-sse.txt); see §4 for provenance). Request:
```json
{ "model": "<slug>",
  "input": [ { "type": "message", "role": "user",
              "content": [ { "type": "input_text", "text": "<prompt>" } ] } ],
  "stream": true, "store": false }
```
Optional: `"instructions": "<system-style>"`, `"reasoning": { "effort": "<level>" }`.
Extra headers: `OpenAI-Beta: responses=experimental`, `Accept: text/event-stream`.
**`store` MUST be `false`.** `[verified-live 2026-08-07]` — SSE contract below.

---

### 3.8 `POST /transcribe` — audio → text

`[verified-live 2026-09-08]` A synthetic WAV containing “This is a transcription
test. The blue notebook contains seven pages.” returned HTTP 200 and:

```json
{"text":"This is a transcription test. The blue notebook contains seven pages."}
```

The route is `https://chatgpt.com/backend-api/transcribe`, outside `/codex`.
The request is `multipart/form-data` with one part named `file`, filename
`audio.wav`, content type `audio/wav`, and the unmodified WAV bytes. No model
or language field was supplied. The Rust client succeeded with askcodex's
existing subscription authorization, account, originator, and User-Agent
headers. Credentials were read only; every live invocation disabled refresh.

Discovery lead: [Codex Desktop dictation report](https://github.com/openai/codex/issues/20668).
Initial Node/fetch diagnostic returned a non-JSON 403. curl multipart and the
implemented Rust/ureq path succeeded. This does not establish the cause of
the Node failure, a required Desktop User-Agent, or a need for an alternate
transport. Local evidence: `/tmp/askcodex/transcribe-20260908/` (`probe-curl.json`,
`rust-result.json`, synthetic `sample.wav`).

`text` is parsed as an optional string and required for a usable result;
missing/null/wrong-type values fail. A present empty string is preserved.
`--json` returns the complete response object, retaining unknown fields.
WAV is the only format exercised here. The 25 MiB cap is imposed locally
to bound memory, not claimed as the server's maximum. Timestamps, language
selection, speaker labels, other formats, duration limits, and model identity
remain unverified. Multipart replay on a single 401 refresh is covered with
offline mocks, not by rotating the user's real credentials.

## 4. SSE framing contract (for the parser in `src/sse.rs`)

`[verified-live 2026-08-07]` — framing was observed in a real stream. The fixture in
[`samples/responses-sse.txt`](samples/responses-sse.txt) is adapted from that capture:
identifiers are redacted, and the original `CS`/`UB` deltas and `CSUB-VERIFY-OK`
text fields were changed to `ASK`/`CODEX` and `ASKCODEX-VERIFY-OK`. These text
values are synthetic; the other event metadata remains from the capture. That
file is also the fixture `src/endpoints/responses.rs` and `src/run.rs` parse in their tests, so this
contract and the parser cannot drift apart silently. The capture stops on the terminal
`event: response.completed` line, before that frame's `data:` line, which is why it doubles as the
truncated-stream fixture. The `response.completed` frame in the example block below is therefore
**schematic** — its payload is elided with `…` — and is not a copy of anything in the file.

- **Frame** = an `event: <name>` line, then a `data: <json>` line, then a **blank line**.
  Line terminator is **LF** (`\n`), not CRLF.
- The event name appears **twice**: in the `event:` line *and* as `"type"` inside the `data` JSON.
  A parser may key off either; askcodex keys off `data`'s `"type"`, which is robust.
- **`data` is always a single line** of JSON in this trace — **no multi-line `data:` continuation**
  observed. (SSE technically allows multi-line `data`; not seen here. `[UNVERIFIED: multi-line data —
  not observed; parser should still concatenate consecutive data: lines within a frame per SSE spec,
  defensively]`.)
- **No `[DONE]` sentinel** is emitted (unlike the OpenAI API-key path). `[verified-live 2026-08-07]`
  — `[DONE]` absent from the whole stream. Tolerating one if present is safe.
- Delta text is in the **`delta`** field of `response.output_text.delta` events.

Event sequence for a normal completion (observed, in order):
```
response.created
response.in_progress
response.output_item.added
response.content_part.added
response.output_text.delta      (×N — accumulate .delta)
response.output_text.done
response.content_part.done
response.output_item.done
response.completed               (terminal — stop here)
```

Parser rules (spec for implementers):
- Accumulate `delta` from every `response.output_text.delta`.
- **Terminate** on `response.completed`. Its payload carries `response.usage` with token counts
  (`input_tokens`, `output_tokens`, `total_tokens`, plus `*_details` objects)
  `[verified-live 2026-08-20]`; askcodex passes the object through raw in `ask --json` and treats a
  missing or `null` field as absent.
- **Raise loudly** (non-zero exit) on `response.failed`, `response.error`, or a top-level `error`
  event — include the raw event JSON in the error. `[verified-source: event names match codex + OpenAI
  Responses API]` `[UNVERIFIED-live: failure events never provoked against the live backend;
  names carried forward from the API contract]`.
- Ignore unrecognized event types (forward-compat).
- A non-200 HTTP status on the POST itself is a hard error (not an SSE event).

Example redacted frames:
```
event: response.output_text.delta
data: {"type":"response.output_text.delta","content_index":0,"delta":"ASK","item_id":"msg_REDACTED","logprobs":[],"obfuscation":"…","output_index":0,"sequence_number":4}

event: response.completed
data: {"type":"response.completed","response":{ … }, "sequence_number":…}
```
(The adapted fixture spells `ASK`,`CODEX`,`-`,`VERIFY`,`-`,`OK` = `ASKCODEX-VERIFY-OK`;
the original verify run spelled `CS`,`UB`,`-`,`VERIFY`,`-`,`OK` = `CSUB-VERIFY-OK`.)

---

## 5. Image path is LOCKED server-side

Every call returns exactly one opaque (RGB, no alpha) PNG. The pixel size is a **server-chosen
value that varies between dates**, not a constant, so nothing in this repository pins it. The
committed evidence is the live test `live_quota_image_create_writes_exactly_one_locked_size_png`
in `tests/live.rs`, which re-reads the opacity and the envelope-size-matches-pixels halves of the
lock out of the returned file's IHDR. The knob-by-knob matrix below comes from the earlier RE
report §2, which is **not in this repository**.

- Output is always **one opaque (RGB, no alpha) PNG** at a server-chosen size.
  `[verified-live 2026-08-07: 1254×1254; 2026-08-20: 1402×1122]`
- **Ignored knobs** (accepted in the request type, but overridden/ignored by the subscription
  backend): `size`, `quality`, `background`/transparency, `output_format`, `n`, and even `model` (a
  nonsense model string still returns 200 + a valid PNG). `[UNVERIFIED in this repository:
  the per-knob matrix rests on RE report §2, which is not committed here, and was probed on
  2026-08-07 only. Nothing depends on it — askcodex sends none of these knobs, so the matrix is the
  REASON for that decision, not a fact askcodex acts on. The consequence that matters, one opaque
  PNG, is verified live.]`
- Therefore the CLI must expose **only** `prompt` (+ reference images for edit). Advertising any of the
  ignored knobs would be a failure-masking default and is prohibited.
- Not available on the subscription path (fields exist in the API type but backend ignores):
  transparent/alpha cutout, custom size/aspect, quality selection, `n>1`, non-PNG output, mask
  inpainting, `input_fidelity`, partial/streaming images, Sora/video, DALL·E. Alpha absence is
  `[verified-live 2026-08-07, 2026-08-20]`; the rest of the list is the RE report §4 inventory and
  carries the same not-committed caveat as the bullet above.

---

## 6. Token refresh flow

The facts below are `[verified-source]` against the pinned codex tree, plus a live read of the
`client_id` claim from the access token on 2026-08-07 (read programmatically; the token value was
never printed). Where an earlier RE-report observation is the only support for a number, it is
flagged inline — that log is not committed here.

A refresh rotates the user's real refresh token and a mistake locks them out of codex, so this
flow is exercised sparingly: it was executed deliberately, with a backup taken first, on
2026-08-07 — all three tokens rotated and persisted, and codex kept working on the rotated file.

- **Endpoint:** `POST https://auth.openai.com/oauth/token`, `Content-Type: application/json`.
  `[verified-source .../codex-rs/login/src/auth/manager.rs#L192]`
  `const REFRESH_TOKEN_URL: &str = "https://auth.openai.com/oauth/token";`
- **Request body:** `{ "client_id": "app_EMoamEEZ73f0CkXaXp7hrann", "grant_type": "refresh_token",
  "refresh_token": "<current>" }`.
  `[verified-source .../codex-rs/login/src/auth/manager.rs#L1604-L1615]` (`struct RefreshRequest { client_id, grant_type: "refresh_token", refresh_token }`)
  `[verified-source .../codex-rs/login/src/auth/manager.rs#L1618]` `pub const CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";`
  `[verified-live 2026-08-07]` the current access-token JWT's own `client_id` claim reads
  `app_EMoamEEZ73f0CkXaXp7hrann` (read out programmatically; token value never printed).
- **Response:** `struct RefreshResponse { id_token?, access_token?, refresh_token? }`
  `[verified-source .../codex-rs/login/src/auth/manager.rs#L1610-L1613]`. The earlier RE report §7
  (not in this repository) records the live response also carrying `expires_in: 864000` (**10 days**)
  `[UNVERIFIED here: no committed artifact. Nothing depends on it — askcodex's RefreshResponse does not
  model expires_in at all (src/models.rs) and derives expiry from the JWT exp claim instead]`. The
  access token's own measured lifetime is exactly **10.0 days**
  (`exp - iat = 864000 s`) `[verified-live 2026-08-07]`, which agrees.
- **Rotation:** the `refresh_token` is **rotated** on each refresh; the new one must be persisted or the
  old one becomes unusable. `[verified-source .../codex-rs/login/src/auth/manager.rs#L1478-L1502]`
  (`persist_tokens` overwrites `tokens.id_token`, `tokens.access_token`, `tokens.refresh_token`, and
  sets `last_refresh = now`).
- **When codex refreshes** `[verified-source .../codex-rs/login/src/auth/manager.rs#L2762-L2783]`
  (`should_refresh_proactively`): refresh if `access_token exp <= now + 5 min`, **or** (when exp is
  unreadable) if `last_refresh < now - 8 days`.
  `[verified-source .../codex-rs/login/src/auth/manager.rs#L183-L184]`
  `const TOKEN_REFRESH_INTERVAL: i64 = 8;` (days) and
  `const CHATGPT_ACCESS_TOKEN_REFRESH_WINDOW_MINUTES: i64 = 5;`. askcodex mirrors both:
  `config::REFRESH_WINDOW_SECS = 300` and `config::REFRESH_MAX_AGE_DAYS = 8`.
- **Persistence requirements** (for `askcodex`'s `auth.rs`): write `tokens.{access_token,id_token,
  refresh_token}` + `last_refresh` back to `auth.json` **atomically**, **mode 0600**, preserving every
  other key; never discard a working refresh token on a failed refresh; back up before writing.
- **Failure classification** `[verified-source .../codex-rs/login/src/auth/manager.rs#L186-L191, L1548-L1571]`:
  distinct permanent errors for `refresh_token_expired` / `_reused` / `_invalidated` / revoked →
  "log out and sign in again". A `askcodex` refresh that gets one of these must fail loudly, not silently
  retry.

---

## 7. `auth.json` schema (KEY NAMES only — never values)

`[verified-source .../codex-rs/login/src/auth/storage.rs#L40-L60]` `struct AuthDotJson`:

| key | type | notes |
|---|---|---|
| `auth_mode` | string enum | `"chatgpt"` for the subscription path (live file: `chatgpt`) |
| `OPENAI_API_KEY` | string / null | serde-renamed from `openai_api_key`; **not used by askcodex** — null/ignored on the sub path |
| `tokens` | object / null | the credential bundle (below) |
| `last_refresh` | RFC3339 datetime / null | updated on each refresh |
| `agent_identity` | object / null | codex-internal; preserve verbatim |
| `personal_access_token` | string / null | codex-internal; preserve verbatim |
| `bedrock_api_key` | object / null | codex-internal; preserve verbatim |

`tokens` = `struct TokenData` `[verified-source .../codex-rs/login/src/token_data.rs#L11-L24]`:

| key | type | notes |
|---|---|---|
| `id_token` | string (JWT) | on disk it's the raw JWT string (codex parses it into claims in memory) |
| `access_token` | string (JWT) | bearer for API calls; `exp` and `client_id` are JWT claims |
| `refresh_token` | string | rotated on refresh |
| `account_id` | string / null | UUID; sent as `ChatGPT-Account-Id` |

**askcodex must preserve unknown/other keys** on write (round-trip the full object) so it never clobbers
codex-internal fields.

### Keyring caveat
`[verified-source .../codex-rs/login/src/auth/storage.rs#L25-L28, L250-L317]` codex can store the same
credentials in the **system keyring** instead of the file, selected by
`AuthCredentialsStoreMode` (`codex_config::types`), via `DefaultKeyringStore`/`KeyringStore`. On the
validation machine the tokens were in `auth.json` (file mode) `[verified-live 2026-08-07]`
(`auth status` read them from the file); the keyring case was therefore never observed end to end
`[UNVERIFIED: keyring storage not exercised]`. `askcodex` must **detect the file-vs-keyring case and fail
loudly with guidance** when `tokens` is absent from the file (do not silently succeed) — per the
project's no-masking rule.

---

## 8. What is NOT used

- **`OPENAI_API_KEY` / `api.openai.com` / platform.openai.com — not used.** The only credential source
  is the ChatGPT-subscription tokens in `~/.codex/auth.json`. An API-key path to `api.openai.com/v1/
  images/*` *would* honor the image knobs, but it requires an API key and is explicitly out of scope.

---

## 9. Open items / declared unverified

Every entry here is a belief whose evidence is either missing or lives outside this repository. They
are listed rather than smoothed over, and each one names where the gap is.

- `/me` raw body: only the merged `whoami` projection was captured, and that projection is what
  [`samples/whoami-fields.json`](samples/whoami-fields.json) holds `[UNVERIFIED: low risk]`.
- Image response envelope values (`created`, `usage`, `background`, `quality`, `output_format`):
  carried from RE report §3, which is not in this repository, and never re-dumped
  `[UNVERIFIED]`. askcodex reads none of them except `size`,
  which IS verified live.
- The per-knob "ignored knobs" matrix in §5 rests on RE report §2, likewise not in this repository
  `[UNVERIFIED]`. Its consequence — one opaque PNG at a server-chosen size — is verified live and
  is what `tests/live.rs` re-checks.
- The refresh response carrying `expires_in: 864000` rests on RE report §7, not in this repository
  `[UNVERIFIED]`. askcodex's `RefreshResponse` does not model the field at all; expiry comes from the JWT
  `exp` claim, whose 10.0-day span was measured live.
- Token refresh: exercised once, deliberately, on 2026-08-07 (rotation risk keeps it rare)
  `[declared]`.
- Keyring credential storage: never exercised — the validation machine stores tokens in the file
  `[UNVERIFIED]`.
- SSE failure events (`response.failed`/`response.error`) were never provoked against the live
  backend `[UNVERIFIED-live]`; they are covered offline by synthesized streams built from the real
  framing.
- Multi-line `data:` frames not observed; parser should still handle them defensively `[UNVERIFIED]`.
- Source pin `2e3a1702…` is repo HEAD (newer than the installed `0.147.x`); paths verified to exist at
  that commit. Constants/structs are stable across this range but re-pin per release.
