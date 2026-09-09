# Design

askcodex performs one requested operation against the ChatGPT/Codex subscription backend and returns a result suitable for a person, script, or agent. Rust, blocking HTTP, explicit failures, and a small executable remain the foundation.

The public CLI is generated in [docs/COMMANDS.md](docs/COMMANDS.md). [docs/OUTPUT.md](docs/OUTPUT.md) defines machine output. Backend observations belong in [docs/PROTOCOL.md](docs/PROTOCOL.md), with dates and limitations.

## Execution pipeline

`Cli → prepared local inputs → AuthSession → checked HTTP target → endpoint result → output`

`reference` is entirely local and requires no credentials. All other commands prepare their inputs before resolving the credential store. A malformed body, invalid media file, oversized input, or unusable image destination fails before authentication refresh or a backend request.

Preparation reads stdin as UTF-8 with a 16 MiB limit. WAV and the combined PNG references have a 25 MiB budget. Media inputs must be regular files; symlinks to regular files work. Descriptor checks and nonblocking open reject devices/FIFOs without hanging. Bounded reads also handle files that grow after metadata inspection.

Prepared image edits own the validated reference bytes. Execution does not reopen paths. Output-file preflight rejects predictable filesystem failures, but cannot guarantee that storage remains writable during generation; final writes still handle errors and retain the previous destination on failure.

## Modules

| Module | Responsibility |
| --- | --- |
| cli | Argument definitions and generated command reference |
| input | Bounded text and regular-file reads |
| run/prepare | Convert arguments into executable, locally validated commands |
| run | Dispatch sessions and prepared commands |
| run/output | Human output, versioned JSON, and fallible event delivery |
| run/artifacts | Destination checks and atomic generated-file publication |
| auth/store | Credential loading, private serialization, backup and atomic persistence |
| auth/session | Freshness, coordinated refresh, and explicit credential-store ownership |
| auth/lock | Kernel-held mutual exclusion for cooperating askcodex processes |
| auth/jwt | Pure JWT expiry and freshness policy |
| http/target | Construct validated destinations with private representation |
| http | Headers, bounded responses, and one-shot authenticated replay |
| endpoints | Backend request/response adapters |
| sse | Byte framing; endpoint code determines stream completion |
| models | Data structures; optional backend fields stay explicit |
| error | Meaningful failures and stable machine codes |

The library exposes parsing, execution, errors, public data models and configuration constants. Credential mutation, transports, endpoints and internal renderers are private. Test constructors cannot be compiled into the production interface.

## Credentials

The credential source remains Codex file storage. System-keyring storage is not implemented. There is no fallback to API keys.

An offline inspection of codex-cli 0.153.4 found a possible future native refresh path: app-server `account/read` accepts `refreshToken: true`, but its response contains account metadata, not credentials. `account/chatgptAuthTokens/refresh` runs in the opposite direction, asking an external host for tokens. A native refresh followed by a file reload is plausible; store selection, persistence ordering and cross-process coordination have not been verified as a replacement for this session implementation. No account RPC or real credential refresh was performed for that inspection.

A CredentialStore retains one resolved path. AuthSession loads its document once and owns both the document and store throughout the operation. The transport receives a session rather than resolving environment variables or rereading files during construction.

Secret, AuthFile and AuthTokens have no generic Serialize implementation. Private adapters explicitly serialize persistence/OAuth documents. Debug hides both recognized credentials and unknown document fields. Parse diagnostics describe category and position without including document values.

Refresh policy remains expiry within 300 seconds or last_refresh older than eight days. An invalid JWT is an error. Automatic refresh is disabled by --no-refresh; explicit auth refresh remains an explicit operation.

A refresh holds an exclusive kernel lock across reread, network renewal and persistence. The .lock file is a persistent regular inode, opened without following symlinks and with close-on-exec. It is never unlinked to reclaim ownership. Process exit releases ownership automatically.

The lock coordinates cooperating new askcodex processes. Codex and older unlink-based askcodex clients do not share this protocol. Rereading under the lock can adopt a newer token generation; this does not prevent arbitrary external edits or guarantee preservation of same-token concurrent metadata changes.

Persistence preserves unknown JSON fields, creates backup/temp files at mode 0600 before writing bytes, flushes and syncs the new document, and atomically renames within the same directory. Failed renewal leaves the previous tokens intact. Persistence failure after remote rotation reports recovery information; a backup may already contain an expired generation. Power-loss durability of the directory entry remains outside the guarantee.

## Transport

Only a Target constructed by the origin policy can reach the sender. The policy compares scheme, host and effective port with the fixed backend origin. Clap rejects HTTP downgrade and foreign raw destinations before credential loading; the sender independently rejects them before constructing credential headers, including for programmatically constructed arguments. Raw paths and absolute same-origin URLs use the same validation. Loopback injection is test-only.

Backend and OAuth requests disable redirects explicitly. OAuth applies this at request scope so an independently constructed agent cannot weaken the rule. Regression tests cover redirect destinations receiving no request.

JSON and multipart bodies share the same sender and replay policy. A 401 can cause one refresh followed by one replay of the prepared body. A second 401 is returned as failure. No replay occurs after streaming output has started.

Connection and OAuth timeouts remain explicit. Response bodies, including streams, are capped at 64 MiB. There is no default overall deadline for long generation streams. A downstream write failure propagates through the delta callback and drops the reader immediately.

The dependency set is locked, not frozen. libc is pinned for the kernel-lock API and tested at the project's MSRV; the version was already present transitively before being made direct.

## Results and failures

Human output stays concise and stdout contains payload only. Semantic --json returns one schema-versioned envelope after success. --events returns compact NDJSON, with text_delta records as ask progresses and exactly one result event on success. Failure produces an error on stderr and no final result.

Known result fields have documented meanings. Where available, backend preserves the complete unmodified JSON alongside the stable result. Raw remains explicit wire access and does not acquire a semantic envelope.

Input absence, response absence and completed empty output are different states. Missing required response data is an error; a completed empty transcript is valid. Unknown optional response fields do not break parsing. An SSE stream without response.completed is never successful.

Errors have stable codes independent of wording. Structured operational diagnostics go to stderr in machine modes. Clap retains exit code 2 for argument errors; operational failures use exit code 1.

## Evidence and verification

Original redacted captures and adapted test fixtures are separate artifacts. A synthetic sentinel change is never represented as a live capture.

The migration matrix covers command compatibility, isolated credentials, complete/failed streams, bounded inputs, installation, generated docs, and deployment. Tests exercise the real binary and loopback HTTP, plus isolated storage failure and cross-process lock scenarios. Live tests remain explicitly ignored unless deliberately enabled.

Source extraction does not reduce review severity: auth subtree changes remain critical and HTTP subtree changes remain high. Automated evidence is separate from maintainer merge authorization and human review.
