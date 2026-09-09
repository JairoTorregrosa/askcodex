# Output contract — schema version 1

The CLI's package version and output schema version are independent. This release introduces schema version 1 for semantic machine output. Scripts written for 0.0.1's unwrapped --json results must select .result in the new envelope.

## Human output

Without --json or --events, stdout contains the requested text, account/model presentation, or image-save result. Ask flushes text deltas as they arrive. A completed empty ask produces no invented text and explains the empty result on stderr. Transcription prints its text followed by a newline, including an empty transcript.

Errors go to stderr. Operational failures exit 1; invalid arguments exit 2.

## JSON

Every semantic --json success prints exactly one document:

```json
{"schema_version":1,"command":"transcribe","result":{"text":"Example transcript."},"backend":{"text":"Example transcript."}}
```

| Command | Stable result fields |
| --- | --- |
| reference | markdown |
| whoami | email, name, plan_type, account_id, user_id (nullable) |
| usage | email, user_id, account_id, plan_type, rate_limit (nullable); nested rate-limit fields follow the public model |
| models | models array; slug, input_modalities, supported_reasoning_levels, visibility and other modeled optional catalog fields |
| transcribe | text |
| ask | model, effort, text, usage (effort/usage may be null) |
| image create / image edit | path, size, bytes, ref_images (size may be null; ref_images is 0 for create or the count for edit) |
| auth status | auth_file, auth_mode, account_id, last_refresh, access_token_expires_at, access_token_expires_in_minutes, access_token_valid |
| auth refresh | refreshed, last_refresh, access_token_expires_at, access_token_expires_in_minutes, access_token_valid |

The command field uses spaces for nested commands, for example auth status and image edit.

The optional backend field is present for usage, models and transcribe and contains their complete original response, including unknown keys. It is an inspection surface, not a stable server schema. Ask preserves the usage object supplied by the terminal event inside result.usage. Image JSON describes the saved artifact and does not duplicate base64 image bytes.

Example selectors:

```sh
askcodex ask "Explain this briefly" --json | jq -r .result.text
askcodex models --json | jq '.result.models'
askcodex usage --json | jq '.result.rate_limit'
askcodex usage --json | jq '.backend'
```

## Events

--events and --json are mutually exclusive. All semantic commands support --events. Each stdout line is a complete compact JSON document and is flushed before delivery continues.

Ask emits zero or more text deltas, then one result:

```json
{"schema_version":1,"event":"text_delta","delta":"Hello"}
{"schema_version":1,"event":"result","command":"ask","result":{"model":"example","effort":null,"text":"Hello","usage":null}}
```

Other semantic commands emit one result event, with the same command/result/backend fields as JSON mode. A successfully completed empty answer has a result event and no invented delta.

If the backend fails, the stream ends early, or the consumer closes its pipe, no final result event is emitted. Previously emitted deltas are partial output, not evidence of success. A failed write stops reading the backend immediately.

## Errors

In --json and --events modes, operational failures emit one JSON diagnostic on stderr:

```json
{"schema_version":1,"error":{"code":"input_invalid","message":"invalid input: stdin must be UTF-8 text"}}
```

Codes are stable; messages provide context and may change:

- input_invalid, input_unreadable
- auth_required, auth_invalid, auth_refresh_failed, auth_persist_failed, auth_busy
- untrusted_origin, transport_error, http_error, rate_limited
- response_invalid, stream_failed, io_error

Inspect the process exit status as well as the stream. Argument parsing uses Clap's human diagnostic and exit 2, including incompatible flags. Operational errors are never encoded as successful results.

## Raw

raw is explicit access to the backend protocol. Nonstreaming raw prints its JSON response without a schema envelope. HTTP 204/205 prints null. raw --stream copies response bytes verbatim.

--json does not change raw's payload. With raw --stream it emits an explanatory stderr advisory; a later operational failure may follow that advisory. --events is rejected for raw before credentials are loaded.
