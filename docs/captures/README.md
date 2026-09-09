# Original redacted captures

`responses-sse-2026-08-07.txt` is restored byte-for-byte from
`2f29bec:docs/samples/responses-sse.txt`. It is an already redacted historical
capture, not a newly collected live response. Its Git blob is
`b04691041fd3cdad5b4d70ba6cb17a7ca5c40276`; SHA-256 is
`d38cd6731b17d259f12ba4e42e1dc85cc889e31ca410f8a3145a2f6b509f3158`.

The capture is truncated: it ends with the `response.completed` event header,
without that event's data or a trailing newline. It cannot prove that a full
stream completed successfully. Preserve its payloads and framing unchanged;
new captures belong in separately dated files.

The executable fixture [responses-sse.txt](../samples/responses-sse.txt) is an
adaptation with provenance comments and a synthetic sentinel. Its first two
text deltas change `CS` / `UB` to `ASK` / `CODEX`, and the three completed
text fields change `CSUB-VERIFY-OK` to `ASKCODEX-VERIFY-OK`. All other payload
fields, including timestamps, model, obfuscation and sequence numbers, are
unchanged. Those inherited metadata values describe the original capture;
they do not substantiate the adapted text as a live server response.

`tests/fixtures.rs` scans both captures and adapted samples for unredacted
identifiers and tokens, pins the original capture's Git blob using the local
Git CLI, and compares the adaptation structurally against only the declared
substitutions. Tests need no repository history, network or credentials.
