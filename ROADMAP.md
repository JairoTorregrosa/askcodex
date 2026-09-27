# Roadmap

## Periodic re-verification of the image path

The subscription image endpoints ignore `model` and, as of the 2026-08-07
probes, `size`, `quality`, `output_format` and `n`, and return exactly one PNG
at a size the server chooses. That was proven with real calls, and it is the
reason askcodex exposes only a prompt, reference images, and an output path:
accepting a knob the server drops would be a default that masks failure.
`background: "transparent"` is honored since at least 2026-09-27 (one call);
a `--transparent` flag is the first candidate under rule 2 below, once more
than one call backs it (docs/PROTOCOL.md §5).

This is a server-side fact, not a contract. Candidate work:

1. Re-run the probe matrix each release and record the date in
   `docs/PROTOCOL.md` §5, so no belief about the backend goes stale.
2. Expose a knob only after a real call proves the server honors it, and
   ship the transcript as the PR's behavior evidence.
3. Fail loudly if a response ever arrives as a non-PNG payload rather
   than writing whatever came back.

## System-keyring credential storage

codex can store credentials in the system keyring instead of
`auth.json`, selected by its `AuthCredentialsStoreMode`. askcodex reads the
file only; in the keyring case it exits non-zero and tells the user to log
in with file-based storage. That is honest, and it is also a gap.

Candidate work: native keyring read support behind the same `Secret`
newtype, with the file path unchanged and the refresh/persist invariants
re-derived for a store that has no atomic-rename equivalent. A partial
implementation that silently falls back to the file is not acceptable.

## Publication to crates.io

The package metadata (description, keywords, categories, dual
`MIT OR Apache-2.0` license, repository URL, release profile) is ready.
Candidate work: reserve the name, verify `cargo package` contents exclude
every local artifact, and publish from a tagged release so the crate and
the GitHub binaries carry the same version.
