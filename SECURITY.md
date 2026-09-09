# Security

askcodex uses the ChatGPT/Codex subscription credentials in
`${CODEX_HOME:-~/.codex}/auth.json`. Credential renewal and persistence are
security-sensitive operations. This document describes the protections and
their limits; [DESIGN.md](DESIGN.md) explains the implementation boundaries.

## Report a vulnerability

Report credential-handling vulnerabilities privately through
[GitHub security advisories](https://github.com/JairoTorregrosa/askcodex/security/advisories/new).
Use fabricated credentials in reproductions. Never include real tokens,
account identifiers, user identifiers, or email addresses. If credentials
were exposed, sign in again with `codex login` before reporting.

Expect acknowledgement within a week. This is a single-maintainer project.

## Credential destinations

Backend requests attach bearer and account headers only to the origin derived
from the fixed `config::BASE_URL`, comparing scheme, host and effective port.
Raw arguments are checked during parsing; the private `http/target::Target`
constructor enforces the policy before the sender can attach credentials.
A foreign host or HTTP downgrade is rejected. Test-only loopback injection
does not exist in the production interface.

Refresh tokens go only to the fixed OAuth endpoint in `config::TOKEN_URL`.
Neither destination can be widened through a flag, environment variable or
configuration file. Backend and OAuth requests disable redirects; OAuth
enforces this at request scope independently of the supplied agent's defaults.

The origin boundary restricts where credentials go. `raw` can still invoke
arbitrary operations on the trusted backend. It is not an endpoint allowlist.

## Credential representation and storage

`Secret` redacts Debug and Display output. `Secret`, `AuthFile` and
`AuthTokens` have no general Serialize implementation. Private adapters in
`auth/store` and the OAuth boundary explicitly expose values only where
persistence or protocol transmission requires them. Credential Debug output
also hides unknown fields; parse diagnostics omit document values.

`CredentialStore` retains one resolved path. `AuthSession` owns the loaded
document and its store, so transport construction does not independently
resolve environment variables or load another credential generation.

Persistence preserves unknown JSON keys. Backup and temporary files are
created with mode 0600 before bytes are written; the replacement is flushed,
synced and atomically renamed within the same directory. A failed remote
renewal does not discard the stored tokens. A persistence failure after
remote rotation is different: the previous backup may already contain an
invalid refresh token, so the error reports recovery information. Directory
entry durability across power loss is not guaranteed.

A kernel-held exclusive lock spans credential reread, renewal and persistence.
Its `.lock` file is a persistent regular inode, opened without following
symlinks and with close-on-exec. It is not unlinked based on age or PID.
Process exit releases the lock automatically.

This lock coordinates cooperating current askcodex processes. Codex and older
askcodex versions with an unlink-based lock do not participate. Rereading under
the lock can adopt a newer token generation; it cannot exclude arbitrary
external writers or guarantee preservation of concurrent same-token metadata edits.

`--no-refresh` disables automatic renewal. Explicit `auth refresh` still
requests rotation. Default installation neither reads credentials nor installs
skills; `--check-auth` performs a no-refresh check and suppresses its account
details. Skill installation is separately selected with `--skills`.

## Inputs, output and tests

Local inputs are prepared before credentials are loaded. Stdin is bounded to
16 MiB UTF-8; WAV files and the combined image references each have a 25 MiB
client budget. Media must be regular files, including regular symlink targets;
devices and FIFOs are rejected. These are memory policies, not backend limits.
Responses are capped at 64 MiB. A failed stream consumer stops further reading.

Operational failures exit nonzero and go to stderr. Machine output follows
[docs/OUTPUT.md](docs/OUTPUT.md); partial deltas are never a successful final
result. Account output and backend payloads can contain personal information:
the Secret type does not sanitize arbitrary backend text or user-supplied data.
Redact material before sharing logs or transcripts.

Offline tests use fabricated credentials in temporary stores and loopback
HTTP. Committed evidence consists of redacted captures and clearly identified
adapted fixtures; see [capture provenance](docs/captures/README.md).
Live tests are ignored by default and require explicit execution plus
authorization gates. They never run in CI, never refresh credentials and
are the documented exception that reads real credentials. CI holds no account
credentials. See [testing](docs/TESTING.md) for exact commands and costs.

`OPENAI_API_KEY` is not read, accepted or used as a fallback. Keyring-only
Codex credentials are not supported.

## Limits of protection

- A process running as the local user can read that user’s credential file.
  askcodex does not provide an enclave, passphrase or additional user boundary.
- An agent allowed to execute arbitrary shell commands can bypass askcodex.
  Origin validation does not sandbox that agent or prevent prompt injection.
- Backend responses and protocol behavior can change without notice.
  [Protocol evidence](docs/PROTOCOL.md) records dated observations and unverified
  assumptions; offline tests cannot establish current backend compatibility.
- The credential lock does not coordinate external applications, and atomic
  replacement cannot reverse a successful server-side token rotation.

## Supported versions

Only the latest release is supported. Fixes land on `main` and ship in the
next tag.
