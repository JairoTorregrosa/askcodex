# Security

askcodex reads and rewrites a live OAuth credential — the ChatGPT/Codex
subscription tokens `codex login` stored in `${CODEX_HOME:-~/.codex}/auth.json`.
A bug here does not produce a wrong number; it hands someone else an account,
or locks the owner out of theirs. This file states what askcodex guarantees, what
it does not, and how to report a failure of either.

## Reporting a vulnerability

Report privately through GitHub's
[security advisories](https://github.com/JairoTorregrosa/askcodex/security/advisories/new).
Do not open a public issue for a credential-handling flaw.

**Never include a real token, `account_id`, `user_id`, or email address in a
report.** A reproduction can always be written against a fabricated
`auth.json`; the maintainer will not ask for a real one. If you believe your
own credentials were exposed by an askcodex bug, rotate them first with
`codex login`, then report.

Expect an acknowledgement within a week. This is a single-maintainer project,
so please size your disclosure timeline accordingly.

## What askcodex guarantees

These are invariants, enforced by code and by tests that fail if they break.

**Credentials go to exactly one origin.** The backend host is the
compile-time constant `config::BASE_URL`, and the trusted origin is derived
from it rather than written down a second time. The bearer token and
`chatgpt-account-id` header are attached only to requests aimed at that
origin. `askcodex raw` takes its target from the command line and is therefore
checked twice: once in the argument parser, and again as the first statement
of the function that builds the request. Scheme equality is part of the
comparison, so an `http://` downgrade of the backend host is refused too.

There is deliberately **no environment variable and no flag that widens the
trusted origin.** Such a knob is the same vulnerability with a supported
name, and requests for one will be declined.

**Token values cannot be printed.** Every token rides in a `Secret` newtype
whose `Debug` and `Display` render a redaction, so a value cannot reach a log
line, an error message, a panic, or a test fixture by accident.
`Secret::expose()` is the single, greppable exposure path and belongs in HTTP
headers and bodies. No `*_token: String` field exists in the crate. Errors
carry claim *names*, HTTP statuses, and bounded body snippets — never values.

**`auth.json` is rewritten atomically or not at all.** A same-directory temp
file is created `0600` by the kernel before the first byte is written, then
flushed, fsynced, and renamed, with a backup taken first. On every path the
file is either the complete old document or the complete new one, and keys
askcodex does not model round-trip untouched. A refresh whose HTTP call fails
leaves both the file and memory alone, because the previous refresh token is
still valid and discarding it would lock the user out. Concurrent refreshes
are serialized by a lock on the credential file; askcodex refuses rather than let
two processes rotate the same token.

**No API key, ever.** `OPENAI_API_KEY` is not read, not accepted, and not a
fallback. The only credential source is the subscription tokens on disk.

**Nothing in this repository is a credential.** Every committed fixture is
fabricated, every transcript is redacted to `acct_REDACTED` / `user_REDACTED`
/ `email_REDACTED`, and no test reads or writes the real `~/.codex` — every
test that touches auth points `CODEX_HOME` at a temp directory. Live tests
are opt-in behind `ASKCODEX_LIVE=1` and never run in CI; CI holds no credentials.

## What askcodex does not protect against

Stated plainly, because an unlisted limitation reads as a guarantee.

- **A compromised local account.** `auth.json` is a file readable by its
  owner. Anything running as that user can read it directly, with or without
  askcodex. askcodex does not add a passphrase, a keyring, or an enclave.
- **The system keyring.** If codex stored the credentials in the keyring
  rather than the file, askcodex says so and exits non-zero. It does not read the
  keyring.
- **What you do with `raw`.** `askcodex raw` can call any backend path on the
  trusted origin, including ones askcodex does not model. The origin check bounds
  *where* your credential goes, not *what* you ask that origin to do.
- **Prompt injection reaching your shell.** askcodex is a well-behaved target — a
  hostile URL is refused — but an agent that can run arbitrary commands as
  you can read `auth.json` without askcodex's help. Sandbox the agent, not the
  CLI.
- **The backend itself.** The wire protocol is reverse-engineered and
  documented in [docs/PROTOCOL.md](docs/PROTOCOL.md) with each claim marked
  verified-live or declared unverified. It can change without notice.

## Supported versions

Only the latest release. This project is pre-1.0; fixes land on `main` and
ship in the next tag.
