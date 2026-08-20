# Instructions for coding agents

This file tells a coding agent how to install, verify, and modify this
project safely. If you are a human, read [README.md](README.md).

askcodex drives the ChatGPT/Codex **subscription** backend with the tokens
`codex login` already stored in `~/.codex/auth.json`. There is no API key
in this project. `OPENAI_API_KEY` is not read, not accepted, and not a
fallback — anywhere.

## Task: install askcodex for the user

### Preconditions — verify, do not assume

1. Run `cargo --version`. Require 1.88 or later: that is the `rust-version`
   (MSRV) declared in `Cargo.toml`. `rust-toolchain.toml` pins builds to
   channel `1.97.1`, which rustup fetches automatically inside the repo.
   If Rust is missing, stop and tell the user to install it from
   https://rustup.rs. Do not build with an older compiler.
2. Confirm the credential file parses. Honor `CODEX_HOME`; it defaults to
   `~/.codex`. Check it **programmatically** — this command prints nothing
   and exits non-zero if the file is missing or malformed:

```sh
python3 -c 'import json,os;h=os.environ.get("CODEX_HOME") or os.path.expanduser("~/.codex");json.load(open(os.path.join(h,"auth.json")))'
```

   If it fails because the file is absent, stop and tell the user to run
   `codex login`. If it fails to parse, STOP and report the parse error —
   do not repair, rewrite, or overwrite the file.
3. Confirm the tokens live in the file and not in the system keyring.
   codex can store the same credentials in the keyring depending on its
   `AuthCredentialsStoreMode`; in that case `auth.json` parses but carries
   no `tokens`. This command prints nothing and exits non-zero in the
   keyring case:

```sh
python3 -c 'import json,os,sys;h=os.environ.get("CODEX_HOME") or os.path.expanduser("~/.codex");d=json.load(open(os.path.join(h,"auth.json")));sys.exit(0 if ((d.get("tokens") or {}).get("access_token")) else 1)'
```

   If it exits non-zero, STOP. Tell the user askcodex needs file-based
   credential storage and to run `codex login` with that mode. Do not
   invent a credential from anywhere else.
4. Confirm `~/.claude/skills/` and `~/.agents/skills/` exist or can be
   created.

Both checks above test for the *presence* of a key. They never print a
value. Never `cat` `auth.json`, never echo a token, never paste any part
of the file into a message, a log, a commit, or a PR.

### Steps — idempotent, safe to re-run

Run `./install.sh`, or run these steps yourself; either way verify the
postconditions afterwards. This list is every file operation the script
performs, in the order it performs them; everything else it does is
printed output — the notes and the rollback line under "Report to the
user". `install.sh` resolves every path from its own location, so it can
be started from any working directory and always builds and installs the
checkout that contains it.

1. Require `cargo`, and require `cargo --version` to report 1.88 or later
   (the MSRV), then `cargo build --release` in that checkout.
2. `mkdir -p ~/.local/bin && install -m 755 <checkout>/target/release/askcodex ~/.local/bin/askcodex`.
   Use `mkdir -p`, never `install -d`: `install -d` forces mode 0755 on an
   existing directory and would silently relax a `~/.local/bin` the user
   hardened.
3. Check postconditions 1 and 2 below **before anything under `~/.claude`
   or `~/.agents` is touched**, so a broken install cannot rewrite the
   user's skill directories. A failure here stops the install with no
   skill written at all — which is why running `install.sh` without
   `codex login` leaves a binary and no skill.
4. Wire the skill into `~/.claude/skills/askcodex`, then identically into
   `~/.agents/skills/askcodex` (the cross-agent skills directory). For each
   destination `<skills>/askcodex`, hold the exclusive lock directory
   `<skills>/askcodex.lock` for that destination's whole operation (two
   concurrent installs must not race over the backup). Copy the repo's
   `skill/` to `<skills>/askcodex.new`, and only once that copy is complete
   move any existing `<skills>/askcodex` aside and rename the staging
   directory into place — `<skills>/askcodex` is therefore always either the
   complete old tree or the complete new one. The backup is
   `<skills>/askcodex.bak`, or a timestamped `<skills>/askcodex.bak.<UTC stamp>`
   when `askcodex.bak` is already taken: an existing backup is **never
   overwritten or deleted**, because it may be the user's only copy of
   what was there before askcodex, and it is the rollback this task reports.
   If `<skills>/askcodex` is already byte-for-byte the repo's `skill/`, it is
   left alone and no backup is made.

Re-running converges on the repo's current `skill/`; it never merges two
versions.

### Postconditions — verify before you report success

1. `~/.local/bin/askcodex --help` exits 0.
2. `~/.local/bin/askcodex auth status --no-refresh` exits 0. Check the exit
   code and discard the output (`>/dev/null`): it never prints a token
   value, but it does print the `account_id` and the auth-file path, which
   the Prohibitions below forbid you from printing or logging.
   `--no-refresh` is mandatory here: install must not mutate `auth.json`.
3. `~/.claude/skills/askcodex/SKILL.md` and `~/.agents/skills/askcodex/SKILL.md`
   exist.

If a postcondition fails, say so and stop. A failed install reported as a
success is worse than no install.

### Report to the user

- For each skill destination (`~/.claude/skills/askcodex` and
  `~/.agents/skills/askcodex`): whether a previous version existed, and the
  backup path if one was made. The rollback is: restore each backup and
  delete `~/.local/bin/askcodex`.
- Whether the bare name `askcodex` on the user's PATH resolves to the binary
  just installed. `install.sh` prints a note when another copy shadows it;
  repeat that note, because every command in the skill uses the bare name.

### Prohibitions

- Do not use sudo. Nothing here needs root.
- Never print, log, or store a token value, an `account_id`, a `user_id`,
  or an email address.
- Never trigger a token refresh during install. Every auth-touching
  command in this task carries `--no-refresh`.
- Never write to `~/.codex/auth.json`, and never create, move, or delete
  anything else under `~/.codex`. It is read-only for install.
- Do not touch `~/.claude/settings.json` or any other Claude Code config.
  askcodex installs a skill; it does not configure the host.
- Touch nothing outside `~/.local/bin/askcodex`, `~/.claude/skills/askcodex*`,
  and `~/.agents/skills/askcodex*`,
  beyond what the build itself writes: step 1 is `cargo build --release`,
  which populates the checkout's `target/` directory and `$CARGO_HOME`
  (`~/.cargo`), and makes rustup fetch the pinned toolchain into
  `$RUSTUP_HOME` (`~/.rustup`) if it is not already there. Nothing in the
  printed rollback removes those; say so if the user asks what was
  written.

## Task: contribute a change

1. Read [agm.json](agm.json). Compute the risk zone: for each changed
   file, take the highest-severity zone whose pattern matches it; the
   change's zone is the highest across all files. `src/auth.rs`,
   `install.sh`, `skill/`, `.github/`, and the governance files are
   critical.
2. Prepare the evidence package in the pull-request body with the
   sections agm.json requires for that zone. Start from
   `.github/PULL_REQUEST_TEMPLATE.md`. Its headings and the confirmation
   line are matched literally by the gate — edit the prose between them,
   never the headings themselves.
3. State every external assumption (the `auth.json` schema, backend
   response shapes, the OAuth refresh contract, SSE event framing) and how
   you verified it against real calls. Redact every transcript you paste:
   `acct_REDACTED`, `user_REDACTED`, `email_REDACTED`, and no token values
   at all. Declare what you could not verify. An unverified assumption
   stated as fact is a governance failure, not a shortcut.
4. For high and critical zones: STOP before you submit. Show the human the
   diff and the package. Ask the human to check the confirmation box. Do
   not check it yourself.
5. Never claim maintainer approval. The `AGM` check passing is not
   approval; the maintainer's review is.
6. Disclose your tool and model in the PR body. Keep the
   `Co-Authored-By` trailer on commits.

## Task: modify the code

- Obey the rules in [DESIGN.md](DESIGN.md) and the wire facts in
  [docs/PROTOCOL.md](docs/PROTOCOL.md). Both are contracts, not notes.
- Run `cargo test` and `cargo clippy --all-targets -- -D warnings` before
  you report done. CI enforces both, plus `cargo fmt --check`.
- Token values ride in the `Secret` newtype (`src/redact.rs`). `Debug` and
  `Display` redact; `Secret::expose()` is the only exposure path and
  belongs in HTTP headers and bodies. No code path may print, log, or
  serialize a token value into an error, a test fixture, or a file in this
  repo.
- `src/auth.rs` is the highest-stakes module: it rewrites the user's real
  credentials. Its invariants are absolute — write atomically through a
  same-directory temp file created 0600 before the first byte, back up
  `auth.json` before replacing it, leave the file either the complete old
  or the complete new document on every path, and never discard a working
  refresh token because a refresh call failed. A bug here locks the user
  out of codex.
- No API key, ever. `OPENAI_API_KEY` may appear only in a sentence saying
  it is not used.
- No defaults that mask failure. Missing auth, a failed refresh, an
  unexpected response shape, a non-image payload: loud error on stderr,
  non-zero exit. No placeholder output, no silent fallback, no retry loop
  that hides the root cause.
- Every new response field is an `Option` and ships with a test that
  exercises the field being absent. Unknown keys round-trip; askcodex never
  clobbers a codex-internal field it does not understand.
- Every test that touches auth sets `CODEX_HOME` to a fresh temp
  directory. No test, fixture, or CI job may read or write the user's real
  `~/.codex`. Live tests are opt-in via `ASKCODEX_LIVE=1` and never run in CI.
