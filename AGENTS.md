# Working on askcodex

askcodex is a Rust CLI for the ChatGPT/Codex subscription backend. It uses credentials created by `codex login`; no API key is read, accepted, or used.

## Product and architecture

- [docs/COMMANDS.md](docs/COMMANDS.md) is generated from Clap with `askcodex reference`. Edit the parser, then regenerate it.
- [docs/OUTPUT.md](docs/OUTPUT.md) defines schema version 1 and human/raw output.
- [DESIGN.md](DESIGN.md) defines internal boundaries and security invariants.
- [docs/PROTOCOL.md](docs/PROTOCOL.md) records dated backend evidence and unverified assumptions.
- [docs/MIGRATION-VERIFICATION.md](docs/MIGRATION-VERIFICATION.md) records migration acceptance.

Keep instructions and implementation aligned. Internal modules may change; preserve the documented public behavior or declare a versioned migration. A dated observation about the backend is not a permanent server guarantee.

## Build and verification

Use the pinned toolchain in `rust-toolchain.toml`; honor the MSRV in `Cargo.toml`.
Run `cargo fmt --check`, `cargo clippy --all-targets --locked -- -D warnings`, and `cargo test --locked`.
Changes to the installer also require `shellcheck install.sh tests/install.bats`, `shfmt -d install.sh`, and `bats tests/install.bats`.
The governance suite is `python3 -m unittest discover -s .github/scripts -p 'test_*.py'`.
CI verifies Linux, macOS, the MSRV, generated command documentation, and scripts.

Tests must use synthetic credentials and isolated paths. Offline tests never read or write the user's credential store, call the real backend, or spend quota. Live tests are explicitly ignored and also require the documented opt-in gates; do not enable them in CI. Run live checks with `--no-refresh` and suppress personal diagnostics.

Dependencies are reviewed changes, not forbidden changes. Keep Cargo.lock, validate required APIs and the MSRV, and preserve durable regression coverage for the behavior that motivates a dependency.

## Credential invariants

- Runtime secrets and credential documents have no generic serialization. Only private storage and OAuth adapters serialize their contents.
- Never print, log, commit, or include real tokens, account identifiers, user identifiers, email addresses, or private payloads in evidence. Synthetic test values are not real credentials.
- Only validated backend targets reach credential-header construction. Do not add a runtime origin or OAuth endpoint override. Test transport injection is compile-time only.
- Disable redirects on backend and OAuth requests. One 401 may trigger one refresh and one replay; never automatically replay a partially consumed stream.
- Resolve local files/stdin before loading or refreshing credentials. All reads are bounded.
- Credential writes use same-directory atomic replacement, mode 0600 from creation, safe backups, and preservation of unknown document fields.
- Never remove a persistent credential lock inode. Kernel lock ownership ends on descriptor close. This coordinates new askcodex processes, not Codex or older clients.
- A failed refresh retains existing credentials. A persistence failure after server rotation must state that recovery may require login.

## Installation

`./install.sh` builds and installs only `~/.local/bin/askcodex`; it requires no login and reads no credentials.
`--skills agents|claude|all` explicitly synchronizes the selected skill directories.
`--check-auth` explicitly checks authentication without refresh and suppresses personal output.

Verify the installed binary's help and PATH resolution. When skills are requested, verify their content and report any backup paths. Preserve existing directory permissions, immutable backups, staging and rollback. Do not alter host-agent configuration. Installation never writes the credential store or triggers refresh.

## Contribution and merge

Read [agm.json](agm.json) and [GOVERNANCE.md](GOVERNANCE.md). The highest matched risk zone applies; all of `src/auth/` is critical and `src/http/` is high. Use the PR template's exact evidence headings.

High/critical changes document assumptions, risk, and validation. Critical changes also need an independent second reviewer, which may be an agent or a human. Record the actual review and resolved findings.

Follow the user's authorized implementation and merge scope. Disclose delegation and the authorizing maintainer; do not impersonate a human or claim human code review from a checkbox or an automated pass. Authenticated GitHub permissions and configured review rules control merges. Never bypass required checks or review rules. A migration PR remains governed by the base-branch gate.

Include the tool/model disclosure and a Co-Authored-By trailer. Resolve review feedback, pass final-head CI, merge, and verify main CI and the installed artifact before reporting completion.
