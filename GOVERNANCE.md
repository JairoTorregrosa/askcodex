# Governance

This document makes agent-mediated contributions reviewable. The rules
live in machine-readable form in [agm.json](agm.json); this file explains
them for humans.

## Why

Agents make contributions cheap to produce. They do not make
contributions cheap to verify. One maintainer reviews every change; a
review is only as fast as the information in front of it. These rules
move the preparation of that information to the contributor and the
contributor's agent, and keep the decision with the maintainer.

The principle is the same one askcodex itself follows: absence must be
declared, not silent. askcodex never fakes a success — a missing credential,
a failed refresh, or an unexpected response shape exits non-zero with a
clear message instead of printing something plausible. A contribution
never presents an unverified assumption as a verified one; it declares
what was checked and what was not.

Three files divide the work. [AGENTS.md](AGENTS.md) tells an agent how to
install, verify, and modify the project. Commit trailers record which tool
produced a change. This document and [agm.json](agm.json) define what a
change must prove before review.

## Risk zones

Every file belongs to a zone. A change's zone is the highest zone among
its changed files.

| Zone | Files | Why |
|---|---|---|
| critical | `install.sh`, `.github/*`, `AGENTS.md`, `CLAUDE.md`, `GOVERNANCE.md`, `agm.json`, `src/auth.rs`, `skill/*` | Writes to user machines, publishes binaries, instructs agents, or changes the rules of review itself. `auth.rs` rewrites the user's real credentials in `~/.codex/auth.json`: a bug there can lock the user out of codex. The `skill/` files are installed into `~/.claude/skills/` and instruct agents. `CLAUDE.md` is a symlink to `AGENTS.md`; replacing it with a file is an agent-instruction change. |
| high | `http.rs`, `main.rs`, `endpoints/*`, `config.rs`, `Cargo.toml`, `Cargo.lock` | Network calls to the live backend, header and error handling, `CODEX_HOME` resolution, the CLI entry point, dependency supply chain. |
| medium | the rest of `src/` | Correctness of output. The product is a truthful CLI; a faked success or a wrong number is worse than a loud error. |
| low | documentation, assets | No runtime effect. |

## Evidence packages

The pull-request body carries the evidence. The required sections grow
with the zone:

| Zone | Required sections |
|---|---|
| low | none — open the PR and CI does the rest |
| medium | Summary · Checks · Behavior evidence |
| high | + External assumptions · Risk |
| critical | + Second review · Human confirmation |

**External assumptions** is the section that tests cannot replace. This
project reads data it does not control: the `auth.json` schema written by
codex, the shapes the `chatgpt.com/backend-api/codex/*` endpoints return,
the OAuth refresh contract, and the framing of the SSE event stream. All
of it is reverse-engineered and can change without notice — see
[docs/PROTOCOL.md](docs/PROTOCOL.md), which marks each fact as verified
against a real call or explicitly declared unverified. CI has no live
backend and no credentials, so a change built on a wrong schema belief
passes CI and still fails — or lies — at runtime. State each belief and
how you verified it against real data.

Evidence is redacted evidence. Paste transcripts with `acct_REDACTED`,
`user_REDACTED`, `email_REDACTED`, and never any token value. A token in a
PR body is a leaked credential, not proof.

**Second review** means an adversarial pass by a second agent or a human:
someone whose task is to refute the change, with findings and their
resolution recorded.

**Human confirmation** is a checkbox only the human contributor sets. An
agent prepares the package; it never confirms it. This is the boundary
between preparation and responsibility.

## Gates

The `AGM` workflow enforces the mechanical gates on every pull request:
it computes the zone from the changed files, compares it with the
declared zone, and checks that the required sections and the
confirmation box are present. Its job summary is the review packet: zone,
evidence status, missing items.

The gate matches the section headings and the confirmation line from
`agm.json` as exact substrings of the pull-request body, and
`.github/PULL_REQUEST_TEMPLATE.md` supplies those exact strings. Editing a
heading on one side alone breaks the gate for everyone; change both
together, and remember that touching either file is itself a critical
change.

The final gate — approval — belongs to the maintainer. No tool sets it,
no contributor statement substitutes for it, and a green `AGM` check does
not imply it.

## Proportionality

A low-risk change carries no added burden: fix a typo, open the PR, done.
The obligations concentrate where a wrong change hurts: the installer that
writes to the user's machine, the workflows that publish binaries, the
skill that instructs other agents, and `src/auth.rs`, which rotates and
rewrites real credentials. For changes that need assurance beyond these
rules (signed commits, protected branches), the maintainer can add
platform controls on top; this document does not replace them.
