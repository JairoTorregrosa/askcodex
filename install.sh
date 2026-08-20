#!/bin/sh
# Installer for askcodex. Safe to re-run.
# Builds the release binary, installs it to ~/.local/bin, and copies the
# repo's skill/ directory to ~/.claude/skills/askcodex and ~/.agents/skills/askcodex
# (moving any previous version aside first, and never overwriting an
# existing backup, so there is always a rollback).
#
# This script is the executable form of the "Task: install askcodex for the
# user" section of AGENTS.md. Beyond the build's own artifacts — step 1 is
# `cargo build --release`, which writes this repo's target/ directory and
# populates $CARGO_HOME (~/.cargo) and, through rustup, $RUSTUP_HOME
# (~/.rustup) — it writes exactly three things:
#   ~/.local/bin/askcodex, ~/.claude/skills/askcodex*, and ~/.agents/skills/askcodex*
# It never uses sudo, never writes to ~/.codex, never edits
# ~/.claude/settings.json, and never triggers a token refresh.
set -eu

say() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

# Every path below is resolved from the script's own location, never from
# the caller's cwd: `sh /path/to/askcodex/install.sh` run from anywhere must
# build and install THAT checkout, not whatever tree the caller sits in.
REPO="$(CDPATH='' cd -- "$(dirname -- "$0")" >/dev/null 2>&1 && pwd)" ||
    die "cannot resolve the directory holding $0"
cd "$REPO" || die "cannot enter $REPO"
[ -f "$REPO/Cargo.toml" ] ||
    die "$REPO/Cargo.toml not found — install.sh must be run from inside an askcodex checkout"
grep -q '^name = "askcodex"$' "$REPO/Cargo.toml" ||
    die "$REPO/Cargo.toml is not askcodex's — install.sh must be run from inside an askcodex checkout"

# --- preconditions --------------------------------------------------------
command -v cargo >/dev/null 2>&1 || die "Rust is required. Install it from https://rustup.rs"

# MSRV gate. Cargo.toml declares rust-version 1.88. rust-toolchain.toml
# pins 1.97.1, but only rustup honours it: a distro or Homebrew cargo below
# the MSRV would otherwise reach `cargo build` and fail with a raw compiler
# error instead of this message.
CARGO_VERSION="$(cargo --version 2>/dev/null | awk 'NR == 1 { print $2 }')"
MSRV_HELP="askcodex needs Rust 1.88 or later. Update with \`rustup update\`, or install
       Rust from https://rustup.rs"
case "$CARGO_VERSION" in
    [0-9]*.[0-9]*) ;;
    *) die "could not read a version out of \`cargo --version\` (got '$CARGO_VERSION'). $MSRV_HELP" ;;
esac
CARGO_MAJOR="${CARGO_VERSION%%.*}"
CARGO_MINOR="${CARGO_VERSION#*.}"
CARGO_MINOR="${CARGO_MINOR%%.*}"
CARGO_MINOR="${CARGO_MINOR%%-*}"
case "$CARGO_MAJOR:$CARGO_MINOR" in
    *[!0-9:]*) die "could not read a version out of \`cargo --version\` (got '$CARGO_VERSION'). $MSRV_HELP" ;;
esac
if [ "$CARGO_MAJOR" -lt 1 ] || { [ "$CARGO_MAJOR" -eq 1 ] && [ "$CARGO_MINOR" -lt 88 ]; }; then
    die "cargo $CARGO_VERSION is older than askcodex's minimum supported Rust. $MSRV_HELP"
fi

# --- step 1: build --------------------------------------------------------
say "› building (release)"
cargo build --release

BUILT="$REPO/target/release/askcodex"
[ -f "$BUILT" ] || die "the build produced no $BUILT (is CARGO_TARGET_DIR set?)"

# --- step 2: install the binary -------------------------------------------
BIN="$HOME/.local/bin/askcodex"
# mkdir -p, never `install -d`: install(1) forces mode 0755 on the final
# component even when it already exists, which would silently relax a
# ~/.local/bin the user hardened. mkdir -p leaves an existing directory
# exactly as it is, and creates a missing one under the user's umask.
mkdir -p "$HOME/.local/bin" || die "cannot create $HOME/.local/bin"
install -m 755 "$BUILT" "$BIN" ||
    die "cannot write $BIN — check the permissions of $HOME/.local/bin"
say "› installed $BIN"

# --- postconditions 1 and 2: the binary runs, and it can read the tokens ---
# Both checks run before anything under ~/.claude is touched, so a broken
# install stops before it rewrites the user's skill directory.
say "› verifying binary"
"$BIN" --help >/dev/null || die "binary failed the smoke test"

# --no-refresh is mandatory here: installing must never rotate the user's
# real tokens. Output is suppressed on purpose — `auth status` prints the
# account_id, and installer logs get pasted into issues.
# shellcheck disable=SC2016  # the ${...} below is documentation, not code.
# Single quotes are the point: the user must READ `${CODEX_HOME:-~/.codex}`,
# the same notation README.md, SECURITY.md and skill/SKILL.md use to name
# where askcodex looks. Expanding it would delete the variable's name from the
# message and print only a path — and CODEX_HOME is usually unset, so it
# would tell the reader nothing they could act on.
AUTH_HELP='auth check failed. askcodex reads ChatGPT-subscription tokens from
       ${CODEX_HOME:-~/.codex}/auth.json. Run `codex login` with file
       credential storage, then re-run ./install.sh.'
"$BIN" auth status --no-refresh >/dev/null || die "$AUTH_HELP"
say "› auth readable (nothing was refreshed, no secret was printed)"

# --- step 3: wire the skill, previous version moved aside -----------------
# The skill is installed twice, with identical semantics: once for Claude
# Code (~/.claude/skills) and once into the cross-agent skills directory
# (~/.agents/skills), so agents that read either location find it.
SRC="$REPO/skill"
[ -d "$SRC" ] || die "skill directory not found at $SRC — install.sh must stay inside an askcodex checkout"
[ -f "$SRC/SKILL.md" ] || die "$SRC/SKILL.md is missing — refusing to install an empty skill"

# State shared with the EXIT trap. Each wire_skill call resets it; the trap
# only ever has to unwind the destination currently in flight.
DST=""
STAGE=""
LOCK=""
BAK=""
SAME=0
SWAPPED=0
LOCKED=""

# The first backup gets askcodex.bak; later ones get a timestamped path. This
# function only ever returns a path that does not exist, so no backup can
# be overwritten by a re-run.
backup_path() {
    if [ ! -e "$DST.bak" ] && [ ! -L "$DST.bak" ]; then
        printf '%s\n' "$DST.bak"
        return 0
    fi
    _stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    _n=0
    while [ "$_n" -lt 100 ]; do
        if [ "$_n" -eq 0 ]; then
            _cand="$DST.bak.$_stamp"
        else
            _cand="$DST.bak.$_stamp.$_n"
        fi
        if [ ! -e "$_cand" ] && [ ! -L "$_cand" ]; then
            printf '%s\n' "$_cand"
            return 0
        fi
        _n=$((_n + 1))
    done
    return 1
}

# Leaves the destination as it was found, on every path out of the script:
# the staging copy is discarded, and a backup taken between the two renames
# is put back.
cleanup() {
    _status=$?
    if [ -n "${LOCKED:-}" ]; then
        rm -rf "$STAGE" 2>/dev/null || :
        if [ "$SWAPPED" -eq 0 ] && [ -n "$BAK" ] && [ ! -e "$DST" ] && [ ! -L "$DST" ]; then
            mv "$BAK" "$DST" 2>/dev/null || :
        fi
        rmdir "$LOCK" 2>/dev/null || :
    fi
    return "$_status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

# Wire the repo's skill/ into $1/askcodex with staging, locking, and backups.
# Leaves per-destination results in DST/BAK/SAME for the caller to report.
wire_skill() {
    SKILLS="$1"
    DST="$SKILLS/askcodex"
    STAGE="$DST.new"
    LOCK="$DST.lock"
    BAK=""
    SAME=0
    SWAPPED=0
    LOCKED=""

    # Every path this function creates under $SKILLS matches askcodex*, the
    # surface declared in the header and in AGENTS.md — the lock included.
    mkdir -p "$SKILLS" || die "cannot create $SKILLS"

    # mkdir is the atomic test-and-set: two overlapping runs must not race
    # over the backup, or one of them deletes the only copy of the user's
    # skill.
    if ! mkdir "$LOCK" 2>/dev/null; then
        if [ -d "$LOCK" ]; then
            die "another ./install.sh is wiring $SKILLS (lock: $LOCK). Wait for it to
       finish; if no install is running, remove that directory by hand."
        fi
        die "cannot create the install lock at $LOCK — is $SKILLS writable?"
    fi
    LOCKED=1

    # Build the new skill beside the destination and rename it into place,
    # so $DST is only ever the complete old tree or the complete new one. A
    # copy that fails halfway (unreadable file, ENOSPC, Ctrl-C) leaves $DST
    # alone.
    if [ -e "$STAGE" ] || [ -L "$STAGE" ]; then
        say "› discarding $STAGE left behind by an interrupted install"
        rm -rf "$STAGE"
    fi
    cp -R "$SRC" "$STAGE" || die "could not stage the skill at $STAGE — $DST was left untouched"
    [ -f "$STAGE/SKILL.md" ] || die "staged skill is incomplete: $STAGE/SKILL.md is missing"

    if [ -e "$DST" ] || [ -L "$DST" ]; then
        if [ ! -L "$DST" ] && [ -d "$DST" ] && diff -r "$STAGE" "$DST" >/dev/null 2>&1; then
            # Already exactly this skill: replacing it would only
            # manufacture a backup of askcodex's own files, and the second such
            # backup would have to displace the first.
            SAME=1
            rm -rf "$STAGE"
            say "› $DST already holds exactly this skill — left as it is"
        else
            # Never reuse or delete a backup path: askcodex.bak may hold the
            # only copy of what the user had before askcodex, and it is the
            # rollback this script prints.
            BAK="$(backup_path)" || die "too many backups beside $DST — move some aside by hand"
            mv "$DST" "$BAK" || die "could not move $DST aside — nothing was replaced"
            say "› previous skill moved to $BAK"
            # Do NOT name $BAK here: the EXIT trap runs after this message
            # and moves the backup back to $DST, so telling the user to
            # look in $BAK would send them to a path that no longer exists
            # by the time they read it.
            mv "$STAGE" "$DST" || die "could not move $STAGE into place — the previous skill was restored at $DST"
            SWAPPED=1
        fi
    else
        mv "$STAGE" "$DST" || die "could not move $STAGE into place"
        SWAPPED=1
    fi

    # --- postcondition 3 ---------------------------------------------------
    [ -f "$DST/SKILL.md" ] || die "skill install failed: $DST/SKILL.md is missing"
    if [ "$SAME" -eq 0 ]; then
        say "› skill installed at $DST"
    fi

    # This destination is complete: release its lock so the EXIT trap never
    # unwinds a finished install.
    rmdir "$LOCK" 2>/dev/null || :
    LOCKED=""
}

wire_skill "$HOME/.claude/skills"
DST1="$DST" BAK1="$BAK" SAME1="$SAME"
wire_skill "$HOME/.agents/skills"
DST2="$DST" BAK2="$BAK" SAME2="$SAME"

# What the user should type afterwards: the bare name only if the bare name
# really resolves to what was just installed.
RUN="askcodex"
case ":${PATH-}:" in
    *":$HOME/.local/bin:"*)
        # `askcodex` on PATH must be the binary this run wrote. An older copy
        # earlier in PATH (~/.cargo/bin from `cargo install`, Homebrew, a
        # shim) would shadow it, and every command in the skill uses the
        # bare name.
        # cmp, not just a path comparison: a second path holding the very
        # same bytes (a link, a mirrored bin directory) is not a shadow.
        RESOLVED="$(command -v askcodex 2>/dev/null || :)"
        if [ -n "$RESOLVED" ] && [ "$RESOLVED" != "$BIN" ] && ! cmp -s "$RESOLVED" "$BIN"; then
            RUN="$BIN"
            say ""
            say "note: \`askcodex\` on your PATH resolves to"
            say "      $RESOLVED,"
            say "      not the binary this installer just wrote. That copy shadows"
            say "      $BIN. Remove it, put $HOME/.local/bin"
            say "      earlier in PATH, or call $BIN by its full path."
        fi
        ;;
    *)
        RUN="$BIN"
        say ""
        say "note: $HOME/.local/bin is not on your PATH. Add it, or invoke"
        say "      $BIN by its full path."
        ;;
esac

# Per-destination rollback line for the report below.
report_skill() {
    _dst="$1"; _bak="$2"; _same="$3"
    say "  skill  : $_dst"
    if [ -n "$_bak" ]; then
        say "  rollback: rm -rf \"$_dst\" && mv \"$_bak\" \"$_dst\""
    elif [ "$_same" -eq 1 ]; then
        say "  rollback: rm -rf \"$_dst\"  (the skill there was already this one;"
        say "            nothing was replaced by this run)"
    else
        say "  rollback: rm -rf \"$_dst\"  (nothing was there before)"
    fi
    if [ -z "$_bak" ] && { [ -e "$_dst.bak" ] || [ -L "$_dst.bak" ]; }; then
        say "  note    : $_dst.bak is an earlier install's backup. This run did not"
        say "            touch it, and no install ever deletes it."
    fi
}

say ""
say "done."
say "  binary : $BIN  (rollback: rm -f \"$BIN\")"
report_skill "$DST1" "$BAK1" "$SAME1"
report_skill "$DST2" "$BAK2" "$SAME2"
say ""
say "run \`$RUN --help\` to start, or \`$RUN auth status --no-refresh\` for token expiry."
say "The skill is live in Claude Code."
