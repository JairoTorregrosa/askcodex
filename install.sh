#!/bin/sh
# Installer for askcodex. Safe to re-run.
# Default: build and install the binary without reading credentials.
# --skills agents|claude|all explicitly synchronizes selected skill directories.
# --check-auth explicitly checks credentials without refreshing or printing them.
# Skill backups live in ${XDG_DATA_HOME:-~/.local/share}/askcodex/skill-backups,
# outside every skills directory, and are never overwritten or deleted.
# No sudo or host configuration edits.
set -eu

say() { printf '%s\n' "$*"; }
die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

usage() {
    say 'Usage: ./install.sh [--skills agents|claude|all] [--check-auth]'
    say 'Default: build and install ~/.local/bin/askcodex; no credentials required.'
    say '--skills selects skill directories to synchronize (no authentication needed).'
    say '--check-auth verifies stored credentials without refreshing them.'
}
SKILL_TARGET=none
CHECK_AUTH=0
while [ "$#" -gt 0 ]; do
    case "$1" in
    --skills)
        [ "$#" -ge 2 ] || die '--skills requires agents, claude, or all'
        [ "$SKILL_TARGET" = none ] || die '--skills may only be specified once'
        case "$2" in agents | claude | all) SKILL_TARGET="$2" ;; *) die '--skills requires agents, claude, or all' ;; esac
        shift 2
        ;;
    --check-auth)
        CHECK_AUTH=1
        shift
        ;;
    --help | -h)
        usage
        exit 0
        ;;
    *) die "unknown option: $1" ;;
    esac
done

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

# Verify the installed binary before any optional operation.
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
       credential storage, then re-run ./install.sh --check-auth.'
if [ "$CHECK_AUTH" -eq 1 ]; then
    "$BIN" auth status --no-refresh >/dev/null 2>&1 || die "$AUTH_HELP"
    say "› auth readable (nothing was refreshed, no secret was printed)"
fi

# Optional skill synchronization uses the existing safe replacement protocol.
SRC="$REPO/skill"
if [ "$SKILL_TARGET" != none ]; then
    [ -d "$SRC" ] || die "skill directory not found at $SRC — install.sh must stay inside an askcodex checkout"
    [ -f "$SRC/SKILL.md" ] || die "$SRC/SKILL.md is missing — refusing to install an empty skill"
fi

# Backups never stay inside a skills directory. Agent hosts load every
# directory there that holds a SKILL.md, so a backup kept beside the
# destination (installers before this one left askcodex.bak and
# askcodex.bak.<stamp>[.n] there) loads as a second askcodex skill with the
# same name and stale instructions, and the agent cannot tell which is
# current. XDG_DATA_HOME counts only when absolute, as the XDG Base Directory
# spec requires: a relative value would resolve against $REPO, the cwd since
# the top of this script, and put the backups inside the checkout.
case "${XDG_DATA_HOME-}" in
/*) BACKUP_ROOT="$XDG_DATA_HOME/askcodex/skill-backups" ;;
*) BACKUP_ROOT="$HOME/.local/share/askcodex/skill-backups" ;;
esac

# State shared with the EXIT trap. Each wire_skill call resets it; the trap
# only ever has to unwind the destination currently in flight. HELD is the
# previous skill parked beside $DST during the swap; BAK is where it ends up.
DST=""
STAGE=""
LOCK=""
HELD=""
BAK=""
SAME=0
SWAPPED=0
LOCKED=""
MOVED=0
STRANDED=0

# Prints the first of $1, $1.1 … $1.99 that does not exist, so a backup is
# never overwritten and never moved into another backup. Names under
# $BACKUP_ROOT start with the target's label and are picked while holding
# that target's lock, so no concurrent install picks the same name.
free_path() {
    _cand="$1"
    _n=0
    while [ -e "$_cand" ] || [ -L "$_cand" ]; do
        _n=$((_n + 1))
        [ "$_n" -lt 100 ] || return 1
        _cand="$1.$_n"
    done
    printf '%s\n' "$_cand"
}

# A backup that could not leave a skills directory. The skill it holds is
# intact (mv never removes a source it failed to copy), but where it sits a
# host loads it as a second, stale askcodex skill: that is the state this
# installer exists to prevent, so the run goes on to finish what it can and
# then exits nonzero instead of reporting a clean install.
stranded() {
    STRANDED=$((STRANDED + 1))
    printf 'error: could not move %s\n' "$1" >&2
    printf '       to %s.\n' "$2" >&2
    printf '       It is still in %s, where agents load it as a second,\n' "$SKILLS" >&2
    printf '       stale askcodex skill. Move it by hand:\n' >&2
    printf '         mkdir -p "%s" && mv "%s" "%s"\n' "$BACKUP_ROOT" "$1" "$2" >&2
    printf '       or re-run ./install.sh with the same --skills, which retries the move.\n' >&2
}

# Leaves the destination as it was found, on every path out of the script:
# the staging copy is discarded, and a skill parked between the two renames
# is put back.
cleanup() {
    _status=$?
    if [ -n "${LOCKED:-}" ]; then
        rm -rf "$STAGE" 2>/dev/null || :
        if [ "$SWAPPED" -eq 0 ] && [ -n "$HELD" ] && [ ! -e "$DST" ] && [ ! -L "$DST" ]; then
            if mv "$HELD" "$DST" 2>/dev/null; then
                say "› previous skill restored at $DST"
            else
                printf 'error: could not put the previous skill back at %s;\n' "$DST" >&2
                printf '       it is at %s\n' "$HELD" >&2
            fi
        fi
        rmdir "$LOCK" 2>/dev/null || :
    fi
    return "$_status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

# Wire the repo's skill/ into $1/askcodex with staging, locking, and backups
# named after $2 (claude or agents). Leaves per-destination results in
# DST/BAK/SAME/MOVED for the caller to report.
wire_skill() {
    SKILLS="$1"
    LABEL="$2"
    DST="$SKILLS/askcodex"
    STAGE="$DST.new"
    LOCK="$DST.lock"
    HELD=""
    BAK=""
    SAME=0
    SWAPPED=0
    LOCKED=""
    MOVED=0
    STAMP="$(date -u +%Y%m%dT%H%M%SZ)"

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

    # Backups that earlier installers left beside the destination are
    # askcodex's own, and where they are they load as a second, stale
    # askcodex skill. Move each one out; never delete or overwrite one. A
    # leftover from a final move that failed below has the same shape and
    # is retried here. Only askcodex.bak and askcodex.bak.* are touched:
    # every other entry in $SKILLS belongs to someone else. This runs after
    # staging succeeded, so a run that cannot stage changes nothing here.
    for _old in "$DST.bak" "$DST".bak.*; do
        [ -e "$_old" ] || [ -L "$_old" ] || continue
        mkdir -p "$BACKUP_ROOT" ||
            die "cannot create $BACKUP_ROOT to move $_old out of $SKILLS — $DST was left untouched"
        _to="$(free_path "$BACKUP_ROOT/$LABEL-${_old##*/}")" ||
            die "too many backups named $LABEL-${_old##*/}* in $BACKUP_ROOT — move some aside by hand"
        if mv "$_old" "$_to"; then
            say "› moved earlier backup $_old to $_to"
            MOVED=$((MOVED + 1))
        else
            stranded "$_old" "$_to"
        fi
    done

    if [ -e "$DST" ] || [ -L "$DST" ]; then
        if [ ! -L "$DST" ] && [ -d "$DST" ] && diff -r "$STAGE" "$DST" >/dev/null 2>&1; then
            # Already exactly this skill: replacing it would only
            # manufacture a backup of askcodex's own files.
            SAME=1
            rm -rf "$STAGE"
            say "› $DST already holds exactly this skill — left as it is"
        else
            # The previous skill may hold the only copy of what the user had
            # before askcodex, and its backup is the rollback this script
            # prints. Everything that can refuse is checked before $DST is
            # touched: the backup directory and a free name in it.
            mkdir -p "$BACKUP_ROOT" ||
                die "cannot create $BACKUP_ROOT for the previous skill — nothing was replaced"
            BAK="$(free_path "$BACKUP_ROOT/$LABEL-$STAMP")" ||
                die "too many backups named $LABEL-$STAMP* in $BACKUP_ROOT — nothing was replaced"
            # Two renames inside $SKILLS: park the old tree beside $DST,
            # then rename the new one into place. Each is atomic, so $DST
            # is only ever the complete old tree or the complete new one,
            # and the EXIT trap can undo the first rename. The old tree
            # moves to $BACKUP_ROOT only after that, because $BACKUP_ROOT
            # may be on another filesystem, where mv copies and then
            # deletes and is not atomic. The parked sibling is visible to
            # hosts only for that moment.
            HELD="$(free_path "$DST.bak.$STAMP")" ||
                die "too many askcodex.bak.$STAMP* entries beside $DST — nothing was replaced"
            mv "$DST" "$HELD" || die "could not move $DST aside — nothing was replaced"
            # Do NOT name $HELD here: the EXIT trap runs after this message
            # and moves the skill back to $DST.
            mv "$STAGE" "$DST" || die "could not move $STAGE into place — putting the previous skill back at $DST"
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

    # The new skill is in place; now take the old one out of $SKILLS. A
    # failure here does not undo the install (the new skill is complete and
    # correct), but the old one stays where hosts load it: stranded() says so
    # with both paths, and the run exits nonzero after finishing.
    if [ -n "$HELD" ]; then
        if [ ! -e "$BAK" ] && [ ! -L "$BAK" ] && mv "$HELD" "$BAK"; then
            say "› previous skill backed up to $BAK"
        else
            stranded "$HELD" "$BAK"
            BAK="$HELD"
        fi
    fi

    # This destination is complete: release its lock so the EXIT trap never
    # unwinds a finished install.
    rmdir "$LOCK" 2>/dev/null || :
    LOCKED=""
}

DST1="" BAK1="" SAME1=0 MOVED1=0
DST2="" BAK2="" SAME2=0 MOVED2=0
if [ "$SKILL_TARGET" = claude ] || [ "$SKILL_TARGET" = all ]; then
    wire_skill "$HOME/.claude/skills" claude
    DST1="$DST" BAK1="$BAK" SAME1="$SAME" MOVED1="$MOVED"
fi
if [ "$SKILL_TARGET" = agents ] || [ "$SKILL_TARGET" = all ]; then
    wire_skill "$HOME/.agents/skills" agents
    DST2="$DST" BAK2="$BAK" SAME2="$SAME" MOVED2="$MOVED"
fi

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

# Per-destination backup and rollback lines for the report below. The
# rollback names wherever the previous skill really is: the backup directory,
# or its parked path beside the destination if the final move failed.
report_skill() {
    _dst="$1"
    _bak="$2"
    _same="$3"
    _moved="$4"
    say "  skill  : $_dst"
    if [ -n "$_bak" ]; then
        say "  backup : $_bak"
        say "  rollback: rm -rf \"$_dst\" && mv \"$_bak\" \"$_dst\""
    elif [ "$_same" -eq 1 ]; then
        say "  rollback: rm -rf \"$_dst\"  (the skill there was already this one;"
        say "            nothing was replaced by this run)"
    else
        say "  rollback: rm -rf \"$_dst\"  (nothing was there before)"
    fi
    if [ "$_moved" -gt 0 ]; then
        say "  moved  : $_moved earlier backup(s) from beside $_dst"
        say "           into $BACKUP_ROOT"
    fi
}

say ""
say "done."
say "  binary : $BIN  (rollback: rm -f \"$BIN\")"
[ -z "$DST1" ] || report_skill "$DST1" "$BAK1" "$SAME1" "$MOVED1"
[ -z "$DST2" ] || report_skill "$DST2" "$BAK2" "$SAME2" "$MOVED2"
say ""
say "run \`$RUN --help\` to start, or \`$RUN auth status --no-refresh\` for token expiry."
[ "$STRANDED" -eq 0 ] ||
    die "$STRANDED askcodex backup(s) are still inside a skills directory, named above.
       The binary and the new skill are installed; move those backups out."
