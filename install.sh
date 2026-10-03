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
# previous skill parked beside $DST during the swap; BAK is where it ends up;
# LEFT is an incomplete remainder of HELD that could not be deleted.
DST=""
STAGE=""
LOCK=""
HELD=""
BAK=""
LEFT=""
SAME=0
SWAPPED=0
LOCKED=""
MOVED=0
STRANDED=0
STASHED=""
LEFTOVER=""
DOOMED=""

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

# A tree in $SKILLS that this run could not finish taking out. Where it sits,
# a host may load it as a second, stale askcodex skill: the state this
# installer exists to prevent. So the run finishes what it can and then exits
# nonzero instead of reporting a clean install.
#
# There is no hand-typed retry here: a path in $BACKUP_ROOT may hold a partial
# copy from the failed attempt, and `mv src existing_dir` would nest the
# source inside it. A re-run picks a fresh name and verifies before it
# publishes.
stranded() {
    STRANDED=$((STRANDED + 1))
    printf 'error: could not back up %s\n' "$1" >&2
    printf '       into %s. It is intact and still in\n' "$BACKUP_ROOT" >&2
    printf '       %s, where agents load it as a second, stale askcodex\n' "$SKILLS" >&2
    printf '       skill. Re-run ./install.sh with the same --skills to retry.\n' >&2
}

# Removes the top-level SKILL.md of directory $1 (what makes it load as a
# skill), making the directory writable first if it has to.
unload() {
    if [ -d "$1" ] && [ ! -L "$1" ]; then
        rm -f "$1/SKILL.md" 2>/dev/null ||
            { chmod u+w "$1" 2>/dev/null && rm -f "$1/SKILL.md" 2>/dev/null; } || :
    fi
}

# Removes $1, the renamed source of a backup already complete and verified
# in $BACKUP_ROOT: askcodex.leftover.* is only ever created after that
# backup was published, so removing it loses nothing. A top-level SKILL.md is
# what makes a directory a skill, so it goes first: the remainder stops
# loading even if the rest cannot be removed. Returns 0 when nothing is left.
# A remainder that still holds a SKILL.md loads as a second, stale askcodex
# skill and fails the run; one without is reported and does not.
finish_leftover() {
    _l="$1"
    DOOMED="$_l"
    unload "$_l"
    if ! rm -rf "$_l" 2>/dev/null; then
        chmod -R u+w "$_l" 2>/dev/null || :
        rm -rf "$_l" 2>/dev/null || :
    fi
    DOOMED=""
    if [ ! -e "$_l" ] && [ ! -L "$_l" ]; then
        return 0
    fi
    if [ -e "$_l/SKILL.md" ] || [ -L "$_l/SKILL.md" ]; then
        STRANDED=$((STRANDED + 1))
        printf 'error: %s could not be removed and still holds\n' "$_l" >&2
        printf '       a SKILL.md, so agents load it as a second, stale askcodex skill.\n' >&2
        printf '       Its backup is complete in %s. Delete it\n' "$BACKUP_ROOT" >&2
        printf '       (it may need chmod -R u+w or its owner): rm -rf "%s"\n' "$_l" >&2
    else
        say "warning: could not remove all of $_l. It holds no SKILL.md, so"
        say "         agents do not load it; its backup is complete in $BACKUP_ROOT."
        say "         Delete it: rm -rf \"$_l\""
    fi
    return 1
}

# True when $BACKUP_ROOT and $SKILLS share a mount, so mv between them is one
# rename(2). link(2) refuses to cross a mount exactly where rename(2) does. A
# probe that fails for any other reason, or a filesystem without hard links,
# only selects the copy path, which is safe everywhere.
same_fs() {
    _probe="$LOCK/fs-probe"
    _peer="$(free_path "$BACKUP_ROOT/.fs-probe-$LABEL")" || return 1
    : >"$_probe" 2>/dev/null || return 1
    _rc=1
    ! ln "$_probe" "$_peer" 2>/dev/null || _rc=0
    rm -f "$_probe" "$_peer" 2>/dev/null || :
    return "$_rc"
}

# Takes $1, a tree of askcodex's own in $SKILLS, out to $BACKUP_ROOT/$2 (or
# $2.<n> if taken). Sets STASHED to the complete backup, or "" if none was
# made (then $1 is untouched), and LEFTOVER to an incomplete remainder of $1
# that could not be removed after its backup was complete.
stash() {
    STASHED=""
    LEFTOVER=""
    DOOMED=""
    _src="$1"
    if ! _to="$(free_path "$BACKUP_ROOT/$2")"; then
        stranded "$_src"
        return 0
    fi
    if [ -L "$_src" ] || same_fs; then
        # One rename, or one symlink re-created: complete or not at all.
        if mv "$_src" "$_to"; then STASHED="$_to"; else stranded "$_src"; fi
        return 0
    fi
    # Across filesystems mv copies and then deletes, and a delete that stops
    # halfway leaves a torn tree at the source. So: copy under a fresh hidden
    # name, verify, publish with a rename inside $BACKUP_ROOT, and only then
    # remove the source. A final name never holds a partial copy, and a
    # failed copy is discarded, never reused.
    if _tmp="$(free_path "$BACKUP_ROOT/.incoming-$2")" &&
        cp -PRp "$_src" "$_tmp" &&
        diff -r "$_src" "$_tmp" >/dev/null 2>&1 &&
        [ ! -e "$_to" ] && [ ! -L "$_to" ] &&
        mv "$_tmp" "$_to"; then
        STASHED="$_to"
        # From here the source is expendable: an interrupt makes the EXIT
        # trap unload it instead of leaving a stale skill until a re-run.
        DOOMED="$_src"
    else
        if [ -n "${_tmp:-}" ] && { [ -e "$_tmp" ] || [ -L "$_tmp" ]; }; then
            chmod -R u+w "$_tmp" 2>/dev/null || :
            rm -rf "$_tmp" 2>/dev/null || :
        fi
        stranded "$_src"
        return 0
    fi
    # The backup is complete, so the source can go. Rename it out of the
    # askcodex.bak* namespace first (one rename in $SKILLS), so a removal
    # that fails or is interrupted never leaves a tree that a later sweep
    # would take for a backup; any later run finishes removing it. A
    # read-only subdirectory would stop rm halfway; making the doomed copy
    # writable changes nothing the user keeps (cp -p kept the modes).
    _doomed="$_src"
    if _left="$(free_path "$DST.leftover.$STAMP")" && mv "$_src" "$_left"; then
        _doomed="$_left"
        DOOMED="$_left"
    fi
    finish_leftover "$_doomed" || LEFTOVER="$_doomed"
}

# Leaves the destination as it was found, on every path out of the script:
# the staging copy is discarded, and a skill parked between the two renames
# is put back. A source whose backup was already verified and published
# (DOOMED) is unloaded rather than left loading beside the new skill: it is
# renamed to askcodex.leftover.* if it is not yet (so no later sweep takes the
# unloaded tree for a backup) and loses its top-level SKILL.md; the next
# run removes the rest. If that rename fails it stays whole, as a sibling
# backup the next run's sweep moves out.
cleanup() {
    _status=$?
    # A second Ctrl-C (or TERM, HUP) must not cut this short: it would skip
    # putting the parked skill back, unloading a doomed one, or releasing the
    # lock.
    trap '' INT TERM HUP
    if [ -n "${LOCKED:-}" ]; then
        if [ -n "${DOOMED:-}" ] && { [ -e "$DOOMED" ] || [ -L "$DOOMED" ]; }; then
            case "${DOOMED##*/}" in
            askcodex.leftover.*) ;;
            *)
                if _l="$(free_path "$DST.leftover.$STAMP")" && mv "$DOOMED" "$_l" 2>/dev/null; then
                    DOOMED="$_l"
                else
                    DOOMED=""
                fi
                ;;
            esac
            if [ -n "$DOOMED" ]; then
                unload "$DOOMED"
                say "› interrupted: $DOOMED no longer loads (its backup is complete);"
                say "  the next run removes it"
            fi
        fi
        rm -rf "$STAGE" 2>/dev/null || :
        if [ "$SWAPPED" -eq 0 ] && [ -n "$HELD" ] && [ ! -e "$DST" ] && [ ! -L "$DST" ]; then
            if mv "$HELD" "$DST" 2>/dev/null; then
                say "› previous skill restored at $DST"
            else
                printf 'error: could not put the previous skill back at %s;\n' "$DST" >&2
                printf '       it is at %s\n' "$HELD" >&2
            fi
        fi
        rm -f "$LOCK/fs-probe" 2>/dev/null || :
        rmdir "$LOCK" 2>/dev/null || :
    fi
    return "$_status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

# Makes sure skills directory $1 exists. mkdir -p cannot create through a
# symlink whose target is missing (it reports "File exists"), so a dangling
# link gets a message that names the cause instead of "cannot create".
ensure_skills_dir() {
    [ ! -d "$1" ] || return 0
    if [ -L "$1" ] && [ ! -e "$1" ]; then
        die "$1 is a symlink to a directory that does not exist. Create that
       directory or remove the link, then re-run."
    fi
    mkdir -p "$1" || die "cannot create $1"
}

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
    LEFT=""
    DOOMED=""
    SAME=0
    SWAPPED=0
    LOCKED=""
    MOVED=0
    STAMP="$(date -u +%Y%m%dT%H%M%SZ)"

    # Every path this function creates under $SKILLS matches askcodex*, the
    # surface declared in the header and in AGENTS.md — the lock included.
    ensure_skills_dir "$SKILLS"

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

    # Remainders of a source whose backup was already complete, left by a
    # removal that failed or was interrupted (possibly with the whole old
    # skill, SKILL.md included, still loading). Not backups: finish them.
    # This runs before the sweep below, which may leave new ones of its own.
    for _left in "$DST".leftover.*; do
        [ -e "$_left" ] || [ -L "$_left" ] || continue
        if finish_leftover "$_left"; then
            say "› removed $_left, left by an earlier run; its backup is in $BACKUP_ROOT"
        fi
    done

    # Backups that earlier installers left beside the destination are
    # askcodex's own, and where they are they load as a second, stale
    # askcodex skill. Move each one out; never delete or overwrite one. A
    # parked skill whose backup failed below has the same shape and is
    # retried here. Only askcodex.bak and askcodex.bak.* are moved: every
    # other entry in $SKILLS belongs to someone else. This runs after
    # staging succeeded, so a run that cannot stage changes nothing here.
    for _old in "$DST.bak" "$DST".bak.*; do
        [ -e "$_old" ] || [ -L "$_old" ] || continue
        mkdir -p "$BACKUP_ROOT" ||
            die "cannot create $BACKUP_ROOT to move $_old out of $SKILLS — $DST was left untouched"
        stash "$_old" "$LABEL-${_old##*/}"
        if [ -n "$STASHED" ]; then
            say "› moved earlier backup $_old to $STASHED"
            MOVED=$((MOVED + 1))
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
            free_path "$BACKUP_ROOT/$LABEL-$STAMP" >/dev/null ||
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
    # correct), and the run exits nonzero after finishing. The rollback
    # source is the verified backup whenever one exists, even if removing
    # the parked copy failed; otherwise it is the parked copy, untouched.
    if [ -n "$HELD" ]; then
        stash "$HELD" "$LABEL-$STAMP"
        if [ -n "$STASHED" ]; then
            BAK="$STASHED"
            LEFT="$LEFTOVER"
            say "› previous skill backed up to $BAK"
        else
            BAK="$HELD"
        fi
    fi

    # This destination is complete: release its lock so the EXIT trap never
    # unwinds a finished install.
    rmdir "$LOCK" 2>/dev/null || :
    LOCKED=""
}

CLAUDE_SKILLS="$HOME/.claude/skills"
AGENTS_SKILLS="$HOME/.agents/skills"
WIRE_CLAUDE=0
WIRE_AGENTS=0
case "$SKILL_TARGET" in
claude) WIRE_CLAUDE=1 ;;
agents) WIRE_AGENTS=1 ;;
all) WIRE_CLAUDE=1 WIRE_AGENTS=1 ;;
esac

# Prints directory $1 with every symlink resolved.
physical() { (CDPATH='' cd -P -- "$1" 2>/dev/null && pwd -P); }

# ~/.claude/skills is often a symlink to ~/.agents/skills (or the reverse).
# Wiring one physical directory twice lets the second pass sweep up what the
# first pass parked or reported, and the first pass's rollback would then
# name a path that no longer exists. A shared directory is wired once,
# through the path that is not the link, and reported once. Whichever of the
# two is not a symlink is created first, in either direction, so a link to
# a directory that does not exist yet stops dangling before it is used.
ALIAS=""
if [ "$WIRE_CLAUDE" -eq 1 ] && [ "$WIRE_AGENTS" -eq 1 ]; then
    for _dir in "$AGENTS_SKILLS" "$CLAUDE_SKILLS"; do
        [ -L "$_dir" ] || ensure_skills_dir "$_dir"
    done
    for _dir in "$AGENTS_SKILLS" "$CLAUDE_SKILLS"; do
        [ ! -L "$_dir" ] || ensure_skills_dir "$_dir"
    done
    P_CLAUDE="$(physical "$CLAUDE_SKILLS")" || die "cannot resolve $CLAUDE_SKILLS"
    P_AGENTS="$(physical "$AGENTS_SKILLS")" || die "cannot resolve $AGENTS_SKILLS"
    if [ "$P_CLAUDE" = "$P_AGENTS" ]; then
        if [ -L "$AGENTS_SKILLS" ] && [ ! -L "$CLAUDE_SKILLS" ]; then
            WIRE_AGENTS=0
            ALIAS="$AGENTS_SKILLS/askcodex"
        else
            WIRE_CLAUDE=0
            ALIAS="$CLAUDE_SKILLS/askcodex"
        fi
    fi
fi

# Prints $1 with every symlink in its longest existing prefix resolved; the
# components that do not exist yet are appended as written.
resolve_path() {
    _p="$1"
    _rest=""
    while [ ! -d "$_p" ]; do
        _rest="/${_p##*/}$_rest"
        _p="${_p%/*}"
        [ -n "$_p" ] || _p=/
    done
    _p="$(physical "$_p")" || return 1
    printf '%s%s\n' "${_p%/}" "$_rest"
}

# Prints the skills directory that $BACKUP_ROOT is, or lies inside, if any.
backup_root_conflict() {
    _root="$(resolve_path "$BACKUP_ROOT")" || die "cannot resolve $BACKUP_ROOT"
    for _dir in "$CLAUDE_SKILLS" "$AGENTS_SKILLS"; do
        _p="$(resolve_path "$_dir")" || continue
        case "$_root/" in "$_p"/*)
            printf '%s\n' "$_dir"
            return 0
            ;;
        esac
    done
}

# An absolute XDG_DATA_HOME can point anywhere, including a skills directory
# ($HOME/.agents/skills, or a link to it). Backups there would be parked
# along with the skill they sit in and load as skills themselves. Such a
# root is replaced by the default, loudly, before anything is touched; if
# even the default resolves inside a skills directory, nothing is wired.
if [ "$SKILL_TARGET" != none ]; then
    CONFLICT="$(backup_root_conflict)"
    if [ -n "$CONFLICT" ] && [ "$BACKUP_ROOT" != "$HOME/.local/share/askcodex/skill-backups" ]; then
        say "warning: $BACKUP_ROOT is inside the skills directory"
        say "         $CONFLICT, where agents would load backups as skills."
        say "         Using $HOME/.local/share/askcodex/skill-backups instead."
        BACKUP_ROOT="$HOME/.local/share/askcodex/skill-backups"
        CONFLICT="$(backup_root_conflict)"
    fi
    [ -z "$CONFLICT" ] ||
        die "the backup directory $BACKUP_ROOT is inside the skills directory
       $CONFLICT, where agents would load backups as skills. No skill was touched."
fi

DST1="" BAK1="" SAME1=0 MOVED1=0 LEFT1=""
DST2="" BAK2="" SAME2=0 MOVED2=0 LEFT2=""
if [ "$WIRE_CLAUDE" -eq 1 ]; then
    wire_skill "$CLAUDE_SKILLS" claude
    DST1="$DST" BAK1="$BAK" SAME1="$SAME" MOVED1="$MOVED" LEFT1="$LEFT"
fi
if [ "$WIRE_AGENTS" -eq 1 ]; then
    wire_skill "$AGENTS_SKILLS" agents
    DST2="$DST" BAK2="$BAK" SAME2="$SAME" MOVED2="$MOVED" LEFT2="$LEFT"
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
# rollback names wherever a complete copy of the previous skill really is:
# the verified backup, or the untouched parked copy beside the destination
# if no backup could be made. A leftover is never a rollback source.
report_skill() {
    _dst="$1"
    _bak="$2"
    _same="$3"
    _moved="$4"
    _left="$5"
    say "  skill  : $_dst"
    if [ -n "$_bak" ] && { [ -e "$_bak" ] || [ -L "$_bak" ]; }; then
        # The rollback restores a copy and keeps the backup. The working
        # skill is never deleted first: the backup is copied (possibly
        # across filesystems, where it can run out of space or be
        # interrupted) into $_dst.restore/askcodex, and only then do two
        # renames inside the skills dir swap it in. $_dst.restore never
        # holds a top-level SKILL.md, so hosts never load it, and it is
        # emptied first, so a retry never copies into a partial tree. If
        # $_dst is already gone (an earlier attempt stopped between the
        # renames), the swap goes on without it.
        _r="$_dst.restore"
        say "  backup : $_bak"
        say "  rollback: rm -rf \"$_r\" && mkdir \"$_r\" && cp -PRp \"$_bak\" \"$_r/askcodex\" && { [ ! -e \"$_dst\" ] && [ ! -L \"$_dst\" ] || mv \"$_dst\" \"$_r/replaced\"; } && mv \"$_r/askcodex\" \"$_dst\" && rm -rf \"$_r\""
        say "            (copies the backup beside the skill, then swaps it in; the backup stays)"
    elif [ -n "$_bak" ]; then
        # Never print a rollback whose source is gone: running it would
        # delete the installed skill and then fail to restore anything.
        NOROLLBACK=$((NOROLLBACK + 1))
        say "  backup : $_bak no longer exists, so no rollback can be printed"
    elif [ "$_same" -eq 1 ]; then
        say "  rollback: rm -rf \"$_dst\"  (the skill there was already this one;"
        say "            nothing was replaced by this run)"
    else
        say "  rollback: rm -rf \"$_dst\"  (nothing was there before)"
    fi
    if [ -n "$_left" ] && { [ -e "$_left" ] || [ -L "$_left" ]; }; then
        say "  leftover: $_left  (incomplete; not a backup — delete it)"
    fi
    if [ "$_moved" -gt 0 ]; then
        say "  moved  : $_moved earlier backup(s) from beside $_dst"
        say "           into $BACKUP_ROOT"
    fi
}

NOROLLBACK=0
say ""
say "done."
say "  binary : $BIN  (rollback: rm -f \"$BIN\")"
[ -z "$DST1" ] || report_skill "$DST1" "$BAK1" "$SAME1" "$MOVED1" "$LEFT1"
[ -z "$DST2" ] || report_skill "$DST2" "$BAK2" "$SAME2" "$MOVED2" "$LEFT2"
if [ -n "$ALIAS" ]; then
    say "  skill  : $ALIAS"
    say "           is that same directory through a symlink: installed once,"
    say "           and the rollback above covers it. Run only that one."
fi
say ""
say "run \`$RUN --help\` to start, or \`$RUN auth status --no-refresh\` for token expiry."
if [ "$STRANDED" -gt 0 ] || [ "$NOROLLBACK" -gt 0 ]; then
    WHY=""
    [ "$STRANDED" -eq 0 ] ||
        WHY="$STRANDED askcodex backup(s) or leftover(s) are still inside a skills directory"
    [ "$NOROLLBACK" -eq 0 ] ||
        WHY="${WHY:+$WHY;
       }$NOROLLBACK rollback(s) could not be printed"
    die "$WHY, named above.
       The binary and the new skill are installed."
fi
