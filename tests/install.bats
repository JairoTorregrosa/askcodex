#!/usr/bin/env bats

setup() {
    TASK_ROOT="$BATS_TEST_TMPDIR/fixture"
    TASK_HOME="$TASK_ROOT/home"
    TASK_REPO="$TASK_ROOT/repo"
    mkdir -p "$TASK_HOME" "$TASK_REPO/skill" "$TASK_ROOT/bin"
    cp "$BATS_TEST_DIRNAME/../install.sh" "$TASK_REPO/install.sh"
    printf 'name = "askcodex"\n' >"$TASK_REPO/Cargo.toml"
    printf 'new skill\n' >"$TASK_REPO/skill/SKILL.md"
    cat >"$TASK_ROOT/bin/cargo" <<'SH'
#!/bin/sh
if [ "$1" = --version ]; then
    echo 'cargo 1.97.1'
else
    mkdir -p target/release
    cat > target/release/askcodex <<'BIN'
#!/bin/sh
printf '%s\n' "$*" >> "$TASK_LOG"
if [ "$1" = auth ]; then
    echo 'private diagnostic' >&2
    exit "${TASK_AUTH_EXIT:-1}"
fi
BIN
    chmod +x target/release/askcodex
fi
SH
    chmod +x "$TASK_ROOT/bin/cargo"
    export TASK_LOG="$TASK_ROOT/calls"
    AGENTS="$TASK_HOME/.agents/skills"
    BACKUPS="$TASK_HOME/.local/share/askcodex/skill-backups"
    STAMP=20261002T120000Z
    TASK_XDG=""
}

# Read-only directories some tests create would make the fixture undeletable.
teardown() {
    chmod -R u+w "$BATS_TEST_TMPDIR" 2>/dev/null || :
}

# XDG_DATA_HOME is removed unless a test sets TASK_XDG: an inherited value
# would send the installer's backups into the real user's data directory.
invoke() {
    local xdg=(-u XDG_DATA_HOME)
    [ -z "$TASK_XDG" ] || xdg=(XDG_DATA_HOME="$TASK_XDG")
    run env "${xdg[@]}" HOME="$TASK_HOME" CODEX_HOME="$TASK_HOME/absent-auth" PATH="$TASK_ROOT/bin:$PATH" \
        sh "$TASK_REPO/install.sh" "$@"
}

# Backup names carry a UTC stamp; a fixed clock makes them predictable.
fake_date() {
    printf '#!/bin/sh\necho %s\n' "$STAMP" >"$TASK_ROOT/bin/date"
    chmod +x "$TASK_ROOT/bin/date"
}

# A wrapper around the real $1 that runs the shell code $4 when its
# positional parameter number $2 matches the case pattern $3. The code sees
# the real command as "$real".
fake_cmd() {
    cat >"$TASK_ROOT/bin/$1" <<SH
#!/bin/sh
real="$(command -v "$1")"
case "\$$2" in $3) $4 ;; esac
exec "\$real" "\$@"
SH
    chmod +x "$TASK_ROOT/bin/$1"
}

# The installer's same-filesystem probe is a hard link: refusing it makes
# the backup directory look like another filesystem, so the installer takes
# its copy, verify, publish, remove path.
cross_fs() {
    printf '#!/bin/sh\nexit 1\n' >"$TASK_ROOT/bin/ln"
    chmod +x "$TASK_ROOT/bin/ln"
}

inode() {
    perl -e 'print((lstat($ARGV[0]))[1])' "$1"
}

# Nothing named askcodex.bak* may remain where hosts load skills. The
# trailing slash makes find enter a skills dir that is itself a symlink.
no_backups_beside() {
    [ -z "$(find "$1/" -mindepth 1 -maxdepth 1 -name 'askcodex.bak*')" ]
}

count_entries() {
    find "$1/" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' '
}

skill_with() {
    mkdir -p "$1"
    printf '%s\n' "$2" >"$1/SKILL.md"
}

# The rollback the installer must print for destination $1 and backup $2:
# copy beside the skill, swap with two renames, keep the backup.
restore_cmd() {
    local r="$1.restore"
    printf 'rm -rf "%s" && mkdir "%s" && cp -PRp "%s" "%s/askcodex" && ' "$r" "$r" "$2" "$r"
    printf '{ [ ! -e "%s" ] && [ ! -L "%s" ] || mv "%s" "%s/replaced"; } && ' "$1" "$1" "$1" "$r"
    printf 'mv "%s/askcodex" "%s" && rm -rf "%s"' "$r" "$1" "$r"
}

@test "default installs without credentials or skill writes" {
    invoke
    [ "$status" -eq 0 ]
    [ -x "$TASK_HOME/.local/bin/askcodex" ]
    [ "$(cat "$TASK_LOG")" = --help ]
    [ ! -e "$TASK_HOME/.agents" ]
    [ ! -e "$TASK_HOME/.claude" ]
    [ ! -e "$TASK_HOME/absent-auth" ]
}

@test "explicit skills select only requested destination without auth" {
    for target in agents claude; do
        invoke --skills "$target"
        [ "$status" -eq 0 ]
        cmp "$TASK_REPO/skill/SKILL.md" "$TASK_HOME/.$target/skills/askcodex/SKILL.md"
        if [ "$target" = agents ]; then
            [ ! -e "$TASK_HOME/.claude" ]
        fi
    done
    run grep -q auth "$TASK_LOG"
    [ "$status" -eq 1 ]
}

@test "all skills move backups out of the skills dirs and converge without new ones" {
    skill_with "$AGENTS/askcodex" old
    skill_with "$AGENTS/askcodex.bak" original
    invoke --skills all
    [ "$status" -eq 0 ]
    [ "$(cat "$BACKUPS/agents-askcodex.bak/SKILL.md")" = original ]
    run grep -rl '^old$' "$BACKUPS"
    [ "$status" -eq 0 ]
    old_backup="$output"
    [[ "$old_backup" == "$BACKUPS"/agents-2*Z/SKILL.md ]]
    no_backups_beside "$AGENTS"
    no_backups_beside "$TASK_HOME/.claude/skills"
    invoke --skills all
    [ "$status" -eq 0 ]
    [ "$(cat "$old_backup")" = old ]
    [[ "$output" == *'already holds exactly this skill'* ]]
    [ "$(count_entries "$BACKUPS")" -eq 2 ]
    [ -f "$TASK_HOME/.claude/skills/askcodex/SKILL.md" ]
}

@test "a replaced skill is backed up outside the skills dir and the printed rollback restores it" {
    fake_date
    skill_with "$AGENTS/askcodex" old
    mkdir -p "$AGENTS/askcodex/references"
    printf 'old reference\n' >"$AGENTS/askcodex/references/notes.md"
    skill_with "$TASK_HOME/.claude/skills/askcodex" 'old claude'
    before="$(inode "$AGENTS/askcodex")"
    invoke --skills all
    [ "$status" -eq 0 ]
    # Same filesystem: the backup is the original tree renamed, not a copy.
    [ "$(inode "$BACKUPS/agents-$STAMP")" = "$before" ]
    cmp "$TASK_REPO/skill/SKILL.md" "$AGENTS/askcodex/SKILL.md"
    cmp "$TASK_REPO/skill/SKILL.md" "$TASK_HOME/.claude/skills/askcodex/SKILL.md"
    backup="$BACKUPS/agents-$STAMP"
    [ "$(cat "$backup/SKILL.md")" = old ]
    [ "$(cat "$backup/references/notes.md")" = 'old reference' ]
    [ "$(cat "$BACKUPS/claude-$STAMP/SKILL.md")" = 'old claude' ]
    [ "$(count_entries "$BACKUPS")" -eq 2 ]
    no_backups_beside "$AGENTS"
    no_backups_beside "$TASK_HOME/.claude/skills"
    [[ "$output" == *"previous skill backed up to $backup"* ]]
    [[ "$output" == *"backup : $backup"* ]]
    rollback="$(printf '%s\n' "$output" | sed -n "s|^  rollback: \(.*$AGENTS.*\)|\1|p")"
    [ "$rollback" = "$(restore_cmd "$AGENTS/askcodex" "$backup")" ]
    sh -c "$rollback"
    [ "$(cat "$AGENTS/askcodex/SKILL.md")" = old ]
    [ "$(cat "$AGENTS/askcodex/references/notes.md")" = 'old reference' ]
    # The backup stays, and the swap leaves nothing behind.
    [ "$(cat "$backup/SKILL.md")" = old ]
    [ "$(cat "$backup/references/notes.md")" = 'old reference' ]
    [ "$(count_entries "$AGENTS")" -eq 1 ]
}

@test "the printed rollback never deletes the working skill before a complete copy exists" {
    fake_date
    skill_with "$AGENTS/askcodex" old
    mkdir -p "$AGENTS/askcodex/references"
    printf 'old reference\n' >"$AGENTS/askcodex/references/notes.md"
    invoke --skills agents
    [ "$status" -eq 0 ]
    backup="$BACKUPS/agents-$STAMP"
    rollback="$(printf '%s\n' "$output" | sed -n 's/^  rollback: //p')"
    # Out of space during the copy: a partial tree, then failure.
    # shellcheck disable=SC2016  # code for the fake cp, expanded there
    fake_cmd cp 3 '*/askcodex.restore/askcodex' 'mkdir -p "$3/references"; exit 1'
    run env PATH="$TASK_ROOT/bin:$PATH" sh -c "$rollback"
    [ "$status" -ne 0 ]
    cmp "$TASK_REPO/skill/SKILL.md" "$AGENTS/askcodex/SKILL.md"
    [ "$(cat "$backup/references/notes.md")" = 'old reference' ]
    # A retry starts from an empty staging dir: nothing nests in the partial.
    rm "$TASK_ROOT/bin/cp"
    sh -c "$rollback"
    [ "$(cat "$AGENTS/askcodex/SKILL.md")" = old ]
    [ "$(cat "$AGENTS/askcodex/references/notes.md")" = 'old reference' ]
    [ ! -e "$AGENTS/askcodex/askcodex" ]
    [ "$(count_entries "$AGENTS")" -eq 1 ]
    [ "$(cat "$backup/SKILL.md")" = old ]
    # An attempt that stopped between the two renames: the skill is gone
    # and both trees sit in the staging dir. The same command finishes.
    mkdir -p "$AGENTS/askcodex.restore"
    mv "$AGENTS/askcodex" "$AGENTS/askcodex.restore/replaced"
    skill_with "$AGENTS/askcodex.restore/askcodex" partial
    sh -c "$rollback"
    [ "$(cat "$AGENTS/askcodex/SKILL.md")" = old ]
    [ "$(count_entries "$AGENTS")" -eq 1 ]
    [ "$(cat "$backup/SKILL.md")" = old ]
}

@test "a skills dir linked to one that does not exist yet is created through the real path" {
    for link in agents claude; do
        rm -rf "$TASK_HOME/.agents" "$TASK_HOME/.claude"
        if [ "$link" = agents ]; then real=claude; else real=agents; fi
        mkdir -p "$TASK_HOME/.$link"
        ln -s "../.$real/skills" "$TASK_HOME/.$link/skills"
        invoke --skills "$link"
        [ "$status" -ne 0 ]
        [[ "$output" == *"$TASK_HOME/.$link/skills is a symlink to a directory that does not exist"* ]]
        [ ! -e "$TASK_HOME/.$real" ]
        invoke --skills all
        [ "$status" -eq 0 ]
        [ -L "$TASK_HOME/.$link/skills" ]
        cmp "$TASK_REPO/skill/SKILL.md" "$TASK_HOME/.$real/skills/askcodex/SKILL.md"
        [[ "$output" == *"skill  : $TASK_HOME/.$link/skills/askcodex"$'\n'"           is that same directory through a symlink"* ]]
        [ "$(count_entries "$TASK_HOME/.$real/skills")" -eq 1 ]
    done
}

@test "backups older installers left beside the skill are moved out and nothing else is touched" {
    skill_with "$AGENTS/askcodex.bak" first
    skill_with "$AGENTS/askcodex.bak.20260908T101010Z" second
    skill_with "$AGENTS/askcodex.bak.20260908T101010Z.1" third
    skill_with "$AGENTS/other" other
    skill_with "$AGENTS/askcodex-notes" notes
    invoke --skills agents
    [ "$status" -eq 0 ]
    [ "$(cat "$BACKUPS/agents-askcodex.bak/SKILL.md")" = first ]
    [ "$(cat "$BACKUPS/agents-askcodex.bak.20260908T101010Z/SKILL.md")" = second ]
    [ "$(cat "$BACKUPS/agents-askcodex.bak.20260908T101010Z.1/SKILL.md")" = third ]
    [ "$(count_entries "$BACKUPS")" -eq 3 ]
    no_backups_beside "$AGENTS"
    [ "$(cat "$AGENTS/other/SKILL.md")" = other ]
    [ "$(cat "$AGENTS/askcodex-notes/SKILL.md")" = notes ]
    cmp "$TASK_REPO/skill/SKILL.md" "$AGENTS/askcodex/SKILL.md"
    [ "$(printf '%s\n' "$output" | grep -c "^› moved earlier backup $AGENTS/askcodex.bak")" -eq 3 ]
    [[ "$output" == *'moved  : 3 earlier backup(s)'* ]]
    [[ "$output" == *'(nothing was there before)'* ]]
}

@test "skills dirs that are one directory through a symlink are wired and rolled back once" {
    fake_date
    # Either direction: the link is never the path that gets wired.
    for link in claude agents; do
        rm -rf "$TASK_HOME/.agents" "$TASK_HOME/.claude" "$TASK_HOME/.local/share"
        if [ "$link" = claude ]; then
            real=agents
            mkdir -p "$TASK_HOME/.claude"
            ln -s ../.agents/skills "$TASK_HOME/.claude/skills"
        else
            real=claude
            mkdir -p "$TASK_HOME/.agents"
            ln -s ../.claude/skills "$TASK_HOME/.agents/skills"
        fi
        dir="$TASK_HOME/.$real/skills"
        skill_with "$dir/askcodex" old
        skill_with "$dir/askcodex.bak" original
        invoke --skills all
        [ "$status" -eq 0 ]
        [ -L "$TASK_HOME/.$link/skills" ]
        no_backups_beside "$dir"
        [ "$(count_entries "$dir")" -eq 1 ]
        [ "$(cat "$BACKUPS/$real-askcodex.bak/SKILL.md")" = original ]
        [ "$(cat "$BACKUPS/$real-$STAMP/SKILL.md")" = old ]
        [ "$(count_entries "$BACKUPS")" -eq 2 ]
        [[ "$output" == *"skill  : $TASK_HOME/.$link/skills/askcodex"$'\n'"           is that same directory through a symlink"* ]]
        [ "$(printf '%s\n' "$output" | grep -c '^  rollback: ')" -eq 1 ]
        [ "$(printf '%s\n' "$output" | grep -c 'already holds exactly this skill')" -eq 0 ]
    done
}

@test "on a shared skills dir a parked skill that cannot leave keeps the only rollback valid" {
    fake_date
    skill_with "$AGENTS/askcodex" old
    mkdir -p "$TASK_HOME/.claude"
    ln -s ../.agents/skills "$TASK_HOME/.claude/skills"
    fake_cmd mv 2 '*/skill-backups/*' 'exit 1'
    invoke --skills all
    [ "$status" -eq 1 ]
    held="$AGENTS/askcodex.bak.$STAMP"
    [ "$(cat "$held/SKILL.md")" = old ]
    rollback="$(printf '%s\n' "$output" | sed -n 's/^  rollback: //p')"
    [ "$rollback" = "$(restore_cmd "$AGENTS/askcodex" "$held")" ]
    rm "$TASK_ROOT/bin/mv"
    sh -c "$rollback"
    [ "$(cat "$AGENTS/askcodex/SKILL.md")" = old ]
    [ "$(cat "$held/SKILL.md")" = old ]
}

@test "a rollback whose source is gone at the end of the run is never printed" {
    fake_date
    skill_with "$AGENTS/askcodex" old
    # A different askcodex earlier on PATH makes the installer compare it
    # with the binary it wrote; this cmp removes the backup meanwhile.
    printf '#!/bin/sh\nexit 0\n' >"$TASK_ROOT/bin/askcodex"
    chmod +x "$TASK_ROOT/bin/askcodex"
    fake_cmd cmp 2 '*' "rm -rf \"$BACKUPS/agents-$STAMP\"; exit 1"
    run env -u XDG_DATA_HOME HOME="$TASK_HOME" CODEX_HOME="$TASK_HOME/absent-auth" \
        PATH="$TASK_ROOT/bin:$TASK_HOME/.local/bin:$PATH" sh "$TASK_REPO/install.sh" --skills agents
    [ "$status" -eq 1 ]
    [ ! -e "$BACKUPS/agents-$STAMP" ]
    [[ "$output" != *'rollback: rm -rf'*'&& mv'* ]]
    [[ "$output" == *"backup : $BACKUPS/agents-$STAMP no longer exists, so no rollback can be printed"* ]]
    [[ "$output" == *'1 rollback(s) could not be printed'* ]]
}

@test "a name already taken in the backup dir, or a partial copy, is never overwritten or reused" {
    fake_date
    for mode in same cross; do
        rm -rf "$TASK_HOME/.agents" "$TASK_HOME/.local/share"
        [ "$mode" = same ] || cross_fs
        skill_with "$BACKUPS/agents-askcodex.bak" kept
        skill_with "$BACKUPS/agents-$STAMP" 'kept too'
        # A partial copy an interrupted cross-filesystem copy left behind.
        mkdir -p "$BACKUPS/.incoming-agents-$STAMP/references"
        skill_with "$AGENTS/askcodex.bak" legacy
        skill_with "$AGENTS/askcodex" old
        invoke --skills agents
        [ "$status" -eq 0 ]
        [ "$(cat "$BACKUPS/agents-askcodex.bak/SKILL.md")" = kept ]
        [ "$(cat "$BACKUPS/agents-$STAMP/SKILL.md")" = 'kept too' ]
        [ "$(cat "$BACKUPS/agents-askcodex.bak.1/SKILL.md")" = legacy ]
        [ "$(cat "$BACKUPS/agents-$STAMP.1/SKILL.md")" = old ]
        [ "$(count_entries "$BACKUPS")" -eq 5 ]
        [ "$(count_entries "$BACKUPS/agents-$STAMP")" -eq 1 ]
        [ "$(count_entries "$BACKUPS/agents-askcodex.bak")" -eq 1 ]
        [ "$(count_entries "$BACKUPS/.incoming-agents-$STAMP")" -eq 1 ]
        no_backups_beside "$AGENTS"
    done
}

@test "across filesystems a read-only subdirectory still yields a complete backup and a clean skills dir" {
    fake_date
    cross_fs
    skill_with "$AGENTS/askcodex" old
    mkdir -p "$AGENTS/askcodex/references"
    printf 'old reference\n' >"$AGENTS/askcodex/references/notes.md"
    chmod 555 "$AGENTS/askcodex/references"
    before="$(inode "$AGENTS/askcodex")"
    invoke --skills agents
    [ "$status" -eq 0 ]
    backup="$BACKUPS/agents-$STAMP"
    [ "$(inode "$backup")" != "$before" ]
    [ "$(cat "$backup/SKILL.md")" = old ]
    [ "$(cat "$backup/references/notes.md")" = 'old reference' ]
    run perl -e 'exit(((stat($ARGV[0]))[2] & 0777) == 0555 ? 0 : 1)' "$backup/references"
    [ "$status" -eq 0 ]
    [ "$(count_entries "$AGENTS")" -eq 1 ]
    [ "$(count_entries "$BACKUPS")" -eq 1 ]
}

# The cross-filesystem path with an old skill that has a subdirectory.
old_skill_cross_fs() {
    fake_date
    cross_fs
    skill_with "$AGENTS/askcodex" old
    mkdir -p "$AGENTS/askcodex/references"
    printf 'old reference\n' >"$AGENTS/askcodex/references/notes.md"
    backup="$BACKUPS/agents-$STAMP"
    left="$AGENTS/askcodex.leftover.$STAMP"
}

@test "a removal that stops after SKILL.md leaves nothing loadable and rollback uses the backup" {
    old_skill_cross_fs
    # rm can unlink the top-level SKILL.md but nothing else, as with a
    # subdirectory owned by someone else.
    # shellcheck disable=SC2016  # code for the fake rm, expanded there
    fake_cmd rm 2 '*/askcodex.leftover.*' '[ "${2##*/}" = SKILL.md ] && exec "$real" "$@"; exit 1'
    invoke --skills agents
    [ "$status" -eq 0 ]
    [ "$(cat "$backup/SKILL.md")" = old ]
    [ "$(cat "$backup/references/notes.md")" = 'old reference' ]
    [ ! -e "$left/SKILL.md" ]
    [ -d "$left/references" ]
    no_backups_beside "$AGENTS"
    [[ "$output" == *"warning: could not remove all of $left. It holds no SKILL.md"* ]]
    [[ "$output" == *"leftover: $left  (incomplete; not a backup"* ]]
    rollback="$(printf '%s\n' "$output" | sed -n 's/^  rollback: //p')"
    [ "$rollback" = "$(restore_cmd "$AGENTS/askcodex" "$backup")" ]
    # A later run finishes the removal and never takes it for a backup.
    rm "$TASK_ROOT/bin/rm"
    invoke --skills agents
    [ "$status" -eq 0 ]
    [[ "$output" == *"removed $left, left by an earlier run"* ]]
    [ ! -e "$left" ]
    [ "$(count_entries "$BACKUPS")" -eq 1 ]
    sh -c "$rollback"
    [ "$(cat "$AGENTS/askcodex/SKILL.md")" = old ]
    [ "$(cat "$AGENTS/askcodex/references/notes.md")" = 'old reference' ]
}

@test "a leftover that still holds a SKILL.md fails every run until it is removed" {
    old_skill_cross_fs
    fake_cmd rm 2 '*/askcodex.leftover.*' 'exit 1'
    for _ in 1 2; do
        invoke --skills agents
        [ "$status" -eq 1 ]
        [ "$(cat "$left/SKILL.md")" = old ]
        [[ "$output" == *"error: $left could not be removed and still holds"* ]]
        [[ "$output" == *'1 askcodex backup(s) or leftover(s) are still inside a skills directory'* ]]
        [ "$(count_entries "$BACKUPS")" -eq 1 ]
        [ "$(cat "$backup/references/notes.md")" = 'old reference' ]
    done
    rm "$TASK_ROOT/bin/rm"
    invoke --skills agents
    [ "$status" -eq 0 ]
    [ ! -e "$left" ]
    [ "$(count_entries "$AGENTS")" -eq 1 ]
}

@test "an interrupt after the backup is published leaves nothing loadable, and the next run removes the rest" {
    # One TERM, once: right after the parked skill becomes askcodex.leftover.*
    # (its first rm), or in between publishing the backup and that rename.
    once="[ -e \"$TASK_ROOT/once\" ] || { : >\"$TASK_ROOT/once\"; kill -TERM \"\$PPID\"; exit 1; }"
    for point in rm mv; do
        rm -rf "$TASK_HOME/.agents" "$TASK_HOME/.local/share" "$TASK_ROOT/once" "$TASK_ROOT/bin/rm" "$TASK_ROOT/bin/mv"
        old_skill_cross_fs
        fake_cmd "$point" 2 '*/askcodex.leftover.*' "$once"
        invoke --skills agents
        [ "$status" -eq 143 ]
        [ "$(cat "$backup/SKILL.md")" = old ]
        [ "$(cat "$backup/references/notes.md")" = 'old reference' ]
        # Not loadable, not mistaken for a backup, lock released.
        [ ! -e "$left/SKILL.md" ]
        [ -d "$left/references" ]
        no_backups_beside "$AGENTS"
        [ ! -e "$AGENTS/askcodex.lock" ]
        [[ "$output" == *"interrupted: $left no longer loads"* ]]
        rm "$TASK_ROOT/bin/$point"
        invoke --skills agents
        [ "$status" -eq 0 ]
        [[ "$output" == *"removed $left, left by an earlier run"* ]]
        [ "$(count_entries "$AGENTS")" -eq 1 ]
        [ "$(count_entries "$BACKUPS")" -eq 1 ]
    done
}

@test "an interrupt before the backup is published rolls back to the parked skill" {
    # TERM while the parked skill is copied (a partial tree exists), or while
    # the copy is verified. Either way no backup exists yet.
    # shellcheck disable=SC2016  # code for the fake cp and diff, expanded there
    for point in cp diff; do
        rm -rf "$TASK_HOME/.agents" "$TASK_HOME/.local/share" "$TASK_ROOT/bin/cp" "$TASK_ROOT/bin/diff"
        old_skill_cross_fs
        if [ "$point" = cp ]; then
            fake_cmd cp 3 '*/.incoming-*' 'mkdir -p "$3/references"; kill -TERM "$PPID"; exit 1'
        else
            fake_cmd diff 3 '*/.incoming-*' 'kill -TERM "$PPID"; exit 1'
        fi
        invoke --skills agents
        [ "$status" -eq 143 ]
        # One loadable skill, the old one, complete; nothing parked or partial.
        [ "$(cat "$AGENTS/askcodex/SKILL.md")" = old ]
        [ "$(cat "$AGENTS/askcodex/references/notes.md")" = 'old reference' ]
        [ "$(count_entries "$AGENTS")" -eq 1 ]
        [ "$(count_entries "$BACKUPS")" -eq 0 ]
        [[ "$output" == *"interrupted before the previous skill was backed up: it is back"* ]]
        rm "$TASK_ROOT/bin/$point"
        invoke --skills agents
        [ "$status" -eq 0 ]
        cmp "$TASK_REPO/skill/SKILL.md" "$AGENTS/askcodex/SKILL.md"
        [ "$(cat "$backup/references/notes.md")" = 'old reference' ]
        [ "$(count_entries "$AGENTS")" -eq 1 ]
    done
}

@test "an XDG_DATA_HOME inside a skills directory falls back to the default backup dir" {
    fake_date
    mkdir -p "$TASK_HOME/.agents/skills"
    ln -s .agents/skills "$TASK_HOME/skills-link"
    for xdg in "$TASK_HOME/.agents/skills" "$TASK_HOME/skills-link" "$TASK_HOME/.claude/skills/data"; do
        rm -rf "$AGENTS/askcodex" "$TASK_HOME/.local/share"
        skill_with "$AGENTS/askcodex" old
        TASK_XDG="$xdg"
        invoke --skills agents
        [ "$status" -eq 0 ]
        [[ "$output" == *"warning: $xdg/askcodex/skill-backups is inside the skills directory"* ]]
        [ "$(cat "$BACKUPS/agents-$STAMP/SKILL.md")" = old ]
        cmp "$TASK_REPO/skill/SKILL.md" "$AGENTS/askcodex/SKILL.md"
        [ "$(count_entries "$AGENTS/askcodex")" -eq 1 ]
        [ "$(count_entries "$AGENTS")" -eq 1 ]
        [ ! -e "$TASK_HOME/.claude/skills/data" ]
        # And it converges.
        invoke --skills agents
        [ "$status" -eq 0 ]
        [[ "$output" == *'already holds exactly this skill'* ]]
        [ "$(count_entries "$BACKUPS")" -eq 1 ]
    done
}

@test "a default backup dir that resolves inside a skills directory refuses before touching skills" {
    skill_with "$AGENTS/askcodex" old
    mkdir -p "$TASK_HOME/.local"
    ln -s ../.agents/skills "$TASK_HOME/.local/share"
    invoke --skills agents
    [ "$status" -ne 0 ]
    [[ "$output" == *"the backup directory $BACKUPS is inside the skills directory"* ]]
    [ "$(cat "$AGENTS/askcodex/SKILL.md")" = old ]
    [ "$(count_entries "$AGENTS")" -eq 1 ]
}

@test "a copy that fails partway publishes nothing, is discarded, and prints no hand-typed retry" {
    fake_date
    cross_fs
    skill_with "$AGENTS/askcodex" old
    mkdir -p "$AGENTS/askcodex/references"
    printf 'old reference\n' >"$AGENTS/askcodex/references/notes.md"
    # Out of space: a partial tree at the destination, then failure.
    # shellcheck disable=SC2016  # code for the fake cp, expanded there
    fake_cmd cp 3 '*/.incoming-*' 'mkdir -p "$3/references"; exit 1'
    invoke --skills agents
    [ "$status" -eq 1 ]
    held="$AGENTS/askcodex.bak.$STAMP"
    cmp "$TASK_REPO/skill/SKILL.md" "$AGENTS/askcodex/SKILL.md"
    [ "$(cat "$held/SKILL.md")" = old ]
    [ "$(cat "$held/references/notes.md")" = 'old reference' ]
    [ "$(count_entries "$BACKUPS")" -eq 0 ]
    [[ "$output" == *"error: could not back up $held"* ]]
    [[ "$output" == *'Re-run ./install.sh with the same --skills to retry'* ]]
    [[ "$output" != *"mv \"$held\" \"$BACKUPS"* ]]
    [[ "$output" == *"rollback: $(restore_cmd "$AGENTS/askcodex" "$held")"* ]]
    rm "$TASK_ROOT/bin/cp"
    invoke --skills agents
    [ "$status" -eq 0 ]
    [ "$(cat "$BACKUPS/agents-askcodex.bak.$STAMP/SKILL.md")" = old ]
    [ "$(cat "$BACKUPS/agents-askcodex.bak.$STAMP/references/notes.md")" = 'old reference' ]
    [ "$(count_entries "$BACKUPS")" -eq 1 ]
    no_backups_beside "$AGENTS"
}

@test "an absolute XDG_DATA_HOME is honored, a relative one ignored, and umask respected" {
    TASK_XDG="$TASK_ROOT/xdg"
    skill_with "$AGENTS/askcodex" old
    umask 077
    invoke --skills agents
    [ "$status" -eq 0 ]
    run grep -rl '^old$' "$TASK_XDG/askcodex/skill-backups"
    [ "$status" -eq 0 ]
    [ ! -e "$TASK_HOME/.local/share" ]
    run perl -e 'exit(((stat($ARGV[0]))[2] & 0777) == 0700 ? 0 : 1)' "$TASK_XDG/askcodex/skill-backups"
    [ "$status" -eq 0 ]
    printf 'older\n' >"$AGENTS/askcodex/SKILL.md"
    TASK_XDG=relative-data
    invoke --skills agents
    [ "$status" -eq 0 ]
    run grep -rl '^older$' "$BACKUPS"
    [ "$status" -eq 0 ]
    [ ! -e "$TASK_REPO/relative-data" ]
    no_backups_beside "$AGENTS"
}

@test "an identical installed skill makes no backup" {
    invoke --skills agents
    [ "$status" -eq 0 ]
    invoke --skills agents
    [ "$status" -eq 0 ]
    [[ "$output" == *'already holds exactly this skill'* ]]
    [[ "$output" == *'nothing was replaced by this run'* ]]
    [[ "$output" != *'backup :'* ]]
    [ ! -e "$TASK_HOME/.local/share/askcodex" ]
    no_backups_beside "$AGENTS"
}

@test "a failed or interrupted swap restores the original skill" {
    skill_with "$AGENTS/askcodex" old
    # The second action is code for the fake mv: $PPID is the installer it
    # interrupts between the two renames, so it must not expand here.
    # shellcheck disable=SC2016
    for action in 'exit 1' 'kill -TERM "$PPID"; exit 1'; do
        fake_cmd mv 1 '*/askcodex.new' "$action"
        invoke --skills agents
        [ "$status" -ne 0 ]
        [ "$(cat "$AGENTS/askcodex/SKILL.md")" = old ]
        [[ "$output" == *"previous skill restored at $AGENTS/askcodex"* ]]
        [ ! -e "$AGENTS/askcodex.new" ]
        [ ! -e "$AGENTS/askcodex.lock" ]
        no_backups_beside "$AGENTS"
        [ "$(count_entries "$BACKUPS")" -eq 0 ]
    done
    [ "$status" -eq 143 ]
    # A second TERM while the cleanup puts the skill back must not cut it
    # short: the skill is restored and the lock released.
    cat >"$TASK_ROOT/bin/mv" <<SH
#!/bin/sh
case "\$1" in
*/askcodex.new) kill -TERM "\$PPID"; exit 1 ;;
*/askcodex.bak.*) kill -TERM "\$PPID" ;;
esac
exec "$(command -v mv)" "\$@"
SH
    invoke --skills agents
    [ "$status" -eq 143 ]
    [ "$(cat "$AGENTS/askcodex/SKILL.md")" = old ]
    [[ "$output" == *"previous skill restored at $AGENTS/askcodex"* ]]
    [ ! -e "$AGENTS/askcodex.lock" ]
    no_backups_beside "$AGENTS"
}

@test "a backup that cannot leave the skills dir is reported loudly, fails the run, and moves on re-run" {
    fake_date
    for mode in same cross; do
        rm -rf "$TASK_HOME/.agents" "$TASK_HOME/.local/share"
        [ "$mode" = same ] || cross_fs
        skill_with "$AGENTS/askcodex" old
        fake_cmd mv 2 '*/skill-backups/*' 'exit 1'
        invoke --skills agents
        [ "$status" -eq 1 ]
        held="$AGENTS/askcodex.bak.$STAMP"
        cmp "$TASK_REPO/skill/SKILL.md" "$AGENTS/askcodex/SKILL.md"
        [ "$(cat "$held/SKILL.md")" = old ]
        [ ! -e "$AGENTS/askcodex.lock" ]
        [ "$(count_entries "$BACKUPS")" -eq 0 ]
        [[ "$output" == *"error: could not back up $held"* ]]
        [[ "$output" == *"into $BACKUPS. It is intact"* ]]
        [[ "$output" != *"mv \"$held\" \"$BACKUPS"* ]]
        [[ "$output" == *"rollback: $(restore_cmd "$AGENTS/askcodex" "$held")"* ]]
        [[ "$output" == *'1 askcodex backup(s) or leftover(s) are still inside a skills directory'* ]]
        rm "$TASK_ROOT/bin/mv"
        invoke --skills agents
        [ "$status" -eq 0 ]
        [ "$(cat "$BACKUPS/agents-askcodex.bak.$STAMP/SKILL.md")" = old ]
        no_backups_beside "$AGENTS"
    done
}

@test "auth check is explicit no-refresh and suppresses private diagnostics" {
    invoke --check-auth --skills all
    [ "$status" -ne 0 ]
    [[ "$output" == *'auth check failed'* ]]
    [[ "$output" != *'private diagnostic'* ]]
    [ "$(tail -n 1 "$TASK_LOG")" = 'auth status --no-refresh' ]
    [ ! -e "$TASK_HOME/.agents" ]
    TASK_AUTH_EXIT=0 invoke --check-auth
    [ "$status" -eq 0 ]
}

@test "invalid arguments and help perform no installation" {
    for args in '--unknown' '--skills' '--skills invalid'; do
        # Intentional splitting exercises the CLI argument vector.
        # shellcheck disable=SC2086
        invoke $args
        [ "$status" -ne 0 ]
        [ ! -e "$TASK_HOME/.local" ]
    done
    invoke --help
    [ "$status" -eq 0 ]
    [ ! -e "$TASK_HOME/.local" ]
}

@test "existing directory permissions and a locked skill remain untouched" {
    mkdir -p "$TASK_HOME/.local/bin" "$TASK_HOME/.agents/skills/askcodex.lock" "$TASK_HOME/.agents/skills/askcodex"
    chmod 700 "$TASK_HOME/.local/bin"
    printf 'old\n' >"$TASK_HOME/.agents/skills/askcodex/SKILL.md"
    invoke --skills agents
    [ "$status" -ne 0 ]
    [ "$(cat "$TASK_HOME/.agents/skills/askcodex/SKILL.md")" = old ]
    [ -d "$TASK_HOME/.agents/skills/askcodex.lock" ]
    run test -x "$TASK_HOME/.local/bin/askcodex"
    [ "$status" -eq 0 ]
    run perl -e 'exit(((stat($ARGV[0]))[2] & 0777) == 0700 ? 0 : 1)' "$TASK_HOME/.local/bin"
    [ "$status" -eq 0 ]
}

@test "failed staging keeps old skill, changes nothing else, and releases its lock" {
    skill_with "$AGENTS/askcodex" old
    skill_with "$AGENTS/askcodex.bak" legacy
    cat >"$TASK_ROOT/bin/cp" <<'SH'
#!/bin/sh
exit 1
SH
    chmod +x "$TASK_ROOT/bin/cp"
    invoke --skills agents
    [ "$status" -ne 0 ]
    [ "$(cat "$AGENTS/askcodex/SKILL.md")" = old ]
    [ "$(cat "$AGENTS/askcodex.bak/SKILL.md")" = legacy ]
    [ ! -e "$AGENTS/askcodex.lock" ]
    [ ! -e "$AGENTS/askcodex.new" ]
    [ "$(count_entries "$AGENTS")" -eq 2 ]
    [ ! -e "$TASK_HOME/.local/share/askcodex" ]
}
