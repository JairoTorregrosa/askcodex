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
}

invoke() {
    run env HOME="$TASK_HOME" CODEX_HOME="$TASK_HOME/absent-auth" PATH="$TASK_ROOT/bin:$PATH" \
        sh "$TASK_REPO/install.sh" "$@"
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

@test "all skills preserve old backups and converge without new backups" {
    mkdir -p "$TASK_HOME/.agents/skills/askcodex" "$TASK_HOME/.agents/skills/askcodex.bak"
    printf 'old\n' >"$TASK_HOME/.agents/skills/askcodex/SKILL.md"
    printf 'original\n' >"$TASK_HOME/.agents/skills/askcodex.bak/SKILL.md"
    invoke --skills all
    [ "$status" -eq 0 ]
    [ "$(cat "$TASK_HOME/.agents/skills/askcodex.bak/SKILL.md")" = original ]
    run grep -rl '^old$' "$TASK_HOME/.agents/skills"
    [ "$status" -eq 0 ]
    old_backup="$output"
    invoke --skills all
    [ "$status" -eq 0 ]
    [ "$(cat "$old_backup")" = old ]
    [[ "$output" == *'already holds exactly this skill'* ]]
    [ -f "$TASK_HOME/.claude/skills/askcodex/SKILL.md" ]
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

@test "failed staging keeps old skill and releases its lock" {
    mkdir -p "$TASK_HOME/.agents/skills/askcodex"
    printf 'old\n' >"$TASK_HOME/.agents/skills/askcodex/SKILL.md"
    cat >"$TASK_ROOT/bin/cp" <<'SH'
#!/bin/sh
exit 1
SH
    chmod +x "$TASK_ROOT/bin/cp"
    invoke --skills agents
    [ "$status" -ne 0 ]
    [ "$(cat "$TASK_HOME/.agents/skills/askcodex/SKILL.md")" = old ]
    [ ! -e "$TASK_HOME/.agents/skills/askcodex.lock" ]
    [ ! -e "$TASK_HOME/.agents/skills/askcodex.new" ]
    [ ! -e "$TASK_HOME/.agents/skills/askcodex.bak" ]
}
