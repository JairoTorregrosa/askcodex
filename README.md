<img src="assets/logo.png" alt="askcodex logo" width="96" align="right">

# askcodex

[![CI](https://github.com/JairoTorregrosa/askcodex/actions/workflows/ci.yml/badge.svg)](https://github.com/JairoTorregrosa/askcodex/actions/workflows/ci.yml)

Text, images, and audio transcription from your terminal using your existing
ChatGPT/Codex subscription credentials. No API key is used or accepted.

```sh
askcodex ask "Explain this stack trace: [trace]"
askcodex image create "a tiny origami crane" -o crane.png
askcodex transcribe recording.wav
askcodex usage
```

## Install

```sh
git clone https://github.com/JairoTorregrosa/askcodex
cd askcodex
./install.sh
```

The installer requires Rust 1.88+, builds the checkout, and installs
`~/.local/bin/askcodex`. Installation does not require credentials, read the
auth file, or install agent skills. It uses no sudo and preserves existing
directory permissions. Add `~/.local/bin` to PATH if needed.

Choose optional operations explicitly:

```sh
./install.sh --skills agents    # ~/.agents/skills/askcodex
./install.sh --skills claude    # ~/.claude/skills/askcodex
./install.sh --skills all       # both destinations, with backups
codex login                    # use file-based credential storage
./install.sh --check-auth      # read-only diagnostic; never refreshes
```

Options can be combined. Skill synchronization preserves earlier backups and
leaves an identical installed skill untouched. `--check-auth` suppresses account
details in installer output. A prebuilt binary can also be downloaded from
[releases](https://github.com/JairoTorregrosa/askcodex/releases); verify its
`SHA256SUMS` before installing.

## Ask a model

```sh
askcodex ask "Write a commit message for this change: [diff]"
askcodex ask - --effort high < brief.txt
askcodex models --json --no-refresh | jq .result.models
```

Answers stream as text. `-` reads up to 16 MiB of UTF-8 prompt text from stdin.
Include the relevant
source text in the prompt; a file path alone does not give the model its contents.
Use the current catalog to choose `--model` and supported `--effort` values.

## Create and edit images

```sh
askcodex image create "a tiny origami crane made of graph paper" -o crane.png
askcodex image edit "same crane, night scene, desk lamp" -i crane.png -o night.png
```

<img src="assets/demo-image.png" alt="Generated origami crane made of graph paper" width="420">

The observed backend output is one opaque PNG at server-selected dimensions.
There are no size, quality, transparency, format, batch, or image-model flags.
Edit accepts up to five PNG references totaling at most 25 MiB; changing an
extension does not convert an image. Local references and output paths are checked before authentication.
Save useful versions under distinct names and inspect the actual result.

## Transcribe audio

```sh
askcodex transcribe recording.wav
askcodex transcribe recording.wav --json > transcript.json
jq -r .result.text transcript.json
```

Input must have a WAV signature and fit the 25 MiB client upload limit. Convert
other formats first, for example with FFmpeg:

```sh
ffmpeg -i recording.mp3 -ar 16000 -ac 1 recording.wav
```

These conversion settings are a starting point, not required server settings.
The command provides transcript text without model or language selectors,
timestamps, or speaker labels. Invalid local audio fails before authentication
or upload.

File inputs must be regular files; symlinks to regular files are supported.
Devices and FIFOs are rejected before reading. The 16 MiB stdin and 25 MiB
audio/combined-image limits are client memory policies, not backend limits.

## Accounts and credentials

```sh
askcodex usage --no-refresh
askcodex whoami --no-refresh
askcodex auth status --no-refresh
```

Credentials come from `${CODEX_HOME:-~/.codex}/auth.json`, written by
`codex login` with file storage. Keyring-only credentials are not supported.
`--no-refresh` prevents automatic renewal; an expired token fails instead.
Explicit `askcodex auth refresh` requests renewal even if `--no-refresh` is set.

Auth status reports claims and expiry, so its output can contain account details.
Do not paste it into public logs without redaction. Tokens are hidden in debug
output and have no general serialization API. Credential writes use a private
persistence path with restricted permissions, atomic replacement, and backups;
unknown credential fields are preserved. The askcodex process lock does not
coordinate with another application writing the same file.

## Machine output

Semantic commands with `--json` print one versioned document on success:

```json
{"schema_version":1,"command":"ask","result":{"model":"example-model","effort":null,"text":"Example answer","usage":null}}
```

`result` is the command result. An optional `backend` field preserves the
original response for commands that expose it; backend fields are not a stable
askcodex schema. Use these paths in scripts:

```sh
askcodex ask - --json < brief.txt > answer.json
jq -r .result.text answer.json
askcodex models --json --no-refresh | jq .result.models
askcodex usage --json --no-refresh | jq .result.rate_limit
```

`--events` selects newline-delimited JSON for semantic commands. `ask` emits
`text_delta` events followed by one `result` event on successful completion;
other semantic commands emit their final result. Check the process exit status:
a partial stream is not a successful answer. `--json` and `--events` are mutually
exclusive. Failures have a nonzero exit and a structured error on stderr with
`schema_version`, `error.code`, and `error.message`; no final success result is emitted.

```sh
askcodex ask - --events < brief.txt > answer.ndjson 2> error.json
askcodex reference > commands.md
```

`reference` generates the command reference locally without authentication or
network access. The checked-in [command reference](docs/COMMANDS.md) is generated
from the same CLI definitions.

For an endpoint without a semantic command, `raw` preserves backend JSON and
stream bytes. It does not wrap the response in the semantic envelope:

```sh
askcodex raw GET /codex/usage --json
askcodex raw POST /codex/responses --body - --stream < request.json
```

`--body -` reads up to 16 MiB of UTF-8 JSON from stdin.

`raw` only sends credentials to the configured backend origin; other origins
are rejected and redirects are disabled. `raw --stream --json` retains its
verbatim stream and reports that exception on stderr. `raw` does not support
`--events`.

## Development

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
bats tests/install.bats
shellcheck install.sh tests/install.bats
shfmt -d -i 4 install.sh tests/install.bats
```

Default tests are offline, using fake credentials and loopback HTTP servers.
Live tests are ignored by default and require explicit execution plus
authorization gates; see [testing](docs/TESTING.md). See [AGENTS.md](AGENTS.md)
for contributor instructions, [design](DESIGN.md) for architecture,
[protocol evidence](docs/PROTOCOL.md) for backend observations, and
[governance](GOVERNANCE.md) for review requirements.

## License

MIT or Apache-2.0, at your option.
