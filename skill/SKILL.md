---
name: askcodex
description: >-
  Use the askcodex CLI to get text and code from OpenAI models, generate or edit
  images, transcribe audio, and inspect available models, subscription usage, or authentication.
  Trigger for requests such as "pregúntale a GPT", "genera una imagen",
  "edita esta foto", "transcribe este audio", "qué modelos tengo", or "cuánta cuota queda", and for
  bounded tasks that benefit from a second model's answer.
---

# askcodex

Use `askcodex` to turn a concrete brief into a text answer, code, image, or audio transcript.
Choose the command, supply the context it needs, inspect the result, and return
the useful output with its saved path.

## Choose the workflow

| Intended result | Command | Read before prompting |
|---|---|---|
| Answer, analysis, extraction, writing, code, or review | `askcodex ask "prompt" --model <slug> --effort <level>` | [Text and code](references/prompting-text.md) |
| New image | `askcodex image create "prompt" -o /tmp/askcodex/image-v1.png` | [Images](references/prompting-images.md) |
| Edit using one or more images | `askcodex image edit "prompt" -i reference.png -o /tmp/askcodex/image-v2.png` | [Images](references/prompting-images.md) |
| Audio transcript | `askcodex transcribe recording.wav` | [Transcription](references/transcription.md) |
| Available text/agent models | `askcodex models --json --no-refresh` | No prompting guide needed |
| Subscription usage | `askcodex usage --json --no-refresh` | No prompting guide needed |
| Account and plan | `askcodex whoami --no-refresh` | No prompting guide needed |
| Authentication status | `askcodex auth status --no-refresh` | No prompting guide needed |

[Prompting by product](references/prompting.md) is the reference index.
Read only the guide relevant to the requested output.

## Work from a complete brief

1. Identify the deliverable, audience, constraints, and definition of success.
2. Supply the source material the model needs. Include text explicitly; attach
   image references with `-i` for image edits.
3. Specify the output format and what must remain unchanged.
4. Run one focused request. For a long-running job, use the machine's queue
   or tmux and save its output to a file.
5. Inspect the result against the brief. Make the next request about a specific
   observed problem; preserve the last useful version.

Treat a second model's answer as input to your work. Verify factual claims,
review generated code, and inspect generated images before reporting success.

## Save and return results

Create `/tmp/askcodex/` before writing artifacts. Use descriptive names and
version suffixes so edits do not overwrite a useful result.

- Images: always pass `-o /tmp/askcodex/<name>-v1.png`.
- Long text answers: use `--json > /tmp/askcodex/<name>.json`; read the answer
  with `jq -r .text /tmp/askcodex/<name>.json`.
- Keep large JSON documents and image payloads out of the conversation.
- Report the outcome, any material limitation, and the artifact path. Display
  the image when the user needs to assess it visually.
- Write into a project directory when the user requests that destination.

## Use the command surface accurately

- `--json` and `--no-refresh` are global flags and work after subcommands.
- `ask` streams text normally. With `--json`, it prints one document after
  completion containing `model`, `effort`, `text`, and `usage`. Usage may be null.
- `models --json` returns an envelope: read `.models`, not the root as an array.
- `transcribe` prints transcript text; `--json` preserves the response object. It accepts
  WAV files up to a 25 MiB client limit, with no model or language selector.
- `ask` accepts `--model`, `--effort`, and `--instructions`. Use the available
  model catalog to choose a slug and a supported effort.
- `image create` and `image edit` have no model, size, quality, transparency,
  output-format, or batch selector. Plan for one PNG per call and inspect its
  actual dimensions. Do not promise transparent output or an exact resolution.
- `image edit` accepts up to five PNG references. Renaming a JPEG to `.png`
  does not convert it; the CLI checks the file signature.
- `raw` is for an explicitly needed backend operation:
  `askcodex raw <METHOD> <PATH> --body '<JSON>'`. It accepts only the configured
  backend origin. Use the regular commands for the workflows above.

## Authentication and errors

The executable is `~/.local/bin/askcodex`. It uses credentials already stored
by `codex login`. If the executable is missing, installation instructions are
in [the askcodex repository](https://github.com/JairoTorregrosa/askcodex).

Use `--no-refresh` for read-only account and authentication checks.
`askcodex auth refresh` rotates credentials and rewrites the auth file; use it
when the user requests a refresh. Never print credentials.

On a nonzero exit, report the error and resolve its cause before another
attempt. Do not loop, fabricate a result, or silently switch models.
