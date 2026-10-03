//! Prepare local inputs before authentication or network work.

use super::*;

pub(super) const STDIN_MARKER: &str = "-";

#[derive(Debug)]
pub(super) enum Resolved {
    Reference,
    Auth(AuthCmd),
    Backend(Backend),
}

#[derive(Debug)]
pub(super) enum Backend {
    Transcribe {
        upload: endpoints::transcription::Upload,
    },
    Whoami,
    Usage,
    Models {
        client_version: String,
    },
    ImageCreate {
        prompt: String,
        out: PathBuf,
        background: Option<Background>,
    },
    ImageEdit {
        prepared: endpoints::images::PreparedEdit,
        out: PathBuf,
    },
    Ask {
        prompt: String,
        model: String,
        instructions: Option<String>,
        effort: Option<Effort>,
        verbosity: Option<Verbosity>,
        /// Already read and parsed: a missing or malformed schema file
        /// never reaches the network.
        schema: Option<Value>,
    },
    Raw {
        method: HttpMethod,
        path: String,
        /// Already parsed: an unparseable `--body` never reaches this far.
        body: Option<Value>,
        stream: bool,
    },
}

pub(super) fn resolve(cmd: Cmd, stdin: &mut dyn Read) -> Result<Resolved, Error> {
    let resolved = match cmd {
        Cmd::Reference => Resolved::Reference,
        Cmd::Transcribe { file } => Resolved::Backend(Backend::Transcribe {
            upload: endpoints::transcription::Upload::read(&file)?,
        }),
        Cmd::Whoami => Resolved::Backend(Backend::Whoami),
        Cmd::Usage => Resolved::Backend(Backend::Usage),
        Cmd::Models { client_version } => Resolved::Backend(Backend::Models { client_version }),
        Cmd::Image {
            cmd:
                ImageCmd::Create {
                    prompt,
                    out,
                    background,
                },
        } => {
            preflight_out_path(&out)?;
            Resolved::Backend(Backend::ImageCreate {
                prompt,
                out,
                background,
            })
        }
        Cmd::Image {
            cmd:
                ImageCmd::Edit {
                    prompt,
                    inputs,
                    out,
                    background,
                },
        } => {
            preflight_out_path(&out)?;
            let refs: Vec<&Path> = inputs.iter().map(PathBuf::as_path).collect();
            let prepared = endpoints::images::PreparedEdit::read(&prompt, &refs, background)?;
            Resolved::Backend(Backend::ImageEdit { out, prepared })
        }
        Cmd::Ask {
            prompt,
            model,
            instructions,
            effort,
            verbosity,
            schema,
        } => {
            let schema = schema.as_deref().map(read_schema).transpose()?;
            let prompt = if prompt == STDIN_MARKER {
                read_stdin(stdin)?
            } else {
                prompt
            };
            Resolved::Backend(Backend::Ask {
                prompt,
                model,
                instructions,
                effort,
                verbosity,
                schema,
            })
        }
        Cmd::Raw {
            method,
            path,
            body,
            stream,
        } => {
            let body = match body {
                None => None,
                Some(raw) => {
                    let raw = if raw == STDIN_MARKER {
                        read_stdin(stdin)?
                    } else {
                        raw
                    };
                    // Loud, and loud HERE: askcodex never posts a body it could
                    // not parse, and never spends a token refresh finding
                    // out that the body was malformed all along.
                    Some(serde_json::from_str::<Value>(&raw)?)
                }
            };
            Resolved::Backend(Backend::Raw {
                method,
                path,
                body,
                stream,
            })
        }
        Cmd::Auth { cmd } => Resolved::Auth(cmd),
    };
    Ok(resolved)
}

/// Read a `--schema` file: a bounded regular file holding one JSON object.
/// Whether it is a valid strict schema is the backend's call (it answers
/// HTTP 400 `invalid_json_schema` naming the problem); a file that is not
/// even a JSON object is refused here, before credentials are loaded.
pub(super) fn read_schema(path: &Path) -> Result<Value, Error> {
    let bytes = crate::input::read_file(path, crate::input::MAX_TEXT_BYTES, "schema file")?;
    match serde_json::from_slice::<Value>(&bytes)? {
        schema @ Value::Object(_) => Ok(schema),
        _ => Err(Error::InvalidInput {
            reason: "--schema must hold a JSON object (a JSON Schema)",
        }),
    }
}

pub(super) fn read_stdin(stdin: &mut dyn Read) -> Result<String, Error> {
    let bytes = crate::input::read_limited(stdin, crate::input::MAX_TEXT_BYTES).map_err(
        |error| match error {
            Error::Io(source) => io_context("reading stdin", source),
            other => other,
        },
    )?;
    String::from_utf8(bytes).map_err(|_| Error::InvalidInput {
        reason: "stdin must be UTF-8 text",
    })
}
