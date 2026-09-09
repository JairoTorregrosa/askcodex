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
            cmd: ImageCmd::Create { prompt, out },
        } => {
            preflight_out_path(&out)?;
            Resolved::Backend(Backend::ImageCreate { prompt, out })
        }
        Cmd::Image {
            cmd:
                ImageCmd::Edit {
                    prompt,
                    inputs,
                    out,
                },
        } => {
            preflight_out_path(&out)?;
            let refs: Vec<&Path> = inputs.iter().map(PathBuf::as_path).collect();
            let prepared = endpoints::images::PreparedEdit::read(&prompt, &refs)?;
            Resolved::Backend(Backend::ImageEdit { out, prepared })
        }
        Cmd::Ask {
            prompt,
            model,
            instructions,
            effort,
        } => {
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
