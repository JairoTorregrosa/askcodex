//! Execute prepared commands using the authenticated client and output adapters.

use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{Value, json};

use crate::cli::{AuthCmd, Cli, Cmd, Effort, HttpMethod, ImageCmd};
use crate::config;
use crate::endpoints;
use crate::error::Error;
use crate::http::Client;
use crate::models::{AskOutput, AuthFile, ImageResult, ModelInfo, ResponsesRequest, UsageResponse};
use crate::{auth, models};

mod artifacts;
mod output;
mod prepare;

use artifacts::*;
use output::*;
use prepare::*;

pub fn run(cli: Cli) -> Result<(), Error> {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let stderr = std::io::stderr();
    let mut err = stderr.lock();
    let stdin = std::io::stdin();
    let mut input = stdin.lock();

    let result = run_with_io(cli, &mut out, &mut err, &mut input);
    // Flush unconditionally: a buffered payload that never reached the pipe
    // is a silent truncation, and a flush failure must be reported rather
    // than swallowed. The command's own error still wins — it is the root
    // cause.
    let flushed = out.flush();
    result?;
    flushed?;
    Ok(())
}

fn run_with_io(
    cli: Cli,
    out: &mut dyn Write,
    err: &mut dyn Write,
    stdin: &mut dyn Read,
) -> Result<(), Error> {
    let mode = if cli.events {
        Mode::Events
    } else {
        Mode::from(cli.json)
    };
    if cli.events && matches!(cli.cmd, Cmd::Raw { .. }) {
        return Err(Error::InvalidInput {
            reason: "raw preserves the wire response and cannot use --events",
        });
    }
    // Resolve every local input before reading or refreshing credentials.
    let resolved = resolve(cli.cmd, stdin)?;
    let load_session = || auth::AuthSession::load(auth::CredentialStore::configured()?);

    match resolved {
        Resolved::Reference => {
            let reference = crate::cli::reference();
            if mode == Mode::Text {
                emit_human(out, &reference)
            } else {
                emit_result(
                    out,
                    mode,
                    "reference",
                    &json!({"markdown": reference}),
                    None,
                )
            }
        }
        // Step 3a: `auth` manages its own freshness — no client, no
        // pre-flight refresh (Python parity).
        Resolved::Auth(cmd) => run_auth(cmd, load_session()?, mode, out),
        // Step 3b: everything else authenticates first.
        Resolved::Backend(cmd) => {
            let mut client = Client::from_session(load_session()?, cli.no_refresh)?;
            // A no-op when `--no-refresh` is set (the flag's contract).
            client.ensure_fresh()?;
            run_backend(cmd, &mut client, mode, out, err)
        }
    }
}

fn run_auth(
    cmd: AuthCmd,
    mut session: auth::AuthSession,
    mode: impl Into<Mode>,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let mode = mode.into();
    let path = session.path().to_path_buf();
    match cmd {
        AuthCmd::Status => {
            let view = AuthStatusView::new(session.document(), path, Utc::now())?;
            if mode != Mode::Text {
                emit_result(out, mode, "auth status", &view.to_json(), None)
            } else {
                emit_human(out, &view.render())
            }
        }
        AuthCmd::Refresh => {
            // Explicit refresh remains independent of --no-refresh.
            session.refresh(&oauth_agent())?;
            let view = RefreshView::new(session.document(), &path, Utc::now())?;
            if mode != Mode::Text {
                emit_result(out, mode, "auth refresh", &view.to_json(), None)
            } else {
                emit_human(out, &view.render())
            }
        }
    }
}

fn oauth_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_secs(config::CONNECT_TIMEOUT_SECS)))
        .user_agent(config::USER_AGENT)
        .build()
        .into()
}

fn run_backend(
    cmd: Backend,
    client: &mut Client,
    mode: impl Into<Mode>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<(), Error> {
    let mode = mode.into();
    match cmd {
        Backend::Whoami => {
            let who = endpoints::account::whoami(client)?;
            if mode != Mode::Text {
                emit_result(out, mode, "whoami", &who, None)
            } else {
                emit_human(out, &render_whoami(&who))
            }
        }
        Backend::Transcribe { upload } => {
            let (text, raw) = upload.transcribe(client)?;
            if mode != Mode::Text {
                emit_result(out, mode, "transcribe", &json!({"text": text}), Some(&raw))
            } else {
                writeln!(out, "{text}").map_err(Error::from)
            }
        }
        Backend::Usage => {
            let (usage, raw) = endpoints::account::usage(client)?;
            if mode != Mode::Text {
                emit_result(out, mode, "usage", &usage, Some(&raw))
            } else {
                emit_human(out, &render_usage(&usage))
            }
        }
        Backend::Models { client_version } => {
            let (models, raw) = endpoints::account::models(client, &client_version)?;
            if mode != Mode::Text {
                emit_result(out, mode, "models", &json!({"models": models}), Some(&raw))
            } else {
                emit_human(out, &render_models(&models))
            }
        }
        Backend::ImageCreate { prompt, out: path } => run_image(&path, None, mode, out, || {
            endpoints::images::create(client, &prompt)
        }),
        Backend::ImageEdit {
            prepared,
            out: path,
        } => run_image(&path, Some(prepared.count()), mode, out, || {
            prepared.send(client)
        }),
        Backend::Ask {
            prompt,
            model,
            instructions,
            effort,
        } => {
            let effort = effort.map(|e| e.as_str().to_string());
            let request =
                ResponsesRequest::user_text(model.clone(), prompt, instructions, effort.clone());
            emit_ask(mode, &model, effort.as_deref(), out, err, |on_delta| {
                endpoints::responses::ask(client, &request, on_delta)
            })
        }
        Backend::Raw {
            method,
            path,
            body,
            stream,
        } => {
            if stream {
                if mode == Mode::Json {
                    advise_raw_stream_json(err)?;
                }
                let mut reader = client.request_stream(method.as_method(), &path, body.as_ref())?;
                copy_stream(&mut *reader, out)
            } else {
                let value = client.request_json(method.as_method(), &path, body.as_ref())?;
                // Already JSON: both modes print the same document.
                emit_json(out, &value)
            }
        }
    }
}

fn io_context(what: &str, source: std::io::Error) -> Error {
    Error::Io(std::io::Error::new(
        source.kind(),
        format!("{what}: {source}"),
    ))
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod migration_tests;
