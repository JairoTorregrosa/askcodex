//! Command dispatch and output rendering (the library's entry point).
//!
//! main.rs stays a thin shell; everything testable lives behind this
//! function.
//!
//! Shared pre-flight (Python parity):
//! 1. `auth::load_auth()`.
//! 2. Resolve every LOCAL input before anything touches the network: a `-`
//!    prompt / `--body` is read from stdin here, and a `--body` string is
//!    parsed as JSON here, so an unparseable body is loud BEFORE the
//!    pre-flight refresh (which is itself a network call).
//! 3. For every command EXCEPT `auth status` / `auth refresh`: build
//!    `http::Client` and call `ensure_fresh()` unless `--no-refresh`.
//!    (`auth` subcommands manage freshness themselves; `--no-refresh`
//!    additionally disables the 401 retry inside the client.)
//! 4. Dispatch per the table below. Errors propagate unchanged; main
//!    prints `askcodex: error: <msg>` on stderr and exits non-zero.
//!
//! Output contract per command (text mode / `--json` mode):
//! - `whoami`: aligned `key : value` lines for email, name, plan,
//!   account_id, user_id (absent -> `-`) / the `models::WhoamiOutput`
//!   struct, pretty JSON.
//! - `usage`: plan, limit_reached+allowed, then one line per present
//!   window (`used %`, window h, resets-in h; absent window -> line
//!   omitted; absent numbers -> `?`) / RAW usage response, pretty JSON.
//! - `models`: count header + one line per model (slug, input modalities,
//!   efforts from `supported_reasoning_levels[].effort` — a model with no
//!   levels and a model with no modalities both render `-`, visibility
//!   flag when not "list") / the RAW catalog envelope `{"models": [...]}`
//!   exactly as the backend sent it, unknown fields intact, pretty JSON.
//! - `image create|edit`: validate `--out` BEFORE the (billed) request,
//!   then write the validated PNG bytes through a same-directory temp file
//!   renamed over `--out`, and print `saved <out>  (<size> PNG, <n>
//!   bytes)` (edit adds `, <k> ref image(s)`). Neither an unusable
//!   destination nor a failed write may cost the user a generation or
//!   damage the file already at `--out`.
//!   AMENDED (declared deviation from the original contract): it said
//!   `--json` had "no separate shape (same line)". That line is not JSON,
//!   so honoring it would break the crate-wide rule that `--json` puts a
//!   single JSON document on stdout and nothing else. `--json` therefore
//!   emits `{"path", "size", "bytes", "ref_images"}`; the human line is
//!   unchanged, byte-for-byte.
//! - `ask`: prompt `-` -> read stdin to EOF first. Text mode: stream
//!   deltas to stdout as they arrive (flush each), final newline if a
//!   NON-EMPTY answer lacks one / JSON mode: print nothing during
//!   streaming, then `models::AskOutput { model, text }` pretty JSON. A
//!   stream that completed with no output text at all adds nothing to
//!   stdout and says so on stderr. `--effort` maps via
//!   `cli::Effort::as_str`.
//! - `raw`: `--body -` reads stdin; the body string must parse as JSON
//!   (loud `Error::Json` otherwise — never sent unvalidated). Without
//!   `--stream`: `Client::request_json`, print pretty JSON (that output is
//!   already JSON, so both modes print it). With `--stream`:
//!   `Client::request_stream` and copy raw SSE lines to stdout verbatim as
//!   they arrive (no framing, no filtering — this is the exploration
//!   escape hatch). `raw --stream` is the ONE stated exception to the
//!   `--json` purity rule: `--json` cannot reshape a verbatim passthrough,
//!   so askcodex says so on stderr instead of silently dropping the flag.
//! - `auth status`: NEVER prints a token value. Lines: auth file path,
//!   auth_mode, account_id, last_refresh, then access-token expiry via
//!   `auth::jwt_exp`: RFC3339 UTC + `(<n> min from now, valid|EXPIRED)`.
//!   `--json`: `{"auth_file", "auth_mode", "account_id", "last_refresh",
//!   "access_token_expires_at", "access_token_expires_in_minutes",
//!   "access_token_valid"}` — claims only, never a token value.
//! - `auth refresh`: force `auth::refresh` (no freshness check), then
//!   print the new expiry minutes and `last_refresh`. Secrets never
//!   printed. `--json`: the `auth status` expiry keys plus
//!   `"refreshed": true`. `--no-refresh` does NOT suppress this command:
//!   that flag suppresses the AUTOMATIC freshness check, and `auth
//!   refresh` is an explicit request.
//!
//! stdout is for payload, stderr is for errors — nothing else ever goes
//! to stdout (scripts pipe askcodex). Every value the backend omitted renders
//! as `-` in text mode and as JSON `null` in `--json` mode: absence is
//! shown, never filled in.
//!
//! Testability: the network lives at the edges. Every renderer is a pure
//! function over already-fetched values, input resolution is a pure
//! function over a `Read`, and streaming is driven through an injected
//! closure — so the unit tests below cover the whole output surface
//! offline, without credentials and without a socket.

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

/// Rendered in text mode wherever the backend (or `auth.json`) omitted a
/// value. Never a substituted value — just a visible "not present".
const ABSENT: &str = "-";

/// Rendered in place of a number the backend omitted.
const UNKNOWN: &str = "?";

/// The argument value that means "read this from stdin".
const STDIN_MARKER: &str = "-";

/// PNG magic. askcodex writes an image file only when the payload starts with
/// these four bytes.
const PNG_MAGIC: [u8; 4] = [0x89, b'P', b'N', b'G'];

/// Execute a parsed CLI invocation to completion.
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

/// [`run`] against explicit streams (the whole dispatch, minus the process
/// handles). stdout carries payload; stderr carries advisories only.
fn run_with_io(
    cli: Cli,
    out: &mut dyn Write,
    err: &mut dyn Write,
    stdin: &mut dyn Read,
) -> Result<(), Error> {
    // Step 1: credentials. A pure file read — loud and cheap, so it happens
    // before askcodex blocks on stdin for a `-` argument.
    let auth = auth::load_auth()?;

    // Step 2: every local input, resolved before ANY network call.
    let resolved = resolve(cli.cmd, stdin)?;

    match resolved {
        // Step 3a: `auth` manages its own freshness — no client, no
        // pre-flight refresh (Python parity).
        Resolved::Auth(cmd) => run_auth(cmd, auth, cli.json, out),
        // Step 3b: everything else authenticates first.
        Resolved::Backend(cmd) => {
            let mut client = Client::new(auth, cli.no_refresh)?;
            // A no-op when `--no-refresh` is set (the flag's contract).
            client.ensure_fresh()?;
            run_backend(cmd, &mut client, cli.json, out, err)
        }
    }
}

// ---------------------------------------------------------------------------
// input resolution (pure; no credentials, no network)
// ---------------------------------------------------------------------------

/// A command whose stdin-fed and locally-validated inputs are already
/// resolved. Splitting `auth` out here is what lets the dispatcher build
/// the backend client for exactly the commands that need one, with no
/// unreachable arm to guard.
#[derive(Debug)]
enum Resolved {
    Auth(AuthCmd),
    Backend(Backend),
}

/// A command that talks to the ChatGPT backend.
#[derive(Debug)]
enum Backend {
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
        prompt: String,
        inputs: Vec<PathBuf>,
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

/// Resolve `-` arguments from `stdin` and validate the `raw` body.
///
/// This runs before the pre-flight refresh, so `askcodex raw POST /x --body '{'`
/// fails on the malformed body instead of after a token round-trip.
fn resolve(cmd: Cmd, stdin: &mut dyn Read) -> Result<Resolved, Error> {
    let resolved = match cmd {
        Cmd::Whoami => Resolved::Backend(Backend::Whoami),
        Cmd::Usage => Resolved::Backend(Backend::Usage),
        Cmd::Models { client_version } => Resolved::Backend(Backend::Models { client_version }),
        Cmd::Image {
            cmd: ImageCmd::Create { prompt, out },
        } => Resolved::Backend(Backend::ImageCreate { prompt, out }),
        Cmd::Image {
            cmd:
                ImageCmd::Edit {
                    prompt,
                    inputs,
                    out,
                },
        } => Resolved::Backend(Backend::ImageEdit {
            prompt,
            inputs,
            out,
        }),
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

/// Read stdin to EOF. Kept verbatim (no trimming): the prompt or JSON body
/// is the user's payload, not askcodex's to edit.
fn read_stdin(stdin: &mut dyn Read) -> Result<String, Error> {
    let mut buffer = String::new();
    stdin
        .read_to_string(&mut buffer)
        .map_err(|source| io_context("reading stdin", source))?;
    Ok(buffer)
}

// ---------------------------------------------------------------------------
// dispatch
// ---------------------------------------------------------------------------

/// `auth status` / `auth refresh`. Neither builds a backend client and
/// neither runs the pre-flight freshness check.
fn run_auth(
    cmd: AuthCmd,
    mut auth: AuthFile,
    json: bool,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let path = config::auth_path()?;
    match cmd {
        AuthCmd::Status => {
            // Everything is computed BEFORE anything is printed, so a
            // malformed access token fails the command outright instead of
            // leaving half a report (or half a JSON document) on stdout.
            let view = AuthStatusView::new(&auth, path, Utc::now())?;
            if json {
                emit_json(out, &view.to_json())
            } else {
                emit_human(out, &view.render())
            }
        }
        AuthCmd::Refresh => {
            // Forced: no freshness check, and `--no-refresh` does not apply
            // (it suppresses the AUTOMATIC check, not an explicit command).
            auth::refresh(&oauth_agent(), &mut auth)?;
            let view = RefreshView::new(&auth, &path, Utc::now())?;
            if json {
                emit_json(out, &view.to_json())
            } else {
                emit_human(out, &view.render())
            }
        }
    }
}

/// The agent used for the ONE OAuth call askcodex makes.
///
/// `auth::refresh` sets `http_status_as_error(false)` and its own global
/// timeout request-scoped, so only the connect timeout and the codex
/// User-Agent come from the agent. (`http::Client` owns an equivalent agent
/// for backend calls, but it does not lend out its `AuthFile` mutably, so
/// `auth refresh` builds its own rather than reaching into the client.)
fn oauth_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_secs(config::CONNECT_TIMEOUT_SECS)))
        .user_agent(config::USER_AGENT)
        .build()
        .into()
}

/// Every command that speaks to the ChatGPT backend.
fn run_backend(
    cmd: Backend,
    client: &mut Client,
    json: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<(), Error> {
    match cmd {
        Backend::Whoami => {
            let who = endpoints::account::whoami(client)?;
            if json {
                emit_json(out, &who)
            } else {
                emit_human(out, &render_whoami(&who))
            }
        }
        Backend::Usage => {
            let (usage, raw) = endpoints::account::usage(client)?;
            if json {
                // RAW: unknown backend fields are never dropped.
                emit_json(out, &raw)
            } else {
                emit_human(out, &render_usage(&usage))
            }
        }
        Backend::Models { client_version } => {
            let (models, raw) = endpoints::account::models(client, &client_version)?;
            if json {
                emit_json(out, &raw)
            } else {
                emit_human(out, &render_models(&models))
            }
        }
        Backend::ImageCreate { prompt, out: path } => run_image(&path, None, json, out, || {
            endpoints::images::create(client, &prompt)
        }),
        Backend::ImageEdit {
            prompt,
            inputs,
            out: path,
        } => {
            let refs: Vec<&Path> = inputs.iter().map(PathBuf::as_path).collect();
            run_image(&path, Some(inputs.len()), json, out, || {
                endpoints::images::edit(client, &prompt, &refs)
            })
        }
        Backend::Ask {
            prompt,
            model,
            instructions,
            effort,
        } => {
            let effort = effort.map(|e| e.as_str().to_string());
            let request =
                ResponsesRequest::user_text(model.clone(), prompt, instructions, effort.clone());
            emit_ask(json, &model, effort.as_deref(), out, err, |on_delta| {
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
                if json {
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

// ---------------------------------------------------------------------------
// emission helpers
// ---------------------------------------------------------------------------

/// Write pre-rendered text. Renderers own the trailing newline.
fn emit_human(out: &mut dyn Write, text: &str) -> Result<(), Error> {
    out.write_all(text.as_bytes())?;
    Ok(())
}

/// Write ONE pretty JSON document and nothing else (the trailing newline is
/// JSON whitespace, so the stream still parses as a single document).
fn emit_json<T: Serialize + ?Sized>(out: &mut dyn Write, value: &T) -> Result<(), Error> {
    let mut text = serde_json::to_string_pretty(value)?;
    text.push('\n');
    out.write_all(text.as_bytes())?;
    Ok(())
}

/// The one stated exception to `--json` purity, announced rather than
/// silently applied.
fn advise_raw_stream_json(err: &mut dyn Write) -> Result<(), Error> {
    writeln!(
        err,
        "askcodex: note: --json does not apply to `raw --stream`; stdout carries the raw event stream"
    )?;
    Ok(())
}

/// Copy an SSE body to stdout verbatim, flushing per line so a long stream
/// is visible as it arrives. Bytes are passed through untouched (not
/// UTF-8-decoded): this is the escape hatch, so what the wire said is what
/// the user sees.
fn copy_stream(reader: &mut dyn BufRead, out: &mut dyn Write) -> Result<(), Error> {
    let mut line = Vec::new();
    loop {
        line.clear();
        if reader.read_until(b'\n', &mut line)? == 0 {
            return Ok(());
        }
        out.write_all(&line)?;
        out.flush()?;
    }
}

/// Announce a completed stream that carried no output text. Not an error
/// (a response whose only item is a refusal really does complete), but
/// silence would leave "the model said nothing" indistinguishable from a
/// blank answer.
fn advise_empty_answer(err: &mut dyn Write) -> Result<(), Error> {
    writeln!(
        err,
        "askcodex: note: the response completed with no output text; the model returned nothing to print"
    )?;
    Ok(())
}

/// Drive an `ask` stream and emit the answer.
///
/// `stream` is injected so the streaming/emission policy is testable
/// without a socket: it receives the delta sink and returns the full
/// accumulated text.
fn emit_ask<F>(
    json: bool,
    model: &str,
    effort: Option<&str>,
    out: &mut dyn Write,
    err: &mut dyn Write,
    stream: F,
) -> Result<(), Error>
where
    F: FnOnce(&mut dyn FnMut(&str)) -> Result<endpoints::responses::AskAnswer, Error>,
{
    let mut write_error: Option<std::io::Error> = None;

    let answer = {
        let mut on_delta = |delta: &str| {
            // `--json` mode: NOTHING during the stream. The single JSON
            // document must be the only thing that reaches stdout.
            if json || write_error.is_some() {
                return;
            }
            // The sink cannot return a Result, so a write failure is
            // captured and raised below — never swallowed.
            if let Err(source) = out.write_all(delta.as_bytes()).and_then(|()| out.flush()) {
                write_error = Some(source);
            }
        };
        // A stream failure wins over a pending write failure: it is the
        // root cause, and a partial answer is never reported as complete.
        stream(&mut on_delta)?
    };

    if let Some(source) = write_error {
        return Err(io_context("writing the answer to stdout", source));
    }

    let text = answer.text;

    // Said once, before either rendering: an empty answer is a real
    // outcome, but it must be visible as one instead of being padded into
    // something that looks like text.
    if text.is_empty() {
        advise_empty_answer(err)?;
    }

    if json {
        emit_json(
            out,
            &AskOutput {
                model: model.to_string(),
                effort: effort.map(str::to_string),
                text,
                usage: answer.usage,
            },
        )
    } else if text.is_empty() || text.ends_with('\n') {
        // Nothing to terminate. A bare newline for an empty answer would
        // be a byte the model never sent — and a 1-byte file for anything
        // redirecting stdout.
        Ok(())
    } else {
        // Terminate the line the model left open, without adding anything
        // it did not say.
        emit_human(out, "\n")
    }
}

// ---------------------------------------------------------------------------
// image output
// ---------------------------------------------------------------------------

/// Generate an image and save it, with the destination proven usable
/// FIRST.
///
/// `generate` is the billed backend call. It is injected for the same
/// reason `emit_ask` injects its stream: it is the only difference between
/// `image create` and `image edit`, and it makes the ORDERING testable
/// offline — a test can prove the call is never reached when `--out` is
/// unusable. Spending a generation and only then discovering that askcodex
/// cannot save it is the exact failure this ordering prevents.
///
/// (The pre-flight token refresh in [`run_with_io`] still runs earlier.
/// That call is unbilled and its rotated token is persisted for later use,
/// so it is not a resource thrown away the way a generation is.)
fn run_image<F>(
    path: &Path,
    ref_images: Option<usize>,
    json: bool,
    out: &mut dyn Write,
    generate: F,
) -> Result<(), Error>
where
    F: FnOnce() -> Result<ImageResult, Error>,
{
    preflight_out_path(path)?;
    let image = generate()?;
    save_image(&image, path, ref_images, json, out)
}

/// Prove `--out` can be written BEFORE anything is spent on the image.
///
/// Every reason askcodex could fail to save the result that is knowable from
/// the local filesystem is checked here: a `--out` with no file name, an
/// existing directory or write-protected file in the way, a parent
/// directory that does not exist or is not writable. The probe creates and
/// immediately removes the SAME temp sibling [`write_png`] will use, so it
/// exercises the real permission set rather than guessing at it.
///
/// It must leave the filesystem exactly as it found it: an existing
/// `--out` is never touched (the probe writes a sibling), the probe file
/// is created with `O_CREAT|O_EXCL` so it can never adopt someone else's
/// file, and it is removed again — a removal failure is raised rather than
/// left behind as a stray that would make the real write fail later.
fn preflight_out_path(path: &Path) -> Result<(), Error> {
    let display = path.display();
    let temp = temp_sibling(path)?;
    ensure_replaceable(path)?;

    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .map_err(|source| io_context(&format!("preparing to write {display}"), source))?;
    std::fs::remove_file(&temp).map_err(|source| {
        io_context(
            &format!("removing the probe file {}", temp.display()),
            source,
        )
    })
}

/// Refuse a destination that must not be replaced.
///
/// Checked by the pre-flight (so it costs no generation) AND by
/// [`write_png`] itself (so the guarantee holds for any future caller —
/// the same belt-and-braces reasoning as the duplicated PNG-magic check).
///
/// The read-only case exists because of HOW askcodex writes now: `rename`
/// needs write permission on the DIRECTORY, not on the target, so an
/// atomic write would happily replace a mode-0444 file that the previous
/// `fs::write` path refused. A write-protected file stays write-protected.
fn ensure_replaceable(path: &Path) -> Result<(), Error> {
    // Not there yet is the normal case, and any other `stat` failure is
    // left to the write itself, which reports the reason that actually
    // stopped it rather than a second-hand one.
    let Ok(metadata) = std::fs::metadata(path) else {
        return Ok(());
    };
    let display = path.display();
    if metadata.is_dir() {
        return Err(io_context(
            &format!("writing {display}"),
            std::io::Error::new(
                std::io::ErrorKind::IsADirectory,
                "the output path is a directory",
            ),
        ));
    }
    if metadata.permissions().readonly() {
        return Err(io_context(
            &format!("writing {display}"),
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "the output path exists and is write-protected",
            ),
        ));
    }
    Ok(())
}

/// The temp file askcodex writes an image through, in the SAME directory as
/// `path` (same filesystem, so the final rename is atomic).
///
/// `with_file_name`, not `parent().join()`: a bare `-o image.png` has
/// `parent() == Some("")`, which would aim the temp somewhere other than
/// beside the target. The pid keeps two concurrent askcodex processes writing
/// the same `--out` from colliding.
fn temp_sibling(path: &Path) -> Result<PathBuf, Error> {
    let Some(file_name) = path.file_name() else {
        return Err(io_context(
            &format!("writing {}", path.display()),
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "the output path has no file name",
            ),
        ));
    };
    Ok(path.with_file_name({
        let mut name = file_name.to_os_string();
        name.push(format!(".askcodex-tmp.{}", std::process::id()));
        name
    }))
}

/// Write the PNG, then report where it went.
fn save_image(
    image: &ImageResult,
    path: &Path,
    ref_images: Option<usize>,
    json: bool,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let bytes = write_png(&image.png, path)?;
    let size = image.size.as_deref();
    if json {
        emit_json(out, &image_json(path, size, bytes, ref_images))
    } else {
        emit_human(out, &render_image_saved(path, size, bytes, ref_images))
    }
}

/// Write PNG bytes to `path` atomically, returning the byte count.
///
/// The magic is verified HERE as well as in the image endpoint: run.rs is
/// the only place that creates the file, so this check is what makes
/// "askcodex never writes a non-PNG" true no matter how the endpoint layer
/// evolves. A rejected payload leaves no file behind.
///
/// The bytes then go through a same-directory temp file that is flushed,
/// fsynced and renamed over `path` — the discipline `auth.rs` uses for
/// credentials, for the same reason. `std::fs::write` opens with
/// `O_CREAT|O_TRUNC`: it empties the destination before the first byte
/// lands, so a write that fails partway (ENOSPC, EIO) would leave a
/// truncated file that still starts with the PNG magic, with the previous
/// image already gone. With the rename, `path` is at every instant either
/// the complete old file or the complete new one, and a failed write
/// leaves the old one untouched.
///
/// Two deliberate divergences from `auth.rs`: no `mode(0o600)` (an image
/// is not a credential, so the file keeps the user's umask, exactly as
/// `fs::write` gave it), and the same consequence every rename-based write
/// has — a `--out` that is a SYMLINK is replaced by the image instead of
/// being followed. `auth.rs` accepted that trade for `auth.json`; an image
/// output is the less sensitive case of the two.
fn write_png(bytes: &[u8], path: &Path) -> Result<usize, Error> {
    if bytes.len() < PNG_MAGIC.len() || bytes[..PNG_MAGIC.len()] != PNG_MAGIC {
        return Err(Error::ImageNotPng {
            magic_hex: hex_prefix(bytes, PNG_MAGIC.len()),
        });
    }
    let display = path.display();
    let temp = temp_sibling(path)?;
    ensure_replaceable(path)?;

    // `create_new` (O_CREAT|O_EXCL): a temp that already exists belongs to
    // another process, and clobbering it is not this function's call. The
    // guard is armed only after a successful open, for that reason.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .map_err(|source| io_context(&format!("creating {}", temp.display()), source))?;
    let mut guard = TempFileGuard::new(&temp);

    let temp_display = temp.display().to_string();
    file.write_all(bytes)
        .map_err(|source| io_context(&format!("writing {temp_display}"), source))?;
    file.flush()
        .map_err(|source| io_context(&format!("flushing {temp_display}"), source))?;
    file.sync_all()
        .map_err(|source| io_context(&format!("syncing {temp_display}"), source))?;
    drop(file);

    std::fs::rename(&temp, path)
        .map_err(|source| io_context(&format!("writing {display}"), source))?;
    guard.disarm();
    Ok(bytes.len())
}

/// Removes the temp file unless explicitly disarmed, so an early `?` — or
/// a panic — cannot leave a stray `<out>.askcodex-tmp.<pid>` beside the user's
/// image. (`auth.rs` has an equivalent for the credential path; it is
/// private to that module and that module is frozen.)
struct TempFileGuard<'a> {
    path: Option<&'a Path>,
}

impl<'a> TempFileGuard<'a> {
    fn new(path: &'a Path) -> Self {
        TempFileGuard { path: Some(path) }
    }

    /// Call after a successful rename: the temp no longer exists under
    /// that name.
    fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for TempFileGuard<'_> {
    fn drop(&mut self) {
        if let Some(path) = self.path {
            // `Drop` cannot propagate, and this failure is self-announcing:
            // a leftover temp makes the next write fail loudly on O_EXCL
            // rather than silently overwrite anything.
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Lowercase hex of the first `max` bytes (Python parity: `raw[:4].hex()`).
fn hex_prefix(bytes: &[u8], max: usize) -> String {
    bytes
        .iter()
        .take(max)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn render_image_saved(
    path: &Path,
    size: Option<&str>,
    bytes: usize,
    ref_images: Option<usize>,
) -> String {
    let path = path.display();
    let size = size.unwrap_or(ABSENT);
    let refs = match ref_images {
        Some(count) => format!(", {count} ref image(s)"),
        None => String::new(),
    };
    format!("saved {path}  ({size} PNG, {bytes} bytes{refs})\n")
}

fn image_json(path: &Path, size: Option<&str>, bytes: usize, ref_images: Option<usize>) -> Value {
    json!({
        "path": path.display().to_string(),
        "size": size,
        "bytes": bytes,
        "ref_images": ref_images.unwrap_or(0),
    })
}

// ---------------------------------------------------------------------------
// text renderers (pure)
// ---------------------------------------------------------------------------

fn render_whoami(who: &models::WhoamiOutput) -> String {
    let rows = [
        ("email", who.email.as_deref()),
        ("name", who.name.as_deref()),
        ("plan", who.plan_type.as_deref()),
        ("account_id", who.account_id.as_deref()),
        ("user_id", who.user_id.as_deref()),
    ];
    let mut text = String::new();
    for (key, value) in rows {
        let value = value.unwrap_or(ABSENT);
        text.push_str(&format!("{key:<10}: {value}\n"));
    }
    text
}

fn render_usage(usage: &UsageResponse) -> String {
    let rate = usage.rate_limit.as_ref();

    let plan = usage.plan_type.as_deref().unwrap_or(ABSENT);
    let limit_reached = render_bool(rate.and_then(|r| r.limit_reached));
    let allowed = render_bool(rate.and_then(|r| r.allowed));

    let mut text = String::new();
    text.push_str(&format!("{:<16}: {plan}\n", "plan"));
    text.push_str(&format!(
        "{:<16}: {limit_reached}  allowed={allowed}\n",
        "limit_reached"
    ));

    for (key, window) in [
        (
            "primary_window",
            rate.and_then(|r| r.primary_window.as_ref()),
        ),
        (
            "secondary_window",
            rate.and_then(|r| r.secondary_window.as_ref()),
        ),
    ] {
        // A window the backend did not send gets no line at all — inventing
        // a zeroed one would read as "you have used nothing".
        let Some(window) = window else { continue };
        let used = match window.used_percent {
            Some(percent) => format!("{percent}"),
            None => UNKNOWN.to_string(),
        };
        let window_hours = render_hours(window.limit_window_seconds);
        let reset_hours = render_hours(window.reset_after_seconds);
        text.push_str(&format!(
            "{key:<16}: used {used}%  window {window_hours}h  resets in {reset_hours}h\n"
        ));
    }
    text
}

fn render_models(models: &[ModelInfo]) -> String {
    let count = models.len();
    let mut text = format!("{count} model(s) available:\n");
    for model in models {
        let slug = &model.slug;
        // Same rule as the efforts below: a model that carries no input
        // modalities (key absent or empty array) renders as ABSENT. An
        // empty `in:` column would read as "this model accepts no input at
        // all", which is a claim the backend never made.
        let modalities = match model.input_modalities.as_slice() {
            [] => ABSENT.to_string(),
            items => items.join(","),
        };
        // Efforts come from `supported_reasoning_levels[].effort`. A model
        // that carries no levels at all (key absent or empty array) renders
        // as ABSENT: an empty `effort:` would read as "no efforts are
        // supported", which is a claim the backend never made.
        let efforts = match model.supported_reasoning_levels.as_slice() {
            [] => ABSENT.to_string(),
            levels => levels
                .iter()
                .map(|level| level.effort.as_deref().unwrap_or(ABSENT))
                .collect::<Vec<_>>()
                .join(","),
        };
        // Anything that is not the plain "list" visibility is called out;
        // a missing visibility is called out too, rather than assumed.
        let flag = match model.visibility.as_deref() {
            Some("list") => String::new(),
            Some(other) => format!("  [{other}]"),
            None => format!("  [{ABSENT}]"),
        };
        text.push_str(&format!(
            "  - {slug:<18} in:{modalities:<12} effort:{efforts}{flag}\n"
        ));
    }
    text
}

fn render_bool(value: Option<bool>) -> String {
    match value {
        Some(value) => value.to_string(),
        None => ABSENT.to_string(),
    }
}

/// Seconds as hours with one decimal; absent stays absent.
fn render_hours(seconds: Option<u64>) -> String {
    match seconds {
        Some(seconds) => format!("{:.1}", seconds as f64 / 3600.0),
        None => UNKNOWN.to_string(),
    }
}

// ---------------------------------------------------------------------------
// auth views (claims only — never a token value)
// ---------------------------------------------------------------------------

/// The access token's expiry, derived from the `exp` claim.
///
/// This struct is the ONLY thing `auth status` / `auth refresh` learn from
/// the token: a timestamp, a countdown, and a verdict. No part of the token
/// value can reach it.
#[derive(Debug, PartialEq, Eq)]
struct Expiry {
    /// RFC3339 UTC, e.g. `2026-08-17T23:32:41+00:00`.
    at: String,
    /// Minutes from `now`; negative once the token has expired.
    minutes: i64,
    valid: bool,
}

impl Expiry {
    fn of_access_token(auth: &AuthFile, path: &Path, now: DateTime<Utc>) -> Result<Self, Error> {
        let token = auth
            .tokens
            .as_ref()
            .and_then(|tokens| tokens.access_token.as_ref())
            .ok_or_else(|| Error::AuthTokensMissing {
                path: path.to_path_buf(),
            })?;
        // Loud on a malformed token (auth::jwt_exp never guesses), and the
        // error it raises names claims only.
        Self::from_exp(auth::jwt_exp(token)?, now)
    }

    fn from_exp(exp: i64, now: DateTime<Utc>) -> Result<Self, Error> {
        let at = DateTime::from_timestamp(exp, 0).ok_or_else(|| Error::JwtInvalid {
            reason: "claim `exp` is outside the representable date range".to_string(),
        })?;
        let remaining = exp.saturating_sub(now.timestamp());
        Ok(Expiry {
            at: at.to_rfc3339(),
            // Rounded for DISPLAY only...
            minutes: round_minutes(remaining),
            // ...the verdict comes from the claim itself. Deriving it from
            // the rounded value reported a token with 20 seconds left — one
            // that still authenticates — as EXPIRED, which is exactly the
            // kind of answer that sends a script off to rotate credentials
            // it did not need to touch.
            valid: remaining > 0,
        })
    }

    fn render(&self) -> String {
        let at = &self.at;
        let minutes = self.minutes;
        let state = if self.valid { "valid" } else { "EXPIRED" };
        format!("{at} ({minutes} min from now, {state})")
    }
}

/// Seconds to whole minutes, rounded (Python parity: `round(secs / 60)`).
fn round_minutes(seconds: i64) -> i64 {
    (seconds as f64 / 60.0).round() as i64
}

#[derive(Debug)]
struct AuthStatusView {
    auth_file: PathBuf,
    auth_mode: Option<String>,
    account_id: Option<String>,
    last_refresh: Option<String>,
    expiry: Expiry,
}

impl AuthStatusView {
    fn new(auth: &AuthFile, auth_file: PathBuf, now: DateTime<Utc>) -> Result<Self, Error> {
        let expiry = Expiry::of_access_token(auth, &auth_file, now)?;
        Ok(AuthStatusView {
            auth_mode: auth.auth_mode.clone(),
            account_id: auth
                .tokens
                .as_ref()
                .and_then(|tokens| tokens.account_id.clone()),
            last_refresh: auth.last_refresh.clone(),
            auth_file,
            expiry,
        })
    }

    fn render(&self) -> String {
        let path = self.auth_file.display();
        let mode = self.auth_mode.as_deref().unwrap_or(ABSENT);
        let account_id = self.account_id.as_deref().unwrap_or(ABSENT);
        let last_refresh = self.last_refresh.as_deref().unwrap_or(ABSENT);
        let expiry = self.expiry.render();

        // Label spelling is frozen, trailing space before the colon
        // included: users and scripts have been grepping this output, and
        // a prettier column is not worth breaking them.
        let mut text = String::new();
        text.push_str(&format!("auth file : {path}\n"));
        text.push_str(&format!("auth_mode : {mode}\n"));
        text.push_str(&format!("account_id: {account_id}\n"));
        text.push_str(&format!("last_refresh: {last_refresh}\n"));
        text.push_str(&format!("access_token expires: {expiry}\n"));
        text
    }

    fn to_json(&self) -> Value {
        json!({
            "auth_file": self.auth_file.display().to_string(),
            "auth_mode": self.auth_mode,
            "account_id": self.account_id,
            "last_refresh": self.last_refresh,
            "access_token_expires_at": self.expiry.at,
            "access_token_expires_in_minutes": self.expiry.minutes,
            "access_token_valid": self.expiry.valid,
        })
    }
}

#[derive(Debug)]
struct RefreshView {
    expiry: Expiry,
    last_refresh: Option<String>,
}

impl RefreshView {
    fn new(auth: &AuthFile, path: &Path, now: DateTime<Utc>) -> Result<Self, Error> {
        Ok(RefreshView {
            expiry: Expiry::of_access_token(auth, path, now)?,
            last_refresh: auth.last_refresh.clone(),
        })
    }

    fn render(&self) -> String {
        let minutes = self.expiry.minutes;
        let last_refresh = self.last_refresh.as_deref().unwrap_or(ABSENT);
        format!("refreshed. new access token valid ~{minutes} min; last_refresh={last_refresh}\n")
    }

    fn to_json(&self) -> Value {
        json!({
            "refreshed": true,
            "access_token_expires_at": self.expiry.at,
            "access_token_expires_in_minutes": self.expiry.minutes,
            "access_token_valid": self.expiry.valid,
            "last_refresh": self.last_refresh,
        })
    }
}

// ---------------------------------------------------------------------------
// misc
// ---------------------------------------------------------------------------

/// Wrap an I/O failure with what askcodex was doing. `Error::Io` carries no
/// path of its own, and "Permission denied" with no subject is a support
/// ticket waiting to happen.
fn io_context(what: &str, source: std::io::Error) -> Error {
    Error::Io(std::io::Error::new(
        source.kind(),
        format!("{what}: {source}"),
    ))
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

// Isolation. Two regimes, both offline, and the boundary between them is
// the `-- the raw escape hatch, end to end --` section at the bottom of
// this module.
//
// 1. EVERY TEST ABOVE THAT SECTION is offline by construction: it opens no
//    socket, reads or writes nothing under `~/.codex`, touches no
//    environment variable, and never calls `auth::load_auth` /
//    `config::auth_path` — the auth-file path is always an invented
//    literal. Fixtures are embedded with `include_str!`, so even the
//    sample files are read at compile time rather than from disk. The only
//    filesystem writes go to a per-test temp directory created and removed
//    by the test itself.
// 2. THE `raw` END-TO-END SECTION drives the real `run_with_io`, so it
//    necessarily does what that function does: it loads `auth.json` from
//    `config::auth_path()` and it makes HTTP requests. Both are contained:
//    the only host any of it addresses is an httpmock server on loopback
//    (reachable in this build because `Client::send_once` passes
//    `cfg!(test)` as `allow_loopback`; false in every shipped artifact),
//    and `config::auth_path()` resolves inside the process-wide scratch
//    `CODEX_HOME` that `auth::isolate_codex_home` installs — never the
//    real `~/.codex`. Those tests hold `auth::lock_codex_home()` for their
//    whole body, because that scratch directory is shared with the
//    equivalent tests in `http.rs`. See the section's own header for the
//    `--no-refresh` invariant that keeps `auth.openai.com` unreachable.
//
// Every token-shaped string here is a made-up literal built in-test.
#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use clap::Parser as _;
    // Only the two method constants are imported: httpmock also exports a
    // `Method` type, and glob-importing its prelude would shadow ureq's.
    use httpmock::Method::{GET, POST};
    use httpmock::MockServer;
    use serde_json::json;

    use super::*;
    use crate::models::{AuthTokens, ResponsesSseEvent, WhoamiOutput};
    use crate::redact::Secret;

    // -- fixtures --------------------------------------------------------

    const USAGE_SAMPLE: &str = include_str!("../docs/samples/usage.json");
    const MODELS_SAMPLE: &str = include_str!("../docs/samples/models.json");
    const WHOAMI_SAMPLE: &str = include_str!("../docs/samples/whoami-fields.json");
    const IMAGE_META_SAMPLE: &str = include_str!("../docs/samples/image-response-meta.json");
    const SSE_SAMPLE: &str = include_str!("../docs/samples/responses-sse.txt");

    /// Invented, non-functional credential values.
    const FAKE_REFRESH_TOKEN: &str = "fake-refresh-token-value";
    const FAKE_ACCOUNT_ID: &str = "acct_fake_0000";
    const FAKE_AUTH_PATH: &str = "/nonexistent/askcodex-test/auth.json";

    /// A syntactically valid JWT whose payload is exactly `{"exp": <exp>}`.
    /// Never a real token — the segments are assembled here.
    fn fake_jwt(exp: i64) -> Secret {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        let payload = URL_SAFE_NO_PAD.encode(format!(r#"{{"exp":{exp}}}"#));
        let signature = URL_SAFE_NO_PAD.encode(b"not-a-signature");
        Secret::new(format!("{header}.{payload}.{signature}"))
    }

    fn fake_auth(exp: i64) -> AuthFile {
        AuthFile {
            auth_mode: Some("chatgpt".to_string()),
            tokens: Some(AuthTokens {
                id_token: None,
                access_token: Some(fake_jwt(exp)),
                refresh_token: Some(Secret::new(FAKE_REFRESH_TOKEN)),
                account_id: Some(FAKE_ACCOUNT_ID.to_string()),
                extra: serde_json::Map::new(),
            }),
            last_refresh: Some("2026-08-07T23:32:41.615755Z".to_string()),
            extra: serde_json::Map::new(),
        }
    }

    fn at(rfc3339: &str) -> DateTime<Utc> {
        rfc3339.parse::<DateTime<Utc>>().expect("valid timestamp")
    }

    /// A writer that remembers each individual `write` and `flush`, so a
    /// test can prove output arrived incrementally rather than in one lump.
    #[derive(Default)]
    struct Recorder {
        writes: Vec<String>,
        flushes: usize,
        bytes: Vec<u8>,
    }

    impl Recorder {
        fn text(&self) -> String {
            String::from_utf8(self.bytes.clone()).expect("utf-8 output")
        }

        /// Assert stdout holds exactly ONE JSON document and nothing else.
        fn single_json_document(&self) -> Value {
            serde_json::from_slice(&self.bytes).unwrap_or_else(|e| {
                panic!(
                    "stdout is not a single JSON document ({e}): {:?}",
                    self.text()
                )
            })
        }
    }

    impl Write for Recorder {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.bytes.extend_from_slice(buf);
            self.writes.push(String::from_utf8_lossy(buf).into_owned());
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }

    /// A unique, self-cleaning scratch directory. Never `CODEX_HOME`,
    /// never `~/.codex`.
    struct ScratchDir(PathBuf);

    impl ScratchDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("askcodex-run-tests-{}-{tag}", std::process::id()));
            std::fs::create_dir_all(&path).expect("create scratch dir");
            ScratchDir(path)
        }

        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }

        /// Every entry currently in the directory, sorted — the way a test
        /// proves askcodex left nothing behind.
        fn entries(&self) -> Vec<String> {
            let mut names: Vec<String> = std::fs::read_dir(&self.0)
                .expect("read scratch dir")
                .map(|entry| entry.expect("dir entry").file_name())
                .map(|name| name.to_string_lossy().into_owned())
                .collect();
            names.sort();
            names
        }
    }

    /// A minimal payload that passes the PNG-magic check. Never a real
    /// image: these tests decode nothing.
    fn png_fixture() -> Vec<u8> {
        [&PNG_MAGIC[..], b"\r\n\x1a\n-askcodex-test-payload-"].concat()
    }

    impl Drop for ScratchDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn parse(argv: &[&str]) -> Cmd {
        Cli::try_parse_from(argv)
            .unwrap_or_else(|e| panic!("{argv:?}: {e}"))
            .cmd
    }

    // -- whoami ----------------------------------------------------------

    fn whoami_from_sample() -> WhoamiOutput {
        let sample: Value = serde_json::from_str(WHOAMI_SAMPLE).unwrap();
        let field = |key: &str| sample.get(key).and_then(Value::as_str).map(str::to_string);
        WhoamiOutput {
            email: field("email"),
            name: field("name"),
            user_id: field("user_id"),
            account_id: field("account_id"),
            plan_type: field("plan_type"),
        }
    }

    #[test]
    fn whoami_human_render_is_aligned_and_uses_the_live_sample() {
        let text = render_whoami(&whoami_from_sample());
        assert_eq!(
            text,
            "email     : email_REDACTED\n\
             name      : email_REDACTED\n\
             plan      : plus\n\
             account_id: acct_REDACTED\n\
             user_id   : user_REDACTED\n"
        );
        // Every key column ends at the same offset.
        for line in text.lines() {
            assert_eq!(line.find(':'), Some(10), "misaligned line: {line:?}");
        }
    }

    #[test]
    fn whoami_json_is_the_composed_struct_and_matches_the_sample() {
        let who = whoami_from_sample();
        let mut out = Recorder::default();
        emit_json(&mut out, &who).unwrap();

        let document = out.single_json_document();
        assert_eq!(
            document,
            serde_json::from_str::<Value>(WHOAMI_SAMPLE).unwrap()
        );
    }

    #[test]
    fn whoami_absent_fields_render_as_absent_not_as_guesses() {
        let who = WhoamiOutput {
            email: None,
            name: None,
            user_id: None,
            account_id: None,
            plan_type: None,
        };
        let text = render_whoami(&who);
        assert_eq!(text.lines().count(), 5);
        for line in text.lines() {
            assert!(line.ends_with(": -"), "expected absent marker: {line:?}");
        }

        // JSON keeps absence as null — never an empty string.
        let mut out = Recorder::default();
        emit_json(&mut out, &who).unwrap();
        let document = out.single_json_document();
        assert_eq!(document["email"], Value::Null);
        assert_eq!(document["plan_type"], Value::Null);
    }

    // -- usage -----------------------------------------------------------

    #[test]
    fn usage_human_render_matches_the_live_sample() {
        let usage: UsageResponse = serde_json::from_str(USAGE_SAMPLE).unwrap();
        let text = render_usage(&usage);
        assert_eq!(
            text,
            "plan            : plus\n\
             limit_reached   : false  allowed=true\n\
             primary_window  : used 20%  window 168.0h  resets in 4.5h\n"
        );
        // The sample's secondary_window is null: no line, no invented zeros.
        assert!(!text.contains("secondary_window"));
    }

    #[test]
    fn usage_absent_numbers_render_as_question_marks() {
        let usage: UsageResponse = serde_json::from_value(json!({
            "email": null, "user_id": null, "account_id": null, "plan_type": null,
            "rate_limit": {
                "limit_reached": null,
                "allowed": null,
                "primary_window": {},
                "secondary_window": {"used_percent": 3.5, "limit_window_seconds": 3600,
                                     "reset_after_seconds": 1800}
            }
        }))
        .unwrap();
        let text = render_usage(&usage);
        assert_eq!(
            text,
            "plan            : -\n\
             limit_reached   : -  allowed=-\n\
             primary_window  : used ?%  window ?h  resets in ?h\n\
             secondary_window: used 3.5%  window 1.0h  resets in 0.5h\n"
        );
    }

    #[test]
    fn usage_json_is_the_raw_response_with_unknown_fields_intact() {
        let raw: Value = serde_json::from_str(USAGE_SAMPLE).unwrap();
        let mut out = Recorder::default();
        emit_json(&mut out, &raw).unwrap();

        let document = out.single_json_document();
        assert_eq!(document, raw);
        // Fields the typed struct does not model survive the JSON path.
        assert!(document.get("credits").is_some());
        assert!(document.get("rate_limit_reset_credits").is_some());
    }

    // -- models ----------------------------------------------------------

    /// The `models` ARRAY inside the sample envelope. `--json` prints the
    /// whole envelope (that is what `endpoints::account::models` hands
    /// back); this helper is for the human renderer, which takes the array.
    ///
    /// `docs/samples/models.json` is the live `GET /codex/models` document,
    /// i.e. the `{"models": [...]}` envelope. The key is required here: a
    /// document without it fails the fixture instead of quietly producing
    /// an empty catalog.
    fn models_array_from_sample() -> Vec<Value> {
        let envelope: Value = serde_json::from_str(MODELS_SAMPLE).unwrap();
        envelope
            .get("models")
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("sample has no `models` array: {envelope}"))
            .clone()
    }

    /// Decode the sample catalog through the real `ModelInfo` type — no
    /// reshaping, no coercion. `supported_reasoning_levels` entries are
    /// objects (`{"effort": "low", "description": ...}`) on the wire and
    /// are decoded as such.
    fn models_from_sample() -> Vec<ModelInfo> {
        models_array_from_sample()
            .into_iter()
            .enumerate()
            .map(|(index, entry)| {
                serde_json::from_value::<ModelInfo>(entry)
                    .unwrap_or_else(|e| panic!("models[{index}] does not decode: {e}"))
            })
            .collect()
    }

    #[test]
    fn models_human_render_matches_the_live_sample() {
        let models = models_from_sample();
        let text = render_models(&models);
        let lines: Vec<&str> = text.lines().collect();

        assert_eq!(lines[0], "8 model(s) available:");
        assert_eq!(
            lines[1],
            "  - gpt-5.6-sol        in:text,image   effort:low,medium,high,xhigh,max,ultra"
        );
        // Efforts are per-model, read off the level OBJECTS: this one
        // really does carry four levels where gpt-5.6-sol carries six.
        assert_eq!(
            lines[5],
            "  - gpt-5.5            in:text,image   effort:low,medium,high,xhigh"
        );
        // Hidden models carry the visibility flag; listed ones do not.
        assert!(lines[2].ends_with("  [hide]"), "{:?}", lines[2]);
        assert!(!lines[3].contains('['), "{:?}", lines[3]);
        assert_eq!(lines.len(), 9);
    }

    #[test]
    fn models_render_flags_unknown_visibility_instead_of_assuming_listed() {
        let models = vec![ModelInfo {
            slug: "mystery".to_string(),
            input_modalities: vec![],
            supported_reasoning_levels: vec![],
            visibility: None,
        }];
        let text = render_models(&models);
        assert_eq!(
            text,
            "1 model(s) available:\n  - mystery            in:-            effort:-  [-]\n"
        );
    }

    /// An absent (or empty) `input_modalities` must READ as absent. An
    /// empty `in:` column is a claim the backend never made — and it is
    /// indistinguishable from one that really did say "no modalities".
    #[test]
    fn models_render_shows_absent_input_modalities_instead_of_an_empty_column() {
        let quiet = ModelInfo {
            slug: "gpt-x".to_string(),
            input_modalities: vec![],
            supported_reasoning_levels: vec![models::ReasoningLevel {
                effort: Some("low".to_string()),
            }],
            visibility: Some("list".to_string()),
        };
        let text = render_models(&[quiet]);
        let line = text.lines().nth(1).expect("one model line");
        assert!(line.contains(&format!("in:{ABSENT}")), "{line:?}");
        assert!(
            !line.contains("in: "),
            "an absent modality list stayed blank: {line:?}"
        );

        // The wire shape that omits the key entirely decodes to the same
        // rendering, rather than to a blank column.
        let omitted: ModelInfo = serde_json::from_value(json!({
            "slug": "gpt-x",
            "supported_reasoning_levels": [{"effort": "low"}],
            "visibility": "list"
        }))
        .expect("a model without input_modalities still decodes");
        assert_eq!(render_models(&[omitted]), text);
    }

    #[test]
    fn models_render_shows_a_model_without_reasoning_levels_as_absent() {
        // The catalog really does vary here, so "no levels" must read as
        // "the backend told us nothing", not as an empty menu.
        let no_levels = ModelInfo {
            slug: "gpt-quiet".to_string(),
            input_modalities: vec!["text".to_string()],
            supported_reasoning_levels: vec![],
            visibility: Some("list".to_string()),
        };
        // A level object whose `effort` key is absent is absent per entry,
        // and does not erase the efforts that ARE there.
        let partial = ModelInfo {
            slug: "gpt-partial".to_string(),
            input_modalities: vec!["text".to_string()],
            supported_reasoning_levels: vec![
                models::ReasoningLevel { effort: None },
                models::ReasoningLevel {
                    effort: Some("high".to_string()),
                },
            ],
            visibility: Some("list".to_string()),
        };
        let text = render_models(&[no_levels, partial]);
        let lines: Vec<&str> = text.lines().collect();
        assert!(lines[1].ends_with("effort:-"), "{:?}", lines[1]);
        assert!(lines[2].ends_with("effort:-,high"), "{:?}", lines[2]);
    }

    /// The wire shape is `supported_reasoning_levels: [{"effort": ...}]`.
    /// A flattened array of bare strings is a DIFFERENT document, and askcodex
    /// says so instead of coercing it into efforts it was never sent.
    #[test]
    fn a_flattened_reasoning_level_is_a_loud_decode_error_not_a_coerced_effort() {
        let flattened = json!({
            "slug": "gpt-5.4",
            "input_modalities": ["text", "image"],
            "supported_reasoning_levels": ["low", "high"],
            "visibility": "list"
        });
        let err = serde_json::from_value::<ModelInfo>(flattened).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("invalid type: string"), "{message}");
        assert!(message.contains("ReasoningLevel"), "{message}");
    }

    #[test]
    fn models_json_is_the_raw_catalog_envelope() {
        // What `endpoints::account::models` hands back for `--json` is the
        // whole `GET /codex/models` document, not `document["models"]`.
        // Slicing the envelope open would discard any sibling key the
        // backend adds later — exactly the kind of silent drop this project
        // refuses — so the fixture here is the envelope itself.
        let raw: Value = serde_json::from_str(MODELS_SAMPLE).unwrap();
        let mut out = Recorder::default();
        emit_json(&mut out, &raw).unwrap();

        let document = out.single_json_document();
        assert_eq!(document, raw);
        let models = document
            .get("models")
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("--json dropped the catalog envelope: {document}"));
        assert_eq!(models.len(), 8);
        // Fields the typed struct drops are still there, at both levels:
        // the model, and the reasoning-level OBJECTS inside it.
        assert_eq!(models[0]["context_window"], json!(272000));
        assert_eq!(
            models[0]["supported_reasoning_levels"][0],
            json!({"effort": "low", "description": "Fast responses with lighter reasoning"})
        );
    }

    // -- image -----------------------------------------------------------

    /// `size` and the decoded byte count as recorded in the sample.
    fn image_facts_from_sample() -> (String, usize) {
        let sample: Value = serde_json::from_str(IMAGE_META_SAMPLE).unwrap();
        let size = sample["generations_response"]["size"]
            .as_str()
            .expect("size")
            .to_string();
        // "<base64 PNG, 708021 bytes decoded>"
        let note = sample["generations_response"]["data"][0]["b64_json"]
            .as_str()
            .expect("b64_json placeholder");
        let bytes = note
            .split(", ")
            .nth(1)
            .and_then(|s| s.split(' ').next())
            .and_then(|s| s.parse::<usize>().ok())
            .expect("byte count in the sample placeholder");
        (size, bytes)
    }

    #[test]
    fn image_create_line_matches_the_live_sample_facts() {
        let (size, bytes) = image_facts_from_sample();
        let line = render_image_saved(Path::new("image.png"), Some(&size), bytes, None);
        assert_eq!(line, "saved image.png  (1254x1254 PNG, 708021 bytes)\n");
    }

    #[test]
    fn image_edit_line_reports_the_reference_count() {
        let line = render_image_saved(
            Path::new("out/edited.png"),
            Some("1254x1254"),
            1_047_605,
            Some(2),
        );
        assert_eq!(
            line,
            "saved out/edited.png  (1254x1254 PNG, 1047605 bytes, 2 ref image(s))\n"
        );
    }

    #[test]
    fn image_json_carries_the_same_facts_as_the_line() {
        let (size, bytes) = image_facts_from_sample();
        let mut out = Recorder::default();
        emit_json(
            &mut out,
            &image_json(Path::new("image.png"), Some(&size), bytes, Some(3)),
        )
        .unwrap();

        let document = out.single_json_document();
        assert_eq!(
            document,
            json!({"path": "image.png", "size": "1254x1254",
                   "bytes": 708021, "ref_images": 3})
        );
    }

    #[test]
    fn image_render_shows_an_absent_size_rather_than_inventing_one() {
        let line = render_image_saved(Path::new("i.png"), None, 10, None);
        assert_eq!(line, "saved i.png  (- PNG, 10 bytes)\n");
        assert_eq!(
            image_json(Path::new("i.png"), None, 10, None)["size"],
            Value::Null
        );
    }

    #[test]
    fn a_non_png_payload_never_reaches_the_filesystem() {
        let dir = ScratchDir::new("not-png");
        let path = dir.join("out.png");

        let err = write_png(b"<html>nope</html>", &path).unwrap_err();
        match err {
            Error::ImageNotPng { ref magic_hex } => assert_eq!(magic_hex, "3c68746d"),
            other => panic!("wrong error: {other:?}"),
        }
        assert!(err.to_string().contains("expected PNG payload"));
        assert!(!path.exists(), "a rejected payload must leave no file");

        // A truncated payload is rejected too, not padded or accepted.
        assert!(matches!(
            write_png(&[0x89, b'P'], &path).unwrap_err(),
            Error::ImageNotPng { .. }
        ));
        assert!(!path.exists());
    }

    #[test]
    fn a_png_payload_is_written_verbatim_and_reported() {
        let dir = ScratchDir::new("png");
        let path = dir.join("out.png");
        let png = [&PNG_MAGIC[..], b"\r\n\x1a\n-rest-of-the-file"].concat();

        let image = ImageResult {
            png: png.clone(),
            size: Some("1254x1254".to_string()),
        };
        let mut out = Recorder::default();
        save_image(&image, &path, Some(1), false, &mut out).unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), png);
        let expected = format!(
            "saved {}  (1254x1254 PNG, {} bytes, 1 ref image(s))\n",
            path.display(),
            png.len()
        );
        assert_eq!(out.text(), expected);
    }

    /// An image generation is metered against the user's subscription, so
    /// a destination askcodex cannot write must fail while it is still FREE.
    /// The injected `generate` closure is the billed call: if it runs, the
    /// user has paid.
    #[test]
    fn an_unusable_output_path_fails_before_the_billed_call() {
        let dir = ScratchDir::new("preflight-order");
        let mut generated = 0usize;
        let mut out = Recorder::default();

        let doomed = dir.join("no-such-dir").join("cat.png");
        let err = run_image(&doomed, None, false, &mut out, || {
            generated += 1;
            Ok(ImageResult {
                png: png_fixture(),
                size: Some("1254x1254".to_string()),
            })
        })
        .unwrap_err();

        assert_eq!(
            generated, 0,
            "askcodex spent a generation it already knew it could not save"
        );
        assert!(
            err.to_string().contains(&doomed.display().to_string()),
            "the error must name the output path: {err}"
        );
        assert!(out.bytes.is_empty(), "nothing is reported as saved");

        // A usable destination still runs the call and saves the file.
        let good = dir.join("cat.png");
        run_image(&good, Some(2), false, &mut out, || {
            generated += 1;
            Ok(ImageResult {
                png: png_fixture(),
                size: Some("1254x1254".to_string()),
            })
        })
        .unwrap();
        assert_eq!(generated, 1);
        assert_eq!(std::fs::read(&good).unwrap(), png_fixture());
        assert!(out.text().starts_with("saved "));
    }

    #[test]
    fn the_output_path_probe_reports_the_reason_and_leaves_no_trace() {
        let dir = ScratchDir::new("preflight-probe");

        // A parent directory that does not exist.
        let missing_parent = dir.join("nope").join("cat.png");
        let err = preflight_out_path(&missing_parent).unwrap_err();
        match err {
            Error::Io(ref source) => assert_eq!(source.kind(), std::io::ErrorKind::NotFound),
            ref other => panic!("wrong error: {other:?}"),
        }
        assert!(err.to_string().contains("cat.png"), "{err}");

        // `-o <an existing directory>`: no rename could ever replace it.
        let as_dir = dir.join("adir");
        std::fs::create_dir(&as_dir).unwrap();
        let err = preflight_out_path(&as_dir).unwrap_err();
        assert!(err.to_string().contains("is a directory"), "{err}");

        // A write-protected file is refused, not silently replaced.
        let protected = dir.join("protected.png");
        std::fs::write(&protected, b"do not touch").unwrap();
        let mut perms = std::fs::metadata(&protected).unwrap().permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(&protected, perms).unwrap();
        let err = preflight_out_path(&protected).unwrap_err();
        assert!(err.to_string().contains("write-protected"), "{err}");
        assert_eq!(
            write_png(&png_fixture(), &protected)
                .unwrap_err()
                .to_string(),
            err.to_string()
        );
        assert_eq!(std::fs::read(&protected).unwrap(), b"do not touch");

        // A path with no file name at all.
        assert!(preflight_out_path(Path::new("/")).is_err());

        // A usable destination passes AND the probe leaves the directory
        // exactly as it found it: no empty file at `--out`, no stray temp.
        let good = dir.join("cat.png");
        preflight_out_path(&good).unwrap();
        assert!(!good.exists(), "the probe must not create --out");
        assert_eq!(dir.entries(), ["adir", "protected.png"]);
    }

    /// The destination is written through a same-directory temp file and
    /// renamed, so a write that does not complete cannot damage what was
    /// already there. Forcing ENOSPC offline is not possible; occupying
    /// the temp sibling makes the same failure deterministic.
    #[test]
    fn a_failed_write_leaves_the_previous_file_intact() {
        let dir = ScratchDir::new("atomic-fail");
        let path = dir.join("out.png");
        let victim = b"the image the user already had".to_vec();
        std::fs::write(&path, &victim).unwrap();

        let temp = temp_sibling(&path).unwrap();
        let squatter = b"another process is mid-write";
        std::fs::write(&temp, squatter).unwrap();

        let err = write_png(&png_fixture(), &path).unwrap_err();
        match err {
            Error::Io(ref source) => {
                assert_eq!(source.kind(), std::io::ErrorKind::AlreadyExists)
            }
            ref other => panic!("wrong error: {other:?}"),
        }
        assert_eq!(
            std::fs::read(&path).unwrap(),
            victim,
            "a failed write destroyed the file that was already at --out"
        );
        // A temp askcodex did not create is not askcodex's to delete.
        assert_eq!(std::fs::read(&temp).unwrap(), squatter);
    }

    #[test]
    fn a_completed_write_replaces_the_destination_and_leaves_no_temp() {
        let dir = ScratchDir::new("atomic-ok");
        let path = dir.join("out.png");
        std::fs::write(&path, b"an older image").unwrap();

        let png = png_fixture();
        assert_eq!(write_png(&png, &path).unwrap(), png.len());
        assert_eq!(std::fs::read(&path).unwrap(), png);
        assert_eq!(
            dir.entries(),
            ["out.png"],
            "the temp file outlived the write"
        );
    }

    #[test]
    fn image_json_mode_puts_only_the_json_document_on_stdout() {
        let dir = ScratchDir::new("png-json");
        let path = dir.join("out.png");
        let png = [&PNG_MAGIC[..], b"\r\n\x1a\npayload"].concat();

        let image = ImageResult {
            png: png.clone(),
            size: Some("1254x1254".to_string()),
        };
        let mut out = Recorder::default();
        save_image(&image, &path, None, true, &mut out).unwrap();

        let document = out.single_json_document();
        assert_eq!(document["bytes"], json!(png.len()));
        assert_eq!(document["ref_images"], json!(0));
        assert!(!out.text().contains("saved "));
    }

    // -- ask -------------------------------------------------------------

    /// The delta sequence of the real captured stream, decoded through the
    /// frozen event classifier.
    fn sample_deltas() -> Vec<String> {
        SSE_SAMPLE
            .lines()
            .filter_map(|line| line.strip_prefix("data: "))
            .filter_map(|payload| serde_json::from_str::<Value>(payload).ok())
            .filter_map(|event| match ResponsesSseEvent::classify(&event) {
                ResponsesSseEvent::OutputTextDelta(delta) => Some(delta),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn the_sse_fixture_still_carries_the_expected_deltas() {
        assert_eq!(sample_deltas(), ["CS", "UB", "-", "VERIFY", "-", "OK"]);
    }

    /// Build an [`endpoints::responses::AskAnswer`] with no usage object.
    fn answer(text: &str) -> endpoints::responses::AskAnswer {
        endpoints::responses::AskAnswer {
            text: text.to_string(),
            usage: None,
        }
    }

    #[test]
    fn ask_text_mode_streams_every_delta_immediately() {
        let deltas = sample_deltas();
        let mut out = Recorder::default();
        let mut err = Recorder::default();

        emit_ask(
            false,
            "gpt-5.4-mini",
            None,
            &mut out,
            &mut err,
            |on_delta| {
                for delta in &deltas {
                    on_delta(delta);
                }
                Ok(answer(&deltas.concat()))
            },
        )
        .unwrap();

        // One write per delta, in order: nothing was buffered until the end.
        assert_eq!(
            out.writes,
            ["CS", "UB", "-", "VERIFY", "-", "OK", "\n"],
            "deltas must reach stdout as they arrive"
        );
        assert!(out.flushes >= 6, "each delta is flushed");
        assert_eq!(out.text(), "CSUB-VERIFY-OK\n");
    }

    #[test]
    fn ask_text_mode_adds_a_newline_only_when_the_answer_lacks_one() {
        let mut out = Recorder::default();
        let mut err = Recorder::default();
        emit_ask(false, "m", None, &mut out, &mut err, |on_delta| {
            on_delta("done\n");
            Ok(answer("done\n"))
        })
        .unwrap();
        assert_eq!(out.text(), "done\n");
        assert!(err.bytes.is_empty(), "stderr: {:?}", err.text());
    }

    /// A stream that completed without a single output-text delta really
    /// did produce nothing. askcodex must not turn that into a byte the model
    /// never sent — `askcodex ask ... > answer.txt` would otherwise leave a
    /// 1-byte file that every `[ -s answer.txt ]` check calls an answer.
    #[test]
    fn an_empty_answer_is_announced_instead_of_padded_with_a_newline() {
        let mut out = Recorder::default();
        let mut err = Recorder::default();
        emit_ask(false, "m", None, &mut out, &mut err, |_on_delta| {
            Ok(answer(""))
        })
        .unwrap();
        assert!(
            out.bytes.is_empty(),
            "askcodex emitted {:?}, which the model never sent",
            out.text()
        );
        assert!(
            err.text().starts_with("askcodex: note:"),
            "{:?}",
            err.text()
        );
        assert!(err.text().contains("no output text"), "{:?}", err.text());

        // JSON mode still emits the document — an empty answer is a fact,
        // not a missing one — and the same note explains it.
        let mut out = Recorder::default();
        let mut err = Recorder::default();
        emit_ask(true, "m", None, &mut out, &mut err, |_on_delta| {
            Ok(answer(""))
        })
        .unwrap();
        assert_eq!(
            out.single_json_document(),
            json!({"model": "m", "effort": null, "text": "", "usage": null})
        );
        assert!(err.text().contains("no output text"), "{:?}", err.text());

        // A one-character answer is still terminated, and says nothing on
        // stderr: only the EMPTY case changed.
        let mut out = Recorder::default();
        let mut err = Recorder::default();
        emit_ask(false, "m", None, &mut out, &mut err, |on_delta| {
            on_delta("x");
            Ok(answer("x"))
        })
        .unwrap();
        assert_eq!(out.text(), "x\n");
        assert!(err.bytes.is_empty(), "stderr: {:?}", err.text());
    }

    #[test]
    fn ask_json_mode_emits_one_document_and_never_interleaves_deltas() {
        let deltas = sample_deltas();
        let mut out = Recorder::default();
        let mut err = Recorder::default();
        let mut fed = 0usize;

        emit_ask(
            true,
            "gpt-5.4-mini",
            Some("medium"),
            &mut out,
            &mut err,
            |on_delta| {
                for delta in &deltas {
                    on_delta(delta);
                    fed += 1;
                }
                Ok(answer(&deltas.concat()))
            },
        )
        .unwrap();

        // The sink really did see every delta...
        assert_eq!(fed, 6);
        // ...and stdout still got exactly one write: the finished document.
        assert_eq!(out.writes.len(), 1, "writes: {:?}", out.writes);
        let document = out.single_json_document();
        assert_eq!(
            document,
            json!({"model": "gpt-5.4-mini", "effort": "medium", "text": "CSUB-VERIFY-OK", "usage": null})
        );
    }

    #[test]
    fn ask_propagates_a_stream_failure_instead_of_reporting_a_partial_answer() {
        let mut out = Recorder::default();
        let mut err = Recorder::default();
        let failure = emit_ask(false, "m", None, &mut out, &mut err, |on_delta| {
            on_delta("partial");
            Err(Error::SseStream {
                detail: "stream ended without response.completed".to_string(),
            })
        })
        .unwrap_err();

        assert!(matches!(failure, Error::SseStream { .. }));
        // What arrived is still on stdout, but the command failed: no
        // trailing newline, no JSON document, non-zero exit upstream.
        assert_eq!(out.text(), "partial");
    }

    #[test]
    fn ask_reports_a_stdout_write_failure_rather_than_swallowing_it() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "downstream closed",
                ))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let mut out = Broken;
        let mut err = Recorder::default();
        let failure = emit_ask(false, "m", None, &mut out, &mut err, |on_delta| {
            on_delta("hi");
            Ok(answer("hi"))
        })
        .unwrap_err();

        match failure {
            Error::Io(ref source) => {
                assert_eq!(source.kind(), std::io::ErrorKind::BrokenPipe);
                assert!(
                    failure.to_string().contains("writing the answer to stdout"),
                    "{failure}"
                );
            }
            other => panic!("wrong error: {other:?}"),
        }
    }

    // -- input resolution ------------------------------------------------

    #[test]
    fn ask_dash_reads_the_prompt_from_stdin_verbatim() {
        let mut stdin = Cursor::new(b"  multi\nline prompt\n".to_vec());
        let resolved = resolve(parse(&["askcodex", "ask", "-"]), &mut stdin).unwrap();

        match resolved {
            Resolved::Backend(Backend::Ask { prompt, model, .. }) => {
                assert_eq!(prompt, "  multi\nline prompt\n");
                assert_eq!(model, config::DEFAULT_ASK_MODEL);
            }
            other => panic!("wrong resolution: {other:?}"),
        }
    }

    #[test]
    fn a_literal_ask_prompt_never_touches_stdin() {
        // An empty stdin would make a stdin read produce "" — the literal
        // prompt must survive instead.
        let mut stdin = Cursor::new(Vec::new());
        let resolved = resolve(
            parse(&[
                "askcodex",
                "ask",
                "why is the sky blue",
                "--effort",
                "xhigh",
            ]),
            &mut stdin,
        )
        .unwrap();

        match resolved {
            Resolved::Backend(Backend::Ask { prompt, effort, .. }) => {
                assert_eq!(prompt, "why is the sky blue");
                assert_eq!(effort, Some(Effort::Xhigh));
                assert_eq!(effort.map(Effort::as_str), Some("xhigh"));
            }
            other => panic!("wrong resolution: {other:?}"),
        }
    }

    #[test]
    fn raw_body_dash_reads_and_parses_stdin() {
        let mut stdin = Cursor::new(br#"{"model": "gpt-5.4-mini", "stream": true}"#.to_vec());
        let resolved = resolve(
            parse(&["askcodex", "raw", "POST", "/codex/responses", "--body", "-"]),
            &mut stdin,
        )
        .unwrap();

        match resolved {
            Resolved::Backend(Backend::Raw {
                method,
                path,
                body,
                stream,
            }) => {
                assert_eq!(method, HttpMethod::Post);
                assert_eq!(path, "/codex/responses");
                assert_eq!(body, Some(json!({"model": "gpt-5.4-mini", "stream": true})));
                assert!(!stream);
            }
            other => panic!("wrong resolution: {other:?}"),
        }
    }

    #[test]
    fn an_invalid_raw_body_fails_before_any_network_call() {
        // `resolve` cannot reach the network: it takes no client and no
        // credentials. Reaching an error here therefore proves the failure
        // happens before the pre-flight refresh and before the request.
        let mut stdin = Cursor::new(Vec::new());
        let err = resolve(
            parse(&["askcodex", "raw", "POST", "/codex/responses", "--body", "{"]),
            &mut stdin,
        )
        .unwrap_err();
        assert!(matches!(err, Error::Json(_)), "wrong error: {err:?}");
        assert!(err.to_string().starts_with("json error:"));

        // Same for a body arriving on stdin.
        let mut stdin = Cursor::new(b"not json at all".to_vec());
        let err = resolve(
            parse(&["askcodex", "raw", "POST", "/x", "--body", "-"]),
            &mut stdin,
        )
        .unwrap_err();
        assert!(matches!(err, Error::Json(_)), "wrong error: {err:?}");
    }

    #[test]
    fn raw_without_a_body_sends_none() {
        let mut stdin = Cursor::new(Vec::new());
        let resolved = resolve(
            parse(&["askcodex", "raw", "GET", "/codex/usage"]),
            &mut stdin,
        )
        .unwrap();
        match resolved {
            Resolved::Backend(Backend::Raw { body, method, .. }) => {
                assert_eq!(body, None);
                assert_eq!(method, HttpMethod::Get);
            }
            other => panic!("wrong resolution: {other:?}"),
        }
    }

    #[test]
    fn auth_commands_resolve_without_reading_stdin() {
        let mut stdin = Cursor::new(Vec::new());
        assert!(matches!(
            resolve(parse(&["askcodex", "auth", "status"]), &mut stdin).unwrap(),
            Resolved::Auth(AuthCmd::Status)
        ));
        assert!(matches!(
            resolve(parse(&["askcodex", "auth", "refresh"]), &mut stdin).unwrap(),
            Resolved::Auth(AuthCmd::Refresh)
        ));
    }

    #[test]
    fn image_commands_resolve_paths_from_the_frozen_cli() {
        let mut stdin = Cursor::new(Vec::new());
        match resolve(
            parse(&["askcodex", "image", "edit", "bluer", "-i", "a.png", "b.png"]),
            &mut stdin,
        )
        .unwrap()
        {
            Resolved::Backend(Backend::ImageEdit {
                prompt,
                inputs,
                out,
            }) => {
                assert_eq!(prompt, "bluer");
                assert_eq!(inputs, [PathBuf::from("a.png"), PathBuf::from("b.png")]);
                assert_eq!(out, PathBuf::from("image-edited.png"));
            }
            other => panic!("wrong resolution: {other:?}"),
        }
    }

    // -- raw streaming ---------------------------------------------------

    #[test]
    fn raw_stream_copies_bytes_verbatim_line_by_line() {
        let mut reader = Cursor::new(SSE_SAMPLE.as_bytes().to_vec());
        let mut out = Recorder::default();
        copy_stream(&mut reader, &mut out).unwrap();

        // Byte-for-byte: no framing, no filtering, no re-encoding.
        assert_eq!(out.bytes, SSE_SAMPLE.as_bytes());
        // One write (and one flush) per line, as it arrives.
        assert_eq!(out.writes.len(), out.flushes);
        assert!(out.writes.len() > 20, "writes: {}", out.writes.len());
        assert_eq!(out.writes[0], "event: response.created\n");
    }

    #[test]
    fn raw_stream_passes_through_non_utf8_and_unterminated_bytes() {
        let payload = b"data: \xff\xfe binary\ndata: no trailing newline";
        let mut reader = Cursor::new(payload.to_vec());
        let mut out = Recorder::default();
        copy_stream(&mut reader, &mut out).unwrap();
        assert_eq!(out.bytes, payload);
    }

    #[test]
    fn raw_stream_with_json_announces_the_exception_on_stderr_only() {
        let mut err = Recorder::default();
        advise_raw_stream_json(&mut err).unwrap();
        assert!(err.text().starts_with("askcodex: note:"));
        assert!(err.text().contains("--json does not apply"));
        assert!(err.text().ends_with('\n'));
    }

    // -- auth views ------------------------------------------------------

    #[test]
    fn auth_status_renders_claims_and_never_a_token_value() {
        let now = at("2026-08-07T23:32:41Z");
        let exp = now.timestamp() + 10 * 86_400; // codex's 10-day lifetime
        let auth = fake_auth(exp);
        let access_token = auth
            .tokens
            .as_ref()
            .unwrap()
            .access_token
            .as_ref()
            .unwrap()
            .expose()
            .to_string();

        let view = AuthStatusView::new(&auth, PathBuf::from(FAKE_AUTH_PATH), now).unwrap();
        let text = view.render();
        assert_eq!(
            text,
            "auth file : /nonexistent/askcodex-test/auth.json\n\
             auth_mode : chatgpt\n\
             account_id: acct_fake_0000\n\
             last_refresh: 2026-08-07T23:32:41.615755Z\n\
             access_token expires: 2026-08-17T23:32:41+00:00 \
             (14400 min from now, valid)\n"
        );

        let mut out = Recorder::default();
        emit_json(&mut out, &view.to_json()).unwrap();
        let document = out.single_json_document();
        assert_eq!(
            document,
            json!({
                "auth_file": FAKE_AUTH_PATH,
                "auth_mode": "chatgpt",
                "account_id": FAKE_ACCOUNT_ID,
                "last_refresh": "2026-08-07T23:32:41.615755Z",
                "access_token_expires_at": "2026-08-17T23:32:41+00:00",
                "access_token_expires_in_minutes": 14400,
                "access_token_valid": true,
            })
        );

        // The token (and every segment of it) stays out of both renderings.
        let json_text = out.text();
        for rendering in [&text, &json_text] {
            assert!(!rendering.contains(&access_token));
            for segment in access_token.split('.') {
                // The rendering is deliberately NOT in the failure message:
                // the whole point of this assertion is that it may contain
                // a credential.
                assert!(!rendering.contains(segment), "a token segment leaked");
            }
            assert!(!rendering.contains(FAKE_REFRESH_TOKEN));
        }
    }

    #[test]
    fn auth_status_flags_an_expired_token_instead_of_refreshing_it() {
        let now = at("2026-08-07T23:32:41Z");
        let auth = fake_auth(now.timestamp() - 3600);
        let view = AuthStatusView::new(&auth, PathBuf::from(FAKE_AUTH_PATH), now).unwrap();

        assert!(view.render().contains("(-60 min from now, EXPIRED)"));
        assert_eq!(view.to_json()["access_token_valid"], json!(false));
        assert_eq!(
            view.to_json()["access_token_expires_in_minutes"],
            json!(-60)
        );
    }

    #[test]
    fn auth_status_renders_absent_optional_fields_without_guessing() {
        let now = at("2026-08-07T23:32:41Z");
        let mut auth = fake_auth(now.timestamp() + 600);
        auth.auth_mode = None;
        auth.last_refresh = None;

        let view = AuthStatusView::new(&auth, PathBuf::from(FAKE_AUTH_PATH), now).unwrap();
        let text = view.render();
        assert!(text.contains("auth_mode : -\n"));
        assert!(text.contains("last_refresh: -\n"));
        assert_eq!(view.to_json()["auth_mode"], Value::Null);
        assert_eq!(view.to_json()["last_refresh"], Value::Null);
    }

    #[test]
    fn auth_status_is_loud_when_the_access_token_is_not_a_jwt() {
        let now = at("2026-08-07T23:32:41Z");
        let mut auth = fake_auth(now.timestamp() + 600);
        auth.tokens.as_mut().unwrap().access_token = Some(Secret::new("not-a-jwt"));

        let err = AuthStatusView::new(&auth, PathBuf::from(FAKE_AUTH_PATH), now).unwrap_err();
        match err {
            Error::JwtInvalid { ref reason } => {
                assert!(reason.contains("3 dot-separated segments"));
            }
            other => panic!("wrong error: {other:?}"),
        }
        // Nothing derived from the token value reaches the message.
        assert!(!err.to_string().contains("not-a-jwt"));
    }

    #[test]
    fn auth_status_is_loud_when_tokens_are_missing_entirely() {
        let mut auth = fake_auth(0);
        auth.tokens = None;
        let err = AuthStatusView::new(
            &auth,
            PathBuf::from(FAKE_AUTH_PATH),
            at("2026-08-07T23:32:41Z"),
        )
        .unwrap_err();
        assert!(matches!(err, Error::AuthTokensMissing { .. }));
    }

    #[test]
    fn auth_refresh_reports_the_new_expiry_and_last_refresh() {
        let now = at("2026-08-07T23:32:41Z");
        let auth = fake_auth(now.timestamp() + 10 * 86_400);
        let view = RefreshView::new(&auth, Path::new(FAKE_AUTH_PATH), now).unwrap();

        assert_eq!(
            view.render(),
            "refreshed. new access token valid ~14400 min; \
             last_refresh=2026-08-07T23:32:41.615755Z\n"
        );

        let mut out = Recorder::default();
        emit_json(&mut out, &view.to_json()).unwrap();
        let document = out.single_json_document();
        assert_eq!(document["refreshed"], json!(true));
        assert_eq!(document["access_token_expires_in_minutes"], json!(14400));
        assert_eq!(
            document["last_refresh"],
            json!("2026-08-07T23:32:41.615755Z")
        );
        assert!(!out.text().contains(FAKE_REFRESH_TOKEN));
    }

    /// Rounding is a DISPLAY concern. A token with seconds left still
    /// authenticates, and reporting it as EXPIRED is what sends a wrapper
    /// script off to rotate a credential that did not need touching.
    #[test]
    fn a_token_with_seconds_left_is_valid_not_rounded_into_expiry() {
        let now = at("2026-08-07T23:32:41Z");
        let base = now.timestamp();

        let live = Expiry::from_exp(base + 20, now).unwrap();
        assert_eq!(live.minutes, 0, "20 seconds still rounds to 0 for display");
        assert!(
            live.valid,
            "a token that still authenticates was called EXPIRED"
        );
        assert!(
            live.render().ends_with("(0 min from now, valid)"),
            "{}",
            live.render()
        );

        // The mirror case stays expired, so the two zero-minute states are
        // still told apart.
        let dead = Expiry::from_exp(base - 20, now).unwrap();
        assert_eq!(dead.minutes, 0);
        assert!(!dead.valid);
        assert!(dead.render().ends_with("(0 min from now, EXPIRED)"));

        // And the reported claim follows the same verdict.
        let view =
            AuthStatusView::new(&fake_auth(base + 20), PathBuf::from(FAKE_AUTH_PATH), now).unwrap();
        assert_eq!(view.to_json()["access_token_valid"], json!(true));
        assert_eq!(view.to_json()["access_token_expires_in_minutes"], json!(0));
    }

    #[test]
    fn expiry_math_rounds_to_whole_minutes_and_is_loud_on_absurd_claims() {
        let now = at("2026-08-07T23:32:41Z");
        let base = now.timestamp();

        assert_eq!(Expiry::from_exp(base + 89, now).unwrap().minutes, 1);
        assert_eq!(Expiry::from_exp(base + 91, now).unwrap().minutes, 2);
        assert_eq!(Expiry::from_exp(base, now).unwrap().minutes, 0);
        assert!(!Expiry::from_exp(base, now).unwrap().valid);
        assert!(Expiry::from_exp(base + 61, now).unwrap().valid);

        // An `exp` outside the representable range is an error, not a
        // clamped-to-something timestamp.
        assert!(matches!(
            Expiry::from_exp(i64::MAX, now),
            Err(Error::JwtInvalid { .. })
        ));
    }

    // -- cross-cutting properties ---------------------------------------

    #[test]
    fn json_mode_puts_exactly_one_json_document_on_stdout() {
        let now = at("2026-08-07T23:32:41Z");
        let auth = fake_auth(now.timestamp() + 600);
        let status = AuthStatusView::new(&auth, PathBuf::from(FAKE_AUTH_PATH), now).unwrap();
        let refresh = RefreshView::new(&auth, Path::new(FAKE_AUTH_PATH), now).unwrap();

        // One entry per `--json` rendering askcodex can produce.
        let documents: Vec<Value> = vec![
            serde_json::to_value(whoami_from_sample()).unwrap(),
            serde_json::from_str(USAGE_SAMPLE).unwrap(),
            serde_json::from_str(MODELS_SAMPLE).unwrap(),
            image_json(Path::new("image.png"), Some("1254x1254"), 708_021, None),
            serde_json::to_value(AskOutput {
                model: "gpt-5.4-mini".to_string(),
                effort: Some("medium".to_string()),
                text: "CSUB-VERIFY-OK".to_string(),
                usage: None,
            })
            .unwrap(),
            status.to_json(),
            refresh.to_json(),
            // `raw` echoes the backend document as-is.
            json!({"plan_type": "plus", "rate_limit": {"allowed": true}}),
        ];

        for document in documents {
            let mut out = Recorder::default();
            emit_json(&mut out, &document).unwrap();

            // Parses whole, with no trailing junk...
            assert_eq!(out.single_json_document(), document);
            // ...and carries nothing but the document plus a final newline.
            let text = out.text();
            assert!(text.ends_with('\n'));
            assert_eq!(
                text.trim_end_matches('\n'),
                serde_json::to_string_pretty(&document).unwrap()
            );
        }
    }

    #[test]
    fn text_renderings_always_end_with_exactly_one_newline() {
        let now = at("2026-08-07T23:32:41Z");
        let auth = fake_auth(now.timestamp() + 600);
        let usage: UsageResponse = serde_json::from_str(USAGE_SAMPLE).unwrap();

        let renderings = [
            render_whoami(&whoami_from_sample()),
            render_usage(&usage),
            render_models(&models_from_sample()),
            render_image_saved(Path::new("i.png"), Some("1254x1254"), 1, Some(1)),
            AuthStatusView::new(&auth, PathBuf::from(FAKE_AUTH_PATH), now)
                .unwrap()
                .render(),
            RefreshView::new(&auth, Path::new(FAKE_AUTH_PATH), now)
                .unwrap()
                .render(),
        ];
        for rendering in renderings {
            assert!(rendering.ends_with('\n'), "{rendering:?}");
            assert!(!rendering.ends_with("\n\n"), "{rendering:?}");
        }
    }

    #[test]
    fn io_errors_keep_the_subject_that_failed() {
        let err = io_context(
            "writing /tmp/x.png",
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
        );
        assert!(err.to_string().contains("writing /tmp/x.png"));
        assert!(err.to_string().contains("denied"));
        match err {
            Error::Io(source) => assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied),
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn hex_prefix_reports_short_payloads_without_padding_them() {
        assert_eq!(hex_prefix(&[0x89, b'P', b'N', b'G', b'X'], 4), "89504e47");
        assert_eq!(hex_prefix(&[0x00], 4), "00");
        assert_eq!(hex_prefix(&[], 4), "");
    }

    // -- the `raw` escape hatch, end to end ------------------------------
    //
    // The seven tests below drive the REAL entry point — a `Cli` value into
    // `run_with_io` — against an httpmock server on loopback, so the whole
    // path from parsed arguments to written bytes runs: credential load,
    // stdin resolution, body validation, `http::Client`, the origin gate,
    // and the emission policy. They were integration tests in
    // `tests/cli.rs`; out there the shipped binary now refuses
    // a loopback target (correctly — that is the fix), so the success paths
    // moved in-crate, where `cfg!(test)` legitimately permits loopback.
    // `tests/cli.rs` keeps the map from each retired test to its
    // replacement here, and keeps the refusal proof against the binary.
    //
    // Three invariants hold for every test in this section.
    //
    // 1. `--no-refresh`, ALWAYS — do not weaken. `run_with_io` builds the
    //    client with `Client::new`, which pins the refresh endpoint to the
    //    production `config::TOKEN_URL` (`auth.openai.com`). There is no
    //    dead-proxy seatbelt in-crate, so `no_refresh` is the ONLY thing
    //    making that endpoint unreachable: it short-circuits
    //    `ensure_fresh` and it makes a 401 final instead of a refresh. The
    //    invariant is enforced mechanically by [`raw_cli`], not by review.
    // 2. `CODEX_HOME` is the process-wide scratch directory installed by
    //    `auth::isolate_codex_home` (one `set_var`, `Once`-guarded, never
    //    called again — `std::env::set_var` is unsound under the threaded
    //    harness, so no test here calls it). It is SHARED, so every test
    //    holds `auth::lock_codex_home()` for its whole body and re-seeds
    //    the directory through [`MockHome`]. The real `~/.codex` is
    //    unreachable by construction.
    // 3. The credential is asserted PRESENT by header existence, never by
    //    value: on a mismatch httpmock prints the header it saw, and
    //    nothing in this crate may print a token. The account id IS matched
    //    by value — it is an invented literal, and it is what proves the
    //    right account header reached the wire.

    /// `exp` of the fixture access token: 2100-01-01T00:00:00Z. Far enough
    /// out that nothing in this section depends on the calendar.
    const FIXTURE_EXP: i64 = 4_102_444_800;

    /// The `raw` target argv carries before [`raw_cli`] substitutes the
    /// mock URL. A legal backend path, so clap accepts it.
    const PLACEHOLDER_TARGET: &str = "/codex/usage";

    /// The shared scratch `CODEX_HOME`, emptied of credentials and
    /// re-seeded with a FAKE `auth.json` that `load_auth` and
    /// `Client::new` both accept.
    ///
    /// Callers MUST hold `auth::lock_codex_home()` for their whole body.
    struct MockHome {
        path: PathBuf,
        /// The exact bytes written, for the "askcodex only read it" checks.
        auth_bytes: Vec<u8>,
        /// Directory listing right after seeding, for the "askcodex left
        /// nothing behind" check. A snapshot rather than a literal
        /// `["auth.json"]`, because the directory is shared: comparing
        /// against what THIS test found is what makes the assertion about
        /// askcodex instead of about whichever test ran before it.
        entries: Vec<String>,
    }

    impl MockHome {
        fn new() -> Self {
            let path = auth::isolate_codex_home();
            for name in ["auth.json", "auth.json.bak"] {
                let stale = path.join(name);
                match std::fs::remove_file(&stale) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => panic!("cannot clean {}: {e}", stale.display()),
                }
            }

            // Serialized through the real `AuthFile`, so the fixture is a
            // document askcodex itself would write — no hand-rolled shape that
            // could drift from the type.
            let mut document = serde_json::to_string_pretty(&fake_auth(FIXTURE_EXP))
                .expect("serialize the fake auth fixture");
            document.push('\n');
            std::fs::write(path.join("auth.json"), &document).expect("write the fake auth.json");

            let auth_bytes = document.into_bytes();
            let mut home = MockHome {
                path,
                auth_bytes,
                entries: Vec::new(),
            };
            home.entries = home.read_entries();
            assert!(
                home.entries.iter().any(|name| name == "auth.json"),
                "the fixture was not seeded: {:?}",
                home.entries
            );
            home
        }

        fn read_entries(&self) -> Vec<String> {
            let mut names: Vec<String> = std::fs::read_dir(&self.path)
                .expect("read the scratch CODEX_HOME")
                .map(|entry| entry.expect("dir entry").file_name())
                .map(|name| name.to_string_lossy().into_owned())
                .collect();
            names.sort();
            names
        }

        /// askcodex read `auth.json`; it must not have rewritten, repaired or
        /// backed it up. Byte-for-byte, and no stray `auth.json.bak`.
        ///
        /// The byte comparison deliberately does not print either side: the
        /// file contains (fake) credentials.
        fn assert_auth_untouched(&self) {
            let after = std::fs::read(self.path.join("auth.json")).expect("read auth.json");
            assert!(
                after == self.auth_bytes,
                "auth.json was modified: {} bytes before, {} bytes after",
                self.auth_bytes.len(),
                after.len()
            );
            assert!(
                !self.path.join("auth.json.bak").exists(),
                "askcodex created auth.json.bak while only reading credentials"
            );
        }

        /// Nothing was added to (or removed from) `CODEX_HOME`.
        fn assert_left_nothing_behind(&self) {
            assert_eq!(
                self.read_entries(),
                self.entries,
                "askcodex changed the contents of CODEX_HOME"
            );
        }
    }

    /// Parse a real argv into the `Cli` that [`run_with_io`] takes, then
    /// point the `raw` target at `url`.
    ///
    /// The substitution is not a shortcut, it is unavoidable: `askcodex raw
    /// <path>` is parsed through clap's `value_parser`, which runs
    /// `http::check_request_target` with `allow_loopback = false`, so a
    /// 127.0.0.1 target is refused AT PARSE TIME. That refusal has its
    /// own tests —
    /// `cli::tests::raw_refuses_a_target_outside_the_backend_origin` in
    /// crate, and the refusal section of `tests/cli.rs` against the shipped
    /// binary — so re-proving it here would be duplication, while working
    /// around it here would be a test that lies about what ships.
    ///
    /// Everything else is genuinely parsed from argv: the global flags,
    /// `--body` (as the raw string `resolve` then validates), and
    /// `--stream`. Nothing downstream of clap is hand-assembled.
    fn raw_cli(argv: &[&str], url: &str) -> Cli {
        let mut cli = Cli::try_parse_from(argv).unwrap_or_else(|e| panic!("{argv:?}: {e}"));
        match cli.cmd {
            Cmd::Raw { ref mut path, .. } => {
                assert_eq!(
                    path, PLACEHOLDER_TARGET,
                    "{argv:?}: the placeholder target moved"
                );
                *path = url.to_string();
            }
            ref other => panic!("{argv:?} is not a `raw` invocation: {other:?}"),
        }
        // Invariant 1, enforced rather than reviewed: without this flag the
        // client would be free to POST the refresh token to the production
        // OAuth endpoint from a unit test.
        assert!(
            cli.no_refresh,
            "{argv:?}: every test in this section must pass --no-refresh"
        );
        cli
    }

    /// One completed `run_with_io` call, with both streams captured.
    struct RunOutcome {
        result: Result<(), Error>,
        out: Recorder,
        err: Recorder,
    }

    impl RunOutcome {
        fn assert_ok(&self) {
            if let Err(e) = &self.result {
                panic!("askcodex failed: {e}\nstderr: {:?}", self.err.text());
            }
        }

        fn error(&self) -> &Error {
            match &self.result {
                Ok(()) => panic!(
                    "expected a loud error; stdout was {:?}",
                    String::from_utf8_lossy(&self.out.bytes)
                ),
                Err(e) => e,
            }
        }

        /// The failure is carried by the ONE returned error and by nothing
        /// else: `main` is what prints it, so anything on stderr here would
        /// be a second report, and anything on stdout would be a payload
        /// emitted by a command that failed.
        fn assert_reported_once(&self, fragments: &[&str]) -> &Error {
            let err = self.error();
            let rendered = err.to_string();
            for fragment in fragments {
                assert!(
                    rendered.contains(fragment),
                    "the error is missing {fragment:?}: {rendered}"
                );
            }
            assert!(
                self.out.bytes.is_empty(),
                "a failed command still wrote to stdout: {:?}",
                String::from_utf8_lossy(&self.out.bytes)
            );
            assert!(
                self.err.bytes.is_empty(),
                "the failure was announced on stderr as well as returned: {:?}",
                self.err.text()
            );
            err
        }
    }

    /// Run `cli` with `stdin` piped in, capturing stdout and stderr.
    ///
    /// Every run doubles as a leak check, exactly as `tests/cli.rs` does:
    /// the fixture credentials are fake, but they are treated as if they
    /// were not, so a regression that printed one fails the nearest test
    /// rather than the next code review.
    fn run_raw(cli: Cli, stdin: &[u8]) -> RunOutcome {
        let mut out = Recorder::default();
        let mut err = Recorder::default();
        let mut input = Cursor::new(stdin.to_vec());
        let result = run_with_io(cli, &mut out, &mut err, &mut input);

        let outcome = RunOutcome { result, out, err };
        let auth = fake_auth(FIXTURE_EXP);
        let access = auth
            .tokens
            .as_ref()
            .and_then(|tokens| tokens.access_token.as_ref())
            .expect("fixture access token")
            .expose()
            .to_string();
        for (name, stream) in [
            ("stdout", &outcome.out.bytes),
            ("stderr", &outcome.err.bytes),
        ] {
            let text = String::from_utf8_lossy(stream);
            // The stream is deliberately NOT in the message: the whole
            // point of this assertion is that it may contain a credential.
            assert!(!text.contains(&access), "the access token leaked to {name}");
            assert!(
                !text.contains(FAKE_REFRESH_TOKEN),
                "the refresh token leaked to {name}"
            );
        }
        outcome
    }

    #[test]
    fn raw_get_prints_the_backend_document_and_nothing_else() {
        let _guard = auth::lock_codex_home();
        let home = MockHome::new();

        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET)
                .path("/codex/usage")
                // The credential is asserted PRESENT, never by value.
                .header_exists("authorization")
                .header("chatgpt-account-id", FAKE_ACCOUNT_ID)
                .header("accept", "application/json")
                // Codex parity, asserted against the crate's own constants
                // so the check cannot drift into testing a stale literal.
                .header("originator", config::ORIGINATOR)
                .header("user-agent", config::USER_AGENT);
            then.status(200)
                .header("content-type", "application/json")
                .body(r#"{"plan":"plus","windows":[{"used_percent":3.5}],"unknown_field":null}"#);
        });
        let url = server.url("/codex/usage");

        let run = run_raw(
            raw_cli(
                &["askcodex", "--no-refresh", "raw", "GET", PLACEHOLDER_TARGET],
                &url,
            ),
            b"",
        );
        run.assert_ok();
        assert_eq!(
            run.out.single_json_document(),
            json!({"plan": "plus", "windows": [{"used_percent": 3.5}], "unknown_field": null}),
            "raw must print the backend document unchanged, unknown fields included"
        );
        assert!(run.err.bytes.is_empty(), "stderr: {:?}", run.err.text());

        // `raw` output is already JSON, so `--json` prints the same
        // document rather than a second, differently shaped one.
        let as_json = run_raw(
            raw_cli(
                &[
                    "askcodex",
                    "--json",
                    "--no-refresh",
                    "raw",
                    "GET",
                    PLACEHOLDER_TARGET,
                ],
                &url,
            ),
            b"",
        );
        as_json.assert_ok();
        assert_eq!(
            as_json.out.single_json_document(),
            run.out.single_json_document(),
            "--json changed the document `raw` prints"
        );

        mock.assert_calls(2);
        home.assert_auth_untouched();
        home.assert_left_nothing_behind();
    }

    #[test]
    fn raw_post_sends_the_validated_body_on_the_wire() {
        let _guard = auth::lock_codex_home();
        let home = MockHome::new();

        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(POST)
                .path("/codex/responses")
                .header_exists("authorization")
                .header("content-type", "application/json; charset=utf-8")
                .json_body(json!({"input": "hi", "nested": {"n": 1, "flag": true}}));
            then.status(200)
                .body(r#"{"id":"resp_test","status":"completed"}"#);
        });

        let run = run_raw(
            raw_cli(
                &[
                    "askcodex",
                    "--no-refresh",
                    "raw",
                    "POST",
                    PLACEHOLDER_TARGET,
                    "--body",
                    r#"{"input": "hi", "nested": {"n": 1, "flag": true}}"#,
                ],
                &server.url("/codex/responses"),
            ),
            b"",
        );
        run.assert_ok();
        assert_eq!(
            run.out.single_json_document(),
            json!({"id": "resp_test", "status": "completed"})
        );
        // The mock only matches the exact body, so a hit IS the proof that
        // the `--body` argument reached the wire intact.
        mock.assert_calls(1);
        home.assert_auth_untouched();
    }

    #[test]
    fn raw_body_dash_sends_the_document_read_from_stdin() {
        // `raw_body_dash_reads_and_parses_stdin` proves stdin is CONSUMED
        // and parsed. This one proves what was consumed is what got sent:
        // the mock matches on the stdin document alone.
        let _guard = auth::lock_codex_home();
        let home = MockHome::new();

        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(POST)
                .path("/codex/responses")
                .header_exists("authorization")
                .json_body(json!({"from_stdin": true, "items": [1, 2, 3]}));
            then.status(200).body(r#"{"ok":true}"#);
        });

        let run = run_raw(
            raw_cli(
                &[
                    "askcodex",
                    "--no-refresh",
                    "raw",
                    "POST",
                    PLACEHOLDER_TARGET,
                    "--body",
                    "-",
                ],
                &server.url("/codex/responses"),
            ),
            b"{\"from_stdin\": true, \"items\": [1, 2, 3]}\n",
        );
        run.assert_ok();
        assert_eq!(run.out.single_json_document(), json!({"ok": true}));
        mock.assert_calls(1);
        home.assert_auth_untouched();
    }

    #[test]
    fn raw_stream_copies_the_event_stream_to_stdout_verbatim() {
        let _guard = auth::lock_codex_home();
        let home = MockHome::new();

        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET)
                .path("/codex/responses")
                .header_exists("authorization")
                // Literals: `ACCEPT_SSE` / `OPENAI_BETA` are private to
                // http.rs, and this is the wire contract either way.
                .header("accept", "text/event-stream")
                .header("openai-beta", "responses=experimental");
            then.status(200)
                .header("content-type", "text/event-stream")
                .body(SSE_SAMPLE);
        });
        let url = server.url("/codex/responses");

        let run = run_raw(
            raw_cli(
                &[
                    "askcodex",
                    "--no-refresh",
                    "raw",
                    "GET",
                    PLACEHOLDER_TARGET,
                    "--stream",
                ],
                &url,
            ),
            b"",
        );
        run.assert_ok();
        // Byte-for-byte: `raw --stream` is the escape hatch, so what the
        // wire said is what the user sees — no reframing, no filtering, no
        // added trailing newline. (The fixture ends WITHOUT one, so a
        // helpfully appended `\n` fails right here.)
        assert!(
            run.out.bytes == SSE_SAMPLE.as_bytes(),
            "raw --stream altered the body: {} bytes in, {} bytes out",
            SSE_SAMPLE.len(),
            run.out.bytes.len()
        );
        assert!(run.err.bytes.is_empty(), "stderr: {:?}", run.err.text());

        // With `--json`, stdout is still the verbatim stream and the
        // advisory goes to stderr — the flag is announced as inapplicable,
        // never silently dropped and never allowed to corrupt the
        // passthrough.
        let as_json = run_raw(
            raw_cli(
                &[
                    "askcodex",
                    "--json",
                    "--no-refresh",
                    "raw",
                    "GET",
                    PLACEHOLDER_TARGET,
                    "--stream",
                ],
                &url,
            ),
            b"",
        );
        as_json.assert_ok();
        assert!(
            as_json.out.bytes == SSE_SAMPLE.as_bytes(),
            "--json reshaped the verbatim passthrough: {} bytes out",
            as_json.out.bytes.len()
        );
        assert_eq!(
            as_json.err.text(),
            "askcodex: note: --json does not apply to `raw --stream`; \
             stdout carries the raw event stream\n"
        );

        mock.assert_calls(2);
        home.assert_auth_untouched();
        home.assert_left_nothing_behind();
    }

    #[test]
    fn a_backend_error_status_is_reported_with_its_body() {
        let _guard = auth::lock_codex_home();
        let home = MockHome::new();

        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET).path("/codex/usage");
            then.status(429).body(r#"{"detail":"rate limit exceeded"}"#);
        });
        let url = server.url("/codex/usage");

        let run = run_raw(
            raw_cli(
                &["askcodex", "--no-refresh", "raw", "GET", PLACEHOLDER_TARGET],
                &url,
            ),
            b"",
        );
        // The status AND the body: an error that hid the backend's
        // explanation would send the user to a support forum instead of to
        // the answer.
        let err = run.assert_reported_once(&[&url, "-> HTTP 429", "rate limit exceeded"]);
        assert!(
            matches!(err, Error::HttpStatus { status: 429, .. }),
            "wrong error: {err:?}"
        );

        mock.assert_calls(1);
        home.assert_auth_untouched();
    }

    #[test]
    fn a_non_json_success_body_is_reported_not_guessed() {
        // HTTP 200 with a body that is not JSON (a captive portal, an HTML
        // error page). askcodex must say so loudly rather than print an empty
        // document and exit 0.
        let _guard = auth::lock_codex_home();
        let home = MockHome::new();

        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET).path("/codex/usage");
            then.status(200)
                .header("content-type", "text/html")
                .body("<html>sign in to continue</html>");
        });

        let run = run_raw(
            raw_cli(
                &["askcodex", "--no-refresh", "raw", "GET", PLACEHOLDER_TARGET],
                &server.url("/codex/usage"),
            ),
            b"",
        );
        // `assert_reported_once` also asserts stdout is EMPTY, which is the
        // "never guessed into an empty document" half of the claim.
        let err =
            run.assert_reported_once(&["returned non-JSON", "<html>sign in to continue</html>"]);
        assert!(
            matches!(err, Error::NonJsonResponse { .. }),
            "wrong error: {err:?}"
        );

        mock.assert_calls(1);
        home.assert_auth_untouched();
    }

    #[test]
    fn a_401_under_no_refresh_is_reported_once_and_rotates_nothing() {
        // `--no-refresh` must mean it: exactly ONE request, no refresh
        // behind the user's back, no retry loop, and an `auth.json` that is
        // still byte-identical afterwards.
        let _guard = auth::lock_codex_home();
        let home = MockHome::new();

        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET).path("/codex/usage");
            then.status(401).body(r#"{"detail":"token expired"}"#);
        });

        let run = run_raw(
            raw_cli(
                &["askcodex", "--no-refresh", "raw", "GET", PLACEHOLDER_TARGET],
                &server.url("/codex/usage"),
            ),
            b"",
        );
        // "Reported exactly once", in-crate: one returned error carrying
        // the whole report, an empty stdout, and an empty stderr.
        let err = run.assert_reported_once(&[
            "-> HTTP 401",
            "token expired",
            "--no-refresh is set",
            "askcodex auth refresh",
        ]);
        assert!(
            matches!(err, Error::HttpStatus { status: 401, .. }),
            "wrong error: {err:?}"
        );

        mock.assert_calls(1);
        home.assert_auth_untouched();
        home.assert_left_nothing_behind();
    }
}
