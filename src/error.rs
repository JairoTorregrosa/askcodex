//! The crate-wide error enum (frozen: every failure askcodex can report).
//!
//! Failure policy (non-negotiable): missing auth, failed refresh, unexpected
//! response shape, or a non-image payload RAISES LOUDLY and exits non-zero.
//! No silent fallbacks, no placeholder output, no retry loop that hides a
//! root cause.
//!
//! Redaction policy: no variant may ever carry a token VALUE. Variants
//! carry claim names, paths, statuses, and bounded body snippets only.
//! Backend error bodies do not contain credentials; the OAuth refresh
//! error body (`RefreshFailed::snippet`) comes from auth.openai.com error
//! responses, which describe the failure and never echo the refresh token.

use std::path::{Path, PathBuf};

/// The recovery sentence for [`Error::PersistFailed`], which differs by
/// whether a backup file exists to point the user at.
fn persist_recovery_hint(path: &Path, backup: &Option<PathBuf>) -> String {
    match backup {
        Some(backup) => format!("A backup of the previous file is at {}.", backup.display()),
        None => format!(
            "{} was not modified and still holds the previous tokens.",
            path.display()
        ),
    }
}

/// All askcodex library errors. `main` maps any of these to
/// `askcodex: error: <Display>` on stderr and exit code 1.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("invalid input: {reason}")]
    InvalidInput { reason: &'static str },
    #[error("input exceeds the {limit_bytes}-byte client limit")]
    InputTooLarge { limit_bytes: u64 },
    #[error("failed to read {kind} file {path}: {source}")]
    InputFileUnreadable {
        path: PathBuf,
        kind: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid audio: {reason}")]
    InvalidAudio { reason: &'static str },
    /// Neither `$CODEX_HOME` nor `$HOME` is set and non-empty.
    #[error(
        "cannot resolve the codex home directory: neither $CODEX_HOME nor $HOME is set.\n\
         Set CODEX_HOME to the directory containing auth.json."
    )]
    NoHomeDir,

    /// `auth.json` does not exist.
    #[error(
        "auth file not found: {path}\n\
         Log in with the codex CLI first: `codex login` (ChatGPT account)."
    )]
    AuthFileMissing { path: PathBuf },

    /// `auth.json` exists but could not be read.
    #[error("failed to read {path}: {source}")]
    AuthFileUnreadable {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// `auth.json` is not valid JSON / not the expected document shape.
    #[error("failed to parse {path}: {source}")]
    AuthFileInvalid {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    /// `auth.json` parses but holds no usable ChatGPT tokens — the
    /// keyring-storage case included.
    #[error(
        "{path} has no ChatGPT tokens.\n\
         This CLI needs file-based ChatGPT subscription tokens. If codex stores your \
         credentials in the system keyring instead, this path is unsupported; re-run \
         `codex login` with file credential storage."
    )]
    AuthTokensMissing { path: PathBuf },

    /// Tokens are present but `account_id` is missing.
    #[error("{path} tokens are missing account_id.")]
    AuthAccountIdMissing { path: PathBuf },

    /// The access token is not a decodable JWT (claim NAMES only in
    /// `reason`; never a token value).
    #[error("cannot decode the access token as a JWT: {reason}")]
    JwtInvalid { reason: String },

    /// A refresh was required but `auth.json` has no `refresh_token`.
    #[error("cannot refresh: no refresh_token in auth.json")]
    RefreshUnavailable,

    /// The OAuth refresh endpoint answered non-200.
    #[error("token refresh failed: HTTP {status}: {snippet}")]
    RefreshFailed { status: u16, snippet: String },

    /// The OAuth refresh endpoint answered 200 but without an
    /// `access_token`. Carries the response's key NAMES (never values).
    #[error("token refresh returned no access_token; keys={keys:?}")]
    RefreshInvalidResponse { keys: Vec<String> },

    /// Writing rotated tokens back to `auth.json` failed. This is the one
    /// state where askcodex may have lost credentials (the server already
    /// rotated the refresh token), so the message says exactly that.
    ///
    /// `backup` is `Some` only when this call actually wrote a backup file.
    /// It is `None` when the write failed before `auth.json` was touched at
    /// all, in which case the previous document is still in `auth.json`
    /// itself. Sending a user to a `.bak` that does not exist — or to one
    /// left from an earlier refresh, holding credentials two generations
    /// dead — is worse than saying nothing, so the two cases get different
    /// sentences.
    #[error(
        "CRITICAL: token refresh succeeded but persisting {path} failed: {source}\n\
         The server has rotated your refresh token and the new tokens could not be \
         saved. {}\n\
         If subsequent calls fail with 401, re-run `codex login`.",
        persist_recovery_hint(.path, .backup)
    )]
    PersistFailed {
        path: PathBuf,
        backup: Option<PathBuf>,
        #[source]
        source: std::io::Error,
    },

    /// The backend answered a non-success HTTP status. `snippet` is the
    /// error body truncated to `config::ERROR_SNIPPET_BYTES`.
    #[error("{method} {path} -> HTTP {status}: {snippet}")]
    HttpStatus {
        method: String,
        path: String,
        status: u16,
        snippet: String,
    },

    /// A 2xx response body that should have been JSON was not.
    #[error("{method} {path} returned non-JSON ({len} bytes): {snippet}")]
    NonJsonResponse {
        method: String,
        path: String,
        len: usize,
        snippet: String,
    },

    /// A JSON response decoded, but not into the documented shape.
    /// `context` names the endpoint and the missing/mismatched part, e.g.
    /// `image response missing data[0].b64_json; keys=[...]`.
    #[error("unexpected response shape: {context}")]
    UnexpectedResponse { context: String },

    /// The image endpoint returned bytes that are not a PNG.
    #[error("expected PNG payload, got magic bytes {magic_hex}")]
    ImageNotPng { magic_hex: String },

    /// `image edit` was given more reference images than the backend
    /// accepts.
    #[error("at most {max} reference images (got {count})")]
    TooManyImages { max: usize, count: usize },

    /// A reference image path passed to `image edit` does not exist.
    #[error("input image not found: {path}")]
    InputImageMissing { path: PathBuf },

    /// A reference image passed to `image edit` is not a PNG. askcodex labels
    /// every reference `image/png` on the wire, so sending other bytes
    /// under that label is a lie told to the backend on the user's behalf —
    /// and it comes back as an opaque server-side rejection instead of the
    /// local, obvious "that file is not a PNG".
    #[error("input image is not a PNG: {path} (magic bytes {magic_hex})")]
    InputImageNotPng { path: PathBuf, magic_hex: String },

    /// The SSE stream delivered `response.failed` / `response.error` /
    /// `error`, or ended without `response.completed`. `detail` is the
    /// raw event JSON truncated to `config::ERROR_SNIPPET_BYTES`.
    #[error("responses stream error: {detail}")]
    SseStream { detail: String },

    /// Transport-level failure (TLS, DNS, connect, timeout, protocol).
    /// NOTE: with the askcodex agent config (`http_status_as_error(false)`)
    /// this never fires for plain non-2xx statuses — those become
    /// `HttpStatus` with a body snippet instead (probe finding: ureq's
    /// default `Error::StatusCode` loses the response body).
    #[error("http transport error: {0}")]
    Transport(#[from] ureq::Error),

    /// Filesystem I/O outside the auth-persist path (e.g. writing an
    /// image output file, reading a reference image).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON (de)serialization failure outside `auth.json` handling (e.g.
    /// an invalid `--body` argument to `raw`).
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// A request was aimed at an origin this client is not credentialed
    /// for. askcodex refuses rather than attaching the user's subscription
    /// bearer token to an arbitrary host — `askcodex raw` accepts absolute
    /// URLs, and a token sent to the wrong host is a credential leak the
    /// user cannot undo.
    #[error(
        "refusing to send credentials to {attempted}\n\
         askcodex only ever authenticates to {expected}. `raw` accepts a path \
         (e.g. /codex/usage) or an absolute URL on that origin."
    )]
    UntrustedOrigin { attempted: String, expected: String },

    /// The per-credential-file lock could not be taken, so another askcodex
    /// process is mid-refresh. Refusing is deliberate: two processes
    /// rotating the same refresh token concurrently can leave the file
    /// holding a generation the server has already retired.
    #[error(
        "another askcodex process is refreshing credentials ({path})\n\
         Retry after the other process exits. Do not delete the lock file."
    )]
    AuthLockUnavailable {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl Error {
    /// Stable machine classification; message wording may evolve independently.
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidInput { .. }
            | Self::InvalidAudio { .. }
            | Self::TooManyImages { .. }
            | Self::InputImageNotPng { .. }
            | Self::Json(_) => "input_invalid",
            Self::InputFileUnreadable { .. } | Self::InputImageMissing { .. } => "input_unreadable",
            Self::InputTooLarge { .. } => "input_invalid",
            Self::NoHomeDir
            | Self::AuthFileMissing { .. }
            | Self::AuthTokensMissing { .. }
            | Self::AuthAccountIdMissing { .. } => "auth_required",
            Self::AuthFileUnreadable { .. }
            | Self::AuthFileInvalid { .. }
            | Self::JwtInvalid { .. } => "auth_invalid",
            Self::RefreshUnavailable
            | Self::RefreshFailed { .. }
            | Self::RefreshInvalidResponse { .. } => "auth_refresh_failed",
            Self::PersistFailed { .. } => "auth_persist_failed",
            Self::AuthLockUnavailable { .. } => "auth_busy",
            Self::HttpStatus { status: 429, .. } => "rate_limited",
            Self::HttpStatus { status: 401, .. } => "auth_required",
            Self::HttpStatus { .. } => "http_error",
            Self::NonJsonResponse { .. }
            | Self::UnexpectedResponse { .. }
            | Self::ImageNotPng { .. } => "response_invalid",
            Self::SseStream { .. } => "stream_failed",
            Self::Transport(_) => "transport_error",
            Self::Io(_) => "io_error",
            Self::UntrustedOrigin { .. } => "untrusted_origin",
        }
    }

    /// Write operational diagnostics to stderr without polluting result stdout.
    pub fn write_diagnostic(
        &self,
        out: &mut dyn std::io::Write,
        machine: bool,
    ) -> std::io::Result<()> {
        if machine {
            let value = serde_json::json!({"schema_version": 1, "error": {"code": self.code(), "message": self.to_string()}});
            serde_json::to_writer(&mut *out, &value)?;
            out.write_all(b"\n")
        } else {
            writeln!(out, "askcodex: error: {self}")
        }
    }

    /// Process exit code for this error. Uniformly 1 (clap owns usage
    /// errors and exits 2 on its own; SIGINT terminates by default).
    pub fn exit_code(&self) -> i32 {
        1
    }
}
