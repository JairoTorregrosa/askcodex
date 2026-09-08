//! Constants and path resolution (frozen: every wire-facing constant).
//!
//! Every wire-facing constant lives here. All values were validated against
//! the live backend on 2026-08-07; docs/PROTOCOL.md records how each one
//! was checked. No constant may be silently defaulted at runtime: if a
//! required input is missing (e.g. `$HOME`), resolution fails loudly.

use std::path::PathBuf;

use crate::error::Error;

/// Root of the ChatGPT backend API. Non-codex endpoints (`/me`) hang off
/// this base.
pub const BASE_URL: &str = "https://chatgpt.com/backend-api";

/// Codex-specific endpoints (`/usage`, `/models`, `/images/*`, `/responses`).
pub const CODEX_BASE_URL: &str = "https://chatgpt.com/backend-api/codex";

/// Standalone dictation route, outside the /codex prefix.
pub const TRANSCRIBE_PATH: &str = "/transcribe";

/// OAuth token refresh endpoint. The ONLY non-chatgpt.com host askcodex talks to.
///
/// This is a compile-time constant on purpose and must stay one: the
/// refresh request carries a LIVE refresh token, so an endpoint settable
/// from the environment, a config file, or a CLI flag would be a
/// credential-exfiltration primitive. The one legitimate way to point the
/// refresh somewhere else is the explicit test-only parameter of
/// [`crate::auth::refresh_with_endpoint`] /
/// [`crate::http::Client::with_token_url`]; both document the rule.
pub const TOKEN_URL: &str = "https://auth.openai.com/oauth/token";

/// OAuth client id of the codex CLI app (from the access-token `client_id`
/// claim; claim NAME only — never a token value).
pub const CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";

/// `originator` header sent on every backend call (codex parity).
pub const ORIGINATOR: &str = "codex_cli_rs";

/// Client version reported to `/codex/models` (query param is required by
/// the backend).
pub const CLIENT_VERSION: &str = "0.147.0";

/// `User-Agent` header sent on every call, codex-style.
pub const USER_AGENT: &str = "codex_cli_rs/0.147.0 (askcodex)";

/// Image model slug codex always sends. The backend ignores it (image
/// output is locked server-side to one opaque PNG at a server-chosen size)
/// but sending it mirrors codex exactly.
pub const IMAGE_MODEL: &str = "gpt-image-2";

/// Default model for `askcodex ask`.
pub const DEFAULT_ASK_MODEL: &str = "gpt-5.6-sol";

/// Default reasoning effort for `askcodex ask`.
pub const DEFAULT_ASK_EFFORT: &str = "medium";

/// Maximum reference images accepted by `/codex/images/edits`.
pub const MAX_EDIT_IMAGES: usize = 5;

/// Refresh the access token when it expires within this window.
pub const REFRESH_WINDOW_SECS: i64 = 300;

/// Also refresh when `last_refresh` is older than this (codex parity).
pub const REFRESH_MAX_AGE_DAYS: i64 = 8;

/// TCP connect timeout for every request. ureq v3 sets NO timeouts by
/// default (probe finding); this is the only agent-level timeout. A global
/// or receive-body timeout must NEVER be set on the shared agent: `ask`
/// streams may legitimately run for minutes.
pub const CONNECT_TIMEOUT_SECS: u64 = 10;

/// Timeout for the OAuth refresh call (short, non-streaming).
pub const REFRESH_TIMEOUT_SECS: u64 = 30;

/// Explicit read limit for response bodies. ureq's plain readers are
/// unlimited and `read_to_string`/`read_to_vec` cap at 10MB (probe finding);
/// askcodex always reads through an explicit limit instead.
pub const BODY_LIMIT_BYTES: u64 = 64 * 1024 * 1024;

/// Max bytes of an error/refresh response body quoted in error messages.
pub const ERROR_SNIPPET_BYTES: usize = 400;

/// Resolve the codex home directory.
///
/// Honors `$CODEX_HOME` verbatim when set and non-empty (no tilde
/// expansion: the shell expands `~` before the variable is stored; a
/// literal `~` in the value would be a caller bug we refuse to guess
/// around). Otherwise `$HOME/.codex`. Fails loudly when neither variable
/// is usable — never invents a path.
pub fn codex_home() -> Result<PathBuf, Error> {
    if let Some(v) = std::env::var_os("CODEX_HOME")
        && !v.is_empty()
    {
        return Ok(PathBuf::from(v));
    }
    match std::env::var_os("HOME") {
        Some(h) if !h.is_empty() => Ok(PathBuf::from(h).join(".codex")),
        _ => Err(Error::NoHomeDir),
    }
}

/// Path to the credential file: `<codex_home>/auth.json`.
pub fn auth_path() -> Result<PathBuf, Error> {
    Ok(codex_home()?.join("auth.json"))
}
