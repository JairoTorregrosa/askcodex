//! Credential loading, freshness, refresh, and atomic persistence.
//!
//! HIGHEST-STAKES MODULE: it rewrites the user's real `~/.codex/auth.json`.
//! A bug here can lock the user out of codex. The contracts below are
//! binding, not descriptive; this module carries the deepest tests in the
//! crate, and an adversarial review targets it first.
//!
//! Iron rules (repeated from the crate contract because they bind hardest
//! here):
//! - NEVER print, log, or embed in any error the VALUE of
//!   `access_token` / `id_token` / `refresh_token`. Claim names only.
//! - Treat a failed refresh as fatal for the command, never as "continue
//!   with the old token" (silent fallbacks mask failures).
//! - Every test sets `CODEX_HOME` to a temp dir — NEVER the real
//!   `~/.codex` (see DESIGN.md, testing strategy).
//!
//! Implementation note: the four public functions are the frozen
//! contract surface. Each one that touches the filesystem or the network
//! is a one-line wrapper over a private helper that takes the auth-file
//! path (and, for refresh, the token URL) as an argument. `config::TOKEN_URL`
//! and `config::auth_path()` are resolved in the wrapper and nowhere else,
//! so the unit tests below drive the helpers against a temp directory and a
//! localhost mock: no test in this file can reach the real `~/.codex`, and
//! no test can reach `auth.openai.com`. Behavior of the public functions is
//! exactly what the doc comments specify — the split is purely injection.
//!
//! Token-endpoint seam: [`refresh_with_endpoint`] exposes the
//! token URL as an explicit parameter so that code OUTSIDE this module —
//! notably [`crate::http::Client`], and through it an offline integration
//! test — can exercise the real refresh path against a localhost mock.
//! It is an argument, never an ambient setting: see that function's docs
//! for why an environment override is forbidden.
//!
//! Cross-process exclusion: a refresh rotates a credential the
//! server also tracks, so the decide -> refresh -> persist sequence runs
//! under an advisory lock file next to `auth.json` and RE-READS the file
//! under that lock before deciding. See [`AuthLock`] and [`refresh_locked`].
//!
//! No API key is read or accepted here (the `OPENAI_API_KEY` key that may
//! exist in `auth.json` is never named in code; it rides through as an
//! unknown key via serde flatten).

use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt; // 0600-at-open; askcodex targets Unix.
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::config;
use crate::error::Error;
use crate::models::{self, AuthFile, RefreshRequest, RefreshResponse};
use crate::redact::{REDACTED, Secret};

/// Seconds in a day, for the `last_refresh` age rule (integer math keeps
/// the comparison panic-free; `chrono::TimeDelta::days` panics on overflow).
const SECS_PER_DAY: i64 = 86_400;

/// How long a refresh waits for the credential lock before giving up.
///
/// Longer than `config::REFRESH_TIMEOUT_SECS` (the hard cap on how long the
/// process holding the lock can be inside its one HTTP call) plus room for
/// the persist, so a normally-behaving concurrent askcodex is waited out rather
/// than reported as a conflict. Waiting here is mutual exclusion, not a
/// retry loop: nothing is attempted twice, and the wait ends in a loud
/// error, never in a silent skip.
const LOCK_WAIT: Duration = Duration::from_secs(35);

/// Polling interval while the lock is held by someone else.
const LOCK_POLL: Duration = Duration::from_millis(50);

/// A lock file older than this was abandoned by a process that died (no
/// signal handler unwinds — see `main.rs`), and is reclaimed. Comfortably
/// above `LOCK_WAIT`, so a live holder is never mistaken for a dead one.
/// This is what keeps a stale lock from making askcodex permanently unusable.
const LOCK_STALE: Duration = Duration::from_secs(600);

/// Load and validate `auth.json` from [`crate::config::auth_path`].
///
/// Contract:
/// - File missing -> `Error::AuthFileMissing` (message tells the user to
///   run `codex login`).
/// - Unreadable -> `Error::AuthFileUnreadable`; unparseable ->
///   `Error::AuthFileInvalid`.
/// - Parsed but `tokens` absent, or `tokens.access_token` absent/empty ->
///   `Error::AuthTokensMissing` (this is also the keyring-storage case:
///   codex may store credentials in the system keyring depending on its
///   `AuthCredentialsStoreMode`; the message must say the file-based path
///   is required and how to get one).
/// - `tokens.account_id` absent/empty -> `Error::AuthAccountIdMissing`.
/// - Unknown top-level or token-level keys are preserved in the returned
///   struct (serde flatten; models.rs guarantees round-trip).
/// - Read-only: this function NEVER writes the file.
pub fn load_auth() -> Result<AuthFile, Error> {
    load_auth_from(&config::auth_path()?)
}

/// [`load_auth`] against an explicit path (see the module note on injection).
fn load_auth_from(path: &Path) -> Result<AuthFile, Error> {
    // `read` + NotFound (rather than `exists()` first) keeps the
    // missing/unreadable distinction race-free.
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            return Err(Error::AuthFileMissing {
                path: path.to_path_buf(),
            });
        }
        Err(source) => {
            return Err(Error::AuthFileUnreadable {
                path: path.to_path_buf(),
                source,
            });
        }
    };

    let auth: AuthFile =
        serde_json::from_slice(&bytes).map_err(|source| Error::AuthFileInvalid {
            path: path.to_path_buf(),
            source,
        })?;

    let has_access_token = auth
        .tokens
        .as_ref()
        .and_then(|tokens| tokens.access_token.as_ref())
        .is_some_and(|token| !token.is_empty());
    if !has_access_token {
        return Err(Error::AuthTokensMissing {
            path: path.to_path_buf(),
        });
    }

    let has_account_id = auth
        .tokens
        .as_ref()
        .and_then(|tokens| tokens.account_id.as_deref())
        .is_some_and(|id| !id.is_empty());
    if !has_account_id {
        return Err(Error::AuthAccountIdMissing {
            path: path.to_path_buf(),
        });
    }

    Ok(auth)
}

/// Decode the `exp` claim (unix epoch seconds) from a JWT access token.
///
/// Contract:
/// - Split on `.`; the payload is segment 1 of 3; decode with
///   base64 URL_SAFE_NO_PAD (probe finding: JWT segments carry no padding —
///   no manual `=` padding).
/// - Malformed token (wrong segment count, bad base64, bad JSON, missing
///   or non-numeric `exp`) -> `Error::JwtInvalid { reason }` where
///   `reason` names the failing step and claim NAMES only — never any
///   part of the token value. LOUD by design: treating an undecodable
///   token as "refresh now" would be a silent guess; askcodex refuses.
pub fn jwt_exp(token: &Secret) -> Result<i64, Error> {
    // NOTE: every `reason` below names a step or a claim NAME. Nothing
    // derived from the token value (not even a base64 error offset, which
    // would disclose one character of it) may enter these strings.
    let mut segments = token.expose().split('.');
    let (Some(_), Some(payload), Some(_), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return Err(Error::JwtInvalid {
            reason: "expected 3 dot-separated segments".to_string(),
        });
    };

    let decoded = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| Error::JwtInvalid {
            reason: "payload segment is not unpadded base64url".to_string(),
        })?;

    let claims: Value = serde_json::from_slice(&decoded).map_err(|_| Error::JwtInvalid {
        reason: "payload segment is not JSON".to_string(),
    })?;
    if !claims.is_object() {
        return Err(Error::JwtInvalid {
            reason: "payload segment is not a JSON object".to_string(),
        });
    }

    let Some(exp) = claims.get("exp") else {
        return Err(Error::JwtInvalid {
            reason: "payload has no `exp` claim".to_string(),
        });
    };
    if let Some(secs) = exp.as_i64() {
        return Ok(secs);
    }
    // RFC 7519 NumericDate permits a non-integer value; truncate toward
    // zero rather than reject a spec-legal token.
    if let Some(secs) = exp.as_f64()
        && secs.is_finite()
        && secs >= i64::MIN as f64
        && secs <= i64::MAX as f64
    {
        return Ok(secs as i64);
    }
    Err(Error::JwtInvalid {
        reason: "claim `exp` is not a number".to_string(),
    })
}

/// Decide whether the access token must be refreshed at time `now`.
///
/// Contract — codex's rule, as recorded in docs/PROTOCOL.md §6
/// (`[verified-source] should_refresh_proactively`): refresh if
/// `access_token exp <= now + 5 min`, **or, when `exp` is unreadable**, if
/// `last_refresh` is older than 8 days. The age rule is a FALLBACK for a
/// token whose expiry cannot be read, not a second, independent trigger:
///
/// - `exp` readable -> true exactly when
///   `jwt_exp(access_token) - now < config::REFRESH_WINDOW_SECS`.
///   `last_refresh` is not consulted at all, so neither an old nor a
///   corrupt one can rotate (or block) a token that is demonstrably valid.
///   (askcodex's boundary is `<` where codex's is `<=`: one second, in the safe
///   direction, and stated here rather than smoothed over.)
/// - `exp` unreadable and `last_refresh` present -> true when it is older
///   than `config::REFRESH_MAX_AGE_DAYS`. An UNPARSEABLE `last_refresh`
///   is `Error::UnexpectedResponse { context }` naming the field — loud,
///   because this is the branch that actually depends on the value and
///   guessing staleness would mask corruption.
/// - `exp` unreadable and `last_refresh` absent -> the `jwt_exp` error,
///   propagated unchanged. DELIBERATE DIVERGENCE from codex, which treats
///   "no signal at all" as "no refresh": with neither an expiry nor a
///   timestamp there is nothing to decide on, and assuming "refresh now"
///   is exactly the guess this module refuses to make. An undecodable
///   access token is corruption, and corruption is loud here.
/// - Requires `tokens.access_token` present (guaranteed by `load_auth`).
pub fn needs_refresh(auth: &AuthFile, now: DateTime<Utc>) -> Result<bool, Error> {
    let Some(access_token) = auth
        .tokens
        .as_ref()
        .and_then(|tokens| tokens.access_token.as_ref())
    else {
        // Only reachable when the caller skipped `load_auth`. Loud, and
        // deliberately NOT a path error: nothing here is about paths.
        return Err(Error::UnexpectedResponse {
            context: "auth.json has no tokens.access_token (load it with load_auth first)"
                .to_string(),
        });
    };

    match jwt_exp(access_token) {
        // The expiry is the authoritative signal; when it is readable it is
        // the ONLY one, so a stale or malformed `last_refresh` can neither
        // rotate the user's credentials early nor disable every command.
        Ok(exp) => Ok(exp.saturating_sub(now.timestamp()) < config::REFRESH_WINDOW_SECS),
        // Fallback path only: `last_refresh` decides when `exp` does not.
        Err(undecodable) => match auth.last_refresh.as_deref() {
            Some(raw) => {
                let last =
                    models::parse_last_refresh(raw).map_err(|_| Error::UnexpectedResponse {
                        context: "auth.json last_refresh is not an RFC3339 timestamp".to_string(),
                    })?;
                Ok(now.timestamp().saturating_sub(last.timestamp())
                    > config::REFRESH_MAX_AGE_DAYS * SECS_PER_DAY)
            }
            None => Err(undecodable),
        },
    }
}

/// Refresh the tokens via `POST config::TOKEN_URL` and persist the result.
///
/// Contract:
/// - Runs under an exclusive advisory lock on `auth.json.lock`, and
///   re-reads `auth.json` under it before deciding anything: see
///   [`refresh_locked`]. Lock unobtainable -> `Error::AuthLockUnavailable`,
///   before any token is sent.
/// - `Ok(())` therefore has two shapes: this process rotated, or another
///   askcodex had just rotated and this one adopted the result rather than
///   spending a token the server has already replaced. In both cases the
///   credentials in memory and on disk are the live ones, so a caller that
///   reports "refreshed" (`run.rs`) is reporting the state accurately;
///   nothing that is not fresh is ever reported as success.
/// - Requires `tokens.refresh_token`; absent -> `Error::RefreshUnavailable`.
/// - Request body: `models::RefreshRequest::new(refresh_token)` as JSON.
///   Headers: `Content-Type: application/json` (send_json sets it),
///   `User-Agent: config::USER_AGENT`. NO Authorization header, NO
///   ChatGPT-Account-Id — this is the OAuth host, not the backend.
///   Timeout: `config::REFRESH_TIMEOUT_SECS` (request-scoped override on
///   the shared agent; probe-verified pattern).
/// - Non-200 -> `Error::RefreshFailed { status, snippet }` with the body
///   truncated to `config::ERROR_SNIPPET_BYTES`. The in-memory `auth` and
///   the file MUST be untouched in this case (the old refresh token is
///   still valid server-side).
/// - 200 without `access_token` -> `Error::RefreshInvalidResponse { keys }`
///   carrying the response's key NAMES only. `auth` untouched.
/// - Success: rotate in memory — `access_token` always; `id_token` and
///   `refresh_token` only when present in the response (a missing rotated
///   refresh_token keeps the old one; NEVER clear it); set `last_refresh`
///   to `models::format_last_refresh(Utc::now())` (byte-exact codex
///   format). Then `persist_atomic(auth)`.
/// - If persistence fails AFTER rotation, propagate
///   `Error::PersistFailed` unchanged (its message explains that tokens
///   rotated server-side and where the backup is). Do NOT retry, do NOT
///   swallow.
/// - This function performs EXACTLY ONE refresh attempt. No retry loops.
///
/// Thin delegation to [`refresh_with_endpoint`] with the production
/// endpoint [`config::TOKEN_URL`]; all behavior above lives there.
pub fn refresh(agent: &ureq::Agent, auth: &mut AuthFile) -> Result<(), Error> {
    refresh_with_endpoint(agent, auth, config::TOKEN_URL)
}

/// [`refresh`] against an explicitly supplied OAuth token endpoint.
///
/// Every invariant of [`refresh`] holds here unchanged — it IS the
/// implementation: exactly one attempt and no retry loop, the auth-file
/// path resolved before the network call, in-memory state and the file
/// left untouched on any failure, a working `refresh_token` never cleared
/// because the response omitted a rotated one, and an atomic persist of
/// the rotated tokens.
///
/// `token_url` EXISTS FOR TESTING AND FOR NOTHING ELSE. It lets an offline
/// test drive a genuine refresh against a localhost mock instead of
/// `auth.openai.com`. Production callers pass [`config::TOKEN_URL`], which
/// is precisely what [`refresh`] and [`crate::http::Client::new`] do.
///
/// It must NEVER be wired to an environment variable, a config file, or a
/// CLI flag. An `ASKCODEX_TOKEN_URL`-style override was considered and is
/// deliberately REJECTED: this request carries a LIVE refresh token, so an
/// externally settable endpoint would be a credential-exfiltration
/// primitive — anything able to plant a variable in the user's environment
/// (a sourced dotfile, a CI job, a compromised dependency's build script)
/// could redirect that token to a host it controls, silently. It is also
/// exactly the kind of invisible default this project forbids. Outside
/// this crate's own tests the endpoint is a compile-time constant, and it
/// stays that way.
pub fn refresh_with_endpoint(
    agent: &ureq::Agent,
    auth: &mut AuthFile,
    token_url: &str,
) -> Result<(), Error> {
    // `auth_path()` is resolved BEFORE the network call: an unresolvable
    // CODEX_HOME must abort while the old refresh token is still the one
    // the server knows.
    let path = config::auth_path()?;
    refresh_inner(agent, auth, token_url, &path)
}

/// [`refresh`] against an explicit token URL and auth-file path (see the
/// module note on injection).
fn refresh_inner(
    agent: &ureq::Agent,
    auth: &mut AuthFile,
    token_url: &str,
    auth_file: &Path,
) -> Result<(), Error> {
    refresh_locked(agent, auth, token_url, auth_file, LOCK_WAIT)
}

/// [`refresh_inner`] with the lock wait as an argument (test injection, in
/// the same spirit as the path and URL parameters above), and the whole
/// cross-process story in one place.
///
/// THE PROBLEM. `fs::rename` makes each write atomic, but atomicity is not
/// mutual exclusion. Two askcodex processes that overlap (an agent issuing
/// parallel tool calls is the realistic case) each load `auth.json`, each
/// decide a refresh is due, and each POST the SAME refresh token. The
/// server rotates on every refresh (docs/PROTOCOL.md §6), so the two
/// requests are two generations, and whichever process persists LAST wins —
/// possibly the one holding the older generation. What that costs depends
/// on a server behavior this project has NOT verified: under strict
/// rotation the loser's request simply fails loudly and the file keeps a
/// usable token; if the server tolerates a grace window, the file is left
/// holding a token that has already been retired. PROTOCOL.md §6 does
/// record `refresh_token_reused` as a distinct PERMANENT error requiring a
/// fresh `codex login`, and both processes demonstrably send the identical
/// token, so the exposure is real even though its worst case is not proven.
///
/// THE FIX, in two parts:
/// 1. An exclusive lock file (`auth.json.lock`) held across the entire
///    decide -> refresh -> persist sequence, so only one process at a time
///    can rotate this credential file.
/// 2. A RE-READ of `auth.json` under that lock. The document in memory was
///    loaded before the lock existed and may be a generation behind; the
///    on-disk one is authoritative. When the on-disk `refresh_token`
///    differs from the one this process holds, another askcodex has already
///    rotated: adopt the on-disk credentials instead of spending the stale
///    token, and skip the network entirely when the adopted document is
///    provably fresh.
///
/// The lock covers this crate's write path, which is the whole of askcodex's.
/// It cannot exclude the codex CLI itself (a different program with no
/// shared lock convention), and the load in `run.rs` still happens outside
/// it — which is exactly why part 2 exists rather than the lock alone.
fn refresh_locked(
    agent: &ureq::Agent,
    auth: &mut AuthFile,
    token_url: &str,
    auth_file: &Path,
    lock_wait: Duration,
) -> Result<(), Error> {
    // Resolved BEFORE the network call, for the same reason `auth_path()`
    // is: if this process could not write the result, it must not ask the
    // server to rotate. A symlinked `auth.json` is followed to the real
    // file so that the lock, the temp and the backup all land beside it
    // (see `resolve_symlink`); a dangling link aborts here, pre-rotation.
    let auth_file = &resolve_symlink(auth_file).map_err(|source| Error::AuthFileUnreadable {
        path: auth_file.to_path_buf(),
        source,
    })?;

    // Held until this function returns, on every path.
    let _lock = AuthLock::acquire(auth_file, lock_wait)?;

    // Part 2: re-read under the lock. A read failure is NOT fatal here —
    // this is a concurrency check, not a validation step. If the file
    // cannot be read or does not validate there is no rotation to detect
    // (and no credential to adopt), so the in-memory document stands and
    // the persist below is the authoritative write, exactly as before.
    if let Ok(on_disk) = load_auth_from(auth_file) {
        let rotated_elsewhere = match (refresh_token_value(&on_disk), refresh_token_value(auth)) {
            // Two usable generations, and ours is not the one on disk:
            // that is the concurrent rotation this lock exists for.
            (Some(theirs), Some(mine)) => theirs != mine,
            // Anything else is NOT a rotation race and must not be papered
            // over by reading credentials off the disk: a caller whose
            // document has no refresh token gets `RefreshUnavailable`
            // below, and a truncated or hand-edited file on disk never
            // takes away a refresh token this process can still use.
            _ => false,
        };
        if rotated_elsewhere {
            *auth = on_disk;
            // Skip the network ONLY when the adopted document is provably
            // fresh. Anything else (due for a refresh, or a freshness check
            // that errors) falls through and refreshes with the ADOPTED
            // refresh token — the live generation — never the spent one.
            if matches!(needs_refresh(auth, Utc::now()), Ok(false)) {
                return Ok(());
            }
        }
    }

    let refresh_token = auth
        .tokens
        .as_ref()
        .and_then(|tokens| tokens.refresh_token.as_ref())
        // An empty string is not a usable credential; failing here is the
        // loud path, sending it would be the masking one.
        .filter(|token| !token.is_empty())
        .ok_or(Error::RefreshUnavailable)?
        .clone();

    // Request-scoped config: `http_status_as_error(false)` so a non-200
    // keeps its body (the caller's agent already sets it; setting it here
    // too makes this function correct for ANY agent), and a short global
    // timeout for this one non-streaming call.
    let response = agent
        .post(token_url)
        .config()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(config::REFRESH_TIMEOUT_SECS)))
        .build()
        .header("User-Agent", config::USER_AGENT)
        // Cloned so the exact value that went on the wire is still
        // available below, to be REMOVED from a failure body.
        .send_json(RefreshRequest::new(refresh_token.clone()))?;

    let status = response.status().as_u16();
    if status != 200 {
        // This body is a string from a third party that this project has
        // never observed: docs/PROTOCOL.md §6 documents the refresh flow
        // from codex source, not from live error responses, and §6 itself
        // names a `refresh_token_reused` failure — a body shaped like
        // `{"error_description":"refresh_token <value> was reused"}` is
        // therefore not a hypothesis anyone here can rule out. askcodex's
        // guarantee that no token value can reach a log line must hold on
        // code, not on an assumption about someone else's server, so every
        // credential this request could possibly echo is removed from the
        // body BEFORE it is truncated and quoted.
        let mut secrets = vec![refresh_token.expose()];
        if let Some(tokens) = auth.tokens.as_ref() {
            for token in [
                tokens.access_token.as_ref(),
                tokens.id_token.as_ref(),
                tokens.refresh_token.as_ref(),
            ]
            .into_iter()
            .flatten()
            {
                secrets.push(token.expose());
            }
        }
        let body = scrub_secrets(read_error_body(response.into_body()), &secrets);
        return Err(Error::RefreshFailed {
            status,
            snippet: truncate_snippet(&body),
        });
    }

    // A 200 body carries LIVE tokens: it must never be quoted in an error.
    // Only lengths, shapes and key NAMES may leave this block.
    let value: Value = response
        .into_body()
        .into_with_config()
        .limit(config::BODY_LIMIT_BYTES)
        .read_json()
        .map_err(|source| Error::UnexpectedResponse {
            context: format!("token refresh returned a body that is not JSON: {source}"),
        })?;

    let Value::Object(object) = &value else {
        return Err(Error::UnexpectedResponse {
            context: "token refresh returned JSON that is not an object".to_string(),
        });
    };
    let mut keys: Vec<String> = object.keys().cloned().collect();
    keys.sort();

    let parsed: RefreshResponse =
        serde_json::from_value(value).map_err(|_| Error::UnexpectedResponse {
            context: format!("token refresh response has unexpected field types; keys={keys:?}"),
        })?;

    let Some(access_token) = parsed.access_token.filter(|token| !token.is_empty()) else {
        return Err(Error::RefreshInvalidResponse { keys });
    };

    let tokens = auth
        .tokens
        .as_mut()
        .ok_or_else(|| Error::UnexpectedResponse {
            context: "auth.json has no tokens object".to_string(),
        })?;

    // Rotate: access_token always; the other two ONLY when the response
    // carries a usable replacement. Clearing a working refresh_token
    // because the server did not rotate it is how users get locked out.
    tokens.access_token = Some(access_token);
    if let Some(id_token) = parsed.id_token.filter(|token| !token.is_empty()) {
        tokens.id_token = Some(id_token);
    }
    if let Some(refresh_token) = parsed.refresh_token.filter(|token| !token.is_empty()) {
        tokens.refresh_token = Some(refresh_token);
    }
    auth.last_refresh = Some(models::format_last_refresh(Utc::now()));

    persist_atomic_to(auth, auth_file)
}

/// Atomically write `auth` back to `config::auth_path()`.
///
/// Contract (crash-safe, permission-safe, rollback-safe):
/// 1. Serialize with `serde_json::to_string_pretty` + trailing newline.
///    Unknown keys ride along (models.rs flatten round-trip).
/// 2. Resolve a symlinked `auth.json` to the file it points at, and do
///    every step below on THAT path (see `resolve_symlink`): a user whose
///    credentials live in a synced store must keep receiving updates
///    there, and the temp file must share a filesystem with the file the
///    rename replaces.
/// 3. Backup FIRST: if `auth.json` exists, copy it to `auth.json.bak`
///    through a `O_CREAT|O_EXCL` + mode-0600 temp file and a rename — the
///    same 0600-at-open discipline as step 4, because the backup holds
///    the same credentials, and never a truncated `.bak`. The backup is
///    best-effort forensics (its refresh token may already be rotated
///    server-side) but preserves `account_id` and unknown keys; a backup
///    failure ABORTS the persist with the original untouched. Doing it
///    before the write is what lets `Error::PersistFailed` name a backup
///    that actually exists and actually holds the document that was there
///    (see `persist_failed`).
/// 4. Create a temp file IN THE SAME DIRECTORY as `auth.json` (same
///    filesystem => atomic rename), name `auth.json.tmp.<pid>`, opened
///    with `O_CREAT|O_EXCL` and mode 0600 BEFORE any byte is written
///    (via `OpenOptions::mode(0o600)` — never chmod-after-write, which
///    would leave a window where the file is readable).
/// 5. Write all bytes, flush, `File::sync_all` (fsync) the temp file.
/// 6. `std::fs::rename(temp, auth.json)` — atomic on POSIX. On any error
///    in steps 2-6: remove the temp file, leave `auth.json` exactly as it
///    was, and return `Error::PersistFailed { path, backup, source }`.
/// 7. Postcondition on EVERY path (success or failure): `auth.json` is
///    either the complete old document or the complete new document —
///    never absent, never truncated, never mode-loosened.
///
/// This function does NOT take the credential lock: it is called with the
/// lock already held on the one path that rotates ([`refresh_locked`]), and
/// taking it again there would deadlock. On its own it neither reads nor
/// spends a server-side credential, and the rename is atomic for readers.
pub fn persist_atomic(auth: &AuthFile) -> Result<(), Error> {
    persist_atomic_to(auth, &config::auth_path()?)
}

/// [`persist_atomic`] against an explicit path (see the module note on
/// injection).
fn persist_atomic_to(auth: &AuthFile, path: &Path) -> Result<(), Error> {
    // Step 1. Serialization happens before anything touches the disk, so a
    // (practically impossible) serde failure cannot leave a temp file.
    let mut document = serde_json::to_string_pretty(auth)?;
    document.push('\n');

    // Step 2. Follow a symlink to the real credential file. Until the
    // target is known, no sibling name can be computed and no backup can
    // exist, so a failure here names `path` itself (which is untouched).
    let target = resolve_symlink(path).map_err(|source| persist_failed(path, None, source))?;
    let path = target.as_path();

    let Some(file_name) = path.file_name() else {
        return Err(persist_failed(
            path,
            None,
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "auth file path has no file name",
            ),
        ));
    };
    // `with_file_name` keeps every sibling in the SAME directory as the
    // target, which is what makes the final rename atomic.
    let sibling = |suffix: &str| -> PathBuf {
        let mut name = file_name.to_os_string();
        name.push(suffix);
        path.with_file_name(name)
    };
    let backup = sibling(".bak");
    let backup_temp = sibling(&format!(".bak.tmp.{}", std::process::id()));
    let temp = sibling(&format!(".tmp.{}", std::process::id()));

    // Step 3. Back up the CURRENT document BEFORE anything else is written.
    // A failure here aborts and leaves the original untouched.
    let exists = path
        .try_exists()
        .map_err(|source| persist_failed(path, None, source))?;
    if exists {
        write_backup(path, &backup, &backup_temp)
            .map_err(|source| persist_failed(path, None, source))?;
    }
    // Everything from here on can name the backup, because from here on it
    // exists and holds the document `auth.json` currently has. Before this
    // point the honest answer is that no backup was taken and `auth.json`
    // itself is still the previous document — so that is what gets named.
    let named_backup: Option<&Path> = if exists { Some(&backup) } else { None };

    // Step 4. O_CREAT|O_EXCL (`create_new`) + mode 0600 applied by the
    // kernel at creation time: there is no window in which the file exists
    // with looser permissions. NOTE: the guard is armed only AFTER a
    // successful open — on EEXIST the temp belongs to someone else and
    // must not be deleted.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)
        .map_err(|source| persist_failed(path, named_backup, source))?;
    let mut guard = TempFileGuard::new(&temp);

    // Step 5.
    file.write_all(document.as_bytes())
        .map_err(|source| persist_failed(path, named_backup, source))?;
    file.flush()
        .map_err(|source| persist_failed(path, named_backup, source))?;
    file.sync_all()
        .map_err(|source| persist_failed(path, named_backup, source))?;
    drop(file);

    // Step 6. Atomic on POSIX: a concurrent reader sees either the old or
    // the new complete document, never a partial one. (The containing
    // directory is deliberately not fsynced: that would only add power-loss
    // durability, which is outside this threat model, and its failure after
    // a completed rename could not be acted on anyway.)
    fs::rename(&temp, path).map_err(|source| persist_failed(path, named_backup, source))?;
    guard.disarm();
    Ok(())
}

/// Copy the current credential document to `backup`, via a temp file and a
/// rename.
///
/// Not `fs::copy` + `set_permissions`: that is the chmod-after-write
/// pattern this module forbids three steps earlier for the temp file, and
/// the backup holds byte-identical credentials. `fs::copy` carries the
/// SOURCE mode over, so a 0644 `auth.json` produced a world-readable
/// `.bak` for the window between the copy and the chmod (measured on
/// macOS), and re-widened an already-hardened `.bak` on the way. Creating
/// the destination with `O_EXCL` + mode 0600 closes that window on every
/// platform; the rename also means `.bak` is never a half-written file.
fn write_backup(path: &Path, backup: &Path, temp: &Path) -> std::io::Result<()> {
    // auth.json is a few KB; reading it whole keeps this a single
    // write-then-rename with no partially-copied intermediate state.
    let previous = fs::read(path)?;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(temp)?;
    let mut guard = TempFileGuard::new(temp);
    file.write_all(&previous)?;
    file.flush()?;
    file.sync_all()?;
    drop(file);

    fs::rename(temp, backup)?;
    guard.disarm();
    Ok(())
}

/// Build the one error variant this module's write path may return.
///
/// `backup` is `Some` only for a path this call actually wrote, and `None`
/// for every failure that happens before `auth.json` is touched — where the
/// previous document is still `auth.json` itself. Sending a user to a file
/// that does not exist, or to a `.bak` left over from an earlier refresh
/// holding credentials two generations dead, is worse than saying nothing,
/// so the two cases render as different sentences.
fn persist_failed(path: &Path, backup: Option<&Path>, source: std::io::Error) -> Error {
    Error::PersistFailed {
        path: path.to_path_buf(),
        backup: backup.map(Path::to_path_buf),
        source,
    }
}

/// Resolve a symlinked credential path to the file it points at; return
/// `path` unchanged when it is not a symlink (including when nothing is
/// there yet).
///
/// `rename(2)` operates on the directory entry, so renaming onto a
/// symlinked `auth.json` would REPLACE the link with a regular file:
/// reads follow the link, writes silently stop following it, and the
/// user's canonical store (a synced directory, a managed secret store)
/// freezes at a refresh-token generation the server has already retired,
/// with nothing in askcodex's output ever mentioning it. Following the link
/// keeps that setup working and puts the temp file on the same filesystem
/// as the file the rename replaces, which is what makes it atomic.
///
/// A dangling link is an error, not a silently created regular file.
fn resolve_symlink(path: &Path) -> std::io::Result<PathBuf> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => fs::canonicalize(path),
        _ => Ok(path.to_path_buf()),
    }
}

/// The `refresh_token` VALUE, or `None` when absent or empty.
///
/// One of this module's few `Secret::expose` call sites, and the only one
/// outside the JWT decode: the value is COMPARED (to detect that another
/// process rotated the credentials) and removed from error bodies. It is
/// never printed, stored, or returned to a caller outside this file.
fn refresh_token_value(auth: &AuthFile) -> Option<&str> {
    auth.tokens
        .as_ref()
        .and_then(|tokens| tokens.refresh_token.as_ref())
        .map(|token| token.expose())
        .filter(|token| !token.is_empty())
}

/// Removes the temp file unless explicitly disarmed. Drop-based so that an
/// early `?` return — or a panic — cannot leave a stray 0600 temp behind.
struct TempFileGuard<'a> {
    path: Option<&'a Path>,
}

impl<'a> TempFileGuard<'a> {
    fn new(path: &'a Path) -> Self {
        TempFileGuard { path: Some(path) }
    }

    /// Call after a successful rename: the temp no longer exists and the
    /// path now belongs to `auth.json`'s directory entry.
    fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for TempFileGuard<'_> {
    fn drop(&mut self) {
        if let Some(path) = self.path {
            // A discarded error, because `Drop` cannot propagate. What the
            // leftover costs, stated accurately:
            //
            // - Within THIS process the failure is self-announcing: the
            //   temp name embeds `std::process::id()`, so the next persist
            //   trips O_EXCL and fails loudly rather than overwriting it.
            // - Across processes it is NOT. A different PID picks a
            //   different name and succeeds silently, and askcodex never
            //   deletes a temp it did not create. So a run killed between
            //   the fsync and the rename (SIGINT does not unwind — see
            //   `main.rs`) leaves an `auth.json.tmp.<pid>` at 0600 that may
            //   hold newer credentials than `auth.json`, and nothing points
            //   the user at it. That is a known, accepted limitation of
            //   this design, not a guarantee.
            //
            // Deliberately NOT "fixed" by a deterministic temp name: a
            // crash orphan would then block every later persist, which
            // trades a recoverable state for an unrecoverable one. Only
            // one askcodex can be inside a refresh at a time (see `AuthLock`),
            // so the same-PID collision above is the crashed-predecessor
            // case, never a live competitor.
            let _ = fs::remove_file(path);
        }
    }
}

/// An exclusive, cross-process lock on one credential file.
///
/// Advisory and cooperative: it excludes other askcodex processes, which is
/// what the concurrent-rotation defect needs (see [`refresh_locked`]). It
/// is a lock FILE rather than `flock(2)` because that would mean a new
/// dependency (`libc`) in a crate whose dependency set is probe-validated
/// and frozen; the trade-off is that abandonment has to be detected by age
/// instead of by the kernel, which [`LOCK_STALE`] does.
///
/// A stale lock can never make askcodex permanently unusable: it is reclaimed
/// automatically once it is older than [`LOCK_STALE`], and until then the
/// error names the exact file to delete.
struct AuthLock {
    path: PathBuf,
    /// What this process wrote into the lock file. Re-checked before the
    /// file is removed, so a lock another process legitimately reclaimed
    /// (because this one hung past `LOCK_STALE`) is not deleted out from
    /// under its new owner.
    owner: String,
}

impl AuthLock {
    /// Acquire the lock for `auth_file`, waiting at most `wait`.
    ///
    /// Loud on every outcome except success: a lock held by a live process
    /// becomes `Error::AuthLockUnavailable` once the wait is exhausted, and
    /// so does any other failure to create the file (an unwritable
    /// directory, for instance) — immediately, because waiting cannot fix
    /// it. Nothing is ever "continued without the lock".
    fn acquire(auth_file: &Path, wait: Duration) -> Result<AuthLock, Error> {
        let Some(file_name) = auth_file.file_name() else {
            return Err(Error::AuthLockUnavailable {
                path: auth_file.to_path_buf(),
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "auth file path has no file name",
                ),
            });
        };
        let path = auth_file.with_file_name({
            let mut name = file_name.to_os_string();
            name.push(".lock");
            name
        });
        // In test builds, catch a test that races the shared scratch
        // CODEX_HOME before it creates the file rather than after.
        #[cfg(test)]
        assert_codex_home_locked(&path);

        let owner = format!("{}\n", std::process::id());

        let deadline = Instant::now() + wait;
        loop {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
            {
                Ok(mut file) => {
                    // The pid is written before the guard exists so that a
                    // failure here can be cleaned up explicitly: there is
                    // no `?` and nothing that can panic between the open
                    // and the return, so no path leaves an unowned lock
                    // file behind. (It is diagnostics for a human, and the
                    // ownership proof `Drop` re-checks. A pid is not a
                    // credential.)
                    if let Err(source) =
                        file.write_all(owner.as_bytes()).and_then(|()| file.flush())
                    {
                        let _ = fs::remove_file(&path);
                        return Err(Error::AuthLockUnavailable { path, source });
                    }
                    return Ok(AuthLock { path, owner });
                }
                Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
                    // Held by someone. Reclaim it only if it is old enough
                    // that no live askcodex could still own it, then loop back
                    // to `create_new` rather than assuming the lock is now
                    // ours — if two processes reclaim at once, O_EXCL still
                    // picks exactly one winner. (Residual, accepted: the
                    // reclaiming unlink is not atomic with the age check,
                    // so a lock that goes stale at that exact instant could
                    // be removed twice; `owner` makes the release safe.)
                    if is_stale(&path) {
                        let _ = fs::remove_file(&path);
                        continue;
                    }
                    if Instant::now() >= deadline {
                        return Err(Error::AuthLockUnavailable { path, source });
                    }
                    std::thread::sleep(LOCK_POLL);
                }
                Err(source) => return Err(Error::AuthLockUnavailable { path, source }),
            }
        }
    }
}

impl Drop for AuthLock {
    fn drop(&mut self) {
        // Release only a lock this process still owns. If it hung past
        // `LOCK_STALE` and another askcodex reclaimed the file, the content is
        // a different pid and removing it would release a lock held by
        // someone else. Errors are discarded because `Drop` cannot
        // propagate; the age-based reclaim above is the backstop.
        match fs::read(&self.path) {
            Ok(content) if content == self.owner.as_bytes() => {
                let _ = fs::remove_file(&self.path);
            }
            _ => {}
        }
    }
}

/// True when a lock file is old enough that its owner must be gone.
fn is_stale(path: &Path) -> bool {
    let Ok(modified) = fs::metadata(path).and_then(|metadata| metadata.modified()) else {
        // Unknown age is not evidence of abandonment: wait instead.
        return false;
    };
    match SystemTime::now().duration_since(modified) {
        Ok(age) => age > LOCK_STALE,
        // Timestamp in the future (clock skew): treat as fresh.
        Err(_) => false,
    }
}

/// Read a non-2xx body for an error message: bounded read, lossy UTF-8.
/// Truncation is the CALLER's last step, after scrubbing, so that a
/// credential cannot survive by straddling the cut.
fn read_error_body(body: ureq::Body) -> String {
    match body
        .into_with_config()
        .limit(config::BODY_LIMIT_BYTES)
        .lossy_utf8(true)
        .read_to_string()
    {
        Ok(text) => text,
        // The status is already known and preserved by the caller; say why
        // the body is missing instead of pretending it was empty.
        Err(source) => format!("<response body unreadable: {source}>"),
    }
}

/// Replace every occurrence of each secret with `redact::REDACTED`.
///
/// Empty values are skipped (replacing "" would splice the placeholder
/// between every character); short ones are not, because a short
/// credential is still a credential and over-redacting an error body costs
/// nothing next to leaking one.
fn scrub_secrets(text: String, secrets: &[&str]) -> String {
    let mut text = text;
    for secret in secrets {
        if !secret.is_empty() && text.contains(secret) {
            text = text.replace(secret, REDACTED);
        }
    }
    text
}

/// Truncate to at most `config::ERROR_SNIPPET_BYTES`, never splitting a
/// UTF-8 character (slicing off a boundary would panic).
fn truncate_snippet(text: &str) -> String {
    if text.len() <= config::ERROR_SNIPPET_BYTES {
        return text.to_string();
    }
    let mut end = config::ERROR_SNIPPET_BYTES;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_string()
}

// ---------------------------------------------------------------------------
// test-only isolation, shared with http.rs
// ---------------------------------------------------------------------------

/// Point `CODEX_HOME` at a per-process scratch directory and return it.
///
/// Test-only, and the single place in the crate that writes that variable:
/// `set_var` is process-wide, so it runs exactly once per test process,
/// before any test can read it (every test in this crate calls this first).
/// Its purpose is defense in depth — even a test that DID let production
/// code resolve `config::auth_path()` lands in the scratch directory
/// instead of the user's real `~/.codex`.
#[cfg(test)]
pub(crate) fn isolate_codex_home() -> std::path::PathBuf {
    use std::sync::Once;

    static ONCE: Once = Once::new();
    let scratch =
        std::env::temp_dir().join(format!("askcodex-test-codex-home-{}", std::process::id()));
    ONCE.call_once(|| {
        fs::create_dir_all(&scratch).expect("create scratch CODEX_HOME");
        // SAFETY: executed exactly once per process, before any test has
        // read the environment, and never again afterwards.
        unsafe { std::env::set_var("CODEX_HOME", &scratch) };
    });
    scratch
}

/// Serialize the tests that let production code resolve AND WRITE
/// `config::auth_path()`, since they all share the one scratch
/// `CODEX_HOME` returned by [`isolate_codex_home`].
///
/// The tests in THIS module never need it (they drive `load_auth_from` /
/// `persist_atomic_to` / `refresh_inner` with their own temp paths); the
/// refresh-through-`Client` tests in http.rs do, and so does any test that
/// asserts on the CONTENTS of the scratch directory. Poisoning is ignored
/// on purpose: one failing test must not cascade into unrelated ones.
///
/// Holding it is not a convention. [`assert_codex_home_locked`] makes it
/// mechanical, because the convention already failed once: a test that
/// reached the credential lock through `Client` without taking this mutex
/// created `auth.json.lock` beside another test's assertion on the
/// directory listing, and the resulting failure surfaced on one CI runner
/// and not on the author's machine.
#[cfg(test)]
pub(crate) fn lock_codex_home() -> CodexHomeGuard {
    let inner = codex_home_mutex()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *codex_home_holder().lock().expect("holder mutex") = Some(std::thread::current().id());
    CodexHomeGuard { _inner: inner }
}

#[cfg(test)]
fn codex_home_mutex() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    &LOCK
}

#[cfg(test)]
fn codex_home_holder() -> &'static std::sync::Mutex<Option<std::thread::ThreadId>> {
    static HOLDER: std::sync::Mutex<Option<std::thread::ThreadId>> = std::sync::Mutex::new(None);
    &HOLDER
}

/// Guard for [`lock_codex_home`]. Records which thread holds the mutex so
/// that a violation can name itself instead of showing up as a mystery
/// directory listing in an unrelated test.
#[cfg(test)]
pub(crate) struct CodexHomeGuard {
    _inner: std::sync::MutexGuard<'static, ()>,
}

#[cfg(test)]
impl Drop for CodexHomeGuard {
    fn drop(&mut self) {
        *codex_home_holder().lock().expect("holder mutex") = None;
    }
}

/// Panic if `path` lives in the shared scratch `CODEX_HOME` and the calling
/// thread does not hold [`lock_codex_home`].
///
/// Called where production code is about to CREATE something there. A test
/// that reaches this point without the mutex is racing every other test
/// that reads the same directory, and the whole point of this project is
/// that a broken invariant is loud at its cause rather than silent until it
/// surfaces somewhere else.
#[cfg(test)]
pub(crate) fn assert_codex_home_locked(path: &Path) {
    let scratch =
        std::env::temp_dir().join(format!("askcodex-test-codex-home-{}", std::process::id()));
    if path.parent() != Some(scratch.as_path()) {
        return;
    }
    let holder = *codex_home_holder().lock().expect("holder mutex");
    assert_eq!(
        holder,
        Some(std::thread::current().id()),
        "this test writes {} in the shared scratch CODEX_HOME without holding \
         auth::lock_codex_home(). Take the guard for the whole test body: \
         `let _guard = auth::lock_codex_home();`",
        path.display()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    use httpmock::prelude::*;

    // ---------------------------------------------------------------
    // Test isolation
    // ---------------------------------------------------------------
    //
    // Two independent guarantees, both required:
    //
    // 1. No test here calls `config::auth_path()` or `config::TOKEN_URL`.
    //    Every filesystem test drives `load_auth_from` / `persist_atomic_to`
    //    with a path inside a per-test temp directory, and every network
    //    test drives `refresh_inner` against a localhost httpmock server.
    //    The real `~/.codex` and `auth.openai.com` are unreachable from
    //    this module's tests by construction.
    // 2. Defense in depth: [`super::isolate_codex_home`] still points
    //    `CODEX_HOME` at a scratch directory once per test process, so
    //    that even a future test that DID resolve the real path would land
    //    in the scratch dir. Nothing here depends on its value, which is
    //    why these tests never take `super::lock_codex_home()`.

    /// A unique directory under the system temp dir, removed on drop.
    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(tag: &str) -> TempDir {
            isolate_codex_home();
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "askcodex-auth-test-{}-{}-{}",
                std::process::id(),
                tag,
                unique
            ));
            fs::create_dir_all(&path).expect("create temp dir");
            TempDir { path }
        }

        fn join(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }

        /// The auth file path used by most tests.
        fn auth(&self) -> PathBuf {
            self.join("auth.json")
        }

        fn entries(&self) -> Vec<String> {
            let mut names: Vec<String> = fs::read_dir(&self.path)
                .expect("read temp dir")
                .map(|entry| {
                    entry
                        .expect("dir entry")
                        .file_name()
                        .to_string_lossy()
                        .into()
                })
                .collect();
            names.sort();
            names
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    // ---------------------------------------------------------------
    // Fixtures
    // ---------------------------------------------------------------

    /// Build a syntactically valid (unsigned, FAKE) JWT whose payload is
    /// `claims`. No real token value exists anywhere in these tests, and
    /// fixtures are built from these plain strings so that `Secret::expose`
    /// never has to be called to construct one.
    fn fake_jwt(claims: &str) -> String {
        format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#),
            URL_SAFE_NO_PAD.encode(claims.as_bytes()),
            URL_SAFE_NO_PAD.encode(b"sig"),
        )
    }

    fn fake_jwt_expiring_at(exp: i64) -> String {
        fake_jwt(&format!(r#"{{"exp":{exp}}}"#))
    }

    fn jwt_with_payload(claims: &str) -> Secret {
        Secret::new(fake_jwt(claims))
    }

    fn jwt_expiring_at(exp: i64) -> Secret {
        Secret::new(fake_jwt_expiring_at(exp))
    }

    fn mode_of(path: &Path) -> u32 {
        fs::metadata(path).expect("metadata").permissions().mode() & 0o777
    }

    /// Identity of the file behind a path: a new inode proves the file was
    /// created rather than rewritten in place.
    fn inode_of(path: &Path) -> u64 {
        use std::os::unix::fs::MetadataExt as _;
        fs::metadata(path).expect("metadata").ino()
    }

    /// A full auth document with an access token expiring at `exp`.
    fn auth_json(exp: i64) -> String {
        format!(
            r#"{{
  "auth_mode": "chatgpt",
  "openai_api_key_placeholder": null,
  "tokens": {{
    "id_token": "{id}",
    "access_token": "{access}",
    "refresh_token": "old-refresh-token",
    "account_id": "acct_test",
    "unknown_token_key": 7
  }},
  "last_refresh": "2026-08-07T23:32:41.615755Z",
  "unknown_top_level": {{"nested": [1, 2, 3]}}
}}"#,
            id = fake_jwt_expiring_at(exp),
            access = fake_jwt_expiring_at(exp),
        )
    }

    fn parse_auth(text: &str) -> AuthFile {
        serde_json::from_str(text).expect("fixture parses")
    }

    // The three accessors below are the ONLY `Secret::expose` calls in this
    // module besides the JWT decode in `jwt_exp`. They exist so the rotation
    // assertions can compare values; every value they touch is a fixture
    // string invented in this file, never a real credential.
    fn access_token_of(auth: &AuthFile) -> String {
        auth.tokens
            .as_ref()
            .and_then(|tokens| tokens.access_token.as_ref())
            .expect("access token")
            .expose()
            .to_string()
    }

    fn refresh_token_of(auth: &AuthFile) -> String {
        auth.tokens
            .as_ref()
            .and_then(|tokens| tokens.refresh_token.as_ref())
            .expect("refresh token")
            .expose()
            .to_string()
    }

    fn id_token_of(auth: &AuthFile) -> Option<String> {
        auth.tokens
            .as_ref()
            .and_then(|tokens| tokens.id_token.as_ref())
            .map(|token| token.expose().to_string())
    }

    /// The agent askcodex builds in production (`http_status_as_error(false)`).
    fn test_agent() -> ureq::Agent {
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_connect(Some(Duration::from_secs(config::CONNECT_TIMEOUT_SECS)))
            .build()
            .into()
    }

    // ---------------------------------------------------------------
    // jwt_exp
    // ---------------------------------------------------------------

    #[test]
    fn jwt_exp_decodes_unpadded_payload() {
        isolate_codex_home();
        // 1 byte of payload mod 3 => the base64 segment would need "==" if
        // it were padded; URL_SAFE_NO_PAD must decode it as-is.
        let token = jwt_with_payload(r#"{"exp":1799999999,"client_id":"app_x"}"#);
        assert_eq!(jwt_exp(&token).unwrap(), 1_799_999_999);
    }

    #[test]
    fn jwt_exp_accepts_negative_and_fractional_numeric_date() {
        isolate_codex_home();
        assert_eq!(jwt_exp(&jwt_expiring_at(-5)).unwrap(), -5);
        // RFC 7519 NumericDate may be non-integer.
        let token = jwt_with_payload(r#"{"exp":1700000000.75}"#);
        assert_eq!(jwt_exp(&token).unwrap(), 1_700_000_000);
    }

    #[test]
    fn jwt_exp_rejects_wrong_segment_count() {
        isolate_codex_home();
        for bad in ["", "onlyone", "two.parts", "a.b.c.d"] {
            let err = jwt_exp(&Secret::new(bad)).unwrap_err();
            assert!(
                matches!(&err, Error::JwtInvalid { reason } if reason.contains("3 dot-separated")),
                "unexpected error for {bad:?}: {err}"
            );
        }
    }

    #[test]
    fn jwt_exp_rejects_bad_base64() {
        isolate_codex_home();
        let err = jwt_exp(&Secret::new("aGVhZGVy.not base64!.c2ln")).unwrap_err();
        assert!(matches!(&err, Error::JwtInvalid { reason } if reason.contains("base64url")));
    }

    #[test]
    fn jwt_exp_rejects_padded_payload() {
        isolate_codex_home();
        // Codex/OpenAI JWTs are unpadded; a padded segment is malformed and
        // must be loud rather than silently re-padded.
        // 10 payload bytes => the padded encoding ends in "==".
        let padded = format!(
            "aGVhZGVy.{}.c2ln",
            base64::engine::general_purpose::URL_SAFE.encode(br#"{"exp":10}"#)
        );
        assert!(padded.contains('='));
        assert!(matches!(
            jwt_exp(&Secret::new(padded)).unwrap_err(),
            Error::JwtInvalid { .. }
        ));
    }

    #[test]
    fn jwt_exp_rejects_non_json_payload() {
        isolate_codex_home();
        let token = Secret::new(format!(
            "aGVhZGVy.{}.c2ln",
            URL_SAFE_NO_PAD.encode(b"not json at all")
        ));
        let err = jwt_exp(&token).unwrap_err();
        assert!(matches!(&err, Error::JwtInvalid { reason } if reason.contains("not JSON")));
    }

    #[test]
    fn jwt_exp_rejects_non_object_payload() {
        isolate_codex_home();
        let token = jwt_with_payload("[1,2,3]");
        let err = jwt_exp(&token).unwrap_err();
        assert!(matches!(&err, Error::JwtInvalid { reason } if reason.contains("JSON object")));
    }

    #[test]
    fn jwt_exp_rejects_missing_exp() {
        isolate_codex_home();
        let token = jwt_with_payload(r#"{"iat":1700000000}"#);
        let err = jwt_exp(&token).unwrap_err();
        assert!(matches!(&err, Error::JwtInvalid { reason } if reason.contains("`exp`")));
    }

    #[test]
    fn jwt_exp_rejects_non_numeric_exp() {
        isolate_codex_home();
        for claims in [
            r#"{"exp":"1700000000"}"#,
            r#"{"exp":null}"#,
            r#"{"exp":true}"#,
            r#"{"exp":{"seconds":1}}"#,
        ] {
            let err = jwt_exp(&jwt_with_payload(claims)).unwrap_err();
            assert!(
                matches!(&err, Error::JwtInvalid { reason } if reason.contains("not a number")),
                "unexpected error for {claims}: {err}"
            );
        }
    }

    #[test]
    fn jwt_errors_never_leak_the_token_value() {
        isolate_codex_home();
        let secret_material = "SUPERSECRETTOKENMATERIAL";
        let tokens = [
            format!("aGVhZGVy.{secret_material}!!!.c2ln"),
            format!("{secret_material}.{}.c2ln", URL_SAFE_NO_PAD.encode(b"[]")),
            secret_material.to_string(),
        ];
        for raw in tokens {
            let rendered = jwt_exp(&Secret::new(raw)).unwrap_err().to_string();
            assert!(
                !rendered.contains(secret_material),
                "error leaked token material: {rendered}"
            );
        }
    }

    // ---------------------------------------------------------------
    // needs_refresh
    // ---------------------------------------------------------------

    fn auth_with(access_exp: i64, last_refresh: Option<&str>) -> AuthFile {
        auth_with_access(&fake_jwt_expiring_at(access_exp), last_refresh)
    }

    /// A document whose access token is `access` verbatim — for the branch
    /// where `exp` cannot be read at all.
    fn auth_with_access(access: &str, last_refresh: Option<&str>) -> AuthFile {
        let last = match last_refresh {
            Some(value) => format!(r#","last_refresh":"{value}""#),
            None => String::new(),
        };
        parse_auth(&format!(
            r#"{{"tokens":{{"access_token":"{access}","account_id":"acct_test"}}{last}}}"#
        ))
    }

    #[test]
    fn needs_refresh_is_false_exactly_at_the_window_edge() {
        isolate_codex_home();
        let now = Utc::now();
        // exp - now == REFRESH_WINDOW_SECS -> NOT less than the window.
        let auth = auth_with(now.timestamp() + config::REFRESH_WINDOW_SECS, None);
        assert!(!needs_refresh(&auth, now).unwrap());
    }

    #[test]
    fn needs_refresh_is_true_one_second_inside_the_window() {
        isolate_codex_home();
        let now = Utc::now();
        let auth = auth_with(now.timestamp() + config::REFRESH_WINDOW_SECS - 1, None);
        assert!(needs_refresh(&auth, now).unwrap());
    }

    #[test]
    fn needs_refresh_is_true_for_an_expired_token() {
        isolate_codex_home();
        let now = Utc::now();
        let auth = auth_with(now.timestamp() - 1, None);
        assert!(needs_refresh(&auth, now).unwrap());
    }

    #[test]
    fn needs_refresh_does_not_overflow_on_absurd_exp() {
        isolate_codex_home();
        let now = Utc::now();
        let auth = auth_with(i64::MAX, None);
        assert!(!needs_refresh(&auth, now).unwrap());
        let auth = auth_with(i64::MIN, None);
        assert!(needs_refresh(&auth, now).unwrap());
    }

    #[test]
    fn needs_refresh_skips_the_age_rule_when_last_refresh_is_absent() {
        isolate_codex_home();
        let now = Utc::now();
        let auth = auth_with(now.timestamp() + 3600, None);
        assert!(auth.last_refresh.is_none());
        assert!(!needs_refresh(&auth, now).unwrap());
    }

    #[test]
    fn needs_refresh_age_rule_boundaries_when_exp_is_unreadable() {
        isolate_codex_home();
        let now = Utc::now();

        let just_inside =
            now - chrono::Duration::seconds(config::REFRESH_MAX_AGE_DAYS * SECS_PER_DAY);
        let auth = auth_with_access("not-a-jwt", Some(&models::format_last_refresh(just_inside)));
        assert!(
            !needs_refresh(&auth, now).unwrap(),
            "exactly REFRESH_MAX_AGE_DAYS old is not yet stale"
        );

        let just_outside = just_inside - chrono::Duration::seconds(2);
        let auth = auth_with_access(
            "not-a-jwt",
            Some(&models::format_last_refresh(just_outside)),
        );
        assert!(needs_refresh(&auth, now).unwrap());
    }

    #[test]
    fn needs_refresh_ignores_last_refresh_while_exp_is_readable() {
        // codex's rule (docs/PROTOCOL.md §6) consults `last_refresh` ONLY
        // when it cannot read `exp`. A token that is valid for another hour
        // but has not been used for nine days must not be rotated: that
        // mutates the user's real credentials for no reason, and it is the
        // state that makes concurrent rotation reachable at all.
        isolate_codex_home();
        let now = Utc::now();
        let ancient = models::format_last_refresh(now - chrono::Duration::days(9));
        assert!(!needs_refresh(&auth_with(now.timestamp() + 3600, Some(&ancient)), now).unwrap());
        // The expiry rule still fires, ancient timestamp or not.
        assert!(needs_refresh(&auth_with(now.timestamp() + 10, Some(&ancient)), now).unwrap());
    }

    #[test]
    fn needs_refresh_does_not_brick_every_command_over_an_unparseable_last_refresh() {
        // `needs_refresh` is the first thing every backend command calls.
        // Failing here on a field the decision does not even depend on took
        // `whoami`, `usage`, `models`, `ask` and `image` down together —
        // for a user whose access token was perfectly valid. The first
        // string below is codex's own format minus the UTC offset.
        isolate_codex_home();
        let now = Utc::now();
        for raw in ["2026-08-07T23:32:41.615755", "last tuesday", ""] {
            assert!(
                !needs_refresh(&auth_with(now.timestamp() + 3600, Some(raw)), now).unwrap(),
                "a valid access token was rejected over last_refresh={raw:?}"
            );
        }
    }

    #[test]
    fn needs_refresh_is_loud_when_the_fallback_signal_is_corrupt() {
        // The other side of the rule: in the branch that DOES depend on
        // `last_refresh`, corruption must surface rather than be guessed at.
        isolate_codex_home();
        let now = Utc::now();
        let err =
            needs_refresh(&auth_with_access("not-a-jwt", Some("last tuesday")), now).unwrap_err();
        assert!(
            matches!(&err, Error::UnexpectedResponse { context } if context.contains("last_refresh")),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn needs_refresh_propagates_jwt_errors_when_there_is_no_other_signal() {
        // Neither a readable expiry nor a timestamp: nothing to decide on,
        // so the decode error is the answer (deliberate divergence from
        // codex, which would treat this as "no refresh needed").
        isolate_codex_home();
        let auth = parse_auth(r#"{"tokens":{"access_token":"not-a-jwt","account_id":"a"}}"#);
        assert!(matches!(
            needs_refresh(&auth, Utc::now()).unwrap_err(),
            Error::JwtInvalid { .. }
        ));
    }

    #[test]
    fn needs_refresh_is_loud_without_an_access_token() {
        isolate_codex_home();
        let auth = parse_auth(r#"{"tokens":{"account_id":"a"}}"#);
        let err = needs_refresh(&auth, Utc::now()).unwrap_err();
        assert!(
            matches!(&err, Error::UnexpectedResponse { context } if context.contains("access_token")),
            "unexpected error: {err}"
        );
    }

    // ---------------------------------------------------------------
    // load_auth
    // ---------------------------------------------------------------

    #[test]
    fn load_auth_reads_a_valid_file_and_keeps_unknown_keys() {
        let dir = TempDir::new("load-ok");
        let raw = auth_json(1_800_000_000);
        fs::write(dir.auth(), &raw).unwrap();

        let auth = load_auth_from(&dir.auth()).unwrap();
        assert_eq!(auth.auth_mode.as_deref(), Some("chatgpt"));
        assert_eq!(refresh_token_of(&auth), "old-refresh-token");
        assert_eq!(
            auth.extra.get("unknown_top_level").unwrap(),
            &serde_json::json!({"nested": [1, 2, 3]})
        );
        // Round-trip is value-identical, unknown keys included.
        let before: Value = serde_json::from_str(&raw).unwrap();
        let after: Value = serde_json::from_str(&serde_json::to_string(&auth).unwrap()).unwrap();
        assert_eq!(before, after);
    }

    #[test]
    fn load_auth_missing_file_is_auth_file_missing() {
        let dir = TempDir::new("load-missing");
        let err = load_auth_from(&dir.auth()).unwrap_err();
        assert!(matches!(err, Error::AuthFileMissing { .. }));
        assert!(err.to_string().contains("codex login"));
    }

    #[test]
    fn load_auth_unreadable_file_is_auth_file_unreadable() {
        let dir = TempDir::new("load-unreadable");
        // A directory where the file should be: readable path, unreadable
        // as a file (EISDIR) — distinct from "missing".
        fs::create_dir(dir.auth()).unwrap();
        assert!(matches!(
            load_auth_from(&dir.auth()).unwrap_err(),
            Error::AuthFileUnreadable { .. }
        ));
    }

    #[test]
    fn load_auth_invalid_json_is_auth_file_invalid() {
        let dir = TempDir::new("load-invalid");
        fs::write(dir.auth(), "{not json").unwrap();
        assert!(matches!(
            load_auth_from(&dir.auth()).unwrap_err(),
            Error::AuthFileInvalid { .. }
        ));
    }

    #[test]
    fn load_auth_missing_or_empty_tokens_is_the_keyring_message() {
        let dir = TempDir::new("load-tokens");
        for document in [
            r#"{"auth_mode":"chatgpt"}"#,
            r#"{"tokens":null}"#,
            r#"{"tokens":{"account_id":"a"}}"#,
            r#"{"tokens":{"access_token":"","account_id":"a"}}"#,
        ] {
            fs::write(dir.auth(), document).unwrap();
            let err = load_auth_from(&dir.auth()).unwrap_err();
            assert!(
                matches!(err, Error::AuthTokensMissing { .. }),
                "unexpected error for {document}: {err}"
            );
            assert!(err.to_string().contains("keyring"));
        }
    }

    #[test]
    fn load_auth_missing_account_id_is_loud() {
        let dir = TempDir::new("load-account");
        for document in [
            r#"{"tokens":{"access_token":"a.b.c"}}"#,
            r#"{"tokens":{"access_token":"a.b.c","account_id":""}}"#,
        ] {
            fs::write(dir.auth(), document).unwrap();
            assert!(
                matches!(
                    load_auth_from(&dir.auth()).unwrap_err(),
                    Error::AuthAccountIdMissing { .. }
                ),
                "unexpected error for {document}"
            );
        }
    }

    #[test]
    fn load_auth_never_writes() {
        let dir = TempDir::new("load-readonly");
        fs::write(dir.auth(), auth_json(1_800_000_000)).unwrap();
        let before = fs::read(dir.auth()).unwrap();
        let modified = fs::metadata(dir.auth()).unwrap().modified().unwrap();

        load_auth_from(&dir.auth()).unwrap();

        assert_eq!(fs::read(dir.auth()).unwrap(), before);
        assert_eq!(
            fs::metadata(dir.auth()).unwrap().modified().unwrap(),
            modified
        );
        assert_eq!(dir.entries(), vec!["auth.json".to_string()]);
    }

    // ---------------------------------------------------------------
    // persist_atomic
    // ---------------------------------------------------------------

    #[test]
    fn persist_writes_pretty_json_with_trailing_newline_and_keeps_unknown_keys() {
        let dir = TempDir::new("persist-roundtrip");
        let raw = auth_json(1_800_000_000);
        fs::write(dir.auth(), &raw).unwrap();
        let auth = load_auth_from(&dir.auth()).unwrap();

        persist_atomic_to(&auth, &dir.auth()).unwrap();

        let written = fs::read_to_string(dir.auth()).unwrap();
        assert!(written.ends_with("}\n"), "missing trailing newline");
        assert!(written.contains("\n  \"tokens\""), "not pretty-printed");
        let before: Value = serde_json::from_str(&raw).unwrap();
        let after: Value = serde_json::from_str(&written).unwrap();
        assert_eq!(before, after, "unknown keys must round-trip");
    }

    #[test]
    fn persist_result_is_0600_and_backs_up_the_previous_document() {
        let dir = TempDir::new("persist-mode");
        let original = auth_json(1_800_000_000);
        fs::write(dir.auth(), &original).unwrap();
        // Deliberately loosen the original: the rewrite must not inherit it.
        fs::set_permissions(dir.auth(), fs::Permissions::from_mode(0o644)).unwrap();

        let mut auth = load_auth_from(&dir.auth()).unwrap();
        auth.last_refresh = Some("2026-08-08T00:00:00.000001Z".to_string());
        persist_atomic_to(&auth, &dir.auth()).unwrap();

        assert_eq!(mode_of(&dir.auth()), 0o600);
        assert_eq!(mode_of(&dir.join("auth.json.bak")), 0o600);

        let backup: Value =
            serde_json::from_str(&fs::read_to_string(dir.join("auth.json.bak")).unwrap()).unwrap();
        assert_eq!(backup, serde_json::from_str::<Value>(&original).unwrap());

        let current: Value =
            serde_json::from_str(&fs::read_to_string(dir.auth()).unwrap()).unwrap();
        assert_eq!(current["last_refresh"], "2026-08-08T00:00:00.000001Z");

        assert_eq!(
            dir.entries(),
            vec!["auth.json".to_string(), "auth.json.bak".to_string()]
        );
    }

    #[test]
    fn persist_without_an_existing_file_creates_no_backup() {
        let dir = TempDir::new("persist-fresh");
        let auth = parse_auth(r#"{"tokens":{"access_token":"a.b.c","account_id":"acct"}}"#);

        persist_atomic_to(&auth, &dir.auth()).unwrap();

        assert_eq!(dir.entries(), vec!["auth.json".to_string()]);
        assert_eq!(mode_of(&dir.auth()), 0o600);
    }

    #[test]
    fn persist_failure_to_create_the_temp_leaves_the_original_intact() {
        let dir = TempDir::new("persist-nodir");
        let target = dir.join("missing-subdir").join("auth.json");
        let auth = parse_auth(r#"{"tokens":{"access_token":"a.b.c","account_id":"acct"}}"#);

        let err = persist_atomic_to(&auth, &target).unwrap_err();
        match &err {
            Error::PersistFailed { path, backup, .. } => {
                assert_eq!(path, &target);
                // No backup was taken (there was no previous document to
                // back up), so the error must not name one at all. Naming
                // a path the user could go read, when nothing was written
                // there, is the failure-masking answer.
                assert_eq!(backup, &None);
            }
            other => panic!("unexpected error: {other}"),
        }
        let rendered = err.to_string();
        assert!(rendered.contains("CRITICAL"));
        assert!(!rendered.contains(".bak"), "{rendered}");
        assert!(
            rendered.contains("was not modified and still holds the previous tokens"),
            "the no-backup message must say where the previous tokens are: {rendered}"
        );
        assert!(dir.entries().is_empty());
    }

    #[test]
    fn persist_aborts_when_the_backup_cannot_be_written() {
        let dir = TempDir::new("persist-backup-fail");
        let original = auth_json(1_800_000_000);
        fs::write(dir.auth(), &original).unwrap();
        // A directory at auth.json.bak makes `fs::copy` fail.
        fs::create_dir(dir.join("auth.json.bak")).unwrap();

        let mut auth = load_auth_from(&dir.auth()).unwrap();
        auth.last_refresh = Some("2030-01-01T00:00:00.000000Z".to_string());

        let err = persist_atomic_to(&auth, &dir.auth()).unwrap_err();
        assert!(matches!(err, Error::PersistFailed { .. }), "got {err}");

        // Postcondition: the original document is byte-identical and no
        // temp file survived.
        assert_eq!(fs::read_to_string(dir.auth()).unwrap(), original);
        assert_eq!(
            dir.entries(),
            vec!["auth.json".to_string(), "auth.json.bak".to_string()]
        );
        assert!(dir.entries().iter().all(|name| !name.contains(".tmp.")));
    }

    #[test]
    fn persist_fails_loudly_when_a_stale_temp_file_exists() {
        // O_EXCL: askcodex refuses to overwrite a temp it did not create, and
        // must not delete it either (it may belong to another process).
        let dir = TempDir::new("persist-excl");
        let original = auth_json(1_800_000_000);
        fs::write(dir.auth(), &original).unwrap();
        let stale = dir.join(&format!("auth.json.tmp.{}", std::process::id()));
        fs::write(&stale, "stale").unwrap();

        let auth = load_auth_from(&dir.auth()).unwrap();
        assert!(matches!(
            persist_atomic_to(&auth, &dir.auth()).unwrap_err(),
            Error::PersistFailed { .. }
        ));
        assert_eq!(fs::read_to_string(&stale).unwrap(), "stale");
        assert_eq!(fs::read_to_string(dir.auth()).unwrap(), original);
    }

    // ---------------------------------------------------------------
    // refresh
    // ---------------------------------------------------------------

    #[test]
    fn refresh_without_a_refresh_token_makes_no_request() {
        let dir = TempDir::new("refresh-unavailable");
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.any_request();
            then.status(200).body("{}");
        });

        for document in [
            r#"{"tokens":{"access_token":"a.b.c","account_id":"acct"}}"#,
            r#"{"tokens":{"access_token":"a.b.c","refresh_token":"","account_id":"acct"}}"#,
        ] {
            let mut auth = parse_auth(document);
            let err = refresh_inner(
                &test_agent(),
                &mut auth,
                &server.url("/oauth/token"),
                &dir.auth(),
            )
            .unwrap_err();
            assert!(matches!(err, Error::RefreshUnavailable), "got {err}");
        }
        assert_eq!(mock.calls(), 0);
        assert!(dir.entries().is_empty());
    }

    #[test]
    fn refresh_sends_the_codex_wire_shape_and_no_backend_headers() {
        let dir = TempDir::new("refresh-wire");
        fs::write(dir.auth(), auth_json(1_800_000_000)).unwrap();
        let mut auth = load_auth_from(&dir.auth()).unwrap();

        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(POST)
                .path("/oauth/token")
                .header("content-type", "application/json; charset=utf-8")
                .header("user-agent", config::USER_AGENT)
                .header_missing("authorization")
                .header_missing("chatgpt-account-id")
                .json_body(serde_json::json!({
                    "client_id": config::CLIENT_ID,
                    "grant_type": "refresh_token",
                    "refresh_token": "old-refresh-token",
                }));
            then.status(200)
                .header("content-type", "application/json")
                .body(r#"{"access_token":"new.access.token"}"#);
        });

        refresh_inner(
            &test_agent(),
            &mut auth,
            &server.url("/oauth/token"),
            &dir.auth(),
        )
        .unwrap();

        mock.assert_calls(1);
    }

    #[test]
    fn refresh_rotates_all_present_fields_and_persists() {
        let dir = TempDir::new("refresh-ok");
        let original = auth_json(1_700_000_000);
        fs::write(dir.auth(), &original).unwrap();
        let mut auth = load_auth_from(&dir.auth()).unwrap();

        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/oauth/token");
            then.status(200).body(
                r#"{"access_token":"new.access.token","id_token":"new.id.token",
                    "refresh_token":"new-refresh-token","expires_in":864000}"#,
            );
        });

        // One second of slack on both sides: `format_last_refresh` truncates
        // to microseconds, so an exact `>=` on the raw clock is fragile.
        let before = Utc::now() - chrono::Duration::seconds(1);
        refresh_inner(
            &test_agent(),
            &mut auth,
            &server.url("/oauth/token"),
            &dir.auth(),
        )
        .unwrap();

        // In memory.
        assert_eq!(access_token_of(&auth), "new.access.token");
        assert_eq!(id_token_of(&auth).as_deref(), Some("new.id.token"));
        assert_eq!(refresh_token_of(&auth), "new-refresh-token");
        let stamp = auth.last_refresh.clone().expect("last_refresh set");
        let parsed = models::parse_last_refresh(&stamp).expect("codex-format timestamp");
        assert_eq!(
            models::format_last_refresh(parsed),
            stamp,
            "byte-exact format"
        );
        assert!(parsed >= before && parsed <= Utc::now() + chrono::Duration::seconds(1));

        // On disk: same document, 0600, backup holds the previous one.
        let written: Value =
            serde_json::from_str(&fs::read_to_string(dir.auth()).unwrap()).unwrap();
        assert_eq!(written["tokens"]["access_token"], "new.access.token");
        assert_eq!(written["tokens"]["refresh_token"], "new-refresh-token");
        assert_eq!(
            written["unknown_top_level"],
            serde_json::json!({"nested": [1, 2, 3]})
        );
        assert_eq!(written["tokens"]["unknown_token_key"], 7);
        assert_eq!(mode_of(&dir.auth()), 0o600);
        let backup: Value =
            serde_json::from_str(&fs::read_to_string(dir.join("auth.json.bak")).unwrap()).unwrap();
        assert_eq!(backup, serde_json::from_str::<Value>(&original).unwrap());
    }

    #[test]
    fn refresh_keeps_the_old_refresh_token_when_the_response_omits_it() {
        let dir = TempDir::new("refresh-keep-rt");
        fs::write(dir.auth(), auth_json(1_700_000_000)).unwrap();
        let mut auth = load_auth_from(&dir.auth()).unwrap();
        let old_id = id_token_of(&auth).unwrap();

        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/oauth/token");
            // Empty strings must be treated as "not rotated", never as a
            // reason to clear a working credential.
            then.status(200)
                .body(r#"{"access_token":"new.access.token","refresh_token":"","id_token":""}"#);
        });

        refresh_inner(
            &test_agent(),
            &mut auth,
            &server.url("/oauth/token"),
            &dir.auth(),
        )
        .unwrap();

        assert_eq!(refresh_token_of(&auth), "old-refresh-token");
        assert_eq!(id_token_of(&auth), Some(old_id));
        let written: Value =
            serde_json::from_str(&fs::read_to_string(dir.auth()).unwrap()).unwrap();
        assert_eq!(written["tokens"]["refresh_token"], "old-refresh-token");
    }

    #[test]
    fn refresh_non_200_leaves_memory_and_file_untouched() {
        let dir = TempDir::new("refresh-400");
        let original = auth_json(1_700_000_000);
        fs::write(dir.auth(), &original).unwrap();
        let mut auth = load_auth_from(&dir.auth()).unwrap();
        let before = format!("{auth:?}");

        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/oauth/token");
            then.status(400)
                .body(r#"{"error":"invalid_grant","error_description":"refresh_token_expired"}"#);
        });

        let err = refresh_inner(
            &test_agent(),
            &mut auth,
            &server.url("/oauth/token"),
            &dir.auth(),
        )
        .unwrap_err();

        match &err {
            Error::RefreshFailed { status, snippet } => {
                assert_eq!(*status, 400);
                assert!(snippet.contains("refresh_token_expired"), "got {snippet}");
            }
            other => panic!("unexpected error: {other}"),
        }
        assert_eq!(
            format!("{auth:?}"),
            before,
            "in-memory tokens must not change"
        );
        assert_eq!(fs::read_to_string(dir.auth()).unwrap(), original);
        assert_eq!(dir.entries(), vec!["auth.json".to_string()]);
    }

    #[test]
    fn refresh_non_200_works_on_a_default_agent_too() {
        // The per-request `http_status_as_error(false)` override means a
        // caller-supplied default agent still yields the status + body,
        // not an opaque ureq StatusCode error.
        let dir = TempDir::new("refresh-default-agent");
        fs::write(dir.auth(), auth_json(1_700_000_000)).unwrap();
        let mut auth = load_auth_from(&dir.auth()).unwrap();

        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/oauth/token");
            then.status(403).body("forbidden");
        });

        let err = refresh_inner(
            &ureq::Agent::new_with_defaults(),
            &mut auth,
            &server.url("/oauth/token"),
            &dir.auth(),
        )
        .unwrap_err();
        assert!(
            matches!(&err, Error::RefreshFailed { status: 403, snippet } if snippet == "forbidden"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn refresh_error_snippet_is_bounded_and_utf8_safe() {
        let dir = TempDir::new("refresh-snippet");
        fs::write(dir.auth(), auth_json(1_700_000_000)).unwrap();
        let mut auth = load_auth_from(&dir.auth()).unwrap();

        // Multibyte characters straddling the truncation point.
        let body = "é".repeat(config::ERROR_SNIPPET_BYTES);
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/oauth/token");
            then.status(500).body(body.clone());
        });

        let err = refresh_inner(
            &test_agent(),
            &mut auth,
            &server.url("/oauth/token"),
            &dir.auth(),
        )
        .unwrap_err();
        match &err {
            Error::RefreshFailed { status, snippet } => {
                assert_eq!(*status, 500);
                assert!(
                    snippet.len() <= config::ERROR_SNIPPET_BYTES,
                    "{}",
                    snippet.len()
                );
                assert!(body.starts_with(snippet.as_str()));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn refresh_200_without_access_token_reports_key_names_only() {
        let dir = TempDir::new("refresh-nokey");
        let original = auth_json(1_700_000_000);
        fs::write(dir.auth(), &original).unwrap();
        let mut auth = load_auth_from(&dir.auth()).unwrap();

        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/oauth/token");
            then.status(200)
                .body(r#"{"error":"server_error","id_token":"leaked.id.token","expires_in":10}"#);
        });

        let err = refresh_inner(
            &test_agent(),
            &mut auth,
            &server.url("/oauth/token"),
            &dir.auth(),
        )
        .unwrap_err();

        match &err {
            Error::RefreshInvalidResponse { keys } => {
                assert_eq!(keys, &["error", "expires_in", "id_token"]);
            }
            other => panic!("unexpected error: {other}"),
        }
        // Key NAMES only: no value from the 200 body may be rendered.
        let rendered = err.to_string();
        assert!(!rendered.contains("leaked.id.token"), "{rendered}");
        assert!(!rendered.contains("server_error"), "{rendered}");
        assert_eq!(fs::read_to_string(dir.auth()).unwrap(), original);
    }

    #[test]
    fn refresh_200_with_empty_access_token_is_rejected() {
        let dir = TempDir::new("refresh-empty");
        fs::write(dir.auth(), auth_json(1_700_000_000)).unwrap();
        let mut auth = load_auth_from(&dir.auth()).unwrap();

        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/oauth/token");
            then.status(200).body(r#"{"access_token":""}"#);
        });

        assert!(matches!(
            refresh_inner(
                &test_agent(),
                &mut auth,
                &server.url("/oauth/token"),
                &dir.auth()
            )
            .unwrap_err(),
            Error::RefreshInvalidResponse { .. }
        ));
        assert_eq!(access_token_of(&auth), fake_jwt_expiring_at(1_700_000_000));
    }

    #[test]
    fn refresh_200_with_a_non_json_body_never_quotes_it() {
        let dir = TempDir::new("refresh-nonjson");
        fs::write(dir.auth(), auth_json(1_700_000_000)).unwrap();
        let mut auth = load_auth_from(&dir.auth()).unwrap();

        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/oauth/token");
            then.status(200).body("access_token=live-token-material");
        });

        let err = refresh_inner(
            &test_agent(),
            &mut auth,
            &server.url("/oauth/token"),
            &dir.auth(),
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(
            matches!(err, Error::UnexpectedResponse { .. }),
            "{rendered}"
        );
        assert!(!rendered.contains("live-token-material"), "{rendered}");
    }

    #[test]
    fn refresh_200_with_a_json_array_body_is_loud() {
        let dir = TempDir::new("refresh-array");
        fs::write(dir.auth(), auth_json(1_700_000_000)).unwrap();
        let mut auth = load_auth_from(&dir.auth()).unwrap();

        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/oauth/token");
            then.status(200).body(r#"["nope"]"#);
        });

        assert!(matches!(
            refresh_inner(
                &test_agent(),
                &mut auth,
                &server.url("/oauth/token"),
                &dir.auth()
            )
            .unwrap_err(),
            Error::UnexpectedResponse { .. }
        ));
    }

    #[test]
    fn refresh_propagates_persist_failure_after_rotation() {
        let dir = TempDir::new("refresh-persist-fail");
        let original = auth_json(1_700_000_000);
        fs::write(dir.auth(), &original).unwrap();
        let mut auth = load_auth_from(&dir.auth()).unwrap();
        // A leftover temp file from an earlier run of THIS process: the
        // persist gets as far as the backup and then trips O_EXCL. (An
        // unwritable directory would now abort before the token is sent —
        // the lock cannot be taken there — which is the better outcome but
        // not the state this test is about.)
        let stale = dir.join(&format!("auth.json.tmp.{}", std::process::id()));
        fs::write(&stale, "stale").unwrap();

        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/oauth/token");
            then.status(200)
                .body(r#"{"access_token":"new.access.token","refresh_token":"new-refresh-token"}"#);
        });

        let err = refresh_inner(
            &test_agent(),
            &mut auth,
            &server.url("/oauth/token"),
            &dir.auth(),
        )
        .unwrap_err();

        assert!(matches!(err, Error::PersistFailed { .. }), "got {err}");
        let rendered = err.to_string();
        assert!(rendered.contains("CRITICAL"));
        assert!(!rendered.contains("new-refresh-token"), "{rendered}");
        // The rotation DID happen in memory; the caller must not retry.
        assert_eq!(access_token_of(&auth), "new.access.token");

        // The backup the message points at is not a claim: it exists, and
        // it holds the document that was on disk when this call started —
        // not a leftover from some earlier refresh.
        let Error::PersistFailed {
            backup: Some(backup),
            ..
        } = &err
        else {
            panic!("a backup was written, so the error must name it: {err}")
        };
        assert_eq!(backup, &dir.join("auth.json.bak"));
        assert!(rendered.contains("auth.json.bak"));
        assert!(backup.exists(), "the named backup does not exist");
        assert_eq!(fs::read_to_string(backup).unwrap(), original);
        assert_eq!(mode_of(backup), 0o600);
    }

    // ---------------------------------------------------------------
    // The credential lock (cross-process rotation safety)
    // ---------------------------------------------------------------

    /// The document a mock rotation hands back, with a far-future expiry so
    /// that a process adopting it can see that it is fresh.
    fn rotated_body(refresh: &str) -> String {
        format!(
            r#"{{"access_token":"{}","refresh_token":"{refresh}"}}"#,
            fake_jwt_expiring_at(4_102_444_800)
        )
    }

    #[test]
    fn a_concurrent_rotation_is_adopted_instead_of_spending_the_stale_token() {
        // THE lost-update case. Two askcodex processes load the same document,
        // both decide a refresh is due. The first rotates GEN1 -> GEN2 and
        // persists. The second still holds GEN1 in memory: without the lock
        // and the re-read it POSTs GEN1 a second time (the identical token
        // the server has just retired — PROTOCOL.md §6 calls that reuse a
        // permanent, re-login-only failure) and then writes ITS snapshot
        // over the file, so whichever process finishes last decides which
        // generation survives.
        let dir = TempDir::new("refresh-concurrent");
        fs::write(dir.auth(), auth_json(1_700_000_000)).unwrap();
        let mut first = load_auth_from(&dir.auth()).unwrap();
        let mut second = load_auth_from(&dir.auth()).unwrap();
        assert_eq!(refresh_token_of(&second), "old-refresh-token");

        let server = MockServer::start();
        // Matching on the token proves WHICH generation was sent.
        let gen1 = server.mock(|when, then| {
            when.method(POST)
                .path("/oauth/token")
                .json_body(serde_json::json!({
                    "client_id": config::CLIENT_ID,
                    "grant_type": "refresh_token",
                    "refresh_token": "old-refresh-token",
                }));
            then.status(200).body(rotated_body("refresh-GEN2"));
        });

        refresh_inner(
            &test_agent(),
            &mut first,
            &server.url("/oauth/token"),
            &dir.auth(),
        )
        .unwrap();
        gen1.assert_calls(1);

        // The second process, still a generation behind, now refreshes.
        refresh_inner(
            &test_agent(),
            &mut second,
            &server.url("/oauth/token"),
            &dir.auth(),
        )
        .unwrap();

        gen1.assert_calls(1);
        assert_eq!(
            refresh_token_of(&second),
            "refresh-GEN2",
            "the lagging process kept its own spent generation"
        );
        let written: Value =
            serde_json::from_str(&fs::read_to_string(dir.auth()).unwrap()).unwrap();
        assert_eq!(
            written["tokens"]["refresh_token"], "refresh-GEN2",
            "auth.json was overwritten with a retired generation"
        );
        // And nothing was left lying around.
        assert_eq!(
            dir.entries(),
            vec!["auth.json".to_string(), "auth.json.bak".to_string()]
        );
    }

    #[test]
    fn a_refresh_blocked_by_another_process_never_sends_the_token() {
        let dir = TempDir::new("refresh-locked-out");
        let original = auth_json(1_700_000_000);
        fs::write(dir.auth(), &original).unwrap();
        let mut auth = load_auth_from(&dir.auth()).unwrap();

        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.any_request();
            then.status(200).body(rotated_body("nope"));
        });

        // A lock held by some other, live process.
        let lock = dir.join("auth.json.lock");
        fs::write(&lock, "999999\n").unwrap();

        let err = refresh_locked(
            &test_agent(),
            &mut auth,
            &server.url("/oauth/token"),
            &dir.auth(),
            Duration::from_millis(80),
        )
        .unwrap_err();

        match &err {
            Error::AuthLockUnavailable { path, .. } => assert_eq!(path, &lock),
            other => panic!("unexpected error: {other}"),
        }
        // Loud, actionable, and nothing was spent or touched.
        let rendered = err.to_string();
        assert!(rendered.contains("auth.json.lock"), "{rendered}");
        assert!(rendered.contains("lock file"), "{rendered}");
        assert_eq!(mock.calls(), 0);
        assert_eq!(fs::read_to_string(dir.auth()).unwrap(), original);
        assert_eq!(
            fs::read_to_string(&lock).unwrap(),
            "999999\n",
            "askcodex deleted a lock it did not own"
        );
    }

    #[test]
    fn a_lock_left_by_a_crashed_process_is_reclaimed_and_released() {
        // A stale lock must never make askcodex permanently unusable.
        let dir = TempDir::new("refresh-stale-lock");
        fs::write(dir.auth(), auth_json(1_700_000_000)).unwrap();
        let mut auth = load_auth_from(&dir.auth()).unwrap();

        let lock = dir.join("auth.json.lock");
        fs::write(&lock, "999999\n").unwrap();
        fs::File::options()
            .write(true)
            .open(&lock)
            .unwrap()
            .set_modified(SystemTime::now() - LOCK_STALE - Duration::from_secs(60))
            .unwrap();

        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(POST).path("/oauth/token");
            then.status(200).body(rotated_body("refresh-after-crash"));
        });

        refresh_locked(
            &test_agent(),
            &mut auth,
            &server.url("/oauth/token"),
            &dir.auth(),
            Duration::from_millis(80),
        )
        .unwrap();

        mock.assert_calls(1);
        assert_eq!(refresh_token_of(&auth), "refresh-after-crash");
        // Released on the way out: no lock file survives a completed run.
        assert_eq!(
            dir.entries(),
            vec!["auth.json".to_string(), "auth.json.bak".to_string()]
        );
    }

    #[test]
    fn the_lock_is_released_even_when_the_refresh_fails() {
        let dir = TempDir::new("refresh-lock-release");
        fs::write(dir.auth(), auth_json(1_700_000_000)).unwrap();
        let mut auth = load_auth_from(&dir.auth()).unwrap();

        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/oauth/token");
            then.status(400).body("nope");
        });

        refresh_inner(
            &test_agent(),
            &mut auth,
            &server.url("/oauth/token"),
            &dir.auth(),
        )
        .unwrap_err();

        assert_eq!(dir.entries(), vec!["auth.json".to_string()]);
    }

    // ---------------------------------------------------------------
    // Backup and symlink handling
    // ---------------------------------------------------------------

    #[test]
    fn the_backup_is_a_new_0600_file_never_a_looser_one_rewritten_in_place() {
        // `fs::copy` onto an existing backup keeps that file's inode AND
        // its mode until a following chmod — the chmod-after-write window
        // this module forbids for the temp file, on a file holding the
        // very same credentials. The backup must therefore be a file
        // created 0600, not a rewritten one.
        let dir = TempDir::new("persist-backup-mode");
        fs::write(dir.auth(), auth_json(1_800_000_000)).unwrap();
        fs::set_permissions(dir.auth(), fs::Permissions::from_mode(0o644)).unwrap();
        let backup = dir.join("auth.json.bak");
        fs::write(&backup, "previous backup").unwrap();
        fs::set_permissions(&backup, fs::Permissions::from_mode(0o644)).unwrap();
        let before = inode_of(&backup);

        let auth = load_auth_from(&dir.auth()).unwrap();
        persist_atomic_to(&auth, &dir.auth()).unwrap();

        assert_ne!(
            inode_of(&backup),
            before,
            "the backup was rewritten in place, so it existed with the source's mode"
        );
        assert_eq!(mode_of(&backup), 0o600);
    }

    #[test]
    fn a_symlinked_auth_json_keeps_pointing_at_the_users_real_file() {
        // rename(2) replaces the LINK, so the user's canonical store would
        // silently stop receiving updates and freeze at a dead generation.
        let dir = TempDir::new("persist-symlink");
        let store = dir.join("real-store");
        fs::create_dir(&store).unwrap();
        let real = store.join("codex-auth.json");
        fs::write(&real, auth_json(1_800_000_000)).unwrap();
        std::os::unix::fs::symlink(&real, dir.auth()).unwrap();

        let mut auth = load_auth_from(&dir.auth()).unwrap();
        auth.last_refresh = Some("2030-01-01T00:00:00.000000Z".to_string());
        persist_atomic_to(&auth, &dir.auth()).unwrap();

        assert!(
            fs::symlink_metadata(dir.auth())
                .unwrap()
                .file_type()
                .is_symlink(),
            "askcodex replaced the symlink with a regular file"
        );
        let written: Value = serde_json::from_str(&fs::read_to_string(&real).unwrap()).unwrap();
        assert_eq!(written["last_refresh"], "2030-01-01T00:00:00.000000Z");
        assert_eq!(mode_of(&real), 0o600);
        // Backup and temp live beside the REAL file (same filesystem as the
        // rename target), not beside the link.
        assert!(store.join("codex-auth.json.bak").exists());
        assert_eq!(
            dir.entries(),
            vec!["auth.json".to_string(), "real-store".to_string()]
        );
    }

    #[test]
    fn a_dangling_symlink_is_loud_and_creates_nothing() {
        let dir = TempDir::new("persist-dangling");
        std::os::unix::fs::symlink(dir.join("nowhere.json"), dir.auth()).unwrap();
        let auth = parse_auth(r#"{"tokens":{"access_token":"a.b.c","account_id":"acct"}}"#);

        assert!(matches!(
            persist_atomic_to(&auth, &dir.auth()).unwrap_err(),
            Error::PersistFailed { .. }
        ));
        assert_eq!(dir.entries(), vec!["auth.json".to_string()]);
    }

    // ---------------------------------------------------------------
    // Refresh-error snippets carry no credential
    // ---------------------------------------------------------------

    #[test]
    fn a_refresh_error_body_that_echoes_a_token_is_scrubbed_before_it_is_quoted() {
        // The OAuth error body is a string from a third party that nobody
        // in this project has ever observed, and PROTOCOL.md §6 documents a
        // `refresh_token_reused` failure — so a body that names the token
        // is exactly the shape that cannot be ruled out. The guarantee has
        // to hold on code, not on an assumption about someone else's
        // server.
        let dir = TempDir::new("refresh-scrub");
        fs::write(dir.auth(), auth_json(1_700_000_000)).unwrap();
        let mut auth = load_auth_from(&dir.auth()).unwrap();
        let access = access_token_of(&auth);
        let id = id_token_of(&auth).unwrap();

        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/oauth/token");
            then.status(400).body(format!(
                r#"{{"error":"invalid_grant","error_description":"refresh_token old-refresh-token was reused","seen":["{access}","{id}"]}}"#
            ));
        });

        let err = refresh_inner(
            &test_agent(),
            &mut auth,
            &server.url("/oauth/token"),
            &dir.auth(),
        )
        .unwrap_err();

        let rendered = err.to_string();
        assert!(matches!(err, Error::RefreshFailed { status: 400, .. }));
        for (name, secret) in [
            ("refresh_token", "old-refresh-token"),
            ("access_token", access.as_str()),
            ("id_token", id.as_str()),
        ] {
            assert!(
                !rendered.contains(secret),
                "the {name} value reached an error message: {rendered}"
            );
        }
        assert!(rendered.contains("REDACTED"), "{rendered}");
        // Still a useful diagnostic: only the values are gone.
        assert!(rendered.contains("invalid_grant"), "{rendered}");
        assert!(rendered.contains("was reused"), "{rendered}");
    }

    #[test]
    fn a_token_straddling_the_snippet_cut_is_scrubbed_rather_than_truncated() {
        // Scrubbing AFTER truncation would leave the head of a token that
        // begins just before the cut. Position one there deliberately.
        let dir = TempDir::new("refresh-scrub-edge");
        fs::write(dir.auth(), auth_json(1_700_000_000)).unwrap();
        let mut auth = load_auth_from(&dir.auth()).unwrap();

        let mut body = String::from(r#"{"error":"invalid_grant","d":""#);
        while body.len() < config::ERROR_SNIPPET_BYTES - 8 {
            body.push('x');
        }
        body.push_str("old-refresh-token");
        body.push_str(r#""}"#);

        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/oauth/token");
            then.status(400).body(body);
        });

        let err = refresh_inner(
            &test_agent(),
            &mut auth,
            &server.url("/oauth/token"),
            &dir.auth(),
        )
        .unwrap_err();

        let Error::RefreshFailed { snippet, .. } = &err else {
            panic!("unexpected error: {err}")
        };
        assert!(
            !snippet.contains("old-refr"),
            "the first bytes of the refresh token survived the cut: {snippet}"
        );
        assert!(snippet.contains("REDACTED"), "{snippet}");
        assert!(
            snippet.len() <= config::ERROR_SNIPPET_BYTES,
            "{}",
            snippet.len()
        );
    }
}
