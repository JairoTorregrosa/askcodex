//! Credential session refresh. Production requests have one fixed OAuth destination.
use super::{
    jwt::needs_refresh,
    lock::AuthLock,
    store::{CredentialStore, load_auth_from, persist_atomic_to, resolve_symlink},
};
use crate::{
    config,
    error::Error,
    models::{self, AuthFile, RefreshResponse},
    redact::{REDACTED, Secret},
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use std::{path::Path, time::Duration};
const LOCK_WAIT: Duration = Duration::from_secs(35);

#[derive(Debug)]
pub(crate) struct AuthSession {
    store: CredentialStore,
    document: AuthFile,
}
impl AuthSession {
    pub(crate) fn load(store: CredentialStore) -> Result<Self, Error> {
        let document = store.load()?;
        Ok(Self { store, document })
    }
    pub(crate) fn path(&self) -> &Path {
        self.store.path()
    }
    #[cfg(test)]
    pub(crate) fn from_document(store: CredentialStore, document: AuthFile) -> Self {
        Self { store, document }
    }
    pub(crate) fn document(&self) -> &AuthFile {
        &self.document
    }
    pub(crate) fn ensure_fresh(
        &mut self,
        agent: &ureq::Agent,
        now: DateTime<Utc>,
    ) -> Result<(), Error> {
        if needs_refresh(&self.document, now)? {
            self.refresh(agent)?;
        }
        Ok(())
    }
    pub(crate) fn refresh(&mut self, agent: &ureq::Agent) -> Result<(), Error> {
        refresh_inner(
            agent,
            &mut self.document,
            config::TOKEN_URL,
            self.store.path(),
        )
    }
    #[cfg(test)]
    pub(crate) fn refresh_with_endpoint(
        &mut self,
        agent: &ureq::Agent,
        url: &str,
    ) -> Result<(), Error> {
        refresh_inner(agent, &mut self.document, url, self.store.path())
    }
}

pub(super) fn refresh_inner(
    agent: &ureq::Agent,
    auth: &mut AuthFile,
    token_url: &str,
    auth_file: &Path,
) -> Result<(), Error> {
    refresh_locked(agent, auth, token_url, auth_file, LOCK_WAIT)
}

pub(super) fn refresh_locked(
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
        .max_redirects(0)
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(config::REFRESH_TIMEOUT_SECS)))
        .build()
        .header("User-Agent", config::USER_AGENT)
        // Cloned so the exact value that went on the wire is still
        // available below, to be REMOVED from a failure body.
        .send_json(RefreshRequest::new(&refresh_token))?;

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

fn refresh_token_value(auth: &AuthFile) -> Option<&str> {
    auth.tokens
        .as_ref()
        .and_then(|tokens| tokens.refresh_token.as_ref())
        .map(|token| token.expose())
        .filter(|token| !token.is_empty())
}

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

fn scrub_secrets(text: String, secrets: &[&str]) -> String {
    let mut text = text;
    for secret in secrets {
        if !secret.is_empty() && text.contains(secret) {
            text = text.replace(secret, REDACTED);
        }
    }
    text
}

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

/// The OAuth request is the only serializer of the runtime refresh token.
/// Its Debug implementation retains Secret's redaction.
#[derive(Debug)]
struct RefreshRequest<'a> {
    refresh_token: &'a Secret,
}
impl<'a> RefreshRequest<'a> {
    fn new(refresh_token: &'a Secret) -> Self {
        Self { refresh_token }
    }
}
impl Serialize for RefreshRequest<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut fields = serializer.serialize_struct("RefreshRequest", 3)?;
        fields.serialize_field("client_id", config::CLIENT_ID)?;
        fields.serialize_field("grant_type", "refresh_token")?;
        fields.serialize_field("refresh_token", self.refresh_token.expose())?;
        fields.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn refresh_request_only_exposes_token_in_wire_serialization() {
        let token = Secret::new("fake-refresh-only");
        let request = RefreshRequest::new(&token);
        let value = serde_json::to_value(&request).unwrap();
        assert_eq!(value["client_id"], config::CLIENT_ID);
        assert_eq!(value["grant_type"], "refresh_token");
        assert_eq!(value["refresh_token"], "fake-refresh-only");
        assert!(!format!("{request:?}").contains("fake-refresh-only"));
    }
}

#[cfg(test)]
mod clock_tests {
    use super::*;
    #[test]
    fn session_uses_injected_time_before_deciding_to_refresh() {
        use base64::Engine as _;
        let claims =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"exp":4102444800}"#);
        let fixture = serde_json::json!({"tokens":{"access_token":format!("fake.{claims}.signature"),"refresh_token":"fake-refresh","account_id":"acct_REDACTED"}});
        let document: AuthFile = serde_json::from_value(fixture).unwrap();
        let store = CredentialStore::from_path(
            std::env::temp_dir().join("askcodex-unused-clock-test-auth.json"),
        );
        let mut session = AuthSession::from_document(store, document);
        let now = DateTime::from_timestamp(2_000_000_000, 0).unwrap();
        assert!(!needs_refresh(session.document(), now).unwrap());
        session
            .ensure_fresh(&ureq::Agent::new_with_defaults(), now)
            .unwrap();
        assert!(
            needs_refresh(
                session.document(),
                DateTime::from_timestamp(4_102_444_800, 0).unwrap()
            )
            .unwrap()
        );
    }
}
