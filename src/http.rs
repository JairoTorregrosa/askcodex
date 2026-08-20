//! Authenticated HTTP client over the codex backend.
//!
//! Owns the ureq agent, the loaded credentials, header injection, error
//! mapping, the credentialed-origin gate, and the single
//! 401 -> refresh -> retry policy. The per-function contracts below are
//! binding, not descriptive.
//!
//! Agent configuration (probe-verified against ureq 3.3.0):
//! - `http_status_as_error(false)` — MANDATORY. ureq's default turns
//!   non-2xx into `Error::StatusCode(u16)` and the response body is
//!   unreachable; askcodex needs both the status (401 detection) and the error
//!   body (loud messages). With `false`, every completed exchange is
//!   `Ok(http::Response<Body>)` and status is branched manually.
//! - `timeout_connect(config::CONNECT_TIMEOUT_SECS)`. NO global and NO
//!   recv-body timeout on the agent: `ask` SSE streams may run for
//!   minutes. Short non-streaming calls may tighten per request via
//!   `.config().timeout_global(..).build()` (request-scoped override,
//!   probe-verified).
//! - `max_redirects(0)` — askcodex follows NO redirect. This is pinned
//!   deliberately rather than inherited: ureq 3.3.0 defaults to following
//!   up to 10, and a probe against two local mock servers showed what that
//!   costs. With the default config a cross-host `302` IS followed;
//!   `Authorization` is dropped (`redirect_auth_headers` defaults to
//!   `Never` — an unset default askcodex must not rely on), but every other
//!   header is replayed to the redirect target: the probe watched
//!   `chatgpt-account-id`, `originator` and `user-agent` arrive at a
//!   foreign host. `ChatGPT-Account-Id` names the user's ChatGPT account
//!   and must not travel anywhere askcodex did not address; worse, ureq builds
//!   the follow-up request internally, so a followed redirect steps around
//!   the origin check in `send_once` entirely. With `max_redirects(0)`
//!   ureq returns the 3xx response AS IS (probe-verified: `Ok`, status 302,
//!   `Location` intact, with `max_redirects_will_error` either way), so askcodex
//!   reports it through the normal non-2xx path as the anomaly it is.
//! - TLS is rustls; the dependency tree contains no openssl/native-tls.
//!
//! Origin scoping: the credentials askcodex holds are the user's ChatGPT
//! subscription tokens, and they are attached to exactly one origin — the
//! scheme+host+port of `config::BASE_URL`. `askcodex raw` takes a target from
//! the command line, so `send_once` refuses any other origin (including a
//! plaintext `http://` downgrade of the backend host) BEFORE it reads the
//! access token. See [`origin_permitted`].
//!
//! Credential source is `~/.codex/auth.json` only; no API key is read,
//! accepted, or sent by this module (the `OPENAI_API_KEY` key that may
//! exist in `auth.json` is deliberately NOT used anywhere in askcodex).
//!
//! Request construction note: every call goes through
//! `Agent::run(http::Request<..>)` rather than the typed
//! `agent.get()/post()` builders, because the method is dynamic (`askcodex raw
//! <METHOD>` allows a bodied DELETE, which the typestate builders cannot
//! express). Two consequences, both handled explicitly below:
//! - `Agent::run` does NOT apply `SendBody`'s content type (ureq only
//!   consumes it in `RequestBuilder::send`), so bodied requests set
//!   `Content-Type: application/json; charset=utf-8` by hand — the exact
//!   value `send_json` would have produced (probe finding).
//! - Headers are written with `HeaderMap::insert` (replace), never
//!   `Builder::header` (append), so `extra_headers` can override a base
//!   header (`Accept` on the SSE path) instead of duplicating it.

use std::io::{BufRead, BufReader, Read};
use std::time::Duration;

use serde_json::Value;
use ureq::Body;
use ureq::http::header::{HeaderName, HeaderValue};
use ureq::http::{Method, Request, Response, Uri};

use crate::config;
use crate::error::Error;
use crate::models::{AuthFile, AuthTokens};
use crate::redact::Secret;

/// Exact `Content-Type` ureq's `send_json` emits (the charset suffix is
/// present). Kept byte-identical so the wire matches codex/ureq.
const JSON_CONTENT_TYPE: &str = "application/json; charset=utf-8";

/// `Accept` sent on every non-streaming backend call.
const ACCEPT_JSON: &str = "application/json";

/// `Accept` sent on the streaming (`/codex/responses`) path.
const ACCEPT_SSE: &str = "text/event-stream";

/// Responses-API opt-in header sent alongside `Accept: text/event-stream`.
const OPENAI_BETA: &str = "responses=experimental";

/// Guidance appended to the snippet of a 401 that `--no-refresh` made
/// final.
///
/// It is charged AGAINST `config::ERROR_SNIPPET_BYTES`, not added on top
/// of it: error.rs documents `HttpStatus.snippet` as "the error body
/// truncated to `config::ERROR_SNIPPET_BYTES`", and a branch that quietly
/// exceeds its own documented bound makes the doc a lie.
const NO_REFRESH_GUIDANCE: &str = " [--no-refresh is set; the access token looks expired or \
                                   rejected — run `askcodex auth refresh`]";

/// Enforced at compile time: the guidance must leave the body more of the
/// budget than it takes itself, or the "bounded snippet" is guidance only.
const _: () = assert!(NO_REFRESH_GUIDANCE.len() * 2 < config::ERROR_SNIPPET_BYTES);

/// Bytes of a rejected target quoted back in an error message. The target
/// comes from argv, so it is bounded and escaped rather than replayed raw.
const TARGET_LABEL_BYTES: usize = 120;

/// Authenticated client. One per process invocation.
pub struct Client {
    agent: ureq::Agent,
    auth: AuthFile,
    no_refresh: bool,

    /// OAuth token endpoint used by the ONE allowed refresh (pre-flight
    /// and 401-retry alike).
    ///
    /// Always `config::TOKEN_URL` in production — [`Client::new`] is the
    /// only constructor the shipped binary uses. It is a field rather than
    /// a hard-coded const solely so that [`Client::with_token_url`] can
    /// point an offline test at a localhost mock; it is NEVER read from
    /// the environment, a config file, or a CLI flag (see that
    /// constructor's docs for why that would be a security hole).
    token_url: String,
}

impl Client {
    /// Build the agent (config above) and wrap the loaded credentials.
    /// `no_refresh` disables BOTH the pre-flight refresh and the
    /// 401-retry (contract of the global `--no-refresh` flag).
    ///
    /// This is the constructor production code uses: it pins the refresh
    /// endpoint to [`config::TOKEN_URL`].
    pub fn new(auth: AuthFile, no_refresh: bool) -> Result<Self, Error> {
        Self::with_token_url(auth, no_refresh, config::TOKEN_URL)
    }

    /// [`Client::new`] with an explicitly supplied OAuth token endpoint.
    ///
    /// Identical to [`Client::new`] in every respect except which host the
    /// single 401 -> refresh -> retry (and the [`Client::ensure_fresh`]
    /// pre-flight) posts the refresh token to.
    ///
    /// `token_url` EXISTS FOR TESTING AND FOR NOTHING ELSE: it is what
    /// lets a black-box test drive a genuine 401 -> refresh -> retry
    /// against a localhost mock without ever reaching `auth.openai.com`
    /// with the user's real credentials. Production callers pass
    /// [`config::TOKEN_URL`] — that is exactly what [`Client::new`] does,
    /// and `new` is the only constructor askcodex itself calls.
    ///
    /// It must NEVER be wired to an environment variable, a config file,
    /// or a CLI flag. An `ASKCODEX_TOKEN_URL`-style override was considered and
    /// is deliberately REJECTED: the refresh request carries a LIVE
    /// refresh token, so an externally settable endpoint would let
    /// anything that can plant a variable in the user's environment
    /// redirect that token to a host it controls. See
    /// [`crate::auth::refresh_with_endpoint`] for the full rationale.
    pub fn with_token_url(
        auth: AuthFile,
        no_refresh: bool,
        token_url: &str,
    ) -> Result<Self, Error> {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            // MANDATORY: keep non-2xx as Ok(response) so status AND body
            // stay reachable (see module docs).
            .http_status_as_error(false)
            // The ONLY agent-level timeout: a global or recv-body timeout
            // would kill long `ask` streams.
            .timeout_connect(Some(Duration::from_secs(config::CONNECT_TIMEOUT_SECS)))
            // Follow NOTHING. ureq's default (10) replays every non-auth
            // header — `ChatGPT-Account-Id` included — at whatever host a
            // `Location` names, and builds that request internally where
            // `origin_permitted` cannot see it. With 0 the 3xx comes back
            // as an ordinary response and becomes a loud `HttpStatus`.
            // See the module docs for the probe that established this.
            .max_redirects(0)
            // Defense in depth: every request sets User-Agent explicitly,
            // this makes ureq's own default unreachable regardless.
            .user_agent(config::USER_AGENT)
            .build()
            .into();

        let client = Client {
            agent,
            auth,
            no_refresh,
            token_url: token_url.to_string(),
        };

        // Fail at construction, not at the first request: a client that
        // cannot authenticate must refuse to exist.
        client.access_token()?;
        client.account_id()?;

        Ok(client)
    }

    /// Read access to the loaded credentials (for `auth status` rendering
    /// and tests). Never exposes token values beyond the `Secret` type.
    pub fn auth(&self) -> &AuthFile {
        &self.auth
    }

    /// The shared agent (auth::refresh borrows it for the OAuth call).
    pub fn agent(&self) -> &ureq::Agent {
        &self.agent
    }

    /// Pre-flight freshness: when `no_refresh` is false and
    /// `auth::needs_refresh(now)` is true, run the one allowed refresh
    /// (which persists) against this client's token endpoint —
    /// `config::TOKEN_URL` for every production client. Called once by
    /// run.rs before dispatch for every command EXCEPT `auth status` /
    /// `auth refresh` (they manage freshness themselves — Python parity).
    pub fn ensure_fresh(&mut self) -> Result<(), Error> {
        if self.no_refresh {
            return Ok(());
        }
        if crate::auth::needs_refresh(&self.auth, chrono::Utc::now())? {
            self.refresh_once()?;
        }
        Ok(())
    }

    /// Core request path. Contract:
    /// - URL: `path` with a leading `/` hangs off `config::BASE_URL` (NOT
    ///   the codex base — callers pass `/codex/...` or `/me` explicitly);
    ///   an absolute http(s) URL is used verbatim; anything else is
    ///   `Error::UntrustedOrigin` (see [`resolve_target`]).
    /// - Origin: the request is sent ONLY if its scheme+host+port is the
    ///   one askcodex is credentialed for, otherwise `Error::UntrustedOrigin`
    ///   and no socket (see [`origin_permitted`]).
    /// - Headers on EVERY call: `Authorization: Bearer <access_token>`
    ///   (via `Secret::expose`, header value only), `ChatGPT-Account-Id`,
    ///   `originator: config::ORIGINATOR`, `User-Agent:
    ///   config::USER_AGENT`, `Accept: application/json` plus
    ///   `extra_headers` (which may override Accept for SSE).
    /// - Body: `Some(v)` -> send_json (sets `Content-Type:
    ///   application/json; charset=utf-8` — probe finding); `None` with a
    ///   body-less method -> plain call.
    /// - 401 policy: on HTTP 401, when `no_refresh` is false, refresh
    ///   EXACTLY ONCE (`auth::refresh`, persists rotated tokens BEFORE the
    ///   retry so a crash cannot lose them) and retry the request EXACTLY
    ///   ONCE with the new token. A second 401 (or `no_refresh` true) ->
    ///   `Error::HttpStatus` with the 401 body snippet. Never loop.
    /// - Any other non-2xx -> `Error::HttpStatus { method, path, status,
    ///   snippet }` (snippet: body truncated to
    ///   `config::ERROR_SNIPPET_BYTES`, lossy UTF-8).
    /// - 2xx: read the body through
    ///   `into_with_config().limit(config::BODY_LIMIT_BYTES)` (plain
    ///   readers are unlimited — probe finding) and parse JSON; a non-JSON
    ///   2xx body -> `Error::NonJsonResponse`. 204/205 carry no content by
    ///   definition and yield `Value::Null` with no error.
    pub fn request_json(
        &mut self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value, Error> {
        let response = self.send_with_refresh(&method, path, body, &[])?;

        let status = response.status().as_u16();
        let (_parts, response_body) = response.into_parts();

        if !is_success(status) {
            return Err(http_status_error(
                &method,
                path,
                status,
                snippet_of_body(response_body),
            ));
        }

        // A body-less success is a SUCCESS. 204 and 205 are defined to
        // carry no content, so there is no document to parse and nothing
        // failed: routing them through `NonJsonResponse` turned a
        // completed `raw DELETE` into exit 1. `Value::Null` is what `raw`
        // prints; a typed endpoint that needed a document still fails
        // loudly on its own decode, so this hides nothing.
        //
        // Deliberately limited to those two statuses: an EMPTY body on a
        // 200 is a response shape askcodex did not expect and stays
        // `NonJsonResponse`.
        if matches!(status, 204 | 205) {
            return Ok(Value::Null);
        }

        let bytes = read_body_limited(response_body, config::BODY_LIMIT_BYTES)?;
        serde_json::from_slice(&bytes).map_err(|_| Error::NonJsonResponse {
            method: method.to_string(),
            path: path.to_string(),
            len: bytes.len(),
            snippet: snippet_of_bytes(&bytes),
        })
    }

    /// Convenience: `request_json(GET, path, None)`.
    pub fn get_json(&mut self, path: &str) -> Result<Value, Error> {
        self.request_json(Method::GET, path, None)
    }

    /// Convenience: `request_json(POST, path, Some(body))`.
    pub fn post_json(&mut self, path: &str, body: &Value) -> Result<Value, Error> {
        self.request_json(Method::POST, path, Some(body))
    }

    /// Streaming request (SSE). Same URL/header/401 contract as
    /// `request_json`, plus `Accept: text/event-stream` and
    /// `OpenAI-Beta: responses=experimental`. The 401 refresh-retry MUST
    /// happen before any stream byte is consumed (status is known at
    /// response-head time).
    ///
    /// Returns a buffered reader over the LIVE response body (bounded by
    /// `config::BODY_LIMIT_BYTES` via `into_with_config().limit(..)`), so
    /// callers stream line-by-line as bytes arrive; sse.rs owns framing.
    pub fn request_stream(
        &mut self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Box<dyn BufRead>, Error> {
        let extra = [("Accept", ACCEPT_SSE), ("OpenAI-Beta", OPENAI_BETA)];
        let response = self.send_with_refresh(&method, path, body, &extra)?;

        let status = response.status().as_u16();
        let (_parts, response_body) = response.into_parts();

        if !is_success(status) {
            return Err(http_status_error(
                &method,
                path,
                status,
                snippet_of_body(response_body),
            ));
        }

        // NOTE: never read_to_end here — the body is consumed live,
        // line by line, by sse.rs. The limit bounds the whole stream.
        let reader = response_body
            .into_with_config()
            .limit(config::BODY_LIMIT_BYTES)
            .reader();
        Ok(Box::new(BufReader::new(reader)))
    }

    // -----------------------------------------------------------------
    // internals
    // -----------------------------------------------------------------

    /// One request, plus AT MOST one refresh-and-retry on 401.
    ///
    /// Never loops: the retry's response is returned as-is, so a second
    /// 401 falls through to the caller's non-2xx handling (a loud
    /// `Error::HttpStatus`).
    fn send_with_refresh(
        &mut self,
        method: &Method,
        path: &str,
        body: Option<&Value>,
        extra_headers: &[(&str, &str)],
    ) -> Result<Response<Body>, Error> {
        let url = resolve_target(path)?;
        let response = self.send_once(method, &url, body, extra_headers)?;

        if response.status().as_u16() != 401 {
            return Ok(response);
        }

        if self.no_refresh {
            // Loud immediately: the user asked for no automatic refresh,
            // so askcodex must not silently mint a new token behind their back.
            let (_parts, response_body) = response.into_parts();
            // The guidance is charged against the documented snippet
            // bound, not appended past it: the body gets whatever
            // `ERROR_SNIPPET_BYTES` leaves after the guidance.
            let body = snippet_of_body_bounded(
                response_body,
                config::ERROR_SNIPPET_BYTES - NO_REFRESH_GUIDANCE.len(),
            );
            let snippet = format!("{body}{NO_REFRESH_GUIDANCE}");
            return Err(http_status_error(method, path, 401, snippet));
        }

        // Exactly one refresh (it persists the rotated tokens itself,
        // BEFORE the retry, so a crash cannot lose them), then exactly one
        // retry with the freshly stored access token.
        drop(response);
        self.refresh_once()?;
        self.send_once(method, &url, body, extra_headers)
    }

    /// The single refresh entry point.
    ///
    /// Goes through `auth::refresh_with_endpoint` rather than
    /// `auth::refresh` so that the endpoint is the one this client was
    /// built with — `config::TOKEN_URL` for every production client (see
    /// [`Client::with_token_url`]). The refresh persists the rotated
    /// tokens itself; nothing is retried here.
    fn refresh_once(&mut self) -> Result<(), Error> {
        crate::auth::refresh_with_endpoint(&self.agent, &mut self.auth, &self.token_url)
    }

    /// Build and execute ONE request. No retry logic lives here.
    ///
    /// Credentials are re-read from `self.auth` on every call, so a retry
    /// after a refresh carries the NEW access token.
    fn send_once(
        &self,
        method: &Method,
        url: &str,
        body: Option<&Value>,
        extra_headers: &[(&str, &str)],
    ) -> Result<Response<Body>, Error> {
        // ORIGIN SCOPING, first statement in the function: no credential
        // is even READ until the destination is known to be the one askcodex
        // is credentialed for. It lives here, at the single point where
        // the Authorization header is built, so that nothing — `raw`, an
        // endpoint module, a future caller, the streaming path — can route
        // around it. See `origin_permitted` for the `cfg!(test)` argument.
        origin_permitted(url, cfg!(test))?;

        // The access token reaches exactly ONE destination: this header
        // value. It is assembled byte-wise rather than with `format!`
        // (redact.rs: `expose()` output must never enter a format/print
        // macro) and marked sensitive, so even an accidental `{:?}` of the
        // request renders it as `Sensitive`.
        let token = self.access_token()?;
        let mut bearer = Vec::with_capacity(b"Bearer ".len() + token.expose().len());
        bearer.extend_from_slice(b"Bearer ");
        bearer.extend_from_slice(token.expose().as_bytes());
        let mut authorization = HeaderValue::from_bytes(&bearer).map_err(http_error)?;
        authorization.set_sensitive(true);

        let mut builder = Request::builder().method(method.clone()).uri(url);

        set_header_value(&mut builder, "Authorization", authorization)?;
        set_header(&mut builder, "ChatGPT-Account-Id", self.account_id()?)?;
        // Literal lowercase header name, codex parity.
        set_header(&mut builder, "originator", config::ORIGINATOR)?;
        set_header(&mut builder, "User-Agent", config::USER_AGENT)?;
        set_header(&mut builder, "Accept", ACCEPT_JSON)?;

        // Applied last and by `insert`, so they REPLACE a base header of
        // the same name (the SSE path overrides `Accept`).
        for (name, value) in extra_headers {
            set_header(&mut builder, name, value)?;
        }

        let response = match body {
            Some(value) => {
                set_header(&mut builder, "Content-Type", JSON_CONTENT_TYPE)?;
                let bytes = serde_json::to_vec(value)?;
                let request = builder.body(bytes).map_err(http_error)?;
                self.agent.run(request)?
            }
            // `()` is ureq's no-body marker: no Content-Length, no
            // Content-Type, nothing sent (Python parity for GET/DELETE).
            None => {
                let request = builder.body(()).map_err(http_error)?;
                self.agent.run(request)?
            }
        };

        Ok(response)
    }

    /// The token bundle, or the loud "no usable credentials" error.
    fn tokens(&self) -> Result<&AuthTokens, Error> {
        match self.auth.tokens.as_ref() {
            Some(tokens) => Ok(tokens),
            None => Err(Error::AuthTokensMissing {
                path: config::auth_path()?,
            }),
        }
    }

    /// The access token. Missing or empty is fatal — never a blank bearer.
    fn access_token(&self) -> Result<&Secret, Error> {
        match self.tokens()?.access_token.as_ref() {
            Some(token) if !token.is_empty() => Ok(token),
            _ => Err(Error::AuthTokensMissing {
                path: config::auth_path()?,
            }),
        }
    }

    /// The account id. Missing or empty is fatal — never a blank header.
    fn account_id(&self) -> Result<&str, Error> {
        match self.tokens()?.account_id.as_deref() {
            Some(id) if !id.is_empty() => Ok(id),
            _ => Err(Error::AuthAccountIdMissing {
                path: config::auth_path()?,
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// origin scoping
// ---------------------------------------------------------------------------

/// Scheme + host + effective port: the unit askcodex compares when deciding
/// whether a request may carry the user's subscription credentials.
#[derive(Debug, PartialEq, Eq)]
struct Origin {
    scheme: String,
    host: String,
    port: u16,
}

impl Origin {
    /// Loopback hosts, in the spellings `Uri::host` can produce (IPv6
    /// hosts keep their brackets).
    fn is_loopback(&self) -> bool {
        matches!(
            self.host.as_str(),
            "localhost" | "127.0.0.1" | "::1" | "[::1]"
        )
    }
}

impl std::fmt::Display for Origin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if default_port(&self.scheme) == Some(self.port) {
            write!(f, "{}://{}", self.scheme, self.host)
        } else {
            write!(f, "{}://{}:{}", self.scheme, self.host, self.port)
        }
    }
}

/// Default port of the only two schemes askcodex speaks. `None` for anything
/// else, which is what makes an unsupported scheme unrepresentable as an
/// [`Origin`] and therefore refused.
fn default_port(scheme: &str) -> Option<u16> {
    match scheme {
        "https" => Some(443),
        "http" => Some(80),
        _ => None,
    }
}

/// The origin of an absolute http(s) URL, or `None` when `url` is not one.
///
/// `None` covers a relative path, a missing or unsupported scheme, a
/// missing host, and an unparseable string alike — every one of those is
/// refused by [`origin_permitted`], so anything askcodex cannot make sense of
/// fails CLOSED.
///
/// Normalization matters here, because this is a security comparison:
/// scheme and host are lowercased (both are case-insensitive) and the port
/// is made explicit, so `https://CHATGPT.COM:443/x` matches the backend
/// while `https://chatgpt.com:8443/x` does not. `Uri::host` returns the
/// host WITHOUT any `user:pass@` prefix, so `https://chatgpt.com@evil/x`
/// yields `evil` — the userinfo spoof cannot produce a match.
fn origin_of(url: &str) -> Option<Origin> {
    let uri: Uri = url.parse().ok()?;
    let scheme = uri.scheme_str()?.to_ascii_lowercase();
    // Rejects every scheme askcodex does not speak, explicit port or not.
    let default = default_port(&scheme)?;
    let port = uri.port_u16().unwrap_or(default);
    let host = uri.host()?.to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    Some(Origin { scheme, host, port })
}

/// The single origin askcodex is credentialed for, DERIVED from
/// `config::BASE_URL` rather than spelled out again here: there is exactly
/// one place that decides which host askcodex talks to, and this is not it.
fn credentialed_origin() -> Option<Origin> {
    origin_of(config::BASE_URL)
}

/// Render the credentialed origin for an error message.
fn expected_label() -> String {
    match credentialed_origin() {
        Some(origin) => origin.to_string(),
        // Unreachable with the shipped constant; if it ever were, the
        // message still names what askcodex was configured with.
        None => config::BASE_URL.to_string(),
    }
}

/// The refusal, with the attempted target rendered safely.
fn untrusted(target: &str) -> Error {
    Error::UntrustedOrigin {
        attempted: match origin_of(target) {
            Some(origin) => origin.to_string(),
            // Not an origin at all: quote it (escaping control characters,
            // which come from argv) and bound it.
            None => format!(
                "{:?}",
                truncate_on_char_boundary(target, TARGET_LABEL_BYTES)
            ),
        },
        expected: expected_label(),
    }
}

/// Refuse `url` unless it names the origin askcodex holds credentials for.
///
/// THIS is the gate that keeps the subscription bearer token and the
/// account id off every host but the backend. `askcodex raw` takes its target
/// from the command line, so without this an argument — a typo, or a line
/// of injected text an agent obeys — is enough to hand a live credential
/// to an arbitrary host, in cleartext if the scheme says so. Scheme
/// equality is part of the comparison, which is also what refuses an
/// `http://` downgrade of the backend host itself.
///
/// `allow_loopback` widens the check to loopback hosts. Its ONLY true
/// caller is this crate's own unit-test build (`cfg!(test)` in
/// [`Client::send_once`]), where the "backend" is an httpmock server on
/// 127.0.0.1. It is false in every artifact that ships and in every
/// integration test, both of which compile this file without `cfg(test)`,
/// so no build a user can run is affected. The refusal itself is tested
/// against the production setting by calling this function directly.
fn origin_permitted(url: &str, allow_loopback: bool) -> Result<(), Error> {
    let attempted = origin_of(url);
    match (&attempted, credentialed_origin()) {
        (Some(attempted), Some(expected)) if *attempted == expected => return Ok(()),
        (Some(attempted), _) if allow_loopback && attempted.is_loopback() => return Ok(()),
        _ => {}
    }
    Err(untrusted(url))
}

/// Resolve a caller-supplied target into the absolute URL to request.
///
/// EXACTLY two shapes are accepted:
/// - a path with a leading `/`, which hangs off `config::BASE_URL` (NOT
///   the codex base — callers pass `/codex/...` or `/me` explicitly);
/// - an absolute http(s) URL, returned verbatim. Whether askcodex may
///   AUTHENTICATE to it is a separate question, answered by
///   [`origin_permitted`] at the point the credentials are attached.
///
/// Anything else is refused loudly instead of being glued onto the base.
/// The old `format!("{BASE_URL}{path}")` turned `codex/usage` into
/// `https://chatgpt.com/backend-apicodex/usage` and then reported the 404
/// against the caller's `codex/usage`, hiding the mangling; and the old
/// `starts_with("http")` test was not a scheme test at all, handing
/// `httpbin/x` straight to the transport.
fn resolve_target(path: &str) -> Result<String, Error> {
    if path.starts_with('/') {
        return Ok(format!("{}{}", config::BASE_URL, path));
    }
    if origin_of(path).is_some() {
        return Ok(path.to_string());
    }
    Err(untrusted(path))
}

/// The exact target check [`Client`] performs, without sending anything.
///
/// `src/cli.rs` runs this as clap's `value_parser` for `askcodex raw <path>`,
/// so a target askcodex would refuse is rejected at parse time with the reason
/// — before the credential file is even opened — instead of failing later.
/// That layer is a courtesy: the refusal that must not be bypassable is
/// the one inside [`Client::send_once`], on the resolved URL, at the point
/// the `Authorization` header is built.
pub fn check_request_target(target: &str) -> Result<(), Error> {
    origin_permitted(&resolve_target(target)?, false)
}

/// Longest prefix of `text` that is at most `max` bytes and ends on a
/// character boundary.
fn truncate_on_char_boundary(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

// ---------------------------------------------------------------------------
// free helpers
// ---------------------------------------------------------------------------

/// 2xx is success; everything else is an error askcodex must report.
fn is_success(status: u16) -> bool {
    (200..300).contains(&status)
}

/// Set (replace) one header on an `http::request::Builder`.
///
/// `HeaderMap::insert` replaces any existing value for the name, which is
/// what makes `extra_headers` an override instead of a duplicate. Invalid
/// header names/values surface as a transport error whose message never
/// contains the offending value (`http`'s `InvalidHeaderValue` prints
/// "failed to parse header value" and nothing else) — required, because
/// one of these values is the access token.
fn set_header(
    builder: &mut ureq::http::request::Builder,
    name: &str,
    value: &str,
) -> Result<(), Error> {
    let value = HeaderValue::from_str(value).map_err(http_error)?;
    set_header_value(builder, name, value)
}

/// [`set_header`] for an already-built value (the sensitive bearer token).
fn set_header_value(
    builder: &mut ureq::http::request::Builder,
    name: &str,
    value: HeaderValue,
) -> Result<(), Error> {
    let name = HeaderName::from_bytes(name.as_bytes()).map_err(http_error)?;
    if let Some(headers) = builder.headers_mut() {
        headers.insert(name, value);
    }
    // `headers_mut()` is None only when the builder already holds an
    // error (bad method/URI); `builder.body(..)` surfaces it loudly.
    Ok(())
}

/// Map an `http` crate error into the crate transport error.
fn http_error(source: impl Into<ureq::http::Error>) -> Error {
    Error::Transport(ureq::Error::Http(source.into()))
}

/// Build the loud non-2xx error.
fn http_status_error(method: &Method, path: &str, status: u16, snippet: String) -> Error {
    Error::HttpStatus {
        method: method.to_string(),
        path: path.to_string(),
        status,
        snippet,
    }
}

/// Read a whole response body through an explicit limit.
///
/// ureq's plain readers are unlimited and `read_to_string`/`read_to_vec`
/// silently cap at 10MB (probe finding), so every read goes through
/// `into_with_config().limit(..)`. Exceeding the limit is an error, never
/// a truncated success: ureq's `BodyExceedsLimit` is wrapped in
/// `io::Error`, and `ureq::Error::from` unwraps it back so the message
/// names the limit. (ureq's `LimitReader` raises on the read that finds
/// the budget exhausted, so a body of EXACTLY `limit` bytes is rejected as
/// well — deliberately conservative; a silent truncation would be worse.)
fn read_body_limited(body: Body, limit: u64) -> Result<Vec<u8>, Error> {
    let mut reader = body.into_with_config().limit(limit).reader();
    let mut buf = Vec::new();
    reader
        .read_to_end(&mut buf)
        .map_err(|e| Error::Transport(ureq::Error::from(e)))?;
    Ok(buf)
}

/// Best-effort bounded snippet of an error body.
///
/// Reads at most `config::ERROR_SNIPPET_BYTES` and never propagates a read
/// failure: the HTTP status is the error being reported and must not be
/// displaced by a failure to gather context. A body that cannot be read at
/// all is reported as such rather than as an empty string.
fn snippet_of_body(body: Body) -> String {
    snippet_of_body_bounded(body, config::ERROR_SNIPPET_BYTES)
}

/// [`snippet_of_body`] with an explicit budget, for the one caller that
/// has to share `config::ERROR_SNIPPET_BYTES` with appended guidance.
fn snippet_of_body_bounded(body: Body, max: usize) -> String {
    // Doubly bounded: ureq's own limit plus a `take` that stops before the
    // limit can fire, so an oversized error body yields a snippet instead
    // of a read error.
    let limit = max as u64;
    let mut reader = body.into_with_config().limit(limit).reader().take(limit);
    let mut buf = Vec::new();
    match reader.read_to_end(&mut buf) {
        Ok(_) if buf.is_empty() => "<empty body>".to_string(),
        Ok(_) => snippet_of_bytes_bounded(&buf, max),
        Err(_) if buf.is_empty() => "<error body unreadable>".to_string(),
        Err(_) => snippet_of_bytes_bounded(&buf, max),
    }
}

/// Lossy UTF-8 of at most `config::ERROR_SNIPPET_BYTES` bytes.
fn snippet_of_bytes(bytes: &[u8]) -> String {
    snippet_of_bytes_bounded(bytes, config::ERROR_SNIPPET_BYTES)
}

/// [`snippet_of_bytes`] with an explicit budget.
///
/// The budget bounds the RENDERED string, not just the slice taken from
/// `bytes`: `from_utf8_lossy` expands, turning each invalid byte into a
/// 3-byte U+FFFD, so a `max`-byte slice can render three times longer. The
/// bound error.rs documents is on the field, so the rendering is trimmed
/// too — on a character boundary, never mid-replacement-character.
fn snippet_of_bytes_bounded(bytes: &[u8], max: usize) -> String {
    let end = bytes.len().min(max);
    let text = String::from_utf8_lossy(&bytes[..end]);
    truncate_on_char_boundary(&text, max).to_string()
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

// Isolation rules for this module, both enforced by construction:
//
// 1. NETWORK. Every client below is built with `Client::with_token_url`,
//    so no test can post a refresh token to `auth.openai.com`: the
//    endpoint is either a localhost httpmock server or
//    `UNREACHABLE_TOKEN_URL` (loopback port 1, where nothing listens), and
//    `Client::new` — the only constructor that points at
//    `config::TOKEN_URL` — is exercised solely by tests that never send a
//    request. Backend calls likewise only ever go to httpmock.
// 2. FILESYSTEM. A successful refresh persists rotated tokens to
//    `config::auth_path()`, so the tests that drive one call
//    `auth::isolate_codex_home()` (process-wide scratch dir, never the
//    real `~/.codex`) and hold `auth::lock_codex_home()` for their whole
//    body, since that scratch dir is shared. Every other test calls
//    `isolate_codex_home()` too, so the one `set_var` is guaranteed to
//    have happened before any test reads the environment.
//
// Every token value below is a made-up literal. No real credential, and no
// call to a real host, appears anywhere in this module.
#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    // Only the two method constants are imported: httpmock also exports a
    // `Method` type, and glob-importing its prelude would shadow ureq's.
    use httpmock::Method::{DELETE, GET, POST};
    use httpmock::MockServer;
    use serde_json::json;

    use super::*;
    use crate::auth::{isolate_codex_home, lock_codex_home};

    /// Invented, non-functional token values.
    const FAKE_ACCESS_TOKEN: &str = "fake.access.token-AAA";
    const FAKE_ROTATED_TOKEN: &str = "fake.access.token-BBB";
    const FAKE_REFRESH_TOKEN: &str = "fake-refresh-token";
    const FAKE_ACCOUNT_ID: &str = "acct_fake_0000";

    /// Token endpoint for clients that must NEVER refresh: loopback port 1,
    /// where nothing listens. An unexpected refresh attempt therefore fails
    /// loudly instead of reaching any real host.
    const UNREACHABLE_TOKEN_URL: &str = "http://127.0.0.1:1/oauth/token";

    fn auth_file() -> AuthFile {
        isolate_codex_home();
        AuthFile {
            auth_mode: Some("chatgpt".to_string()),
            tokens: Some(AuthTokens {
                id_token: None,
                access_token: Some(Secret::new(FAKE_ACCESS_TOKEN)),
                refresh_token: Some(Secret::new(FAKE_REFRESH_TOKEN)),
                account_id: Some(FAKE_ACCOUNT_ID.to_string()),
                extra: serde_json::Map::new(),
            }),
            last_refresh: None,
            extra: serde_json::Map::new(),
        }
    }

    /// A client whose refresh endpoint is unreachable (see
    /// [`UNREACHABLE_TOKEN_URL`]) — for the tests that must not refresh.
    fn client(no_refresh: bool) -> Client {
        client_with_token_url(no_refresh, UNREACHABLE_TOKEN_URL)
    }

    fn client_with_token_url(no_refresh: bool, token_url: &str) -> Client {
        Client::with_token_url(auth_file(), no_refresh, token_url).expect("valid fake credentials")
    }

    /// A syntactically valid, FAKE, unsigned JWT expiring at `exp` — the
    /// `ensure_fresh` path decodes the access token, unlike the 401 path.
    fn fake_jwt_expiring_at(exp: i64) -> String {
        format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#),
            URL_SAFE_NO_PAD.encode(format!(r#"{{"exp":{exp}}}"#).as_bytes()),
            URL_SAFE_NO_PAD.encode(b"sig"),
        )
    }

    fn access_token_of(client: &Client) -> String {
        client
            .auth()
            .tokens
            .as_ref()
            .and_then(|tokens| tokens.access_token.as_ref())
            .expect("access token")
            .expose()
            .to_string()
    }

    /// Empty the shared scratch `CODEX_HOME` and return it. Callers MUST
    /// hold [`lock_codex_home`].
    fn reset_codex_home() -> PathBuf {
        let home = isolate_codex_home();
        for name in ["auth.json", "auth.json.bak"] {
            remove_if_present(&home.join(name));
        }
        home
    }

    /// Loud on every failure except "it was not there in the first place".
    fn remove_if_present(path: &Path) {
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => panic!("cannot clean {}: {e}", path.display()),
        }
    }

    fn read_json(path: &Path) -> Value {
        let text = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        serde_json::from_str(&text).expect("persisted auth.json is JSON")
    }

    /// `Box<dyn BufRead>` is not `Debug`, so `unwrap_err` is unavailable.
    fn expect_stream_error(result: Result<Box<dyn BufRead>, Error>) -> Error {
        match result {
            Ok(_) => panic!("expected a loud error, got a stream"),
            Err(e) => e,
        }
    }

    // -- URL construction ------------------------------------------------

    #[test]
    fn relative_paths_hang_off_base_url_absolute_ones_are_verbatim() {
        isolate_codex_home();
        assert_eq!(
            resolve_target("/codex/usage").unwrap(),
            "https://chatgpt.com/backend-api/codex/usage"
        );
        assert_eq!(
            resolve_target("/me").unwrap(),
            "https://chatgpt.com/backend-api/me"
        );
        // Resolution is not permission: an absolute URL comes back
        // verbatim, and `origin_permitted` is what then refuses it.
        assert_eq!(
            resolve_target("https://example.invalid/x").unwrap(),
            "https://example.invalid/x"
        );
        assert!(origin_permitted("https://example.invalid/x", false).is_err());
        // A scheme-relative target cannot escape the base: `BASE_URL` has a
        // path component, so `//host` lands under /backend-api, not on
        // `host`. Checked empirically, locked here.
        for escape in ["//evil.invalid/x", "/..//evil.invalid"] {
            let resolved = resolve_target(escape).unwrap();
            assert_eq!(
                origin_of(&resolved).unwrap(),
                credentialed_origin().unwrap(),
                "{escape} resolved off-origin: {resolved}"
            );
        }
    }

    #[test]
    fn a_target_that_is_neither_a_path_nor_a_url_is_refused_not_concatenated() {
        isolate_codex_home();
        // Used to silently become https://chatgpt.com/backend-apicodex/usage
        // and then report the 404 against `codex/usage`.
        for target in ["codex/usage", "httpbin/x", "httpfoo://x", "", " /codex"] {
            match resolve_target(target) {
                Err(Error::UntrustedOrigin {
                    attempted,
                    expected,
                }) => {
                    assert_eq!(expected, "https://chatgpt.com");
                    assert!(
                        attempted.contains(target.trim()) || target.trim().is_empty(),
                        "{target}: message does not name it: {attempted}"
                    );
                }
                other => panic!("{target} must be refused, got {other:?}"),
            }
        }
    }

    // -- origin scoping --------------------------------------------------

    #[test]
    fn credentials_are_refused_for_every_origin_but_the_backend() {
        isolate_codex_home();
        for target in [
            // THE reported exploit: `askcodex raw GET http://127.0.0.1:8731/x`
            // handed a live bearer token to a foreign listener in
            // cleartext. Checked with allow_loopback=false — the
            // production setting — so the cfg(test) allowance that keeps
            // the httpmock suites running cannot mask this.
            "http://127.0.0.1:8731/anything",
            "http://localhost:8731/anything",
            "https://collector.example/q",
            "https://evil.invalid/collect",
            // A plaintext downgrade of the backend host itself.
            "http://chatgpt.com/backend-api/codex/usage",
            // Userinfo spoof: the real host is `evil.invalid`.
            "https://chatgpt.com@evil.invalid/x",
            // Suffix and prefix lookalikes.
            "https://chatgpt.com.evil.invalid/x",
            "https://notchatgpt.com/x",
            // Same host, different port.
            "https://chatgpt.com:8443/backend-api/codex/usage",
            // Schemes askcodex does not speak.
            "ftp://chatgpt.com/x",
            "file:///etc/passwd",
        ] {
            match origin_permitted(target, false) {
                Err(Error::UntrustedOrigin { expected, .. }) => {
                    assert_eq!(expected, "https://chatgpt.com");
                }
                other => panic!("{target} must be refused, got {other:?}"),
            }
        }
    }

    #[test]
    fn the_backend_origin_is_accepted_in_its_equivalent_spellings() {
        isolate_codex_home();
        for target in [
            config::BASE_URL,
            "https://chatgpt.com/backend-api/codex/usage",
            // Host and scheme are case-insensitive; :443 is the default.
            "HTTPS://CHATGPT.COM/backend-api/me",
            "https://chatgpt.com:443/backend-api/me",
            "https://chatgpt.com/backend-api/codex/models?client_version=0.147.0",
        ] {
            origin_permitted(target, false)
                .unwrap_or_else(|e| panic!("{target} must be allowed: {e}"));
        }
    }

    /// The gate's doc claims that anything askcodex cannot make sense of fails
    /// CLOSED. That claim is only worth what it is tested against, so this
    /// is the awkward input, not the obvious input: URL forms that a
    /// browser, a proxy, or a resolver might read differently than
    /// `http::Uri` does.
    ///
    /// Every case here is refused. Two of them (the trailing-dot FQDN and
    /// the punycode host) name something that DNS would resolve to the
    /// backend, so refusing them is stricter than strictly necessary —
    /// which is the correct direction for a credential gate, and is pinned
    /// here so a future "fix" for the inconvenience has to argue with a
    /// failing test first.
    #[test]
    fn exotic_url_spellings_fail_closed() {
        isolate_codex_home();
        for target in [
            // Trailing-dot FQDN. Resolves to the backend; not string-equal.
            "https://chatgpt.com./x",
            "https://ChatGPT.CoM./x",
            // Backslash: browsers normalize `\` to `/`, so a reader could
            // see host `chatgpt.com` where the real authority is elsewhere.
            "https://chatgpt.com\\@evil.invalid/x",
            // Percent-encoded dot in the host.
            "https://chatgpt%2ecom/x",
            // A control character before the userinfo separator.
            "https://chatgpt.com\t@evil.invalid/x",
            // Punycode homograph (xn-- form of a lookalike domain).
            "https://xn--chtgpt-hva.com/x",
            // IPv4-mapped IPv6 loopback: still loopback, still not the
            // backend, and not spelled like either.
            "https://[::ffff:127.0.0.1]:8731/x",
            // Scheme-relative: no scheme means no origin.
            "//chatgpt.com/x",
        ] {
            assert!(
                origin_permitted(target, false).is_err(),
                "{target} must fail closed"
            );
        }
    }

    /// The other half of fail-closed: these LOOK adversarial and are not.
    /// The authority really is the backend in every one, so refusing them
    /// would be a bug in the opposite direction — a gate that cries wolf
    /// gets an escape hatch bolted on, and the escape hatch is the
    /// vulnerability.
    #[test]
    fn url_forms_that_only_look_hostile_are_still_the_backend() {
        isolate_codex_home();
        for target in [
            // `#` opens the fragment: the authority ended at `.com`.
            "https://chatgpt.com#@evil.invalid/x",
            // `?` opens the query: likewise.
            "https://chatgpt.com?@evil.invalid/x",
            // Leading zero in the port, and an empty port, both mean 443.
            "https://chatgpt.com:0443/x",
            "https://chatgpt.com:/x",
        ] {
            origin_permitted(target, false)
                .unwrap_or_else(|e| panic!("{target} is the backend origin: {e}"));
        }
    }

    #[test]
    fn the_loopback_allowance_is_the_only_widening_and_it_is_opt_in() {
        isolate_codex_home();
        // The allowance exists so the crate's httpmock suites can run; it
        // is passed `cfg!(test)`, false in every shipped artifact.
        assert!(origin_permitted("http://127.0.0.1:8731/x", true).is_ok());
        assert!(origin_permitted("http://[::1]:8731/x", true).is_ok());
        // It widens nothing else.
        assert!(origin_permitted("https://evil.invalid/x", true).is_err());
        assert!(origin_permitted("http://127.0.0.1.evil.invalid/x", true).is_err());
    }

    #[test]
    fn a_client_refuses_to_address_a_foreign_origin_and_sends_nothing() {
        // `.invalid` never resolves and the refusal happens before any
        // socket, so this test is offline by construction. It is not
        // loopback, so the cfg(test) allowance does not apply.
        let foreign = "https://evil.invalid/collect";

        let mut client = client(false);
        let err = client.get_json(foreign).unwrap_err();
        assert!(
            matches!(err, Error::UntrustedOrigin { .. }),
            "wrong error: {err:?}"
        );
        assert!(err.to_string().contains("refusing to send credentials"));
        assert!(!err.to_string().contains(FAKE_ACCESS_TOKEN));
        assert!(!err.to_string().contains(FAKE_ACCOUNT_ID));

        // The streaming path is the same gate, not a second one.
        let err = expect_stream_error(client.request_stream(Method::POST, foreign, None));
        assert!(
            matches!(err, Error::UntrustedOrigin { .. }),
            "wrong error: {err:?}"
        );

        // And the raw one-shot entry point, which takes an already
        // resolved URL, refuses it too.
        let err = client
            .send_once(&Method::GET, foreign, None, &[])
            .unwrap_err();
        assert!(
            matches!(err, Error::UntrustedOrigin { .. }),
            "wrong error: {err:?}"
        );
    }

    #[test]
    fn a_401_from_a_foreign_origin_can_never_mint_a_token() {
        // A refresh is only reachable through a 401, and a 401 is only
        // reachable through a request. Refusing the request first is what
        // makes "foreign host answers 401 -> askcodex rotates the user's real
        // refresh token and hands the new one over" unreachable.
        let server = MockServer::start();
        let token = server.mock(|when, then| {
            when.method(POST).path("/oauth/token");
            then.status(200)
                .body(format!(r#"{{"access_token":"{FAKE_ROTATED_TOKEN}"}}"#));
        });

        let mut client = client_with_token_url(false, &server.url("/oauth/token"));
        let err = client.get_json("https://evil.invalid/collect").unwrap_err();

        assert!(
            matches!(err, Error::UntrustedOrigin { .. }),
            "wrong error: {err:?}"
        );
        assert_eq!(token.calls(), 0, "no refresh may be triggered by a refusal");
    }

    // -- redirects -------------------------------------------------------

    #[test]
    fn a_cross_host_redirect_is_never_followed_and_never_replays_the_account_id() {
        // ureq 3.3.0's DEFAULT is to follow up to 10 redirects, replaying
        // every non-auth header — `ChatGPT-Account-Id` included — at the
        // `Location` host, in a request askcodex's origin check never sees.
        // askcodex pins `max_redirects(0)`: the 3xx comes back as a response
        // and becomes a loud error.
        let target = MockServer::start();
        let landing = target.mock(|when, then| {
            when.method(GET).path("/landing");
            then.status(200).body(r#"{"landed":true}"#);
        });

        let origin = MockServer::start();
        let hop = origin.mock(|when, then| {
            when.method(GET).path("/go");
            then.status(302).header("location", target.url("/landing"));
        });

        let mut client = client(false);
        let err = client.get_json(&origin.url("/go")).unwrap_err();

        match err {
            Error::HttpStatus { status, .. } => assert_eq!(status, 302),
            other => panic!("wrong error: {other:?}"),
        }
        assert_eq!(hop.calls(), 1);
        assert_eq!(
            landing.calls(),
            0,
            "the redirect target must never be contacted, let alone with the account id"
        );
    }

    // -- construction ----------------------------------------------------

    #[test]
    fn new_rejects_credentials_that_cannot_authenticate() {
        let mut auth = auth_file();
        auth.tokens = None;
        assert!(matches!(
            Client::new(auth, false),
            Err(Error::AuthTokensMissing { .. })
        ));

        let mut auth = auth_file();
        auth.tokens.as_mut().unwrap().access_token = Some(Secret::new(""));
        assert!(matches!(
            Client::new(auth, false),
            Err(Error::AuthTokensMissing { .. })
        ));

        let mut auth = auth_file();
        auth.tokens.as_mut().unwrap().account_id = None;
        assert!(matches!(
            Client::new(auth, false),
            Err(Error::AuthAccountIdMissing { .. })
        ));

        let mut auth = auth_file();
        auth.tokens.as_mut().unwrap().account_id = Some(String::new());
        assert!(matches!(
            Client::new(auth, false),
            Err(Error::AuthAccountIdMissing { .. })
        ));
    }

    #[test]
    fn new_pins_the_refresh_endpoint_to_the_production_constant() {
        // `Client::new` is a delegation to `with_token_url` — this is the
        // one assertion that keeps production pointed at auth.openai.com
        // (and it sends nothing: construction performs no request).
        let client = Client::new(auth_file(), false).expect("valid fake credentials");
        assert_eq!(client.token_url, config::TOKEN_URL);
        assert_eq!(config::TOKEN_URL, "https://auth.openai.com/oauth/token");

        // The injected endpoint is stored verbatim, never merged with or
        // overridden by anything ambient.
        let injected = client_with_token_url(false, "http://127.0.0.1:9/oauth/token");
        assert_eq!(injected.token_url, "http://127.0.0.1:9/oauth/token");
    }

    // -- headers ---------------------------------------------------------

    #[test]
    fn every_call_carries_the_backend_headers() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET)
                .path("/codex/usage")
                .header("authorization", format!("Bearer {FAKE_ACCESS_TOKEN}"))
                .header("chatgpt-account-id", FAKE_ACCOUNT_ID)
                .header("originator", config::ORIGINATOR)
                .header("user-agent", config::USER_AGENT)
                .header("accept", "application/json");
            then.status(200)
                .header("content-type", "application/json")
                .body(r#"{"plan_type":"plus"}"#);
        });

        let mut client = client(false);
        let value = client.get_json(&server.url("/codex/usage")).unwrap();

        assert_eq!(value, json!({"plan_type": "plus"}));
        mock.assert();
    }

    #[test]
    fn bodied_requests_send_compact_json_with_the_ureq_content_type() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(POST)
                .path("/codex/images/generations")
                .header("content-type", "application/json; charset=utf-8")
                .header("authorization", format!("Bearer {FAKE_ACCESS_TOKEN}"))
                .json_body(json!({"prompt": "a cat", "model": "gpt-image-2"}));
            then.status(200).body(r#"{"created":1}"#);
        });

        let mut client = client(false);
        let value = client
            .post_json(
                &server.url("/codex/images/generations"),
                &json!({"prompt": "a cat", "model": "gpt-image-2"}),
            )
            .unwrap();

        assert_eq!(value, json!({"created": 1}));
        mock.assert();
    }

    #[test]
    fn body_less_requests_send_no_content_type_and_no_body() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET)
                .path("/me")
                .is_true(|req| {
                    !req.headers_vec()
                        .iter()
                        .any(|(name, _)| name.eq_ignore_ascii_case("content-type"))
                })
                .is_true(|req| req.body_ref().is_empty());
            then.status(200).body(r#"{"name":"Someone"}"#);
        });

        let mut client = client(false);
        client.get_json(&server.url("/me")).unwrap();
        mock.assert();
    }

    // -- error mapping ---------------------------------------------------

    #[test]
    fn non_2xx_becomes_http_status_with_a_bounded_body_snippet() {
        let long_body = format!("{}TAIL", "x".repeat(config::ERROR_SNIPPET_BYTES));
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET).path("/codex/usage");
            then.status(404).body(long_body.clone());
        });

        let mut client = client(false);
        let err = client.get_json(&server.url("/codex/usage")).unwrap_err();
        mock.assert();

        match err {
            Error::HttpStatus {
                ref method,
                status,
                ref snippet,
                ..
            } => {
                assert_eq!(method, "GET");
                assert_eq!(status, 404);
                assert_eq!(snippet.len(), config::ERROR_SNIPPET_BYTES);
                assert!(!snippet.contains("TAIL"));
            }
            other => panic!("wrong error: {other:?}"),
        }
        // The rendered message keeps method, status and the body snippet.
        let rendered = err.to_string();
        assert!(rendered.contains("GET"));
        assert!(rendered.contains("HTTP 404"));
        assert!(!rendered.contains(FAKE_ACCESS_TOKEN));
    }

    #[test]
    fn empty_error_body_is_reported_as_such_not_as_blank() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/codex/usage");
            then.status(500).body("");
        });

        let mut client = client(false);
        let err = client.get_json(&server.url("/codex/usage")).unwrap_err();
        match err {
            Error::HttpStatus {
                status, snippet, ..
            } => {
                assert_eq!(status, 500);
                assert_eq!(snippet, "<empty body>");
            }
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn a_204_no_content_is_a_success_not_a_failure() {
        // 204 is the canonical answer to a DELETE, which is exactly what
        // the `raw` escape hatch exists to express. It used to be routed
        // through `NonJsonResponse` ("returned non-JSON (0 bytes)") and
        // exit 1, so a script keying on the exit code retried a delete
        // that had already succeeded.
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(DELETE).path("/codex/thing");
            then.status(204);
        });

        let mut client = client(false);
        let value = client
            .request_json(Method::DELETE, &server.url("/codex/thing"), None)
            .unwrap();

        assert_eq!(value, Value::Null);
        mock.assert();
    }

    #[test]
    fn an_empty_200_is_still_a_loud_unexpected_shape() {
        // The 204/205 allowance is exactly those two statuses: a 200 that
        // carries nothing is a response askcodex did not expect, and saying so
        // is the point.
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/codex/usage");
            then.status(200).body("");
        });

        let mut client = client(false);
        let err = client.get_json(&server.url("/codex/usage")).unwrap_err();
        assert!(
            matches!(err, Error::NonJsonResponse { len: 0, .. }),
            "wrong error: {err:?}"
        );
    }

    #[test]
    fn non_json_2xx_becomes_non_json_response() {
        let body = "<html>definitely not json</html>";
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET).path("/codex/usage");
            then.status(200).body(body);
        });

        let mut client = client(false);
        let err = client.get_json(&server.url("/codex/usage")).unwrap_err();
        mock.assert();

        match err {
            Error::NonJsonResponse {
                method,
                len,
                snippet,
                ..
            } => {
                assert_eq!(method, "GET");
                assert_eq!(len, body.len());
                assert_eq!(snippet, body);
            }
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn body_reads_are_bounded_by_an_explicit_limit() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/big");
            then.status(200).body("0123456789ABCDEF");
        });

        let client = client(false);
        let response = client
            .send_once(&Method::GET, &server.url("/big"), None, &[])
            .unwrap();
        let (_parts, body) = response.into_parts();

        // A body larger than the limit is an error, never a silent truncation.
        let err = read_body_limited(body, 8).unwrap_err();
        assert!(
            matches!(
                err,
                Error::Transport(ureq::Error::BodyExceedsLimit(8))
                    | Error::Transport(ureq::Error::Io(_))
            ),
            "wrong error: {err:?}"
        );
        assert!(err.to_string().contains("transport"));
    }

    #[test]
    fn bodies_within_the_limit_read_completely() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/big");
            then.status(200).body("0123456789ABCDEF");
        });

        let client = client(false);
        let response = client
            .send_once(&Method::GET, &server.url("/big"), None, &[])
            .unwrap();
        let (_parts, body) = response.into_parts();
        assert_eq!(read_body_limited(body, 1024).unwrap(), b"0123456789ABCDEF");
    }

    // -- 401 policy ------------------------------------------------------
    //
    // These drive the REAL `auth::refresh_with_endpoint` (no test double)
    // through `Client::with_token_url`: the OAuth POST goes to an httpmock
    // server and the rotated tokens are persisted to the scratch
    // CODEX_HOME. That is the whole point of the seam — the 401 -> refresh
    // -> retry path is exercised end to end without a live credential.

    #[test]
    fn a_401_refreshes_once_and_retries_once_with_the_new_token() {
        let _guard = lock_codex_home();
        let home = reset_codex_home();

        let server = MockServer::start();
        let unauthorized = server.mock(|when, then| {
            when.method(GET)
                .path("/codex/usage")
                .header("authorization", format!("Bearer {FAKE_ACCESS_TOKEN}"));
            then.status(401).body(r#"{"error":"expired"}"#);
        });
        let authorized = server.mock(|when, then| {
            when.method(GET)
                .path("/codex/usage")
                .header("authorization", format!("Bearer {FAKE_ROTATED_TOKEN}"));
            then.status(200).body(r#"{"plan_type":"plus"}"#);
        });
        // The OAuth host gets the codex wire shape and NO backend headers —
        // proof that the real refresh code ran, not a stand-in.
        let token = server.mock(|when, then| {
            when.method(POST)
                .path("/oauth/token")
                .header_missing("authorization")
                .header_missing("chatgpt-account-id")
                .json_body(json!({
                    "client_id": config::CLIENT_ID,
                    "grant_type": "refresh_token",
                    "refresh_token": FAKE_REFRESH_TOKEN,
                }));
            then.status(200).body(format!(
                r#"{{"access_token":"{FAKE_ROTATED_TOKEN}","refresh_token":"rotated-refresh-token"}}"#
            ));
        });

        let mut client = client_with_token_url(false, &server.url("/oauth/token"));
        let value = client.get_json(&server.url("/codex/usage")).unwrap();

        assert_eq!(value, json!({"plan_type": "plus"}));
        assert_eq!(unauthorized.calls(), 1, "exactly one original request");
        assert_eq!(authorized.calls(), 1, "exactly one retry");
        assert_eq!(token.calls(), 1, "exactly one refresh");

        // Rotated in memory...
        assert_eq!(access_token_of(&client), FAKE_ROTATED_TOKEN);
        // ...and persisted BEFORE the retry, so a crash cannot lose them.
        let written = read_json(&home.join("auth.json"));
        assert_eq!(written["tokens"]["access_token"], FAKE_ROTATED_TOKEN);
        assert_eq!(written["tokens"]["refresh_token"], "rotated-refresh-token");
        assert_eq!(written["tokens"]["account_id"], FAKE_ACCOUNT_ID);
        assert!(written["last_refresh"].is_string());
    }

    #[test]
    fn a_second_401_is_loud_and_never_loops() {
        let _guard = lock_codex_home();
        reset_codex_home();

        let server = MockServer::start();
        let always_401 = server.mock(|when, then| {
            when.method(GET).path("/codex/usage");
            then.status(401).body(r#"{"error":"still expired"}"#);
        });
        let token = server.mock(|when, then| {
            when.method(POST).path("/oauth/token");
            then.status(200)
                .body(format!(r#"{{"access_token":"{FAKE_ROTATED_TOKEN}"}}"#));
        });

        let mut client = client_with_token_url(false, &server.url("/oauth/token"));
        let err = client.get_json(&server.url("/codex/usage")).unwrap_err();

        match err {
            Error::HttpStatus {
                status, snippet, ..
            } => {
                assert_eq!(status, 401);
                assert_eq!(snippet, r#"{"error":"still expired"}"#);
            }
            other => panic!("wrong error: {other:?}"),
        }
        assert_eq!(always_401.calls(), 2, "original + exactly one retry");
        assert_eq!(token.calls(), 1, "exactly one refresh, never a loop");
    }

    #[test]
    fn a_refresh_that_cannot_run_is_propagated_and_the_request_is_not_retried() {
        // This test reaches the refresh path, so it touches the shared
        // scratch CODEX_HOME (the credential lock file is created beside
        // `auth.json`) even though the refresh fails before sending
        // anything. `auth::assert_codex_home_locked` enforces this guard.
        let _guard = lock_codex_home();
        let server = MockServer::start();
        let backend = server.mock(|when, then| {
            when.method(GET).path("/codex/usage");
            then.status(401).body("nope");
        });
        let token = server.mock(|when, then| {
            when.method(POST).path("/oauth/token");
            then.status(200)
                .body(format!(r#"{{"access_token":"{FAKE_ROTATED_TOKEN}"}}"#));
        });

        // No refresh_token in the file: the refresh must fail before it
        // sends anything, and the request must not be retried.
        let mut auth = auth_file();
        auth.tokens.as_mut().unwrap().refresh_token = None;
        let mut client = Client::with_token_url(auth, false, &server.url("/oauth/token"))
            .expect("valid fake credentials");

        let err = client.get_json(&server.url("/codex/usage")).unwrap_err();

        assert!(
            matches!(err, Error::RefreshUnavailable),
            "wrong error: {err:?}"
        );
        assert_eq!(backend.calls(), 1, "no retry after a failed refresh");
        assert_eq!(token.calls(), 0, "nothing is sent without a refresh_token");
    }

    #[test]
    fn a_rejected_refresh_is_loud_and_leaves_auth_json_untouched() {
        let _guard = lock_codex_home();
        let home = reset_codex_home();
        // A sentinel document: a failed refresh must not rewrite a single
        // byte of it (the old refresh token is still the live one).
        let sentinel = r#"{"sentinel":"untouched"}"#;
        std::fs::write(home.join("auth.json"), sentinel).expect("seed auth.json");

        let server = MockServer::start();
        let backend = server.mock(|when, then| {
            when.method(GET).path("/codex/usage");
            then.status(401).body("expired");
        });
        let token = server.mock(|when, then| {
            when.method(POST).path("/oauth/token");
            then.status(400)
                .body(r#"{"error":"invalid_grant","error_description":"refresh_token_expired"}"#);
        });

        let mut client = client_with_token_url(false, &server.url("/oauth/token"));
        let err = client.get_json(&server.url("/codex/usage")).unwrap_err();

        match &err {
            Error::RefreshFailed { status, snippet } => {
                assert_eq!(*status, 400);
                assert!(snippet.contains("refresh_token_expired"), "got {snippet}");
            }
            other => panic!("wrong error: {other:?}"),
        }
        assert_eq!(backend.calls(), 1, "no retry after a failed refresh");
        assert_eq!(token.calls(), 1, "exactly one refresh attempt");
        // A failed refresh writes NOTHING: the old credentials are still
        // the ones the server knows.
        assert_eq!(access_token_of(&client), FAKE_ACCESS_TOKEN);
        assert_eq!(
            std::fs::read_to_string(home.join("auth.json")).expect("auth.json still there"),
            sentinel
        );
        assert!(
            !home.join("auth.json.bak").exists(),
            "nothing was persisted, so nothing was backed up"
        );
    }

    #[test]
    fn no_refresh_makes_a_401_immediately_loud_with_guidance() {
        let server = MockServer::start();
        let backend = server.mock(|when, then| {
            when.method(GET).path("/codex/usage");
            then.status(401).body(r#"{"error":"expired"}"#);
        });
        let token = server.mock(|when, then| {
            when.method(POST).path("/oauth/token");
            then.status(200)
                .body(format!(r#"{{"access_token":"{FAKE_ROTATED_TOKEN}"}}"#));
        });

        let mut client = client_with_token_url(true, &server.url("/oauth/token"));
        let err = client.get_json(&server.url("/codex/usage")).unwrap_err();

        match err {
            Error::HttpStatus {
                status,
                ref snippet,
                ..
            } => {
                assert_eq!(status, 401);
                assert!(snippet.starts_with(r#"{"error":"expired"}"#));
                assert!(snippet.contains("askcodex auth refresh"));
                assert!(snippet.contains("--no-refresh"));
            }
            ref other => panic!("wrong error: {other:?}"),
        }
        assert!(!err.to_string().contains(FAKE_ACCESS_TOKEN));
        assert_eq!(backend.calls(), 1, "no retry when --no-refresh is set");
        assert_eq!(
            token.calls(),
            0,
            "--no-refresh must not mint a token behind the user's back"
        );
    }

    #[test]
    fn the_no_refresh_401_snippet_stays_inside_the_documented_bound() {
        // error.rs documents `HttpStatus.snippet` as bounded by
        // `config::ERROR_SNIPPET_BYTES`. This branch used to append its
        // guidance AFTER an already-maximal snippet, emitting ~494 bytes
        // on a field documented as 400. The shipped test only ever used a
        // 19-byte body, so the bound was never reached.
        let long_body = "x".repeat(config::ERROR_SNIPPET_BYTES * 2);
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/codex/usage");
            then.status(401).body(long_body);
        });

        let mut client = client_with_token_url(true, UNREACHABLE_TOKEN_URL);
        let err = client.get_json(&server.url("/codex/usage")).unwrap_err();

        match err {
            Error::HttpStatus {
                status,
                ref snippet,
                ..
            } => {
                assert_eq!(status, 401);
                assert!(
                    snippet.len() <= config::ERROR_SNIPPET_BYTES,
                    "snippet is {} bytes, bound is {}",
                    snippet.len(),
                    config::ERROR_SNIPPET_BYTES
                );
                // Bounded, but still both halves: body first, guidance
                // intact — truncating the guidance away would be worse
                // than the over-long field.
                assert!(snippet.starts_with("xxxx"));
                assert!(snippet.contains("--no-refresh"));
                assert!(snippet.ends_with("run `askcodex auth refresh`]"));
            }
            ref other => panic!("wrong error: {other:?}"),
        }
    }

    // -- pre-flight freshness --------------------------------------------

    #[test]
    fn ensure_fresh_refreshes_an_expired_token_through_the_injected_endpoint() {
        let _guard = lock_codex_home();
        let home = reset_codex_home();

        let server = MockServer::start();
        let token = server.mock(|when, then| {
            when.method(POST).path("/oauth/token").json_body(json!({
                "client_id": config::CLIENT_ID,
                "grant_type": "refresh_token",
                "refresh_token": FAKE_REFRESH_TOKEN,
            }));
            then.status(200)
                .body(format!(r#"{{"access_token":"{FAKE_ROTATED_TOKEN}"}}"#));
        });

        let mut auth = auth_file();
        // Expired an hour ago: needs_refresh decodes this, so it must be a
        // well-formed (fake) JWT rather than the opaque literal.
        auth.tokens.as_mut().unwrap().access_token = Some(Secret::new(fake_jwt_expiring_at(
            chrono::Utc::now().timestamp() - 3600,
        )));
        let mut client = Client::with_token_url(auth, false, &server.url("/oauth/token"))
            .expect("valid fake credentials");

        client.ensure_fresh().unwrap();

        assert_eq!(token.calls(), 1, "exactly one pre-flight refresh");
        assert_eq!(access_token_of(&client), FAKE_ROTATED_TOKEN);
        assert_eq!(
            read_json(&home.join("auth.json"))["tokens"]["access_token"],
            FAKE_ROTATED_TOKEN
        );
    }

    #[test]
    fn no_refresh_skips_the_preflight_refresh() {
        let server = MockServer::start();
        let token = server.mock(|when, then| {
            when.method(POST).path("/oauth/token");
            then.status(200)
                .body(format!(r#"{{"access_token":"{FAKE_ROTATED_TOKEN}"}}"#));
        });

        // An access token that expired an hour ago: without --no-refresh
        // this would refresh. With it, ensure_fresh must not even ask.
        let expired = fake_jwt_expiring_at(chrono::Utc::now().timestamp() - 3600);
        let mut auth = auth_file();
        auth.tokens.as_mut().unwrap().access_token = Some(Secret::new(expired.clone()));
        let mut client = Client::with_token_url(auth, true, &server.url("/oauth/token"))
            .expect("valid fake credentials");

        client.ensure_fresh().unwrap();

        assert_eq!(token.calls(), 0);
        assert_eq!(
            access_token_of(&client),
            expired,
            "the stored token is untouched"
        );
    }

    // -- streaming -------------------------------------------------------

    #[test]
    fn streaming_sets_sse_headers_and_yields_lines_incrementally() {
        let stream = "event: response.output_text.delta\n\
                      data: {\"type\":\"response.output_text.delta\",\"delta\":\"Hi\"}\n\
                      \n\
                      event: response.completed\n\
                      data: {\"type\":\"response.completed\"}\n\n";
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(POST)
                .path("/codex/responses")
                .header("accept", "text/event-stream")
                .header("openai-beta", "responses=experimental")
                .header("content-type", "application/json; charset=utf-8")
                // Exactly one Accept header: extra headers replace the
                // base `Accept: application/json`, they do not duplicate it.
                .is_true(|req| {
                    req.headers_vec()
                        .iter()
                        .filter(|(name, _)| name.eq_ignore_ascii_case("accept"))
                        .count()
                        == 1
                })
                .json_body(json!({"model": "gpt-5.4-mini", "stream": true}));
            then.status(200)
                .header("content-type", "text/event-stream")
                .body(stream);
        });

        let mut client = client(false);
        let reader = client
            .request_stream(
                Method::POST,
                &server.url("/codex/responses"),
                Some(&json!({"model": "gpt-5.4-mini", "stream": true})),
            )
            .unwrap();

        let data_lines: Vec<String> = reader
            .lines()
            .map(|l| l.unwrap())
            .filter(|l| l.starts_with("data:"))
            .collect();

        assert_eq!(
            data_lines,
            vec![
                r#"data: {"type":"response.output_text.delta","delta":"Hi"}"#.to_string(),
                r#"data: {"type":"response.completed"}"#.to_string(),
            ]
        );
        mock.assert();
    }

    #[test]
    fn streaming_hands_back_an_unconsumed_reader() {
        // The whole body is never buffered: the first line is available
        // and the rest of the stream can simply be dropped.
        let mut stream = String::new();
        for i in 0..2000 {
            stream.push_str(&format!("data: {{\"n\":{i}}}\n\n"));
        }
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/codex/responses");
            then.status(200)
                .header("content-type", "text/event-stream")
                .body(stream);
        });

        let mut client = client(false);
        let mut reader = client
            .request_stream(Method::POST, &server.url("/codex/responses"), None)
            .unwrap();

        let mut first = String::new();
        reader.read_line(&mut first).unwrap();
        assert_eq!(first, "data: {\"n\":0}\n");
        drop(reader);
    }

    #[test]
    fn streaming_non_2xx_is_loud_before_any_byte_is_consumed() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/codex/responses");
            then.status(429).body(r#"{"error":"rate limited"}"#);
        });

        let mut client = client(false);
        let err = expect_stream_error(client.request_stream(
            Method::POST,
            &server.url("/codex/responses"),
            Some(&json!({"model": "gpt-5.4-mini"})),
        ));

        match err {
            Error::HttpStatus {
                method,
                status,
                snippet,
                ..
            } => {
                assert_eq!(method, "POST");
                assert_eq!(status, 429);
                assert_eq!(snippet, r#"{"error":"rate limited"}"#);
            }
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn streaming_401_with_no_refresh_is_loud() {
        let server = MockServer::start();
        let backend = server.mock(|when, then| {
            when.method(POST).path("/codex/responses");
            then.status(401).body("unauthorized");
        });
        let token = server.mock(|when, then| {
            when.method(POST).path("/oauth/token");
            then.status(200)
                .body(format!(r#"{{"access_token":"{FAKE_ROTATED_TOKEN}"}}"#));
        });

        let mut client = client_with_token_url(true, &server.url("/oauth/token"));
        let err = expect_stream_error(client.request_stream(
            Method::POST,
            &server.url("/codex/responses"),
            None,
        ));

        assert!(matches!(err, Error::HttpStatus { status: 401, .. }));
        assert!(err.to_string().contains("askcodex auth refresh"));
        assert_eq!(backend.calls(), 1);
        assert_eq!(token.calls(), 0, "no refresh when --no-refresh is set");
    }

    #[test]
    fn streaming_401_refreshes_once_and_retries_before_any_byte_is_consumed() {
        let _guard = lock_codex_home();
        reset_codex_home();

        let server = MockServer::start();
        let unauthorized = server.mock(|when, then| {
            when.method(POST)
                .path("/codex/responses")
                .header("authorization", format!("Bearer {FAKE_ACCESS_TOKEN}"));
            then.status(401).body("unauthorized");
        });
        let authorized = server.mock(|when, then| {
            when.method(POST)
                .path("/codex/responses")
                .header("authorization", format!("Bearer {FAKE_ROTATED_TOKEN}"));
            then.status(200)
                .header("content-type", "text/event-stream")
                .body("data: {\"type\":\"response.completed\"}\n\n");
        });
        let token = server.mock(|when, then| {
            when.method(POST).path("/oauth/token");
            then.status(200)
                .body(format!(r#"{{"access_token":"{FAKE_ROTATED_TOKEN}"}}"#));
        });

        let mut client = client_with_token_url(false, &server.url("/oauth/token"));
        let mut reader = client
            .request_stream(Method::POST, &server.url("/codex/responses"), None)
            .unwrap();

        let mut first = String::new();
        reader.read_line(&mut first).unwrap();
        assert_eq!(first, "data: {\"type\":\"response.completed\"}\n");
        assert_eq!(unauthorized.calls(), 1);
        assert_eq!(authorized.calls(), 1);
        assert_eq!(token.calls(), 1);
    }

    // -- transport -------------------------------------------------------

    #[test]
    fn transport_failures_are_loud_and_never_silently_empty() {
        // Port 1 on loopback: nothing listens, so the connect fails.
        let mut client = client(false);
        let err = client
            .get_json("http://127.0.0.1:1/codex/usage")
            .unwrap_err();
        assert!(matches!(err, Error::Transport(_)), "wrong error: {err:?}");
    }

    #[test]
    fn snippet_helpers_never_exceed_the_configured_bound() {
        isolate_codex_home();
        let bytes = vec![b'z'; config::ERROR_SNIPPET_BYTES * 3];
        assert_eq!(snippet_of_bytes(&bytes).len(), config::ERROR_SNIPPET_BYTES);
        assert_eq!(snippet_of_bytes(b"short"), "short");
        // Invalid UTF-8 is replaced, not dropped or panicked on.
        assert!(!snippet_of_bytes(&[0xff, 0xfe]).is_empty());
        // ...and the replacement does not blow the bound: `from_utf8_lossy`
        // turns each invalid byte into a 3-byte U+FFFD, so the RENDERED
        // string is bounded too, not just the slice it was made from.
        let invalid = vec![0xffu8; config::ERROR_SNIPPET_BYTES * 3];
        assert!(snippet_of_bytes(&invalid).len() <= config::ERROR_SNIPPET_BYTES);
    }
}
