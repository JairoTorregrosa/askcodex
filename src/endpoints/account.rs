//! Account/identity endpoints: usage, profile, models catalog.
//!
//! Every function here does exactly ONE backend call per endpoint (the
//! 401 -> refresh -> retry policy lives in `http::Client` and is the only
//! retry in askcodex; nothing in this module loops).
//!
//! Two shapes come back from each call: the typed decode (for human
//! rendering) and the RAW `serde_json::Value` — the WHOLE wire document,
//! never a slice of it — which is what `--json` prints, so a `--json` run
//! never loses a field askcodex does not model.
//!
//! Failure policy: a body that does not decode into the documented shape is
//! `Error::UnexpectedResponse` naming the endpoint, what did not fit, and
//! the key NAMES that were present — never a partial value, never a
//! default. Unknown/extra keys are NOT a failure: askcodex is a client of a
//! backend it does not control.
//!
//! Test seam: each public function is a one-line wrapper over an `*_at`
//! core that takes an ORIGIN prefix. Production passes `""`, which leaves
//! the path relative so `http::Client` prefixes `config::BASE_URL`; the
//! unit tests pass a local httpmock root, so no test can reach the real
//! backend. The production paths themselves are pinned by
//! `paths_match_the_wire_contract`.

use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::error::Error;
use crate::http::Client;
use crate::models::{MeResponse, ModelInfo, UsageResponse, WhoamiOutput};

/// Usage/quota endpoint, relative to `config::BASE_URL`.
const USAGE_PATH: &str = "/codex/usage";

/// Profile endpoint. It hangs off `/backend-api` DIRECTLY — putting it
/// under `/codex` yields a silent 404 (docs/PROTOCOL.md §3.2).
const ME_PATH: &str = "/me";

/// Model catalog endpoint. Always requested with the `client_version`
/// query parameter, which the backend requires (docs/PROTOCOL.md §3.3).
const MODELS_PATH: &str = "/codex/models";

/// `GET /codex/usage`.
///
/// Contract: returns the typed decode AND the raw value (the `--json`
/// output for `askcodex usage` is the raw value, pretty-printed). A decode
/// failure is loud: `Error::UnexpectedResponse` naming `/codex/usage` and
/// the serde error, never a partial default.
pub fn usage(client: &mut Client) -> Result<(UsageResponse, Value), Error> {
    usage_at(client, "")
}

/// `GET /me` (under `/backend-api`, NOT `/codex` — Python parity).
/// Same typed+raw contract as [`usage`].
/// Compose `usage` + `me` into the whoami identity (email, name, user_id,
/// account_id, plan_type). Both calls must succeed; there is no partial
/// whoami. The returned struct is the `--json` output shape.
pub fn whoami(client: &mut Client) -> Result<WhoamiOutput, Error> {
    whoami_at(client, "")
}

/// `GET /codex/models?client_version=<v>` — the query param is REQUIRED by
/// the backend; `v` comes from the CLI (default `config::CLIENT_VERSION`).
///
/// The wire document is the envelope `{"models": [ ... ]}`
/// (docs/PROTOCOL.md §3.3).
///
/// Contract: returns the typed model list AND the raw WHOLE envelope —
/// the `--json` output for `askcodex models` is that envelope, byte-faithful,
/// so an envelope-level sibling askcodex does not model (a `default_model`, a
/// paging cursor) reaches the user instead of vanishing. A response
/// without a `models` array is `Error::UnexpectedResponse`.
///
/// Returning only the inner `models` array would silently discard every
/// sibling key — a truncated catalog presented as the whole catalog once
/// the backend starts paging, which the crate-wide "no partial result
/// presented as success" rule forbids, and which would contradict the
/// `--json` promise in README.md and DESIGN.md. Scripts that want just
/// the array read `.models`.
pub fn models(client: &mut Client, client_version: &str) -> Result<(Vec<ModelInfo>, Value), Error> {
    models_at(client, "", client_version)
}

// ---------------------------------------------------------------------------
// cores (origin-parameterized; see the module docs)
// ---------------------------------------------------------------------------

fn usage_at(client: &mut Client, origin: &str) -> Result<(UsageResponse, Value), Error> {
    let raw = client.get_json(&format!("{origin}{USAGE_PATH}"))?;
    let typed = decode(&raw, USAGE_PATH, "usage response")?;
    Ok((typed, raw))
}

fn me_at(client: &mut Client, origin: &str) -> Result<(MeResponse, Value), Error> {
    let raw = client.get_json(&format!("{origin}{ME_PATH}"))?;
    let typed = decode(&raw, ME_PATH, "profile response")?;
    Ok((typed, raw))
}

fn whoami_at(client: &mut Client, origin: &str) -> Result<WhoamiOutput, Error> {
    // Both calls must succeed — a whoami built from one of them would be a
    // partial result presented as a whole. Individual FIELDS are a
    // different matter: every one is `Option` on the wire and in
    // `WhoamiOutput`, and run.rs renders an absent one as `-`, so a missing
    // field is surfaced as absent rather than invented or errored on.
    let (usage, _) = usage_at(client, origin)?;
    let (me, _) = me_at(client, origin)?;

    // Field provenance is NOT interchangeable (Python parity, cmd_whoami):
    // `name` comes from /me; email, ids and plan come from /codex/usage —
    // even when /me also carries an `email`.
    Ok(WhoamiOutput {
        email: usage.email,
        name: me.name,
        user_id: usage.user_id,
        account_id: usage.account_id,
        plan_type: usage.plan_type,
    })
}

fn models_at(
    client: &mut Client,
    origin: &str,
    client_version: &str,
) -> Result<(Vec<ModelInfo>, Value), Error> {
    let path = models_path(client_version);
    let raw = client.get_json(&format!("{origin}{path}"))?;
    let typed = decode_models(&raw, &path)?;
    // The whole document, not `raw["models"]`: see the `models` contract.
    Ok((typed, raw))
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Relative path for the model catalog, including the required query
/// parameter.
///
/// Python parity: `client_version` is interpolated verbatim, not
/// percent-encoded. A value that is not URI-safe therefore produces an
/// invalid URI and fails loudly in the transport layer, instead of being
/// silently rewritten into something the user did not ask for.
fn models_path(client_version: &str) -> String {
    format!("{MODELS_PATH}?client_version={client_version}")
}

/// Typed decode of a whole response body, loud on any mismatch.
fn decode<T: DeserializeOwned>(raw: &Value, path: &str, what: &str) -> Result<T, Error> {
    serde_json::from_value(raw.clone()).map_err(|source| {
        unexpected(format!(
            "GET {path} did not decode as the {what}: {source}; {}",
            shape_of(raw)
        ))
    })
}

/// Typed decode of the catalog envelope's `models` array, for the human
/// rendering only — the raw value `--json` prints is the whole envelope
/// `models_at` already holds, so nothing is sliced out of it here.
///
/// `models::ModelsResponse` is deliberately NOT used: its `models` field
/// carries `#[serde(default)]`, so an envelope without the key would decode
/// as an empty catalog — a default that masks a broken response. The key is
/// required here and its absence is loud.
fn decode_models(raw: &Value, path: &str) -> Result<Vec<ModelInfo>, Error> {
    let Some(Value::Array(entries)) = raw.get("models") else {
        return Err(unexpected(format!(
            "GET {path} response has no `models` array; {}",
            shape_of(raw)
        )));
    };

    let mut typed = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let model: ModelInfo = serde_json::from_value(entry.clone()).map_err(|source| {
            unexpected(format!(
                "GET {path}: models[{index}] did not decode as a model entry: {source}; {}",
                shape_of(entry)
            ))
        })?;
        typed.push(model);
    }

    Ok(typed)
}

/// Describe a JSON value for an error message: key NAMES (sorted) for an
/// object, the type otherwise.
///
/// Never renders values — these payloads carry `email`, `user_id` and
/// `account_id`, and an error message is not the place for them.
fn shape_of(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&str> = map.keys().map(String::as_str).collect();
            keys.sort_unstable();
            format!("keys={keys:?}")
        }
        Value::Array(items) => format!("body is a JSON array of {} item(s)", items.len()),
        Value::Null => "body is JSON null".to_string(),
        Value::Bool(_) => "body is a JSON boolean".to_string(),
        Value::Number(_) => "body is a JSON number".to_string(),
        Value::String(_) => "body is a JSON string".to_string(),
    }
}

fn unexpected(context: String) -> Error {
    Error::UnexpectedResponse { context }
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

// Isolation: every test below drives the `*_at` cores against a LOCAL
// httpmock origin, so no request can reach chatgpt.com. Nothing here
// performs filesystem I/O: `Client::new` only consults `config::auth_path()`
// on the failure paths, and these credentials are (invented) valid ones, so
// the real `~/.codex/auth.json` is never opened. The public wrappers are
// deliberately NOT called — with origin `""` they resolve to the real
// backend; their paths are pinned by `paths_match_the_wire_contract`
// instead.
#[cfg(test)]
mod tests {
    use httpmock::Method::GET;
    use httpmock::MockServer;
    use serde_json::json;

    use super::*;
    use crate::config;
    use crate::models::{AuthFile, AuthTokens};
    use crate::redact::Secret;

    /// The sanitized payloads captured from the live backend. Using the
    /// files themselves (compile-time include, no runtime I/O) keeps the
    /// fixtures from drifting away from what the backend actually sent.
    const USAGE_SAMPLE: &str = include_str!("../../docs/samples/usage.json");
    /// NOTE: this sample is the whole wire document — the envelope
    /// `{"models": [ ... ]}` — and that is exactly what `askcodex models
    /// --json` prints, so tests that assert on the raw value compare
    /// against the whole `sample(MODELS_SAMPLE)`, never a slice of it.
    const MODELS_SAMPLE: &str = include_str!("../../docs/samples/models.json");

    /// Invented, non-functional credential values.
    const FAKE_ACCESS_TOKEN: &str = "fake.access.token-AAA";
    const FAKE_REFRESH_TOKEN: &str = "fake-refresh-token";
    const FAKE_ACCOUNT_ID: &str = "acct_fake_0000";

    fn client() -> Client {
        let auth = AuthFile {
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
        };
        // `true`: never even consider a refresh from a test.
        Client::new(auth, true).expect("valid fake credentials")
    }

    fn sample(raw: &str) -> Value {
        serde_json::from_str(raw).expect("captured sample is valid JSON")
    }

    fn models_envelope(entries: Value) -> Value {
        json!({ "models": entries })
    }

    // -- paths -----------------------------------------------------------

    #[test]
    fn paths_match_the_wire_contract() {
        assert_eq!(USAGE_PATH, "/codex/usage");
        assert_eq!(
            models_path("0.147.0"),
            "/codex/models?client_version=0.147.0"
        );
        // /me hangs off /backend-api directly; under /codex it 404s.
        assert_eq!(ME_PATH, "/me");
        assert!(!ME_PATH.contains("codex"));
        // The CLI default must be what the endpoint actually asks for.
        assert!(models_path(config::CLIENT_VERSION).ends_with(config::CLIENT_VERSION));
    }

    // -- usage -----------------------------------------------------------

    #[test]
    fn usage_decodes_the_captured_sample_and_returns_it_raw() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET).path("/codex/usage");
            then.status(200)
                .header("content-type", "application/json")
                .body(USAGE_SAMPLE);
        });

        let mut client = client();
        let (typed, raw) = usage_at(&mut client, &server.base_url()).unwrap();
        mock.assert();

        assert_eq!(typed.plan_type.as_deref(), Some("plus"));
        let rate_limit = typed.rate_limit.expect("sample carries rate_limit");
        assert_eq!(rate_limit.allowed, Some(true));
        assert_eq!(rate_limit.limit_reached, Some(false));
        let primary = rate_limit
            .primary_window
            .expect("sample has a primary window");
        assert_eq!(primary.used_percent, Some(20.0));
        assert_eq!(primary.limit_window_seconds, Some(604_800));
        assert_eq!(primary.reset_after_seconds, Some(16361));
        // A null window stays absent instead of becoming a zeroed default.
        assert!(rate_limit.secondary_window.is_none());

        // The raw value is byte-faithful: fields askcodex does not model (and a
        // per-window field it does not model either) survive for `--json`.
        assert_eq!(raw, sample(USAGE_SAMPLE));
        assert!(raw.get("credits").is_some());
        assert_eq!(
            raw["rate_limit"]["primary_window"]["reset_at"],
            1_786_176_171_i64
        );
    }

    #[test]
    fn usage_tolerates_unknown_fields_and_absent_known_ones() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/codex/usage");
            then.status(200).json_body(json!({
                "plan_type": "pro",
                "brand_new_key": {"nested": [1, 2, 3]},
                "rate_limit": {
                    "allowed": true,
                    "primary_window": {"used_percent": 3.5, "future_field": "ignored"}
                }
            }));
        });

        let mut client = client();
        let (typed, raw) = usage_at(&mut client, &server.base_url()).unwrap();

        assert_eq!(typed.plan_type.as_deref(), Some("pro"));
        // Absent means absent — never an empty string.
        assert!(typed.email.is_none());
        assert!(typed.user_id.is_none());
        assert!(typed.account_id.is_none());
        let window = typed
            .rate_limit
            .and_then(|r| r.primary_window)
            .expect("primary window present");
        assert_eq!(window.used_percent, Some(3.5));
        assert!(window.limit_window_seconds.is_none());
        assert_eq!(raw["brand_new_key"]["nested"], json!([1, 2, 3]));
    }

    #[test]
    fn usage_shape_mismatch_is_loud_and_names_the_endpoint() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/codex/usage");
            then.status(200)
                .json_body(json!({"plan_type": "plus", "rate_limit": "unlimited"}));
        });

        let mut client = client();
        let err = usage_at(&mut client, &server.base_url()).unwrap_err();

        match err {
            Error::UnexpectedResponse { ref context } => {
                assert!(context.contains("/codex/usage"), "{context}");
                assert!(context.contains("usage response"), "{context}");
                // The keys that WERE present, by name.
                assert!(context.contains("\"rate_limit\""), "{context}");
                assert!(context.contains("\"plan_type\""), "{context}");
            }
            other => panic!("wrong error: {other:?}"),
        }
        assert!(err.to_string().starts_with("unexpected response shape:"));
    }

    #[test]
    fn usage_non_2xx_surfaces_status_and_body_snippet() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET).path("/codex/usage");
            then.status(503).body(r#"{"detail":"backend down"}"#);
        });

        let mut client = client();
        let err = usage_at(&mut client, &server.base_url()).unwrap_err();
        mock.assert();

        match err {
            Error::HttpStatus {
                ref method,
                status,
                ref snippet,
                ..
            } => {
                assert_eq!(method, "GET");
                assert_eq!(status, 503);
                assert_eq!(snippet, r#"{"detail":"backend down"}"#);
            }
            ref other => panic!("wrong error: {other:?}"),
        }
        let rendered = err.to_string();
        assert!(rendered.contains("HTTP 503"), "{rendered}");
        assert!(rendered.contains("backend down"), "{rendered}");
        assert!(!rendered.contains(FAKE_ACCESS_TOKEN));
    }

    #[test]
    fn usage_non_json_body_is_loud() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/codex/usage");
            then.status(200).body("<html>login</html>");
        });

        let mut client = client();
        let err = usage_at(&mut client, &server.base_url()).unwrap_err();
        assert!(
            matches!(err, Error::NonJsonResponse { .. }),
            "wrong error: {err:?}"
        );
    }

    // -- /me -------------------------------------------------------------

    #[test]
    fn me_reads_the_profile_from_backend_api_not_codex() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            // Exactly `/me`: a request under /codex would not match, which
            // is what a wrong base would produce.
            when.method(GET).path("/me");
            then.status(200).json_body(json!({
                "name": "Fake Person",
                "email": "someone@example.invalid",
                "picture": "https://example.invalid/a.png"
            }));
        });

        let mut client = client();
        let (typed, raw) = me_at(&mut client, &server.base_url()).unwrap();
        mock.assert();

        assert_eq!(typed.name.as_deref(), Some("Fake Person"));
        assert_eq!(typed.email.as_deref(), Some("someone@example.invalid"));
        // Unknown fields survive on the raw path.
        assert_eq!(raw["picture"], "https://example.invalid/a.png");
    }

    #[test]
    fn me_absent_name_is_none_never_an_empty_string() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/me");
            then.status(200).json_body(json!({}));
        });

        let mut client = client();
        let (typed, _) = me_at(&mut client, &server.base_url()).unwrap();
        assert!(typed.name.is_none());
        assert!(typed.email.is_none());
    }

    #[test]
    fn me_shape_mismatch_is_loud_and_names_the_endpoint() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/me");
            then.status(200).json_body(json!([{"name": "Fake Person"}]));
        });

        let mut client = client();
        let err = me_at(&mut client, &server.base_url()).unwrap_err();

        match err {
            Error::UnexpectedResponse { context } => {
                assert!(context.contains("/me"), "{context}");
                assert!(context.contains("profile response"), "{context}");
                assert!(context.contains("JSON array of 1 item"), "{context}");
            }
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn me_non_2xx_surfaces_status_and_body_snippet() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/me");
            then.status(404).body("not found");
        });

        let mut client = client();
        let err = me_at(&mut client, &server.base_url()).unwrap_err();
        match err {
            Error::HttpStatus {
                status,
                path,
                snippet,
                ..
            } => {
                assert_eq!(status, 404);
                assert!(path.ends_with("/me"), "{path}");
                assert_eq!(snippet, "not found");
            }
            other => panic!("wrong error: {other:?}"),
        }
    }

    // -- whoami ----------------------------------------------------------

    #[test]
    fn whoami_takes_name_from_me_and_everything_else_from_usage() {
        let server = MockServer::start();
        let usage_mock = server.mock(|when, then| {
            when.method(GET).path("/codex/usage");
            then.status(200).json_body(json!({
                "email": "usage@example.invalid",
                "user_id": "user_fake_1",
                "account_id": "acct_fake_1",
                "plan_type": "plus"
            }));
        });
        let me_mock = server.mock(|when, then| {
            when.method(GET).path("/me");
            then.status(200).json_body(json!({
                "name": "Fake Person",
                // Deliberately different: whoami must NOT take email here.
                "email": "profile@example.invalid"
            }));
        });

        let mut client = client();
        let out = whoami_at(&mut client, &server.base_url()).unwrap();
        usage_mock.assert();
        me_mock.assert();

        assert_eq!(out.email.as_deref(), Some("usage@example.invalid"));
        assert_eq!(out.name.as_deref(), Some("Fake Person"));
        assert_eq!(out.user_id.as_deref(), Some("user_fake_1"));
        assert_eq!(out.account_id.as_deref(), Some("acct_fake_1"));
        assert_eq!(out.plan_type.as_deref(), Some("plus"));

        // This struct IS the `--json` shape: exactly these five keys.
        let rendered = serde_json::to_value(&out).unwrap();
        let mut keys: Vec<&str> = rendered
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["account_id", "email", "name", "plan_type", "user_id"]
        );
    }

    #[test]
    fn whoami_absent_fields_stay_null_instead_of_being_invented() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/codex/usage");
            then.status(200).json_body(json!({"plan_type": "plus"}));
        });
        server.mock(|when, then| {
            when.method(GET).path("/me");
            then.status(200).json_body(json!({}));
        });

        let mut client = client();
        let out = whoami_at(&mut client, &server.base_url()).unwrap();

        assert!(out.email.is_none());
        assert!(out.name.is_none());
        assert!(out.user_id.is_none());
        assert!(out.account_id.is_none());
        assert_eq!(out.plan_type.as_deref(), Some("plus"));
        assert_eq!(serde_json::to_value(&out).unwrap()["name"], Value::Null);
    }

    #[test]
    fn whoami_fails_when_the_profile_call_fails_no_partial_identity() {
        let server = MockServer::start();
        let usage_mock = server.mock(|when, then| {
            when.method(GET).path("/codex/usage");
            then.status(200)
                .json_body(json!({"email": "usage@example.invalid", "plan_type": "plus"}));
        });
        server.mock(|when, then| {
            when.method(GET).path("/me");
            then.status(500).body("boom");
        });

        let mut client = client();
        let err = whoami_at(&mut client, &server.base_url()).unwrap_err();

        assert_eq!(
            usage_mock.calls(),
            1,
            "one call per endpoint, no retry loop"
        );
        match err {
            Error::HttpStatus {
                status,
                path,
                snippet,
                ..
            } => {
                assert_eq!(status, 500);
                assert!(path.ends_with("/me"), "{path}");
                assert_eq!(snippet, "boom");
            }
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn whoami_fails_when_the_usage_call_fails_and_never_calls_me() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/codex/usage");
            then.status(500).body("boom");
        });
        let me_mock = server.mock(|when, then| {
            when.method(GET).path("/me");
            then.status(200).json_body(json!({"name": "Fake Person"}));
        });

        let mut client = client();
        let err = whoami_at(&mut client, &server.base_url()).unwrap_err();

        assert!(matches!(err, Error::HttpStatus { status: 500, .. }));
        assert_eq!(me_mock.calls(), 0, "the first failure aborts whoami");
    }

    // -- models ----------------------------------------------------------

    #[test]
    fn models_sends_the_required_client_version_query_param() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET)
                .path("/codex/models")
                .query_param("client_version", "9.9.9-test");
            then.status(200)
                .header("content-type", "application/json")
                .body(MODELS_SAMPLE);
        });

        let mut client = client();
        let (typed, _) = models_at(&mut client, &server.base_url(), "9.9.9-test").unwrap();

        mock.assert();
        assert_eq!(typed.len(), 8);
    }

    #[test]
    fn models_decodes_the_captured_envelope_and_returns_the_whole_raw_document() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/codex/models");
            then.status(200)
                .header("content-type", "application/json")
                .body(MODELS_SAMPLE);
        });

        let mut client = client();
        let (typed, raw) = models_at(&mut client, &server.base_url(), "0.147.0").unwrap();

        assert_eq!(typed.len(), 8);
        assert_eq!(typed[0].slug, "gpt-5.6-sol");
        assert_eq!(typed[0].input_modalities, ["text", "image"]);
        assert_eq!(typed[0].visibility.as_deref(), Some("list"));
        let efforts: Vec<&str> = typed[0]
            .supported_reasoning_levels
            .iter()
            .filter_map(|level| level.effort.as_deref())
            .collect();
        assert_eq!(efforts, ["low", "medium", "high", "xhigh", "max", "ultra"]);
        assert_eq!(typed[1].visibility.as_deref(), Some("hide"));

        // The captured entries really are OBJECTS, not bare strings: the
        // sibling `description` key is what a flattened capture would lose.
        assert_eq!(
            raw["models"][0]["supported_reasoning_levels"][0]["effort"],
            "low"
        );
        assert_eq!(
            raw["models"][0]["supported_reasoning_levels"][0]["description"],
            "Fast responses with lighter reasoning"
        );

        // `--json` prints the WHOLE envelope, byte-faithful (fields askcodex
        // does not model included, at every level).
        assert_eq!(raw, sample(MODELS_SAMPLE));
        assert!(raw.is_object());
        assert_eq!(raw["models"].as_array().map(Vec::len), Some(8));
        assert_eq!(raw["models"][0]["display_name"], "GPT-5.6-Sol");
    }

    #[test]
    fn models_decodes_the_reasoning_level_objects_the_backend_sends() {
        // The one true shape (docs/PROTOCOL.md §3.3, re-verified live):
        // `supported_reasoning_levels[]` are objects with an `effort` key.
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/codex/models");
            then.status(200).json_body(models_envelope(json!([{
                "slug": "gpt-5.6-sol",
                "visibility": "list",
                "input_modalities": ["text", "image"],
                "supported_reasoning_levels": [
                    {"effort": "low", "description": "Fast responses with lighter reasoning"},
                    {"effort": "ultra"}
                ]
            }])));
        });

        let mut client = client();
        let (typed, _) = models_at(&mut client, &server.base_url(), "0.147.0").unwrap();

        let efforts: Vec<&str> = typed[0]
            .supported_reasoning_levels
            .iter()
            .filter_map(|level| level.effort.as_deref())
            .collect();
        assert_eq!(efforts, ["low", "ultra"]);
    }

    #[test]
    fn models_bare_string_reasoning_level_is_loud_never_coerced() {
        // A bare string is NOT the wire shape. askcodex must not quietly read it
        // as `{"effort": <string>}`: coercing an undocumented encoding into
        // the documented one would hide a real protocol change behind a
        // catalog that still looks complete.
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/codex/models");
            then.status(200).json_body(models_envelope(json!([{
                "slug": "gpt-5.6-sol",
                "visibility": "list",
                "supported_reasoning_levels": ["low", "high"]
            }])));
        });

        let mut client = client();
        let err = models_at(&mut client, &server.base_url(), "0.147.0").unwrap_err();

        match err {
            Error::UnexpectedResponse { context } => {
                assert!(context.contains("models[0]"), "{context}");
                assert!(context.contains("did not decode"), "{context}");
                // A type error, not a skipped entry or an empty effort list.
                assert!(context.contains("invalid type"), "{context}");
                assert!(context.contains("supported_reasoning_levels"), "{context}");
            }
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn models_tolerates_unknown_fields_and_absent_optional_ones() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/codex/models");
            then.status(200).json_body(json!({
                "models": [{"slug": "gpt-future", "brand_new_field": {"a": 1}}],
                "envelope_extension": "ignored"
            }));
        });

        let mut client = client();
        let (typed, raw) = models_at(&mut client, &server.base_url(), "0.147.0").unwrap();

        assert_eq!(typed[0].slug, "gpt-future");
        assert!(typed[0].input_modalities.is_empty());
        assert!(typed[0].supported_reasoning_levels.is_empty());
        assert!(typed[0].visibility.is_none());
        assert_eq!(raw["models"][0]["brand_new_field"], json!({"a": 1}));
        // Unknown keys survive at the ENVELOPE level too, not just inside
        // an entry.
        assert_eq!(raw["envelope_extension"], "ignored");
    }

    #[test]
    fn models_raw_keeps_envelope_level_siblings_it_does_not_model() {
        // Regression guard: the raw value used to be the envelope's
        // `models` array, so every sibling key was dropped on the way to
        // `--json` — silently, with no stderr note. A paging cursor lost
        // that way turns a truncated catalog into what looks like the whole
        // catalog, which is a partial result presented as success.
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/codex/models");
            then.status(200).json_body(json!({
                "models": [{"slug": "gpt-5.6-sol"}],
                "default_model": "gpt-5.6-sol",
                "next_cursor": "page-2"
            }));
        });

        let mut client = client();
        let (typed, raw) = models_at(&mut client, &server.base_url(), "0.147.0").unwrap();

        // The typed catalog is still just the entries — the human
        // rendering is unchanged by this.
        assert_eq!(typed.len(), 1);
        assert_eq!(typed[0].slug, "gpt-5.6-sol");

        // ... and the `--json` value is the whole document the backend
        // sent, so both siblings reach the user.
        assert_eq!(raw["default_model"], "gpt-5.6-sol");
        assert_eq!(raw["next_cursor"], "page-2");
        assert_eq!(raw["models"][0]["slug"], "gpt-5.6-sol");
        let mut keys: Vec<&str> = raw
            .as_object()
            .expect("the raw value is the envelope OBJECT, not the inner array")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, ["default_model", "models", "next_cursor"]);
    }

    #[test]
    fn models_without_a_models_array_is_loud() {
        for body in [
            json!({"data": [], "object": "list"}),
            json!({"models": {"gpt-5.4": {}}}),
        ] {
            let server = MockServer::start();
            server.mock(|when, then| {
                when.method(GET).path("/codex/models");
                then.status(200).json_body(body.clone());
            });

            let mut client = client();
            let err = models_at(&mut client, &server.base_url(), "0.147.0").unwrap_err();

            match err {
                Error::UnexpectedResponse { context } => {
                    assert!(context.contains("`models` array"), "{context}");
                    assert!(
                        context.contains("/codex/models?client_version=0.147.0"),
                        "{context}"
                    );
                    // The keys that WERE present.
                    let expected = if body.get("data").is_some() {
                        "\"data\""
                    } else {
                        "\"models\""
                    };
                    assert!(context.contains(expected), "{context}");
                }
                other => panic!("wrong error: {other:?}"),
            }
        }
    }

    #[test]
    fn models_entry_missing_slug_is_loud_and_says_which_entry() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/codex/models");
            then.status(200).json_body(models_envelope(json!([
                {"slug": "gpt-5.4-mini", "visibility": "list"},
                {"visibility": "hide", "display_name": "Nameless"}
            ])));
        });

        let mut client = client();
        let err = models_at(&mut client, &server.base_url(), "0.147.0").unwrap_err();

        match err {
            Error::UnexpectedResponse { context } => {
                assert!(context.contains("models[1]"), "{context}");
                assert!(context.contains("slug"), "{context}");
                assert!(context.contains("\"display_name\""), "{context}");
                assert!(context.contains("\"visibility\""), "{context}");
            }
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn models_entry_with_an_undecodable_reasoning_level_is_loud() {
        // Anything that is not a reasoning-level OBJECT fails loudly; no
        // entry shape is ever repaired, skipped or defaulted.
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/codex/models");
            then.status(200).json_body(models_envelope(json!([{
                "slug": "gpt-5.4",
                "supported_reasoning_levels": [7]
            }])));
        });

        let mut client = client();
        let err = models_at(&mut client, &server.base_url(), "0.147.0").unwrap_err();
        assert!(
            matches!(err, Error::UnexpectedResponse { ref context } if context.contains("models[0]")),
            "wrong error: {err:?}"
        );
    }

    #[test]
    fn models_empty_catalog_is_a_valid_answer() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/codex/models");
            then.status(200).json_body(models_envelope(json!([])));
        });

        let mut client = client();
        let (typed, raw) = models_at(&mut client, &server.base_url(), "0.147.0").unwrap();
        assert!(typed.is_empty());
        // An empty catalog is still reported as the envelope that carried
        // it, so `--json` consumers parse one shape in every case.
        assert_eq!(raw, json!({"models": []}));
    }

    #[test]
    fn models_non_2xx_surfaces_status_and_body_snippet() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET).path("/codex/models");
            then.status(400)
                .body(r#"{"detail":"client_version is required"}"#);
        });

        let mut client = client();
        let err = models_at(&mut client, &server.base_url(), "0.147.0").unwrap_err();
        mock.assert();

        match err {
            Error::HttpStatus {
                status,
                path,
                snippet,
                ..
            } => {
                assert_eq!(status, 400);
                assert!(path.contains("client_version=0.147.0"), "{path}");
                assert_eq!(snippet, r#"{"detail":"client_version is required"}"#);
            }
            other => panic!("wrong error: {other:?}"),
        }
    }

    // -- helpers ---------------------------------------------------------

    #[test]
    fn shape_of_reports_key_names_never_values() {
        let value = json!({"email": "someone@example.invalid", "plan_type": "plus"});
        let described = shape_of(&value);
        assert_eq!(described, r#"keys=["email", "plan_type"]"#);
        assert!(!described.contains("example.invalid"));

        assert_eq!(
            shape_of(&json!([1, 2])),
            "body is a JSON array of 2 item(s)"
        );
        assert_eq!(shape_of(&Value::Null), "body is JSON null");
        assert_eq!(shape_of(&json!("hi")), "body is a JSON string");
        assert_eq!(shape_of(&json!(1)), "body is a JSON number");
        assert_eq!(shape_of(&json!(true)), "body is a JSON boolean");
    }
}
