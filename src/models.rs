//! Wire and file types (frozen: the serde contract with the backend).
//!
//! Serde request/response types for every endpoint askcodex speaks to, plus the
//! `auth.json` document model. Shapes were validated against the live
//! backend on 2026-08-07; anything the backend may omit is an `Option` and
//! rendering decides how to surface absence. Anything askcodex itself REQUIRES
//! is checked loudly at the use site (never silently defaulted).
//!
//! `--json` parity rule: endpoints that print backend data under `--json`
//! print the RAW response `serde_json::Value` (so unknown fields are never
//! dropped); the typed structs here exist for the human-readable rendering
//! and for internal checks.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::redact::Secret;

// ---------------------------------------------------------------------------
// auth.json document (round-trip safe)
// ---------------------------------------------------------------------------

/// The whole `~/.codex/auth.json` document.
///
/// Round-trip contract: every key askcodex does not model is preserved
/// byte-for-byte as a JSON value through `extra` (probe-verified, including
/// null-valued legacy keys, which askcodex must never name in code). `Option`
/// fields skip serialization when absent so a rewrite never invents keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthFile {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens: Option<AuthTokens>,
    /// RFC3339 UTC with exactly 6 fractional digits and `Z`, e.g.
    /// `2026-08-07T23:32:41.615755Z` (codex's own format). Kept as a
    /// `String` so an unexpected upstream format is preserved verbatim on
    /// rewrite; use [`format_last_refresh`] / [`parse_last_refresh`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_refresh: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

/// The `tokens` object inside `auth.json`. All credential values are
/// [`Secret`]s; `account_id` is not a credential but must still be redacted
/// in anything destined for the repo or evidence files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthTokens {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<Secret>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<Secret>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<Secret>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

/// Format a `last_refresh` timestamp exactly the way codex writes it
/// (probe-verified byte-identical against the real file: 6-digit
/// microseconds, `Z` suffix). chrono's default serde emit is variable
/// precision and MUST NOT be used for this field.
pub fn format_last_refresh(t: chrono::DateTime<chrono::Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}

/// Parse a `last_refresh` timestamp (accepts any RFC3339 fractional
/// precision, as codex's own parser does).
pub fn parse_last_refresh(s: &str) -> Result<chrono::DateTime<chrono::Utc>, chrono::ParseError> {
    s.parse()
}

// ---------------------------------------------------------------------------
// OAuth refresh (POST https://auth.openai.com/oauth/token)
// ---------------------------------------------------------------------------

/// Refresh request body. `grant_type` is always `"refresh_token"`.
#[derive(Debug, Serialize)]
pub struct RefreshRequest {
    pub client_id: &'static str,
    pub grant_type: &'static str,
    pub refresh_token: Secret,
}

impl RefreshRequest {
    pub fn new(refresh_token: Secret) -> Self {
        RefreshRequest {
            client_id: crate::config::CLIENT_ID,
            grant_type: "refresh_token",
            refresh_token,
        }
    }
}

/// Refresh response. `access_token` is required by askcodex (checked loudly in
/// auth.rs — `Error::RefreshInvalidResponse` carries the key names);
/// `id_token` and `refresh_token` rotate only when present. Other fields
/// (`expires_in`, `scope`, ...) are ignored.
#[derive(Debug, Deserialize)]
pub struct RefreshResponse {
    #[serde(default)]
    pub access_token: Option<Secret>,
    #[serde(default)]
    pub id_token: Option<Secret>,
    #[serde(default)]
    pub refresh_token: Option<Secret>,
}

// ---------------------------------------------------------------------------
// GET /codex/usage
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct UsageResponse {
    pub email: Option<String>,
    pub user_id: Option<String>,
    pub account_id: Option<String>,
    pub plan_type: Option<String>,
    pub rate_limit: Option<RateLimit>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RateLimit {
    pub limit_reached: Option<bool>,
    pub allowed: Option<bool>,
    pub primary_window: Option<RateWindow>,
    pub secondary_window: Option<RateWindow>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RateWindow {
    pub used_percent: Option<f64>,
    pub limit_window_seconds: Option<u64>,
    pub reset_after_seconds: Option<u64>,
}

// ---------------------------------------------------------------------------
// GET /me (under /backend-api, NOT /codex)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct MeResponse {
    pub name: Option<String>,
    pub email: Option<String>,
}

/// Composed identity for `askcodex whoami` (usage + /me). This struct IS the
/// `--json` output shape for whoami.
#[derive(Debug, Clone, Serialize)]
pub struct WhoamiOutput {
    pub email: Option<String>,
    pub name: Option<String>,
    pub user_id: Option<String>,
    pub account_id: Option<String>,
    pub plan_type: Option<String>,
}

// ---------------------------------------------------------------------------
// GET /codex/models?client_version=...
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct ModelsResponse {
    #[serde(default)]
    pub models: Vec<ModelInfo>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ModelInfo {
    pub slug: String,
    #[serde(default)]
    pub input_modalities: Vec<String>,
    #[serde(default)]
    pub supported_reasoning_levels: Vec<ReasoningLevel>,
    pub visibility: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReasoningLevel {
    pub effort: Option<String>,
}

// ---------------------------------------------------------------------------
// POST /codex/images/generations and /codex/images/edits
// ---------------------------------------------------------------------------

/// Generation request. The backend returns one opaque PNG at a size it
/// chooses; size/quality/background/output_format/n knobs are accepted but
/// ignored server-side, so askcodex deliberately does not model them
/// (advertising a dropped control is a failure-masking default).
#[derive(Debug, Serialize)]
pub struct ImageGenerationRequest {
    pub prompt: String,
    /// Always `config::IMAGE_MODEL` (codex parity; backend ignores it).
    pub model: &'static str,
}

/// Edit request: generation plus up to `config::MAX_EDIT_IMAGES` reference
/// images as data URLs.
#[derive(Debug, Serialize)]
pub struct ImageEditRequest {
    pub prompt: String,
    pub model: &'static str,
    pub images: Vec<ImageRef>,
}

/// One reference image: `{"image_url": "data:image/png;base64,..."}`.
#[derive(Debug, Serialize)]
pub struct ImageRef {
    pub image_url: String,
}

/// Image response envelope. `data[0].b64_json` is a raw base64 PNG;
/// its absence is a loud `Error::UnexpectedResponse` at the use site.
#[derive(Debug, Deserialize)]
pub struct ImageResponse {
    pub created: Option<i64>,
    #[serde(default)]
    pub data: Vec<ImageDatum>,
    pub background: Option<String>,
    pub quality: Option<String>,
    pub size: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ImageDatum {
    pub b64_json: Option<String>,
}

/// Decoded, validated image result handed from the endpoint to rendering.
pub struct ImageResult {
    /// Raw PNG bytes (magic verified).
    pub png: Vec<u8>,
    /// The `size` string the backend reported (e.g. "1254x1254"), if any.
    pub size: Option<String>,
}

// ---------------------------------------------------------------------------
// POST /codex/responses (streaming)
// ---------------------------------------------------------------------------

/// Responses-API request. `stream` is always true and `store` MUST always
/// be false (validated live; storing is not acceptable for a CLI).
#[derive(Debug, Serialize)]
pub struct ResponsesRequest {
    pub model: String,
    pub input: Vec<InputItem>,
    pub stream: bool,
    pub store: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning: Option<Reasoning>,
}

impl ResponsesRequest {
    /// The one shape askcodex sends: a single user text message.
    pub fn user_text(
        model: impl Into<String>,
        text: impl Into<String>,
        instructions: Option<String>,
        effort: Option<String>,
    ) -> Self {
        ResponsesRequest {
            model: model.into(),
            input: vec![InputItem {
                item_type: "message",
                role: "user",
                content: vec![ContentPart {
                    part_type: "input_text",
                    text: text.into(),
                }],
            }],
            stream: true,
            store: false,
            instructions,
            reasoning: effort.map(|e| Reasoning { effort: e }),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct InputItem {
    #[serde(rename = "type")]
    pub item_type: &'static str,
    pub role: &'static str,
    pub content: Vec<ContentPart>,
}

#[derive(Debug, Serialize)]
pub struct ContentPart {
    #[serde(rename = "type")]
    pub part_type: &'static str,
    pub text: String,
}

#[derive(Debug, Serialize)]
pub struct Reasoning {
    pub effort: String,
}

/// Classified SSE event from the responses stream. The wire carries many
/// event types; askcodex distinguishes exactly these four classes (validated
/// live).
#[derive(Debug, Clone, PartialEq)]
pub enum ResponsesSseEvent {
    /// `response.output_text.delta` — append `delta` to the answer.
    OutputTextDelta(String),
    /// `response.completed` — the stream is done. Carries the raw event so
    /// the caller can read `response.usage` (token counts) out of it.
    Completed { raw: Value },
    /// `response.failed` | `response.error` | `error` — abort loudly.
    /// Carries the raw event for the error message.
    Error { raw: Value },
    /// Any other event type (`response.created`, `response.in_progress`,
    /// `response.output_item.added`, ...) — deliberately ignored. An event
    /// without a string `type` is also `Other` (protocol noise; aborting
    /// on it would break streams that otherwise complete).
    Other,
}

impl ResponsesSseEvent {
    /// Classify one decoded `data:` payload.
    pub fn classify(event: &Value) -> Self {
        match event.get("type").and_then(Value::as_str) {
            Some("response.output_text.delta") => ResponsesSseEvent::OutputTextDelta(
                event
                    .get("delta")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            ),
            Some("response.completed") => ResponsesSseEvent::Completed { raw: event.clone() },
            Some("response.failed") | Some("response.error") | Some("error") => {
                ResponsesSseEvent::Error { raw: event.clone() }
            }
            _ => ResponsesSseEvent::Other,
        }
    }
}

/// `--json` output shape for `askcodex ask`. Absent values render as `null`,
/// never as an invented default: `usage` is whatever object the backend's
/// `response.completed` event carried (unknown keys preserved), or `null`
/// when the event carried none.
#[derive(Debug, Serialize)]
pub struct AskOutput {
    pub model: String,
    pub effort: Option<String>,
    pub text: String,
    pub usage: Option<Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_file_round_trip_preserves_unknown_and_null_keys() {
        let input = r#"{"auth_mode":"chatgpt","legacy_null_key":null,"tokens":{"id_token":"i","access_token":"a","refresh_token":"r","account_id":"acct_REDACTED","future":123},"last_refresh":"2026-08-07T23:32:41.615755Z","future_key":{"x":1}}"#;
        let parsed: AuthFile = serde_json::from_str(input).unwrap();
        let out = serde_json::to_string(&parsed).unwrap();
        let a: Value = serde_json::from_str(input).unwrap();
        let b: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(a, b);
        // Secrets stay redacted in Debug.
        let dbg = format!("{parsed:?}");
        assert!(!dbg.contains("\"a\"") || dbg.contains("Secret(REDACTED)"));
        assert!(dbg.contains("Secret(REDACTED)"));
    }

    #[test]
    fn absent_optional_keys_stay_absent_on_rewrite() {
        let input = r#"{"tokens":{"access_token":"a","account_id":"x"}}"#;
        let parsed: AuthFile = serde_json::from_str(input).unwrap();
        let out = serde_json::to_string(&parsed).unwrap();
        assert!(!out.contains("last_refresh"));
        assert!(!out.contains("id_token"));
        assert!(!out.contains("refresh_token"));
        assert!(!out.contains("auth_mode"));
    }

    #[test]
    fn last_refresh_format_matches_codex_byte_exact() {
        let observed = "2026-08-07T23:32:41.615755Z";
        let parsed = parse_last_refresh(observed).unwrap();
        assert_eq!(format_last_refresh(parsed), observed);
    }

    #[test]
    fn responses_request_minimal_wire_shape() {
        let req = ResponsesRequest::user_text("gpt-5.4-mini", "hi", None, None);
        let v = serde_json::to_value(&req).unwrap();
        assert_eq!(
            v,
            serde_json::json!({
                "model": "gpt-5.4-mini",
                "input": [{"type": "message", "role": "user",
                            "content": [{"type": "input_text", "text": "hi"}]}],
                "stream": true,
                "store": false
            })
        );
    }

    #[test]
    fn responses_request_with_options() {
        let req = ResponsesRequest::user_text(
            "gpt-5.6-sol",
            "hi",
            Some("be brief".into()),
            Some("xhigh".into()),
        );
        let v = serde_json::to_value(&req).unwrap();
        assert_eq!(v["instructions"], "be brief");
        assert_eq!(v["reasoning"], serde_json::json!({"effort": "xhigh"}));
    }

    #[test]
    fn sse_event_classification() {
        let delta = serde_json::json!({"type": "response.output_text.delta", "delta": "Hi"});
        assert_eq!(
            ResponsesSseEvent::classify(&delta),
            ResponsesSseEvent::OutputTextDelta("Hi".into())
        );
        let done = serde_json::json!({"type": "response.completed", "response": {"id": "r"}});
        assert_eq!(
            ResponsesSseEvent::classify(&done),
            ResponsesSseEvent::Completed { raw: done.clone() }
        );
        for t in ["response.failed", "response.error", "error"] {
            let ev = serde_json::json!({"type": t, "code": "boom"});
            assert!(matches!(
                ResponsesSseEvent::classify(&ev),
                ResponsesSseEvent::Error { .. }
            ));
        }
        let noise = serde_json::json!({"type": "response.in_progress"});
        assert_eq!(
            ResponsesSseEvent::classify(&noise),
            ResponsesSseEvent::Other
        );
        let untyped = serde_json::json!({"delta": "x"});
        assert_eq!(
            ResponsesSseEvent::classify(&untyped),
            ResponsesSseEvent::Other
        );
    }

    #[test]
    fn refresh_request_wire_shape() {
        let req = RefreshRequest::new(Secret::new("rt"));
        let v = serde_json::to_value(&req).unwrap();
        assert_eq!(v["client_id"], crate::config::CLIENT_ID);
        assert_eq!(v["grant_type"], "refresh_token");
        assert_eq!(v["refresh_token"], "rt"); // serializes for the wire...
        let dbg = format!("{req:?}");
        assert!(!dbg.contains("rt\"")); // ...but never appears in Debug
    }
}
