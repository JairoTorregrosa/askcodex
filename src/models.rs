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
/// fields are emitted by the private credential-store adapter only when present.
/// Runtime credentials intentionally do not implement Serialize.
#[derive(Clone, Deserialize)]
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
#[derive(Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UsageResponse {
    pub email: Option<String>,
    pub user_id: Option<String>,
    pub account_id: Option<String>,
    pub plan_type: Option<String>,
    pub rate_limit: Option<RateLimit>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RateLimit {
    pub limit_reached: Option<bool>,
    pub allowed: Option<bool>,
    pub primary_window: Option<RateWindow>,
    pub secondary_window: Option<RateWindow>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
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

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ModelsResponse {
    #[serde(default)]
    pub models: Vec<ModelInfo>,
}

/// One catalog entry, reduced to what a caller needs to pick a model. The
/// backend sends ~50 keys per model (most of them Codex's own prompts and
/// tool settings); `--backend` returns the whole document. Absent keys are
/// `null`, never a guessed default.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ModelInfo {
    pub slug: String,
    #[serde(default)]
    pub input_modalities: Vec<String>,
    #[serde(default)]
    pub supported_reasoning_levels: Vec<ReasoningLevel>,
    pub visibility: Option<String>,
    pub display_name: Option<String>,
    pub description: Option<String>,
    /// Codex's default effort for this model. `ask` does not use it: it
    /// always sends `--effort` (default `medium`).
    pub default_reasoning_level: Option<String>,
    /// Codex's ordering; lower comes first in its picker.
    pub priority: Option<i64>,
    pub context_window: Option<u64>,
    /// Verbatim `upgrade` object (`model`, `migration_markdown`,
    /// `retirement_at`) when the backend recommends moving off this model.
    pub upgrade: Option<Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReasoningLevel {
    pub effort: Option<String>,
}

// ---------------------------------------------------------------------------
// POST /codex/images/generations and /codex/images/edits
// ---------------------------------------------------------------------------

/// Generation request. The backend returns one PNG at a size it chooses;
/// model/size/quality/output_format/n knobs are accepted but ignored
/// server-side, so askcodex deliberately does not model them (advertising a
/// dropped control is a failure-masking default). `background` is honored
/// since at least 2026-09-27 but not modelled: the prompt already reaches
/// transparency (docs/PROTOCOL.md §5).
#[derive(Debug, Serialize)]
pub struct ImageGenerationRequest {
    pub prompt: String,
    /// Always `config::IMAGE_MODEL` (codex parity; backend ignores it).
    pub model: &'static str,
    /// `transparent` | `opaque` from `--background`; absent unless the user
    /// asked, so the prompt decides.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub background: Option<&'static str>,
}

/// Edit request: generation plus up to `config::MAX_EDIT_IMAGES` reference
/// images as data URLs.
#[derive(Debug, Serialize)]
pub struct ImageEditRequest {
    pub prompt: String,
    pub model: &'static str,
    pub images: Vec<ImageRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub background: Option<&'static str>,
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
    /// The `background` the backend reported (`transparent`, `opaque`), if
    /// any. Check the PNG's alpha before relying on it.
    pub background: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<TextControls>,
}

/// The Responses `text` object: verbosity and/or a strict JSON Schema
/// output format, the same shape Codex sends (codex-api `common.rs` at
/// rust-v0.160.0). Sent only when the user set one of them.
#[derive(Debug, Serialize)]
pub struct TextControls {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verbosity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<TextFormat>,
}

#[derive(Debug, Serialize)]
pub struct TextFormat {
    #[serde(rename = "type")]
    pub format_type: &'static str,
    pub strict: bool,
    pub schema: Value,
    pub name: &'static str,
}

impl TextControls {
    /// `None` when neither control is set, so the key is not sent at all.
    pub fn new(verbosity: Option<String>, schema: Option<Value>) -> Option<Self> {
        if verbosity.is_none() && schema.is_none() {
            return None;
        }
        Some(TextControls {
            verbosity,
            format: schema.map(|schema| TextFormat {
                format_type: "json_schema",
                strict: true,
                schema,
                name: "codex_output_schema",
            }),
        })
    }
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
            text: None,
        }
    }

    /// Attach `--verbosity` / `--schema`; a no-op when both are unset.
    pub fn with_text(mut self, verbosity: Option<String>, schema: Option<Value>) -> Self {
        self.text = TextControls::new(verbosity, schema);
        self
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
    /// `response.failed` | `response.error` | `error` |
    /// `response.incomplete` — abort loudly.
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
            // `response.incomplete` is terminal too (Codex treats it as an
            // interrupted completion): the answer is cut short, so it is a
            // failure here, never a shorter success.
            Some("response.failed")
            | Some("response.error")
            | Some("error")
            | Some("response.incomplete") => ResponsesSseEvent::Error { raw: event.clone() },
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
    /// `--verbosity` as sent, or `null` when the backend default applied.
    pub verbosity: Option<String>,
    pub text: String,
    /// The answer parsed as JSON. Present only with `--schema`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub json: Option<Value>,
    pub usage: Option<Value>,
}

impl std::fmt::Debug for AuthFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthFile")
            .field("has_auth_mode", &self.auth_mode.is_some())
            .field("tokens", &self.tokens)
            .field("has_last_refresh", &self.last_refresh.is_some())
            .field("extra_field_count", &self.extra.len())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for AuthTokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthTokens")
            .field("id_token", &self.id_token)
            .field("access_token", &self.access_token)
            .field("refresh_token", &self.refresh_token)
            .field("has_account_id", &self.account_id.is_some())
            .field("extra_field_count", &self.extra.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_file_round_trip_preserves_unknown_and_null_keys() {
        let input = r#"{"auth_mode":"chatgpt","legacy_null_key":null,"tokens":{"id_token":"i","access_token":"a","refresh_token":"r","account_id":"acct_REDACTED","future":123},"last_refresh":"2026-08-07T23:32:41.615755Z","future_key":{"x":1}}"#;
        let parsed: AuthFile = serde_json::from_str(input).unwrap();
        let out = crate::auth::test_document(&parsed).to_string();
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
        let out = crate::auth::test_document(&parsed).to_string();
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
    fn text_controls_mirror_codex_and_are_absent_when_unset() {
        let plain = ResponsesRequest::user_text("m", "hi", None, None).with_text(None, None);
        let v = serde_json::to_value(&plain).unwrap();
        assert!(
            v.get("text").is_none(),
            "unset controls must send no key: {v}"
        );

        let schema = serde_json::json!({"type": "object", "properties": {}, "required": [],
                                        "additionalProperties": false});
        let both = ResponsesRequest::user_text("m", "hi", None, None)
            .with_text(Some("low".into()), Some(schema.clone()));
        let v = serde_json::to_value(&both).unwrap();
        assert_eq!(
            v["text"],
            serde_json::json!({
                "verbosity": "low",
                "format": {"type": "json_schema", "strict": true, "schema": schema,
                           "name": "codex_output_schema"}
            })
        );

        let only_verbosity =
            ResponsesRequest::user_text("m", "hi", None, None).with_text(Some("high".into()), None);
        let v = serde_json::to_value(&only_verbosity).unwrap();
        assert_eq!(v["text"], serde_json::json!({"verbosity": "high"}));
    }

    #[test]
    fn model_info_keeps_the_picking_fields_and_nulls_the_absent_ones() {
        let entry = serde_json::json!({
            "slug": "gpt-old", "visibility": "list", "display_name": "GPT-Old",
            "description": "Legacy.", "default_reasoning_level": "medium", "priority": 13,
            "context_window": 272000, "base_instructions": "x".repeat(5000),
            "upgrade": {"model": "gpt-new", "retirement_at": "2026-10-14T19:00:00Z",
                        "migration_markdown": "Switch."}
        });
        let model: ModelInfo = serde_json::from_value(entry).unwrap();
        let v = serde_json::to_value(&model).unwrap();
        assert_eq!(v["default_reasoning_level"], "medium");
        assert_eq!(v["upgrade"]["model"], "gpt-new");
        assert!(
            v.get("base_instructions").is_none(),
            "prompts stay in --backend"
        );

        let bare: ModelInfo = serde_json::from_value(serde_json::json!({"slug": "s"})).unwrap();
        let v = serde_json::to_value(&bare).unwrap();
        for key in [
            "description",
            "default_reasoning_level",
            "priority",
            "upgrade",
        ] {
            assert!(v[key].is_null(), "{key} must be null, not a default: {v}");
        }
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
        for t in [
            "response.failed",
            "response.error",
            "error",
            "response.incomplete",
        ] {
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
}
