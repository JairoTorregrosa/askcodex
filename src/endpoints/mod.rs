//! Semantic endpoint wrappers over [`crate::http::Client`].
//!
//! Each submodule owns one backend domain and returns typed results plus —
//! where `--json` must echo backend data — the RAW `serde_json::Value`
//! (unknown fields are never dropped on the JSON path; see models.rs).
//!
//! The `raw` CLI command intentionally has no wrapper here: run.rs calls
//! `Client::request_json` / `Client::request_stream` directly (it is the
//! escape hatch, not a semantic endpoint).

pub mod account;
pub mod images;
pub mod responses;
pub mod transcription;
