//! askcodex — your ChatGPT/Codex subscription as a CLI.
//!
//! Library crate: everything except arg-parsing entry and exit-code
//! mapping (src/main.rs) lives here so it is testable against mocked HTTP
//! (httpmock) and temp CODEX_HOME dirs.
//!
//! Credential source: `~/.codex/auth.json` (ChatGPT subscription tokens
//! written by `codex login`). No API key is used or accepted anywhere in
//! this crate.
//!
//! Module map (see DESIGN.md for the rationale and the frozen-contract
//! list):
//! - [`cli`]     — clap command tree (FROZEN contract).
//! - [`config`]  — constants + CODEX_HOME resolution (FROZEN, complete).
//! - [`error`]   — the crate error enum (FROZEN, complete).
//! - [`models`]  — wire/file serde types (FROZEN, complete).
//! - [`redact`]  — the Secret newtype (FROZEN, complete).
//! - [`auth`]    — load/refresh/persist credentials.
//! - [`http`]    — authenticated client, origin gate, 401 policy.
//! - [`sse`]     — SSE framing over BufRead.
//! - [`endpoints`] — account / images / responses wrappers.
//! - [`run`]     — dispatch + rendering.

pub mod auth;
pub mod cli;
pub mod config;
pub mod endpoints;
pub mod error;
pub mod http;
pub mod models;
pub mod redact;
pub mod run;
pub mod sse;

pub use cli::Cli;
pub use error::Error;
pub use redact::Secret;
pub use run::run;
