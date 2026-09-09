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
//! Module map (see DESIGN.md for architectural decisions):
//! - [`cli`]     — clap command tree.
//! - [`config`]  — constants + CODEX_HOME resolution.
//! - [`error`]   — the crate error enum.
//! - [`models`]  — wire/file serde types.
//! - `redact`  — the Secret newtype.
//! - `auth`    — load/refresh/persist credentials.
//! - `http`    — authenticated client, origin gate, 401 policy.
//! - `sse`     — SSE framing over BufRead.
//! - `endpoints` — account / images / responses wrappers.
//! - [`run()`]     — dispatch + rendering.

mod auth;
pub mod cli;
pub mod config;
mod endpoints;
pub mod error;
mod http;
mod input;
pub mod models;
mod redact;
mod run;
mod sse;

pub use cli::Cli;
pub use error::Error;
pub use redact::Secret;
pub use run::run;
