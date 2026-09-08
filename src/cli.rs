//! The clap command tree (frozen: this file IS the command surface).
//!
//! This file IS the command-surface contract. The surface is EXACTLY:
//!
//! ```text
//! askcodex whoami
//! askcodex usage
//! askcodex models [--client-version <v>]
//! askcodex transcribe <file.wav>
//! askcodex image create <prompt> [-o <file>]
//! askcodex image edit  <prompt> -i <ref>... [-o <file>]
//! askcodex ask <prompt> [--model <m>] [--effort <e>] [--instructions <s>]   (prompt "-" = stdin)
//! askcodex raw <METHOD> <path> [--body <json|->] [--stream]
//! askcodex auth status
//! askcodex auth refresh
//! ```
//!
//! Global flags `--json` and `--no-refresh` are accepted anywhere,
//! including after the deepest subcommand (probe-verified).
//!
//! Credential source is ~/.codex/auth.json (ChatGPT subscription tokens).
//! No API key is used or accepted — there is deliberately no flag, env
//! var, or config knob for one.
//!
//! `raw <path>` is the one argument that names a URL, so it is the one
//! argument that could aim the user's credentials somewhere. It is parsed
//! through [`crate::http::check_request_target`]: a path with a leading
//! `/`, or an absolute URL on the backend's own origin, and nothing else.
//! There is deliberately no flag that widens that set.
//!
//! The image commands expose ONLY the prompt (+ reference images for
//! edit): the backend returns a single opaque PNG at a size it chooses and
//! ignores size/quality/background/format/n. Advertising ignored knobs
//! would be a failure-masking default, so they do not exist here.

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

use crate::config;

/// Codex subscription CLI (uses ~/.codex/auth.json; no API key).
#[derive(Parser, Debug)]
#[command(
    name = "askcodex",
    version,
    about = "Your ChatGPT/Codex subscription as a CLI.",
    long_about = "Drives the ChatGPT/Codex subscription backend \
                  (chatgpt.com/backend-api/codex) with the tokens already stored in \
                  ~/.codex/auth.json by `codex login`. No API key is used or accepted.",
    disable_help_subcommand = true
)]
pub struct Cli {
    /// Machine-readable JSON output.
    #[arg(long, global = true)]
    pub json: bool,

    /// Do not auto-refresh the access token even if near expiry (also
    /// disables the 401 refresh-and-retry).
    #[arg(long, global = true)]
    pub no_refresh: bool,

    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Transcribe a WAV audio file to text.
    Transcribe {
        /// WAV audio file. Convert other formats to WAV before uploading.
        file: PathBuf,
    },
    /// Show account identity and plan.
    Whoami,

    /// Show rate-limit / quota usage.
    Usage,

    /// List available agent/LLM models and modalities.
    Models {
        /// Client version reported to the backend (required query param).
        #[arg(long, default_value = config::CLIENT_VERSION)]
        client_version: String,
    },

    /// Generate or edit images (always one opaque PNG; the backend picks the size).
    Image {
        #[command(subcommand)]
        cmd: ImageCmd,
    },

    /// Streaming text completion via /codex/responses.
    Ask {
        /// Prompt text, or "-" to read it from stdin.
        prompt: String,

        /// Model slug (see `askcodex models`).
        #[arg(long, default_value = config::DEFAULT_ASK_MODEL)]
        model: String,

        /// System-style instructions.
        #[arg(long)]
        instructions: Option<String>,

        /// Reasoning effort.
        #[arg(long, value_enum, default_value = config::DEFAULT_ASK_EFFORT)]
        effort: Option<Effort>,
    },

    /// Call an arbitrary backend path (escape hatch).
    Raw {
        /// HTTP method (uppercase).
        #[arg(value_enum)]
        method: HttpMethod,

        /// Backend path (e.g. /codex/usage) or a full https URL on the
        /// backend origin.
        #[arg(value_parser = raw_target)]
        path: String,

        /// JSON request body as a string, or "-" to read it from stdin.
        #[arg(long)]
        body: Option<String>,

        /// Stream the raw SSE response to stdout.
        #[arg(long)]
        stream: bool,
    },

    /// Inspect or refresh the stored tokens.
    Auth {
        #[command(subcommand)]
        cmd: AuthCmd,
    },
}

#[derive(Subcommand, Debug)]
pub enum ImageCmd {
    /// Text -> image.
    Create {
        /// Image prompt.
        prompt: String,

        /// Output PNG path.
        #[arg(short, long, default_value = "image.png")]
        out: PathBuf,
    },

    /// Edit / reference-guided image (up to 5 reference images).
    Edit {
        /// Edit prompt.
        prompt: String,

        /// Reference image path(s).
        #[arg(short = 'i', long = "inputs", num_args = 1.., required = true)]
        inputs: Vec<PathBuf>,

        /// Output PNG path.
        #[arg(short, long, default_value = "image-edited.png")]
        out: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
pub enum AuthCmd {
    /// Show token status (never prints secret values).
    Status,

    /// Force a token refresh now (rotates and persists tokens).
    Refresh,
}

/// Reasoning effort accepted by `--effort` (backend-validated set).
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Effort {
    Low,
    Medium,
    High,
    Xhigh,
    Max,
    Ultra,
    None,
}

impl Effort {
    /// The wire string for the `reasoning.effort` field.
    pub fn as_str(self) -> &'static str {
        match self {
            Effort::Low => "low",
            Effort::Medium => "medium",
            Effort::High => "high",
            Effort::Xhigh => "xhigh",
            Effort::Max => "max",
            Effort::Ultra => "ultra",
            Effort::None => "none",
        }
    }
}

/// clap `value_parser` for `askcodex raw <path>`.
///
/// Runs [`crate::http::check_request_target`] — the SAME predicate
/// `http::Client` enforces before it attaches the subscription bearer
/// token — so a target askcodex would refuse is rejected while parsing argv,
/// naming the reason, before the credential file is even opened.
///
/// This layer is a courtesy, not the defense: the refusal that cannot be
/// bypassed is the one inside the client, on the resolved URL, at the
/// point the `Authorization` header is built. Having one predicate serve
/// both layers is what keeps them from drifting apart.
fn raw_target(target: &str) -> Result<String, crate::error::Error> {
    crate::http::check_request_target(target)?;
    Ok(target.to_string())
}

/// HTTP methods accepted by `raw`. Uppercase literals only (probe-verified:
/// lowercase is rejected).
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum HttpMethod {
    #[value(name = "GET")]
    Get,
    #[value(name = "POST")]
    Post,
    #[value(name = "PUT")]
    Put,
    #[value(name = "PATCH")]
    Patch,
    #[value(name = "DELETE")]
    Delete,
}

impl HttpMethod {
    /// Convert to the `http` crate method (re-exported by ureq).
    pub fn as_method(self) -> ureq::http::Method {
        match self {
            HttpMethod::Get => ureq::http::Method::GET,
            HttpMethod::Post => ureq::http::Method::POST,
            HttpMethod::Put => ureq::http::Method::PUT,
            HttpMethod::Patch => ureq::http::Method::PATCH,
            HttpMethod::Delete => ureq::http::Method::DELETE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_surface_parses() {
        for argv in [
            vec!["askcodex", "whoami"],
            vec!["askcodex", "usage"],
            vec!["askcodex", "models"],
            vec!["askcodex", "models", "--client-version", "0.150.0"],
            vec!["askcodex", "image", "create", "a cat", "-o", "cat.png"],
            vec!["askcodex", "image", "create", "a cat"],
            vec![
                "askcodex", "image", "edit", "bluer", "-i", "a.png", "b.png", "-o", "out.png",
            ],
            vec!["askcodex", "ask", "hello"],
            vec![
                "askcodex",
                "ask",
                "-",
                "--model",
                "gpt-5.6-sol",
                "--effort",
                "xhigh",
            ],
            vec!["askcodex", "ask", "x", "--instructions", "be brief"],
            vec!["askcodex", "raw", "GET", "/codex/usage"],
            vec![
                "askcodex",
                "raw",
                "POST",
                "/codex/responses",
                "--body",
                "{}",
                "--stream",
            ],
            vec!["askcodex", "auth", "status"],
            vec!["askcodex", "auth", "refresh"],
        ] {
            Cli::try_parse_from(&argv).unwrap_or_else(|e| panic!("{argv:?}: {e}"));
        }
    }

    #[test]
    fn global_flags_parse_after_deepest_subcommand() {
        let c =
            Cli::try_parse_from(["askcodex", "auth", "status", "--no-refresh", "--json"]).unwrap();
        assert!(c.no_refresh);
        assert!(c.json);
        let c = Cli::try_parse_from(["askcodex", "--json", "usage"]).unwrap();
        assert!(c.json);
    }

    #[test]
    fn edit_inputs_multi_value_stops_at_next_flag() {
        let c = Cli::try_parse_from([
            "askcodex", "image", "edit", "p", "-i", "a.png", "b.png", "-o", "o.png",
        ])
        .unwrap();
        match c.cmd {
            Cmd::Image {
                cmd: ImageCmd::Edit { inputs, out, .. },
            } => {
                assert_eq!(inputs, [PathBuf::from("a.png"), PathBuf::from("b.png")]);
                assert_eq!(out, PathBuf::from("o.png"));
            }
            other => panic!("wrong parse: {other:?}"),
        }
    }

    #[test]
    fn raw_rejects_lowercase_method_and_unknown_effort() {
        assert!(Cli::try_parse_from(["askcodex", "raw", "post", "/x"]).is_err());
        assert!(Cli::try_parse_from(["askcodex", "ask", "x", "--effort", "huge"]).is_err());
    }

    #[test]
    fn defaults_match_contract() {
        let c = Cli::try_parse_from(["askcodex", "ask", "hi"]).unwrap();
        match c.cmd {
            Cmd::Ask { model, .. } => assert_eq!(model, config::DEFAULT_ASK_MODEL),
            other => panic!("wrong parse: {other:?}"),
        }
        let c = Cli::try_parse_from(["askcodex", "models"]).unwrap();
        match c.cmd {
            Cmd::Models { client_version } => assert_eq!(client_version, config::CLIENT_VERSION),
            other => panic!("wrong parse: {other:?}"),
        }
        let c = Cli::try_parse_from(["askcodex", "image", "create", "p"]).unwrap();
        match c.cmd {
            Cmd::Image {
                cmd: ImageCmd::Create { out, .. },
            } => assert_eq!(out, PathBuf::from("image.png")),
            other => panic!("wrong parse: {other:?}"),
        }
    }

    #[test]
    fn raw_refuses_a_target_outside_the_backend_origin() {
        // `raw` is the only argument that names a URL. Before this check,
        // `askcodex raw GET http://127.0.0.1:8731/anything` sent the user's
        // live subscription bearer token and account id to that listener
        // in cleartext and exited 0.
        for target in [
            "http://127.0.0.1:8731/anything",
            "http://localhost:9/steal",
            "https://collector.example/q",
            // Plaintext downgrade of the backend host.
            "http://chatgpt.com/backend-api/codex/usage",
            // Lookalikes and the userinfo spoof.
            "https://chatgpt.com.evil.invalid/x",
            "https://chatgpt.com@evil.invalid/x",
            // Not a path and not a URL: silently glued onto the base URL
            // before, so the resulting 404 blamed the endpoint.
            "codex/usage",
            "httpbin/x",
        ] {
            let parsed = Cli::try_parse_from(["askcodex", "raw", "GET", target]);
            assert!(parsed.is_err(), "{target} must be refused at parse time");
            let rendered = parsed.unwrap_err().to_string();
            assert!(
                rendered.contains("refusing to send credentials")
                    || rendered.contains("chatgpt.com"),
                "{target}: unhelpful message: {rendered}"
            );
        }

        for target in [
            "/codex/usage",
            "/me",
            "https://chatgpt.com/backend-api/codex/usage",
        ] {
            Cli::try_parse_from(["askcodex", "raw", "GET", target])
                .unwrap_or_else(|e| panic!("{target} must be accepted: {e}"));
        }
    }

    #[test]
    fn no_api_key_flag_exists() {
        // The credential source is auth.json only; any api-key-shaped flag
        // must fail to parse.
        assert!(Cli::try_parse_from(["askcodex", "usage", "--api-key", "x"]).is_err());
    }
}
