//! The Clap command tree and generated public command reference.
//!
//! The parser defines the command surface:
//!
//! ```text
//! askcodex reference
//! askcodex whoami
//! askcodex usage
//! askcodex models [--client-version <v>]
//! askcodex transcribe <file.wav>
//! askcodex image create <prompt> [-o <file>] [--background <b>]
//! askcodex image edit  <prompt> -i <ref>... [-o <file>] [--background <b>]
//! askcodex ask <prompt> [--model <m>] [--effort <e>] [--instructions <s>]
//!              [--verbosity <v>] [--schema <file.json>]   (prompt "-" = stdin)
//! askcodex raw <METHOD> <path> [--body <json|->] [--stream]
//! askcodex auth status
//! askcodex auth refresh
//! ```
//!
//! Global flags `--json`, `--events`, `--backend` and `--no-refresh` are
//! accepted anywhere, including after the deepest subcommand (probe-verified).
//!
//! Credential source is ~/.codex/auth.json (ChatGPT subscription tokens).
//! No API key is used or accepted — there is deliberately no flag, env
//! var, or config knob for one.
//!
//! `raw <path>` is the one argument that names a URL, so it is the one
//! argument that could aim the user's credentials somewhere. It is parsed
//! through `crate::http::check_request_target`: a path with a leading
//! `/`, or an absolute URL on the backend's own origin, and nothing else.
//! There is deliberately no flag that widens that set.
//!
//! The image commands expose the prompt (+ reference images for edit) and
//! `--background`, the one knob the backend was observed to honor in both
//! directions (docs/PROTOCOL.md §5). It returns a single PNG at a size it
//! chooses and ignores model/size/quality/format/n. Advertising ignored knobs
//! would be a failure-masking default, so they do not exist here.

use std::path::PathBuf;

use clap::{CommandFactory, Parser, Subcommand, ValueEnum};

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
    /// One versioned JSON result (raw commands preserve the wire response).
    #[arg(long, global = true, conflicts_with = "events")]
    pub json: bool,

    /// Versioned newline-delimited JSON events for semantic commands.
    #[arg(long, global = true, conflicts_with = "json")]
    pub events: bool,

    /// With --json, add the backend's original response as `backend` to the
    /// result of `usage`, `models` and `transcribe` (the catalog is ~700 KB).
    #[arg(long, global = true)]
    pub backend: bool,

    /// Do not auto-refresh the access token even if near expiry (also
    /// disables the 401 refresh-and-retry).
    #[arg(long, global = true)]
    pub no_refresh: bool,

    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Print the command reference generated from this executable's parser.
    Reference,
    /// Transcribe a WAV audio file to text.
    Transcribe {
        /// Regular WAV file, at most 25 MiB. Convert other formats first.
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

    /// Generate or edit images (one PNG per call; the backend picks the size).
    Image {
        #[command(subcommand)]
        cmd: ImageCmd,
    },

    /// Streaming text completion via /codex/responses.
    Ask {
        /// Prompt text, or "-" to read it from stdin (UTF-8, at most 16 MiB).
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

        /// Answer length and detail (`text.verbosity`). Unset, the backend
        /// answers at its own default, observed as medium.
        #[arg(long, value_enum)]
        verbosity: Option<Verbosity>,

        /// JSON Schema file the answer must match (strict structured output).
        /// The parsed answer is also returned as `result.json`.
        #[arg(long, value_name = "FILE")]
        schema: Option<PathBuf>,
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

        /// JSON request body as a string, or "-" to read it from stdin (UTF-8, at most 16 MiB).
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

impl Cli {
    /// Parse argv, then enforce the cross-level rule clap cannot express for
    /// global flags (a `requires` between two globals fails when they sit on
    /// different sides of the subcommand): `--backend` needs `--json`.
    /// Violations exit 2 with clap's own diagnostic, like any usage error.
    pub fn parse_checked() -> Self {
        Self::check(Self::parse()).unwrap_or_else(|e| e.exit())
    }

    /// The post-parse checks, separate so tests can drive them.
    pub fn check(self) -> Result<Self, clap::Error> {
        if self.backend && !self.json {
            return Err(Self::command().error(
                clap::error::ErrorKind::MissingRequiredArgument,
                "--backend requires --json",
            ));
        }
        Ok(self)
    }
}

/// Generate documentation from the same command tree that parses user input.
pub fn reference() -> String {
    fn visit(mut command: clap::Command, name: &str, output: &mut String) {
        command = command.bin_name(name);
        command.build();
        output.push_str(&format!(
            "## `{name}`\n\n```text\n{}\n```\n\n",
            command.render_long_help()
        ));
        for child in command.get_subcommands() {
            if !child.is_hide_set() {
                visit(
                    child.clone(),
                    &format!("{name} {}", child.get_name()),
                    output,
                );
            }
        }
    }
    let mut output = "# Command reference\n\nGenerated by `askcodex reference`; edit the Clap definitions to change this file.\n\n".to_string();
    visit(Cli::command(), "askcodex", &mut output);
    let lines: Vec<_> = output.lines().map(str::trim_end).collect();
    format!("{}\n", lines.join("\n").trim_end())
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

        /// Force a transparent or an opaque background. Unset, the prompt
        /// decides.
        #[arg(long, value_enum)]
        background: Option<Background>,
    },

    /// Edit / reference-guided image (up to 5 reference images).
    Edit {
        /// Edit prompt.
        prompt: String,

        /// Regular PNG reference files, at most 25 MiB combined.
        #[arg(short = 'i', long = "inputs", num_args = 1.., required = true)]
        inputs: Vec<PathBuf>,

        /// Output PNG path.
        #[arg(short, long, default_value = "image-edited.png")]
        out: PathBuf,

        /// Force a transparent or an opaque background. Unset, the prompt
        /// decides.
        #[arg(long, value_enum)]
        background: Option<Background>,
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
///
/// The catalog also lists `ultra` for some models, but that is a Codex
/// client-side multi-agent mode: `/codex/responses` rejects it with HTTP 400
/// for every model, so it is not offered here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Effort {
    Low,
    Medium,
    High,
    Xhigh,
    Max,
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
            Effort::None => "none",
        }
    }
}

/// Answer verbosity accepted by `--verbosity` (`text.verbosity`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Verbosity {
    Low,
    Medium,
    High,
}

impl Verbosity {
    /// The wire string for the `text.verbosity` field.
    pub fn as_str(self) -> &'static str {
        match self {
            Verbosity::Low => "low",
            Verbosity::Medium => "medium",
            Verbosity::High => "high",
        }
    }
}

/// Image background accepted by `--background`. Codex 0.160.0 always sends
/// one of these two; `auto` exists in its enum but is not offered here
/// because leaving the flag unset already lets the prompt decide.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Background {
    Transparent,
    Opaque,
}

impl Background {
    /// The wire string for the `background` field.
    pub fn as_str(self) -> &'static str {
        match self {
            Background::Transparent => "transparent",
            Background::Opaque => "opaque",
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
    fn agent_controls_parse_and_reject_unknown_values() {
        let c = Cli::try_parse_from([
            "askcodex",
            "ask",
            "x",
            "--verbosity",
            "low",
            "--schema",
            "s.json",
        ])
        .unwrap();
        match c.cmd {
            Cmd::Ask {
                verbosity, schema, ..
            } => {
                assert_eq!(verbosity, Some(Verbosity::Low));
                assert_eq!(schema, Some(PathBuf::from("s.json")));
            }
            other => panic!("{other:?}"),
        }
        let c = Cli::try_parse_from(["askcodex", "ask", "x"]).unwrap();
        assert!(matches!(
            c.cmd,
            Cmd::Ask {
                verbosity: None,
                schema: None,
                ..
            }
        ));
        for sub in [vec!["create", "p"], vec!["edit", "p", "-i", "a.png"]] {
            let mut argv = vec!["askcodex", "image"];
            argv.extend(sub.iter().copied());
            argv.extend(["--background", "transparent"]);
            Cli::try_parse_from(&argv).unwrap_or_else(|e| panic!("{argv:?}: {e}"));
        }
        // `auto` is what an unset flag already means; `max` is not a
        // verbosity. Both are usage errors, before any credential read.
        assert!(
            Cli::try_parse_from(["askcodex", "image", "create", "p", "--background", "auto"])
                .is_err()
        );
        assert!(Cli::try_parse_from(["askcodex", "ask", "x", "--verbosity", "max"]).is_err());
    }

    #[test]
    fn backend_requires_json_wherever_either_flag_sits() {
        for argv in [
            vec!["askcodex", "--json", "models", "--backend"],
            vec!["askcodex", "--backend", "models", "--json"],
            vec!["askcodex", "models", "--json", "--backend"],
        ] {
            let cli = Cli::try_parse_from(&argv).unwrap();
            assert!(cli.check().is_ok(), "{argv:?}");
        }
        for argv in [
            vec!["askcodex", "models", "--backend"],
            vec!["askcodex", "--events", "usage", "--backend"],
        ] {
            let cli = Cli::try_parse_from(&argv).unwrap();
            let err = cli.check().expect_err("--backend without --json");
            assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
            assert_eq!(err.exit_code(), 2);
        }
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
        // Catalog-only effort: /codex/responses answers HTTP 400 to it, so
        // the parser refuses it before any credential is loaded.
        assert!(Cli::try_parse_from(["askcodex", "ask", "x", "--effort", "ultra"]).is_err());
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
