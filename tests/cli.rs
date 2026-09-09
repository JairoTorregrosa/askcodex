//! End-to-end tests: the compiled `askcodex` binary, exercised the way a user
//! (or a script) actually runs it.
//!
//! The in-crate unit tests cover renderers, parsers and the HTTP client
//! against mocks. They cannot cover what this file covers: process exit
//! codes, which stream each byte lands on, and the fact that `--json` puts
//! exactly one JSON document on stdout and nothing else. Those are
//! properties of the *binary*, so they are tested by running the binary
//! (`env!("CARGO_BIN_EXE_askcodex")`).
//!
//! # Offline by construction
//!
//! Nothing here reaches the internet, and nothing here reads or writes the
//! real `~/.codex`. Every child process is launched with:
//!
//! - `Command::env_clear()`, so no ambient variable (including
//!   `NO_PROXY`, a real proxy, or `HOME`) can influence the run. Env is
//!   set on the CHILD; the tests never call `std::env::set_var`, which is
//!   process-global and unsound under a threaded test harness.
//! - `CODEX_HOME` and `HOME` pointed at a fresh per-test temp directory
//!   under `target/tmp`. The real auth file is unreachable by construction:
//!   `config::codex_home()` reads exactly those two variables.
//! - `ALL_PROXY` / `HTTPS_PROXY` / `HTTP_PROXY` pointed at a closed
//!   loopback port. ureq's default config reads those, so if a regression
//!   ever made a command reach the network it fails instantly with
//!   `Connection refused` on 127.0.0.1 instead of sending a bearer token to
//!   chatgpt.com. This is a seatbelt, not the safety argument: every test
//!   asserts a specific *pre-network* error string, so an unexpected
//!   request fails the test either way.
//! - `current_dir()` set to the temp home, so a regression that writes an
//!   output file cannot drop it into the source tree.
//!
//! # Where the success paths live
//!
//! Every command's host is the compile-time constant `config::BASE_URL`,
//! and askcodex attaches credentials to that origin and no other — including
//! for `raw`, whose target comes from the command line. So a loopback mock
//! is unreachable from out here BY DESIGN, and the success paths are tested
//! in-crate instead (`src/run.rs`), where `cfg!(test)` permits loopback and
//! the same dispatch, rendering and client code runs.
//!
//! What this file tests about `raw`'s target is therefore the refusal: the
//! section near the end points the shipped binary at a real loopback server
//! and asserts that server recorded zero calls. Those runs add
//! `NO_PROXY=127.0.0.1,localhost`, so the mock WOULD be reachable past the
//! dead proxy — which is what makes its silence evidence about askcodex rather
//! than about the proxy.
//!
//! # `--no-refresh`
//!
//! INVARIANT — do not weaken: every run that reaches askcodex's dispatch with
//! the [`TempHome::write_valid_auth`] fixture passes `--no-refresh`.
//! Without it, `Client::ensure_fresh` consults `auth::needs_refresh`, which
//! is time-dependent (`REFRESH_MAX_AGE_DAYS` against the fixture's fixed
//! `last_refresh`), and a run that is inert today would start POSTing to
//! the real OAuth endpoint on a later calendar date. The dead proxy would
//! block it, but the failure would be a mystery in some future year. Runs
//! that never reach dispatch (`--help`, clap usage errors, and the ones
//! whose home has no usable `auth.json`) do not need the flag.
//!
//! # `auth refresh`
//!
//! `askcodex auth refresh` rotates real credentials, so it is invoked here in
//! exactly one situation: against a temp home whose `auth.json` is missing
//! or unusable. `run_with_io` loads `auth.json` as step 1, before any
//! dispatch, so those runs fail before the OAuth path is reachable and
//! there is no token in the directory to rotate.
//!
//! INVARIANT — do not weaken: no test may execute `auth refresh` (or any
//! `auth refresh` alias) against a home that contains a usable
//! `refresh_token`. That would post a refresh request for real. The fixture
//! written by [`TempHome::write_valid_auth`] contains a `refresh_token`, so
//! `auth refresh` must never be run against it.
//!
//! # Token hygiene
//!
//! The fixture credentials below are fake, but they are treated as if they
//! were not: [`Run::new`] fails the test if any of them appears in stdout
//! or stderr, so every single invocation in this file — including the ones
//! whose assertions are about something else entirely — doubles as a leak
//! check.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

use httpmock::Method::{GET, POST};
use httpmock::MockServer;
use serde_json::{Value, json};

/// The binary under test, built by cargo for this integration target.
const BIN: &str = env!("CARGO_BIN_EXE_askcodex");

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

/// A syntactically valid but entirely fake JWT: `{"alg":"none"}` header,
/// `{"exp":4102444800,...}` payload (2100-01-01T00:00:00Z, so `auth status`
/// reports it as valid without any clock games), and a signature segment
/// that is not base64 at all. It is accepted only because `auth::jwt_exp`
/// reads the `exp` claim and deliberately does not verify signatures.
///
/// Regenerate with:
/// ```text
/// python3 -c 'import base64,json
/// b=lambda x: base64.urlsafe_b64encode(x).decode().rstrip("=")
/// print(b(json.dumps({"alg":"none","typ":"JWT"},separators=(",",":")).encode())+"."
///      +b(json.dumps({"exp":4102444800,"iss":"askcodex-test-fixture",
///                     "note":"fake token, never a real credential"},
///                    separators=(",",":")).encode())+".askcodex-fixture-signature-do-not-print")'
/// ```
const FIXTURE_ACCESS_TOKEN: &str = concat!(
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.",
    "eyJleHAiOjQxMDI0NDQ4MDAsImlzcyI6ImNzdWItdGVzdC1maXh0dXJlIiwibm90ZSI6",
    "ImZha2UgdG9rZW4sIG5ldmVyIGEgcmVhbCBjcmVkZW50aWFsIn0.",
    "askcodex-fixture-signature-do-not-print"
);

/// The payload segment on its own. Checked separately so a leak that prints
/// only part of the token is still caught.
const FIXTURE_JWT_PAYLOAD: &str = concat!(
    "eyJleHAiOjQxMDI0NDQ4MDAsImlzcyI6ImNzdWItdGVzdC1maXh0dXJlIiwibm90ZSI6",
    "ImZha2UgdG9rZW4sIG5ldmVyIGEgcmVhbCBjcmVkZW50aWFsIn0"
);

const FIXTURE_JWT_SIGNATURE: &str = "askcodex-fixture-signature-do-not-print";
const FIXTURE_ID_TOKEN: &str = "askcodex-fixture-id-token-do-not-print";
const FIXTURE_REFRESH_TOKEN: &str = "askcodex-fixture-refresh-token-do-not-print";

/// Not a credential, but redacted anyway: this is the shape askcodex prints for
/// a real account, and the repo is public.
const FIXTURE_ACCOUNT_ID: &str = "acct_REDACTED";

/// `exp` of [`FIXTURE_ACCESS_TOKEN`], rendered the way `auth status` prints
/// it.
const FIXTURE_EXPIRY_RFC3339: &str = "2100-01-01T00:00:00+00:00";

const FIXTURE_LAST_REFRESH: &str = "2026-08-07T23:32:41.615755Z";

/// Every value that must never appear on stdout or stderr, with the name
/// used in the failure message. The VALUE is never printed by the assertion
/// — only the name — so a failing leak check does not itself leak.
const SECRETS: &[(&str, &str)] = &[
    ("tokens.access_token", FIXTURE_ACCESS_TOKEN),
    ("tokens.access_token[payload segment]", FIXTURE_JWT_PAYLOAD),
    (
        "tokens.access_token[signature segment]",
        FIXTURE_JWT_SIGNATURE,
    ),
    ("tokens.id_token", FIXTURE_ID_TOKEN),
    ("tokens.refresh_token", FIXTURE_REFRESH_TOKEN),
];

/// A closed port on loopback. Any attempted request is refused immediately.
const DEAD_PROXY: &str = "http://127.0.0.1:1";

/// askcodex's own wording for a transport failure. Its PRESENCE proves a
/// request was attempted (and refused by the dead proxy); its ABSENCE
/// proves a command failed before the network.
const TRANSPORT_ERROR: &str = "http transport error";

/// A minimal but real PNG header. Reference images are never sent anywhere
/// in these tests; the bytes exist so the files are not empty.
const PNG_BYTES: &[u8] = b"\x89PNG\r\n\x1a\n askcodex test fixture, not an image";

// ---------------------------------------------------------------------------
// temp CODEX_HOME
// ---------------------------------------------------------------------------

/// A private `CODEX_HOME` for one test.
///
/// Lives under `CARGO_TARGET_TMPDIR` (`target/tmp/...`) rather than the
/// system temp dir: cargo hands that path to integration tests precisely
/// for this, it ignores `TMPDIR`, and a directory leaked by a panicking
/// test stays inside `target/` where `cargo clean` removes it.
struct TempHome {
    dir: PathBuf,
}

impl TempHome {
    fn new(tag: &str) -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join("cli")
            .join(format!("{tag}-{}-{unique}", std::process::id()));
        // A leftover directory would silently share state between runs.
        if dir.exists() {
            fs::remove_dir_all(&dir).expect("clear a leftover temp home");
        }
        fs::create_dir_all(&dir).expect("create the temp home");
        TempHome { dir }
    }

    fn path(&self) -> &Path {
        &self.dir
    }

    fn auth_path(&self) -> PathBuf {
        self.dir.join("auth.json")
    }

    /// The auth path as askcodex prints it in error messages.
    fn auth_path_display(&self) -> String {
        self.auth_path().display().to_string()
    }

    /// Write `auth.json` verbatim (used for the malformed / incomplete
    /// documents — no serializer is involved, so the bytes are exactly
    /// what the test intends).
    fn write_auth(&self, contents: &str) {
        fs::write(self.auth_path(), contents).expect("write auth.json");
    }

    /// A complete, well-formed `auth.json` carrying the fake fixture
    /// credentials. Enough for `load_auth` and `Client::new` to succeed, so
    /// commands get as far as their own local validation.
    fn write_valid_auth(&self) {
        self.write_auth(&format!(
            concat!(
                "{{\n",
                "  \"auth_mode\": \"chatgpt\",\n",
                "  \"tokens\": {{\n",
                "    \"id_token\": \"{id}\",\n",
                "    \"access_token\": \"{access}\",\n",
                "    \"refresh_token\": \"{refresh}\",\n",
                "    \"account_id\": \"{account}\"\n",
                "  }},\n",
                "  \"last_refresh\": \"{last_refresh}\"\n",
                "}}\n"
            ),
            id = FIXTURE_ID_TOKEN,
            access = FIXTURE_ACCESS_TOKEN,
            refresh = FIXTURE_REFRESH_TOKEN,
            account = FIXTURE_ACCOUNT_ID,
            last_refresh = FIXTURE_LAST_REFRESH,
        ));
    }

    /// Create a file inside the home and return its absolute path.
    fn write_file(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.dir.join(name);
        fs::write(&path, bytes).expect("write a fixture file");
        path
    }

    fn read_auth_bytes(&self) -> Vec<u8> {
        fs::read(self.auth_path()).expect("read auth.json")
    }

    /// Sorted file names directly inside the home.
    fn entries(&self) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(&self.dir)
            .expect("list the temp home")
            .map(|entry| {
                entry
                    .expect("read a temp home entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        names
    }

    /// askcodex read `auth.json`; it must not have rewritten, repaired or
    /// backed it up. Byte-for-byte, and no stray `auth.json.bak`.
    fn assert_auth_untouched(&self, before: &[u8]) {
        let after = self.read_auth_bytes();
        assert!(
            after == before,
            "auth.json was modified: {} bytes before, {} bytes after",
            before.len(),
            after.len()
        );
        assert!(
            !self.dir.join("auth.json.bak").exists(),
            "askcodex created auth.json.bak while only reading credentials"
        );
    }

    fn assert_entries(&self, expected: &[&str]) {
        assert_eq!(
            self.entries(),
            expected,
            "unexpected files in the temp CODEX_HOME"
        );
    }
}

impl Drop for TempHome {
    fn drop(&mut self) {
        // Best effort: cleanup failure says nothing about the code under
        // test, and Drop cannot report it. Anything left behind is inside
        // target/tmp.
        let _ = fs::remove_dir_all(&self.dir);
    }
}

// ---------------------------------------------------------------------------
// the runner
// ---------------------------------------------------------------------------

/// One completed `askcodex` invocation.
struct Run {
    args: String,
    code: i32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl Run {
    /// Spawn `askcodex <args>` against `home` with `stdin` piped in.
    ///
    /// Sets up the isolation described in the module docs and, before
    /// returning, fails the test if a fixture credential reached either
    /// stream.
    fn new(home: &TempHome, args: &[&str], stdin: &[u8]) -> Run {
        Self::with_env(home, args, stdin, &[])
    }

    /// [`Run::new`] plus extra environment variables for the child.
    fn with_env(home: &TempHome, args: &[&str], stdin: &[u8], env: &[(&str, &str)]) -> Run {
        let mut command = Command::new(BIN);
        command
            // Nothing ambient reaches the child: no real HOME, no real
            // CODEX_HOME, no NO_PROXY escape hatch, no proxy of the
            // developer's.
            .env_clear()
            .env("CODEX_HOME", home.path())
            .env("HOME", home.path())
            .env("ALL_PROXY", DEAD_PROXY)
            .env("HTTPS_PROXY", DEAD_PROXY)
            .env("HTTP_PROXY", DEAD_PROXY)
            .current_dir(home.path())
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (key, value) in env {
            command.env(key, value);
        }

        let mut child = command
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {BIN}: {e}"));
        {
            let mut pipe = child.stdin.take().expect("child stdin");
            match pipe.write_all(stdin) {
                Ok(()) => {}
                // The child is entitled to exit before reading stdin (most
                // of these runs fail on auth first). Any OTHER write error
                // is a real problem and must not be swallowed.
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
                Err(e) => panic!("write to child stdin: {e}"),
            }
        }
        let output = child.wait_with_output().expect("wait for askcodex");

        let run = Run {
            args: args.join(" "),
            // A signal death (None) is never expected and must not be
            // silently mapped onto some placeholder code.
            code: output
                .status
                .code()
                .unwrap_or_else(|| panic!("`askcodex {}` was killed by a signal", args.join(" "))),
            stdout: output.stdout,
            stderr: output.stderr,
        };
        // FIRST, before any other assertion can print the streams.
        run.assert_no_secret_leak();
        run
    }

    /// No fixture credential may appear on either stream, ever.
    fn assert_no_secret_leak(&self) {
        for (name, secret) in SECRETS {
            for (stream, bytes) in [("stdout", &self.stdout), ("stderr", &self.stderr)] {
                assert!(
                    !contains(bytes, secret.as_bytes()),
                    "`askcodex {}` leaked {name} on {stream} \
                     (streams withheld from this message on purpose)",
                    self.args
                );
            }
        }
    }

    fn stdout(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    fn stderr(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }

    /// Context for a failed assertion. Safe to print: the leak check above
    /// already ran.
    fn dump(&self) -> String {
        format!(
            "`askcodex {}` -> exit {}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            self.args,
            self.code,
            self.stdout(),
            self.stderr()
        )
    }

    fn assert_code(&self, expected: i32) -> &Self {
        assert_eq!(self.code, expected, "wrong exit code\n{}", self.dump());
        self
    }

    fn assert_stdout_empty(&self) -> &Self {
        assert!(
            self.stdout.is_empty(),
            "stdout must stay empty on failure\n{}",
            self.dump()
        );
        self
    }

    fn assert_stderr_empty(&self) -> &Self {
        assert!(
            self.stderr.is_empty(),
            "stderr must stay empty on success\n{}",
            self.dump()
        );
        self
    }

    fn assert_stdout_has(&self, needle: &str) -> &Self {
        assert!(
            contains(&self.stdout, needle.as_bytes()),
            "stdout is missing {needle:?}\n{}",
            self.dump()
        );
        self
    }

    fn assert_stdout_lacks(&self, needle: &str) -> &Self {
        assert!(
            !contains(&self.stdout, needle.as_bytes()),
            "stdout must not contain {needle:?}\n{}",
            self.dump()
        );
        self
    }

    fn assert_stderr_has(&self, needle: &str) -> &Self {
        assert!(
            contains(&self.stderr, needle.as_bytes()),
            "stderr is missing {needle:?}\n{}",
            self.dump()
        );
        self
    }

    fn assert_stderr_lacks(&self, needle: &str) -> &Self {
        assert!(
            !contains(&self.stderr, needle.as_bytes()),
            "stderr must not contain {needle:?}\n{}",
            self.dump()
        );
        self
    }

    /// A askcodex runtime failure: exit 1, a `askcodex: error: ` line on stderr,
    /// and NOTHING on stdout (scripts pipe stdout; a half-written payload
    /// next to an error would be worse than no payload).
    fn assert_askcodex_error(&self, needles: &[&str]) -> &Self {
        self.assert_code(1).assert_stdout_empty();
        if self
            .args
            .split_whitespace()
            .any(|arg| arg == "--json" || arg == "--events")
        {
            let stderr = self.stderr();
            let mut lines: Vec<&str> = stderr.lines().collect();
            let document = parse_single_json_document(lines.pop().expect("missing JSON error"));
            assert_eq!(sorted_keys(&document), ["error", "schema_version"]);
            assert_eq!(document["schema_version"], json!(1));
            assert_eq!(sorted_keys(&document["error"]), ["code", "message"]);
            assert!(
                document["error"]["code"]
                    .as_str()
                    .is_some_and(|code| !code.is_empty())
            );
            let message = document["error"]["message"]
                .as_str()
                .expect("string error message");
            for needle in needles {
                assert!(message.contains(needle), "error message missing {needle:?}");
            }
            if self.args.split_whitespace().any(|arg| arg == "--stream") {
                assert_eq!(
                    lines,
                    [
                        "askcodex: note: --json does not apply to `raw --stream`; stdout carries the raw event stream"
                    ]
                );
            } else {
                assert!(
                    lines.is_empty(),
                    "machine stderr has extraneous diagnostics"
                );
            }
            return self;
        }
        assert!(
            self.stderr().starts_with("askcodex: error: ")
                || contains(&self.stderr, b"\naskcodex: error: "),
            "stderr carries no `askcodex: error: ` line\n{}",
            self.dump()
        );
        for needle in needles {
            self.assert_stderr_has(needle);
        }
        self
    }

    /// A clap usage failure. Exit code 2 is clap's, asserted (not assumed)
    /// — probed against this binary.
    fn assert_usage_error(&self) -> &Self {
        self.assert_code(2).assert_stdout_empty();
        assert!(
            self.stderr().starts_with("error: "),
            "clap usage errors start with `error: ` on stderr\n{}",
            self.dump()
        );
        self
    }

    /// A clean success: exit 0 and an empty stderr.
    fn assert_ok(&self) -> &Self {
        self.assert_code(0).assert_stderr_empty();
        self
    }

    /// The command failed BEFORE it could reach the network. Backed by the
    /// dead proxy: had a request been attempted, askcodex would have reported
    /// `http transport error` instead of (or in addition to) the local
    /// failure.
    fn assert_no_request_attempted(&self) -> &Self {
        self.assert_stderr_lacks(TRANSPORT_ERROR)
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && needle.len() <= haystack.len()
        && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Shorthand for a run with no stdin.
fn askcodex(home: &TempHome, args: &[&str]) -> Run {
    Run::new(home, args, b"")
}

// ---------------------------------------------------------------------------
// `--json` purity
// ---------------------------------------------------------------------------

/// Parse `text` as exactly ONE JSON document and return it.
///
/// This is the real parser, not an approximation: cargo makes a package's
/// `[dependencies]` available to its integration-test targets, so
/// `serde_json` is nameable here without touching the frozen manifest.
///
/// `serde_json::from_str` is precisely the right check for `--json` purity
/// because it rejects trailing non-whitespace bytes. So a second document,
/// a stray log line, or a truncated payload on stdout all fail here — the
/// three ways the "one JSON document and nothing else" contract can break.
fn parse_single_json_document(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or_else(|e| {
        panic!("stdout is not exactly one JSON document ({e}):\n{text}");
    })
}

fn parse_semantic_result(text: &str, command: &str) -> Value {
    let mut document = parse_single_json_document(text);
    assert_eq!(document["schema_version"], json!(1));
    assert_eq!(document["command"], json!(command));
    assert_eq!(
        sorted_keys(&document),
        ["command", "result", "schema_version"]
    );
    document["result"].take()
}

/// The sorted key set of a JSON object, for exact-shape assertions.
///
/// Exact beats "contains": asserting the full key set is what proves askcodex
/// did not ADD a key (a token-shaped one, say) as well as that it emitted
/// the documented ones.
fn sorted_keys(value: &Value) -> Vec<String> {
    let object = value
        .as_object()
        .unwrap_or_else(|| panic!("expected a JSON object, got: {value}"));
    let mut keys: Vec<String> = object.keys().cloned().collect();
    keys.sort();
    keys
}

#[test]
fn the_json_purity_check_rejects_impure_stdout() {
    // A guard on the guard. The `--json` tests are only as strong as the
    // parser behind them, so the property that makes `from_str` the right
    // check — trailing bytes are an ERROR, not something it tolerates — is
    // pinned here rather than assumed.
    for impure in [
        // two documents
        "{\"a\":1}\n{\"b\":2}\n",
        // truncated
        "{\"a\":1",
        // a stray line sharing the stream
        "askcodex: note: something\n{\"a\":1}\n",
        // a trailing line after a complete document
        "{\"a\":1}\ndone\n",
        // nothing at all
        "",
    ] {
        assert!(
            serde_json::from_str::<Value>(impure).is_err(),
            "the purity check would have accepted impure stdout: {impure:?}"
        );
    }
    // What askcodex actually emits — one document plus the trailing newline —
    // is accepted, so the check is not vacuously strict.
    assert_eq!(parse_single_json_document("{\"a\":1}\n"), json!({"a": 1}));
}

// ---------------------------------------------------------------------------
// help / version
// ---------------------------------------------------------------------------

#[test]
fn help_describes_the_whole_command_surface() {
    let home = TempHome::new("help-root");
    let run = askcodex(&home, &["--help"]);
    run.assert_ok();

    for needle in [
        "whoami",
        "usage",
        "models",
        "image",
        "ask",
        "raw",
        "auth",
        "--json",
        "--no-refresh",
        "--help",
        "--version",
    ] {
        run.assert_stdout_has(needle);
    }
    // The credential contract is part of the help text, not folklore.
    run.assert_stdout_has("~/.codex/auth.json");
    run.assert_stdout_has("codex login");
    run.assert_stdout_has("No API key is used or accepted");
}

#[test]
fn help_advertises_no_api_key_knob() {
    let home = TempHome::new("help-no-key");
    let run = askcodex(&home, &["--help"]);
    run.assert_ok();
    // The only mention of an API key anywhere is the sentence saying there
    // is none; there must be no flag that takes one.
    for absent in [
        "--api-key",
        "--openai-api-key",
        "--key",
        "--token",
        "OPENAI",
    ] {
        run.assert_stdout_lacks(absent);
    }
}

#[test]
fn short_help_and_version_exit_zero() {
    let home = TempHome::new("help-short");
    askcodex(&home, &["-h"])
        .assert_ok()
        .assert_stdout_has("Usage:");
    askcodex(&home, &["--version"])
        .assert_ok()
        .assert_stdout_has("askcodex ");
    askcodex(&home, &["-V"])
        .assert_ok()
        .assert_stdout_has("askcodex ");
}

#[test]
fn every_subcommand_help_names_its_own_flags() {
    const CASES: &[(&[&str], &[&str])] = &[
        (
            &["whoami", "--help"],
            &["Show account identity and plan", "--json", "--no-refresh"],
        ),
        (
            &["usage", "--help"],
            &["Show rate-limit / quota usage", "--json", "--no-refresh"],
        ),
        (&["models", "--help"], &["--client-version", "--json"]),
        (&["image", "--help"], &["create", "edit", "one opaque PNG"]),
        (
            &["image", "create", "--help"],
            &["<PROMPT>", "--out", "[default: image.png]"],
        ),
        (
            &["image", "edit", "--help"],
            &["--inputs", "-i,", "--out", "[default: image-edited.png]"],
        ),
        (
            &["ask", "--help"],
            &[
                "<PROMPT>",
                "\"-\" to read it from stdin",
                "--model",
                "--instructions",
                "--effort",
                "[possible values: low, medium, high, xhigh, max, ultra, none]",
            ],
        ),
        (
            &["raw", "--help"],
            &[
                "<METHOD>",
                "<PATH>",
                "--body",
                "--stream",
                "[possible values: GET, POST, PUT, PATCH, DELETE]",
                "\"-\" to read it from stdin",
            ],
        ),
        (&["auth", "--help"], &["status", "refresh"]),
        (
            &["auth", "status", "--help"],
            &["never prints secret values", "--json"],
        ),
        (
            &["auth", "refresh", "--help"],
            &["Force a token refresh now", "--json"],
        ),
    ];

    let home = TempHome::new("help-subcommands");
    for (args, needles) in CASES {
        let run = askcodex(&home, args);
        run.assert_ok();
        for needle in *needles {
            run.assert_stdout_has(needle);
        }
    }
}

#[test]
fn help_advertises_the_defaults_the_binary_actually_uses() {
    // These needles are BUILT from the crate's own constants rather than
    // pasted as literals. The property under test is "the help text and the
    // behaviour agree", so a `default_value` that drifts from
    // `config::` — or a `hide_default_value` slipped into the derive —
    // fails here, while a deliberate constant bump does not produce a
    // spurious failure in a test that is not about the constant's value.
    let home = TempHome::new("help-defaults");

    askcodex(&home, &["models", "--help"])
        .assert_ok()
        .assert_stdout_has(&format!("[default: {}]", askcodex::config::CLIENT_VERSION));

    askcodex(&home, &["ask", "--help"])
        .assert_ok()
        .assert_stdout_has(&format!(
            "[default: {}]",
            askcodex::config::DEFAULT_ASK_MODEL
        ));

    // The reference-image cap is prose in the help and a hard check in
    // `endpoints::images::edit`. Deriving the sentence from the constant is
    // what stops the two from drifting apart silently.
    askcodex(&home, &["image", "edit", "--help"])
        .assert_ok()
        .assert_stdout_has(&format!(
            "up to {} reference images",
            askcodex::config::MAX_EDIT_IMAGES
        ));
}

#[test]
fn help_never_executes_the_command() {
    // No auth.json in this home. `--help` still exits 0 for every command,
    // including the ones that would otherwise need credentials, which is
    // what proves help short-circuits before any auth or network work.
    let home = TempHome::new("help-inert");
    for args in [
        ["whoami", "--help"],
        ["usage", "--help"],
        ["ask", "--help"],
        ["auth", "--help"],
    ] {
        askcodex(&home, &args)
            .assert_ok()
            .assert_stdout_has("Usage:");
    }
    askcodex(&home, &["auth", "refresh", "--help"])
        .assert_ok()
        .assert_stdout_has("Usage: askcodex auth refresh");
    // ... and it created nothing.
    home.assert_entries(&[]);
}

// ---------------------------------------------------------------------------
// missing auth.json
// ---------------------------------------------------------------------------

/// Every command that needs credentials, in the shape a user would type.
///
/// `auth refresh` is included ONLY because these runs have no `auth.json`:
/// `run_with_io` loads credentials as step 1, so the refresh path is
/// unreachable and there is nothing in the directory to rotate. See the
/// module docs.
const CREDENTIALED_COMMANDS: &[&[&str]] = &[
    &["whoami"],
    &["usage"],
    &["models"],
    &["image", "create", "a cat"],
    &["image", "edit", "bluer", "-i", "ref.png"],
    &["ask", "hello"],
    &["raw", "GET", "/codex/usage"],
    &["raw", "POST", "/codex/responses", "--body", "{}"],
    &["auth", "status"],
    &["auth", "refresh"],
];

#[test]
fn missing_auth_json_fails_every_credentialed_command() {
    let home = TempHome::new("auth-missing");
    home.write_file("ref.png", PNG_BYTES);
    let expected_path = home.auth_path_display();

    for command in CREDENTIALED_COMMANDS {
        let mut args = vec!["--no-refresh"];
        args.extend_from_slice(command);
        let run = askcodex(&home, &args);
        run.assert_askcodex_error(&[
            "auth file not found",
            &expected_path,
            "codex login",
            "ChatGPT account",
        ]);
        // Loud and local: it never got as far as a request.
        run.assert_no_request_attempted();
    }

    // askcodex must not have invented an auth file to make itself work.
    home.assert_entries(&["ref.png"]);
}

#[test]
fn missing_auth_json_keeps_stdout_empty_under_json() {
    // `--json` must not turn a failure into a half-written document on
    // stdout: the error still goes to stderr and stdout stays byte-empty.
    let home = TempHome::new("auth-missing-json");
    home.write_file("ref.png", PNG_BYTES);
    for command in CREDENTIALED_COMMANDS {
        let mut args = vec!["--json", "--no-refresh"];
        args.extend_from_slice(command);
        askcodex(&home, &args)
            .assert_askcodex_error(&["auth file not found"])
            .assert_no_request_attempted();
    }
    home.assert_entries(&["ref.png"]);
}

#[test]
fn openai_api_key_in_the_environment_is_not_a_credential_source() {
    // askcodex has exactly one credential source: ~/.codex/auth.json. The
    // variable below is planted purely to prove it is NOT used — with it
    // set and no auth.json present, askcodex must still fail and still tell the
    // user to run `codex login`.
    let home = TempHome::new("auth-env-key");
    let run = Run::with_env(
        &home,
        &["--no-refresh", "usage"],
        b"",
        &[("OPENAI_API_KEY", "sk-this-must-be-ignored-by-askcodex")],
    );
    run.assert_askcodex_error(&["auth file not found", "codex login"]);
    run.assert_no_request_attempted();
}

#[test]
fn no_codex_home_and_no_home_fails_loudly() {
    // Neither variable usable: askcodex must refuse rather than guess a path.
    let home = TempHome::new("auth-no-home");
    let mut command = Command::new(BIN);
    let output = command
        .env_clear()
        .env("CODEX_HOME", "")
        .env("HOME", "")
        .env("ALL_PROXY", DEAD_PROXY)
        .current_dir(home.path())
        .args(["--no-refresh", "usage"])
        .output()
        .expect("run askcodex without a home");

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty(), "stdout must stay empty");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.starts_with("askcodex: error: cannot resolve the codex home directory"),
        "unexpected stderr: {stderr}"
    );
    assert!(stderr.contains("Set CODEX_HOME"), "stderr: {stderr}");
}

// ---------------------------------------------------------------------------
// unusable auth.json — reported, never repaired
// ---------------------------------------------------------------------------

#[test]
fn malformed_auth_json_is_reported_and_never_rewritten() {
    let home = TempHome::new("auth-malformed");
    home.write_file("ref.png", PNG_BYTES);
    // Invalid JSON: an unquoted key and no closing brace.
    let original = "{ auth_mode: chatgpt, \"tokens\": {\n";
    home.write_auth(original);
    let before = home.read_auth_bytes();
    let expected_path = home.auth_path_display();

    for command in CREDENTIALED_COMMANDS {
        let mut args = vec!["--no-refresh"];
        args.extend_from_slice(command);
        askcodex(&home, &args)
            .assert_askcodex_error(&["failed to parse", &expected_path])
            .assert_no_request_attempted();

        // The critical part: askcodex reads credentials, it does not repair
        // them. A "helpful" rewrite here would destroy the only copy of a
        // user's tokens.
        home.assert_auth_untouched(&before);
    }
    home.assert_entries(&["auth.json", "ref.png"]);
    assert_eq!(
        String::from_utf8(home.read_auth_bytes()).expect("utf8"),
        original,
        "auth.json must be byte-identical after a parse failure"
    );
}

#[test]
fn auth_json_without_tokens_explains_the_keyring_case() {
    let home = TempHome::new("auth-no-tokens");
    home.write_file("ref.png", PNG_BYTES);
    home.write_auth("{\"auth_mode\": \"chatgpt\", \"last_refresh\": null}\n");
    let before = home.read_auth_bytes();
    let expected_path = home.auth_path_display();

    for command in CREDENTIALED_COMMANDS {
        let mut args = vec!["--no-refresh"];
        args.extend_from_slice(command);
        askcodex(&home, &args)
            .assert_askcodex_error(&[
                &expected_path,
                "has no ChatGPT tokens",
                "keyring",
                "codex login",
            ])
            .assert_no_request_attempted();
        home.assert_auth_untouched(&before);
    }
}

#[test]
fn auth_json_with_an_empty_access_token_is_rejected() {
    let home = TempHome::new("auth-empty-token");
    home.write_auth(&format!(
        "{{\"auth_mode\":\"chatgpt\",\"tokens\":{{\"access_token\":\"\",\
         \"account_id\":\"{FIXTURE_ACCOUNT_ID}\"}}}}\n"
    ));
    let before = home.read_auth_bytes();

    askcodex(&home, &["--no-refresh", "usage"])
        .assert_askcodex_error(&["has no ChatGPT tokens"])
        .assert_no_request_attempted();
    home.assert_auth_untouched(&before);
}

#[test]
fn auth_json_without_account_id_is_rejected() {
    let home = TempHome::new("auth-no-account");
    home.write_auth(&format!(
        "{{\"auth_mode\":\"chatgpt\",\"tokens\":{{\"access_token\":\"{FIXTURE_ACCESS_TOKEN}\"}}}}\n"
    ));
    let before = home.read_auth_bytes();

    askcodex(&home, &["--no-refresh", "usage"])
        .assert_askcodex_error(&["tokens are missing account_id"])
        .assert_no_request_attempted();
    home.assert_auth_untouched(&before);
}

// ---------------------------------------------------------------------------
// local validation happens before the network
// ---------------------------------------------------------------------------

#[test]
fn transcribe_rejects_invalid_audio_before_refresh_or_upload() {
    let home = TempHome::new("transcribe-invalid");
    home.write_valid_auth();
    let before = home.read_auth_bytes();
    let file = home.write_file("renamed.wav", b"ID3not a WAV");
    // No --no-refresh: local rejection must precede even the pre-flight refresh.
    askcodex(&home, &["transcribe", file.to_str().unwrap()])
        .assert_askcodex_error(&["invalid audio", "RIFF/WAVE"])
        .assert_no_request_attempted();
    assert_eq!(before, home.read_auth_bytes());
}

#[test]
fn transcribe_missing_file_reports_path_before_refresh_or_upload() {
    let home = TempHome::new("transcribe-missing");
    home.write_valid_auth();
    let before = home.read_auth_bytes();
    let file = home.path().join("missing-recording.wav");
    askcodex(&home, &["transcribe", file.to_str().unwrap()])
        .assert_askcodex_error(&["failed to read audio file", file.to_str().unwrap()])
        .assert_no_request_attempted();
    assert_eq!(before, home.read_auth_bytes());
}

#[test]
fn transcribe_requires_a_file_argument() {
    let home = TempHome::new("transcribe-argument");
    let output = Command::new(env!("CARGO_BIN_EXE_askcodex"))
        .env_clear()
        .env("CODEX_HOME", home.path())
        .env("HOME", home.path())
        .arg("transcribe")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
}

#[test]
fn image_edit_rejects_a_missing_reference_before_any_request() {
    let home = TempHome::new("image-missing-ref");
    home.write_valid_auth();
    let before = home.read_auth_bytes();
    let present = home.write_file("ref.png", PNG_BYTES);
    let missing = home.path().join("does-not-exist.png");
    let missing_display = missing.display().to_string();

    // Only reference is missing.
    askcodex(
        &home,
        &[
            "--no-refresh",
            "image",
            "edit",
            "bluer",
            "-i",
            &missing_display,
        ],
    )
    .assert_askcodex_error(&["input image not found", &missing_display])
    .assert_no_request_attempted();

    // A good reference followed by a bad one: every input is resolved
    // before the request is built, so the typo in the last path still costs
    // no round trip.
    askcodex(
        &home,
        &[
            "--no-refresh",
            "image",
            "edit",
            "bluer",
            "-i",
            &present.display().to_string(),
            &missing_display,
        ],
    )
    .assert_askcodex_error(&["input image not found", &missing_display])
    .assert_no_request_attempted();

    home.assert_auth_untouched(&before);
    // No output image was produced by a failed edit.
    home.assert_entries(&["auth.json", "ref.png"]);
}

#[test]
fn image_edit_rejects_one_reference_image_too_many() {
    // `MAX_EDIT_IMAGES` is 5, so this is the "six reference images" case.
    // It is expressed as max+1 so that the test keeps testing the RULE
    // rather than the number: were the cap ever raised, a hard-coded six
    // would quietly become a request askcodex is supposed to accept.
    let max = askcodex::config::MAX_EDIT_IMAGES;
    let too_many = max + 1;

    let home = TempHome::new("image-too-many-refs");
    home.write_valid_auth();
    let before = home.read_auth_bytes();

    // REAL files, all of them: this proves the count itself is rejected,
    // not that some file happened to be unreadable.
    let paths: Vec<String> = (0..too_many)
        .map(|i| {
            home.write_file(&format!("ref{i}.png"), PNG_BYTES)
                .display()
                .to_string()
        })
        .collect();

    let mut args = vec!["--no-refresh", "image", "edit", "bluer", "-i"];
    args.extend(paths.iter().map(String::as_str));

    askcodex(&home, &args)
        .assert_askcodex_error(&[&format!("at most {max} reference images (got {too_many})")])
        .assert_no_request_attempted();

    home.assert_auth_untouched(&before);
}

#[test]
fn raw_rejects_a_non_json_body_before_any_request() {
    let home = TempHome::new("raw-bad-body");
    home.write_valid_auth();
    let before = home.read_auth_bytes();

    for body in ["not json", "{", "{\"a\": }", ""] {
        askcodex(
            &home,
            &["--no-refresh", "raw", "POST", "/x", "--body", body],
        )
        .assert_askcodex_error(&["json error"])
        .assert_no_request_attempted();
    }

    home.assert_auth_untouched(&before);
}

#[test]
fn a_failed_image_command_leaves_no_output_file() {
    // The only run in this file that deliberately reaches the request
    // stage; the dead loopback proxy refuses it instantly. What matters is
    // the postcondition: a command that did not receive a verified PNG
    // writes nothing at all — no zero-byte file, no placeholder.
    let home = TempHome::new("image-no-partial");
    home.write_valid_auth();
    let before = home.read_auth_bytes();

    askcodex(&home, &["--no-refresh", "image", "create", "a cat"])
        .assert_askcodex_error(&[])
        .assert_stderr_has(TRANSPORT_ERROR);

    askcodex(
        &home,
        &["--no-refresh", "image", "create", "a cat", "-o", "out.png"],
    )
    .assert_askcodex_error(&[])
    .assert_stderr_has(TRANSPORT_ERROR);

    // Default output path is `image.png` in the cwd (the temp home).
    home.assert_entries(&["auth.json"]);
    home.assert_auth_untouched(&before);
}

// ---------------------------------------------------------------------------
// stdin wiring
// ---------------------------------------------------------------------------

#[test]
fn ask_dash_reads_the_prompt_from_stdin() {
    let home = TempHome::new("ask-stdin");
    home.write_valid_auth();

    // Invalid UTF-8 on stdin. the stdin preparation code is the ONLY thing in askcodex
    // that can produce this message, so seeing it proves `ask -` consumed
    // stdin — and that it did so before touching the network.
    Run::new(&home, &["--no-refresh", "ask", "-"], b"\xff\xfe")
        .assert_askcodex_error(&["stdin must be UTF-8 text"])
        .assert_no_request_attempted();
}

#[test]
fn ask_with_a_literal_prompt_does_not_read_stdin() {
    // Control for the test above: the same unreadable stdin, but a literal
    // prompt. askcodex must ignore stdin entirely and fail later, at the
    // request (refused by the dead proxy) — not with a stdin error.
    let home = TempHome::new("ask-no-stdin");
    home.write_valid_auth();

    Run::new(&home, &["--no-refresh", "ask", "hello"], b"\xff\xfe")
        .assert_askcodex_error(&[])
        .assert_stderr_lacks("stdin must be UTF-8 text")
        .assert_stderr_has(TRANSPORT_ERROR);
}

#[test]
fn raw_body_dash_reads_the_body_from_stdin() {
    let home = TempHome::new("raw-stdin");
    home.write_valid_auth();

    // 1. Unreadable stdin -> the stdin error. Only reachable by reading it.
    Run::new(
        &home,
        &["--no-refresh", "raw", "POST", "/x", "--body", "-"],
        b"\xff\xfe",
    )
    .assert_askcodex_error(&["stdin must be UTF-8 text"])
    .assert_no_request_attempted();

    // 2. Empty stdin -> "EOF while parsing a value", i.e. askcodex parsed an
    //    EMPTY body. Had it parsed the literal "-" instead of reading
    //    stdin, there would have been a character to reject.
    Run::new(
        &home,
        &["--no-refresh", "raw", "POST", "/x", "--body", "-"],
        b"",
    )
    .assert_askcodex_error(&["json error", "EOF while parsing a value"])
    .assert_no_request_attempted();

    // 3. Malformed JSON on stdin -> the body from stdin is what got
    //    parsed, and it is rejected before any request.
    Run::new(
        &home,
        &["--no-refresh", "raw", "POST", "/x", "--body", "-"],
        b"{\"stdin_wired\": }",
    )
    .assert_askcodex_error(&["json error"])
    .assert_no_request_attempted();
}

// ---------------------------------------------------------------------------
// clap surface errors
// ---------------------------------------------------------------------------

#[test]
fn unknown_subcommands_and_bad_values_exit_two() {
    let home = TempHome::new("usage-errors");
    home.write_valid_auth();
    let before = home.read_auth_bytes();

    const CASES: &[(&[&str], &str)] = &[
        (&["bogus"], "unrecognized subcommand"),
        (&["image", "bogus", "p"], "unrecognized subcommand"),
        (&["auth", "bogus"], "unrecognized subcommand"),
        (&["ask", "x", "--effort", "huge"], "invalid value 'huge'"),
        (&["raw", "post", "/x"], "invalid value 'post'"),
        (&["raw", "GET"], "required arguments were not provided"),
        (
            &["image", "edit", "p"],
            "required arguments were not provided",
        ),
        (&["image", "create"], "required arguments were not provided"),
        (&["ask"], "required arguments were not provided"),
        (&["usage", "--api-key", "x"], "unexpected argument"),
        (&["usage", "--openai-api-key", "x"], "unexpected argument"),
        (&["usage", "--bogus-flag"], "unexpected argument"),
        (&["models", "--client-version"], "a value is required"),
    ];

    for (args, needle) in CASES {
        askcodex(&home, args)
            .assert_usage_error()
            .assert_stderr_has(needle)
            .assert_no_request_attempted();
    }

    // A rejected command line never touches credentials.
    home.assert_auth_untouched(&before);
}

// ---------------------------------------------------------------------------
// auth status: the one command that fully succeeds offline
// ---------------------------------------------------------------------------

#[test]
fn auth_status_reports_claims_and_never_a_token() {
    let home = TempHome::new("auth-status");
    home.write_valid_auth();
    let before = home.read_auth_bytes();

    let run = askcodex(&home, &["--no-refresh", "auth", "status"]);
    run.assert_ok();
    for needle in [
        "auth file : ",
        &home.auth_path_display(),
        "auth_mode : chatgpt",
        &format!("account_id: {FIXTURE_ACCOUNT_ID}"),
        &format!("last_refresh: {FIXTURE_LAST_REFRESH}"),
        &format!("access_token expires: {FIXTURE_EXPIRY_RFC3339}"),
        "valid",
    ] {
        run.assert_stdout_has(needle);
    }
    // Claims only. (The blanket leak check in Run::new also covers this;
    // stating it here is what makes the guarantee legible at the call
    // site.)
    run.assert_stdout_lacks("eyJ");
    run.assert_stdout_lacks("access_token\":");

    // Reading status is a read: nothing is rewritten, nothing is rotated.
    home.assert_auth_untouched(&before);
    home.assert_entries(&["auth.json"]);
}

#[test]
fn auth_status_json_is_exactly_one_document_on_stdout() {
    let home = TempHome::new("auth-status-json");
    home.write_valid_auth();
    let before = home.read_auth_bytes();

    let run = askcodex(&home, &["--json", "--no-refresh", "auth", "status"]);
    run.assert_ok();
    let doc = parse_semantic_result(&run.stdout(), "auth status");

    // The EXACT key set, not a containment check: this is what proves askcodex
    // reports claims and adds nothing else — no `access_token`, no
    // `refresh_token`, no `id_token`, now or after a future edit.
    assert_eq!(
        sorted_keys(&doc),
        [
            "access_token_expires_at",
            "access_token_expires_in_minutes",
            "access_token_valid",
            "account_id",
            "auth_file",
            "auth_mode",
            "last_refresh",
        ],
        "auth status --json changed shape: {doc:#}"
    );
    assert_eq!(doc["auth_file"], json!(home.auth_path_display()));
    assert_eq!(doc["auth_mode"], json!("chatgpt"));
    assert_eq!(doc["account_id"], json!(FIXTURE_ACCOUNT_ID));
    assert_eq!(doc["last_refresh"], json!(FIXTURE_LAST_REFRESH));
    assert_eq!(
        doc["access_token_expires_at"],
        json!(FIXTURE_EXPIRY_RFC3339)
    );
    assert_eq!(doc["access_token_valid"], json!(true));
    assert!(
        doc["access_token_expires_in_minutes"].is_i64(),
        "expiry must be reported as a number: {doc:#}"
    );

    home.assert_auth_untouched(&before);
}

#[test]
fn global_flags_are_accepted_after_the_deepest_subcommand() {
    let home = TempHome::new("global-flags");
    home.write_valid_auth();

    // Same invocation, flags trailing rather than leading.
    let trailing = askcodex(&home, &["auth", "status", "--no-refresh", "--json"]);
    trailing.assert_ok();
    let trailing_doc = parse_semantic_result(&trailing.stdout(), "auth status");

    // ... and in front, for parity.
    let leading = askcodex(&home, &["--no-refresh", "--json", "auth", "status"]);
    leading.assert_ok();
    let leading_doc = parse_semantic_result(&leading.stdout(), "auth status");

    // Flag POSITION must not change the result. Only the countdown differs
    // between two runs a moment apart, so it is compared out.
    assert_eq!(
        sorted_keys(&trailing_doc),
        sorted_keys(&leading_doc),
        "flag position changed the output shape"
    );
    for key in [
        "auth_file",
        "auth_mode",
        "account_id",
        "last_refresh",
        "access_token_expires_at",
        "access_token_valid",
    ] {
        assert_eq!(
            trailing_doc[key], leading_doc[key],
            "flag position changed {key}"
        );
    }
}

#[test]
fn raw_stream_with_json_announces_that_json_does_not_apply() {
    // `raw --stream` is the one stated exception to `--json` purity: a
    // verbatim SSE passthrough cannot be reshaped, so askcodex says so on
    // stderr instead of silently dropping the flag. The advisory is
    // written before the request, which is what makes it observable
    // offline (the request itself is then refused by the dead proxy).
    let home = TempHome::new("raw-stream-json");
    home.write_valid_auth();

    let run = askcodex(
        &home,
        &[
            "--json",
            "--no-refresh",
            "raw",
            "GET",
            "/codex/usage",
            "--stream",
        ],
    );
    run.assert_askcodex_error(&[]);
    run.assert_stderr_has(
        "askcodex: note: --json does not apply to `raw --stream`; \
         stdout carries the raw event stream",
    );
    // Refused at the socket: no event stream was ever received, so stdout
    // stayed empty (asserted by assert_askcodex_error).
    run.assert_stderr_has("transport_error");
    run.assert_stderr_has("http transport error");
}

// ---------------------------------------------------------------------------
// the credentialed-origin refusal, proven against the shipped binary
// ---------------------------------------------------------------------------
//
// `raw` is the only command whose host comes from the command line; every
// other command's host is the compile-time `config::BASE_URL`. That makes
// `raw` the one place where a user — or a prompt-injected agent driving
// askcodex — could aim the account's bearer token at a host of their choosing.
// askcodex refuses: the trusted origin is derived from `config::BASE_URL`, the
// check runs in the argument parser, and there is deliberately no runtime
// knob that widens it.
//
// These tests spin a real loopback server precisely so the refusal can be
// proven by its ABSENCE of traffic. `assert_calls(0)` is the assertion that
// matters — not the message, but the fact that no byte, and therefore no
// credential, ever left the process.
//
// Earlier revisions of this file drove the SUCCESS paths through `raw` at a
// loopback mock, which only worked because the binary would send credentials
// anywhere. Those cases did not lose coverage; they moved in-crate, to the
// `-- the raw escape hatch, end to end --` section of `src/run.rs`, where
// `cfg!(test)` legitimately permits loopback and the same code runs — each
// one still driving the real entry point (a `Cli` value into `run_with_io`)
// against an httpmock server, keeping the strongest assertion it made here.
//
// Full names, not globs, so this map is checkable with `cargo test <name>`
// rather than merely asserted:
//
//   raw GET prints the backend document
//     -> run.rs  raw_get_prints_the_backend_document_and_nothing_else
//   raw POST sends the validated body
//     -> run.rs  raw_post_sends_the_validated_body_on_the_wire
//   raw --body - sends the stdin document
//     -> run.rs  raw_body_dash_sends_the_document_read_from_stdin
//   raw --stream copies the stream verbatim
//     -> run.rs  raw_stream_copies_the_event_stream_to_stdout_verbatim
//   a backend error status carries its body
//     -> run.rs  a_backend_error_status_is_reported_with_its_body
//   a non-JSON 200 is reported, not guessed
//     -> run.rs  a_non_json_success_body_is_reported_not_guessed
//   401 under --no-refresh rotates nothing
//     -> run.rs  a_401_under_no_refresh_is_reported_once_and_rotates_nothing
//
// The one thing a loopback mock cannot prove from out here is what a shipped
// binary does with a hostile URL — which is what this section proves instead.

/// Child environment that would make loopback reachable if askcodex agreed to
/// go there. The dead proxy stays in force for every other host, so a
/// regression that aimed a request at chatgpt.com would still be refused at
/// the socket rather than sent.
const REACH_LOOPBACK: &[(&str, &str)] = &[("NO_PROXY", "127.0.0.1,localhost")];

fn askcodex_vs_mock(home: &TempHome, args: &[&str], stdin: &[u8]) -> Run {
    Run::with_env(home, args, stdin, REACH_LOOPBACK)
}

/// The origin askcodex is credentialed for, derived here the same way the crate
/// derives it — from `config::BASE_URL` — so this assertion cannot drift
/// into checking a stale literal.
///
/// Every refusal renders the same way: clap's exit 2, an empty stdout, and
/// a message naming both the origin that was refused and the only one askcodex
/// will ever authenticate to.
fn backend_origin() -> String {
    let (scheme, rest) = askcodex::config::BASE_URL
        .split_once("://")
        .expect("BASE_URL carries a scheme");
    let host = rest.split('/').next().expect("BASE_URL carries a host");
    format!("{scheme}://{host}")
}

fn assert_refused(run: &Run, attempted_origin: &str) {
    run.assert_usage_error();
    run.assert_stderr_has("refusing to send credentials to");
    run.assert_stderr_has(attempted_origin);
    run.assert_stderr_has(&backend_origin());
    // The refusal is a local decision: nothing was dialled, so no transport
    // error can appear alongside it.
    run.assert_no_request_attempted();
}

#[test]
fn raw_refuses_to_send_credentials_to_another_origin() {
    let home = TempHome::new("origin-refused-get");
    home.write_valid_auth();
    let before = home.read_auth_bytes();

    // A server that answers anything, so the only reason it records zero
    // calls is that askcodex declined to make one.
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(GET).path("/codex/usage");
        then.status(200).body(r#"{"plan":"plus"}"#);
    });
    let url = server.url("/codex/usage");

    let run = askcodex_vs_mock(&home, &["--no-refresh", "raw", "GET", &url], b"");
    assert_refused(&run, &server.url(""));

    mock.assert_calls(0);
    home.assert_auth_untouched(&before);
    home.assert_entries(&["auth.json"]);
}

#[test]
fn the_refusal_lands_before_the_body_and_the_credential_are_read() {
    // `--body -` would consume stdin and `POST` would attach the bearer
    // token. Neither happens: the origin check is an argument-parse
    // failure, so it precedes both. Proven by the mock's silence — the
    // body could not have been sent because no request was made at all.
    let home = TempHome::new("origin-refused-post");
    home.write_valid_auth();
    let before = home.read_auth_bytes();

    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(POST).path("/codex/responses");
        then.status(200).body(r#"{"ok":true}"#);
    });

    let run = askcodex_vs_mock(
        &home,
        &[
            "--no-refresh",
            "raw",
            "POST",
            &server.url("/codex/responses"),
            "--body",
            "-",
        ],
        b"{\"from_stdin\": true}\n",
    );
    assert_refused(&run, &server.url(""));

    mock.assert_calls(0);
    home.assert_auth_untouched(&before);
}

#[test]
fn the_stream_escape_hatch_is_refused_on_another_origin_too() {
    // `--stream` takes a different path through the client (a streamed
    // response instead of a buffered one), so it gets its own proof rather
    // than an argument that it must behave like the others.
    let home = TempHome::new("origin-refused-stream");
    home.write_valid_auth();

    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(GET).path("/codex/responses");
        then.status(200)
            .header("content-type", "text/event-stream")
            .body("event: response.completed\ndata: {}\n\n");
    });

    let run = askcodex_vs_mock(
        &home,
        &[
            "--no-refresh",
            "raw",
            "GET",
            &server.url("/codex/responses"),
            "--stream",
        ],
        b"",
    );
    assert_refused(&run, &server.url(""));
    mock.assert_calls(0);
}

#[test]
fn an_absolute_url_on_the_backend_origin_is_still_accepted() {
    // The positive control, without which the three tests above would pass
    // just as well if `raw` refused every absolute URL. This one gets past
    // the parser and dies at the socket on the dead proxy — `raw` still
    // accepts a fully-qualified backend URL, as its help says it does.
    let home = TempHome::new("origin-allowed");
    home.write_valid_auth();

    let url = format!("{}/codex/usage", askcodex::config::BASE_URL);
    askcodex(&home, &["--no-refresh", "raw", "GET", &url])
        .assert_askcodex_error(&["http transport error"]);
}

// ---------------------------------------------------------------------------
// the leak guarantee, stated as its own test
// ---------------------------------------------------------------------------

#[test]
fn no_invocation_ever_prints_a_token_value() {
    // Run::new checks this after every invocation in this file. This test
    // makes the guarantee an explicit, named requirement rather than a side
    // effect, and sweeps the commands most likely to echo credentials: the
    // ones that render auth state, and the failure paths that quote the
    // auth file.
    let home = TempHome::new("leak-sweep");
    home.write_valid_auth();

    let sweep: &[&[&str]] = &[
        &["--no-refresh", "auth", "status"],
        &["--json", "--no-refresh", "auth", "status"],
        &["--no-refresh", "image", "edit", "p", "-i", "nope.png"],
        &["--no-refresh", "raw", "POST", "/x", "--body", "nope"],
        &["--no-refresh", "usage"],
        &["--json", "--no-refresh", "whoami"],
        &["ask", "x", "--effort", "huge"],
        &["--help"],
    ];

    for args in sweep {
        let run = askcodex(&home, args);
        // Explicit re-check, independent of the runner's own assertion.
        for (name, secret) in SECRETS {
            assert!(
                !contains(&run.stdout, secret.as_bytes())
                    && !contains(&run.stderr, secret.as_bytes()),
                "`askcodex {}` leaked {name}",
                run.args
            );
        }
    }

    // A malformed token must not be echoed either: the JWT error names
    // claims, never values.
    let broken = TempHome::new("leak-sweep-broken-jwt");
    broken.write_auth(&format!(
        "{{\"auth_mode\":\"chatgpt\",\"tokens\":{{\
         \"access_token\":\"{FIXTURE_JWT_SIGNATURE}\",\
         \"account_id\":\"{FIXTURE_ACCOUNT_ID}\"}}}}\n"
    ));
    askcodex(&broken, &["--no-refresh", "auth", "status"])
        .assert_askcodex_error(&["cannot decode the access token as a JWT"])
        .assert_no_request_attempted();
}
