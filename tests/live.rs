//! Opt-in LIVE integration tests: they call the real ChatGPT/Codex backend
//! with the caller's real ChatGPT-subscription credentials.
//!
//! Ignored by default; explicit --ignored runs also require authorization gates.
//! See docs/TESTING.md for read-only and quota commands.
//!
//! ## This suite NEVER refreshes a token
//!
//! Every invocation goes through [`Live::run`], which injects the global
//! `--no-refresh` flag and refuses an argv that could reach a refresh
//! (`auth refresh`, or a `raw` call at the OAuth host). The reason is not
//! stylistic: a refresh ROTATES the refresh token in `~/.codex/auth.json`,
//! the server invalidates the old one immediately, and a crash or a failed
//! write in that window can lock the user out of codex until they run
//! `codex login` again. A test suite is the last place that risk belongs,
//! so the capability is removed rather than merely avoided.
//! `live_read_only_suite_never_mutates_auth_json` then proves the file was
//! not touched.
//!
//! A consequence, and it is deliberate: if the stored access token has
//! already expired, these tests FAIL loudly (401) instead of quietly
//! renewing it. Refreshing is the user's call, not the test suite's.
//!
//! ## Two gates, because one of them spends money
//!
//! - `ASKCODEX_LIVE=1` — the read-only tier: `auth status`, `whoami`, `usage`,
//!   `models`, `raw GET /codex/usage`. Network + real credentials, zero
//!   quota.
//! - `ASKCODEX_LIVE=1 ASKCODEX_LIVE_QUOTA=1` — additionally the tier that consumes
//!   the user's subscription quota: two image generations and one `ask`
//!   message. Running the read-only tier can never trigger these.
//!
//! Accepted values are exactly `1` (run) and unset/empty (no authorization). Anything
//! else panics rather than silently skipping: a user who typed
//! `ASKCODEX_LIVE=true` and saw a green run would believe the backend was
//! verified when it was not.
//!
//! ## Deliberate exception to the CODEX_HOME isolation rule
//!
//! DESIGN.md requires every test that touches auth to point `CODEX_HOME`
//! at a fresh temp directory. THIS FILE IS THE ONE EXCEPTION: it inherits
//! the environment on purpose, because verifying the real backend requires
//! the real credentials. The exception is bounded by the rules above —
//! read-only commands, `--no-refresh` always, and a metadata guard test
//! that fails if `auth.json` changed.
//!
//! ## Nothing personal leaves these tests
//!
//! Assertions check SHAPE, never identity: no email, account id, user id,
//! plan name, or model list is compared against a literal, and no payload
//! is ever embedded in a panic message. Any external text that does reach a
//! failure message (child stderr, a serde error) passes through [`scrub`]
//! first, which is itself self-tested at every gate check.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde_json::Value;

use askcodex::config;
use askcodex::models::{ModelInfo, UsageResponse};

/// Gate for the read-only live tier.
const LIVE_VAR: &str = "ASKCODEX_LIVE";

/// Additional gate for the tier that spends the user's quota.
const QUOTA_VAR: &str = "ASKCODEX_LIVE_QUOTA";

/// Optional override for the `image edit` reference image. Unset means the
/// embedded 64x64 PNG below is used; set to a path that does not exist and
/// the test fails rather than falling back.
const REF_IMAGE_VAR: &str = "ASKCODEX_LIVE_REF_IMAGE";

/// The 8-byte PNG signature (RFC 2083 §3.1).
const PNG_SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];

/// PNG color type 2: truecolor RGB, with NO alpha channel (the alpha-
/// bearing types are 4 and 6). docs/PROTOCOL.md §5 records `hasAlpha: no`
/// as verified against the bytes the backend actually returned, not merely
/// as an envelope field — so the "opaque" half of the documented image lock
/// is a claim this suite is entitled to check, exactly like the size.
const PNG_COLOR_TYPE_RGB: u8 = 2;

/// A 64x64 8-bit RGB PNG (166 bytes), used as the reference input for
/// `image edit` so the test needs neither a fixture file nor a preliminary
/// `image create` call (which would double the quota it spends). Decoded
/// and checked at every gate, so a corrupted literal is loud BEFORE any
/// quota is spent.
///
/// If the backend ever rejects a reference this small, the fallback is to
/// point `ASKCODEX_LIVE_REF_IMAGE` at a real photo, or to chain one
/// `image create` and feed its output here.
const REFERENCE_PNG_BASE64: &str = concat!(
    "iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAIAAAAlC+aJAAAAbUlEQVR42u3XMQ0AIAxFQeSgBBEo",
    "QR1KEIOBMnWBcAljB256+aW2Eb41e/huuy8AAAAAACnAKx893QMAAAAA5ABKDAAAAGAPKDEAAACA",
    "PaDEAAAAAPaAEgMAAADYA0oMAAAAYA8oMQAAAMA3gA0BhNFLDIg9DQAAAABJRU5ErkJggg==",
);
const REFERENCE_PNG_BYTES: usize = 166;
const REFERENCE_PNG_SIDE: u32 = 64;

// ---------------------------------------------------------------------------
// gates
// ---------------------------------------------------------------------------

/// Proof that the live gate was checked. [`Live::run`] is the only way to
/// spawn askcodex, and a `Live` is the only way to call it — so a test that
/// returned early at its gate cannot reach the network by accident.
#[derive(Debug)]
struct Live(());

/// Read one gate variable. Unset or empty means "do not run"; exactly `1`
/// means "run"; anything else is a typo we refuse to interpret.
fn gate(var: &str) -> bool {
    match std::env::var(var) {
        Err(std::env::VarError::NotPresent) => false,
        Err(std::env::VarError::NotUnicode(_)) => panic!(
            "{var} is set to a non-UTF-8 value. The only accepted value is \"1\" \
             (unset or empty = do not run the live tests)."
        ),
        Ok(value) if value.is_empty() => false,
        Ok(value) if value == "1" => true,
        Ok(value) => panic!(
            "{var} is set to {value:?}. The only accepted value is \"1\" (unset or \
             empty = do not run the live tests). Refusing to guess: silently \
             skipping here would report a green run of tests that never executed."
        ),
    }
}

/// Both gates, with the one combination that is a user error rather than a
/// choice.
fn gates() -> (bool, bool) {
    let live = gate(LIVE_VAR);
    let quota = gate(QUOTA_VAR);
    assert!(
        !(quota && !live),
        "{QUOTA_VAR}=1 is set but {LIVE_VAR} is not. The quota tier runs on top of \
         the live tier; set both ({LIVE_VAR}=1 {QUOTA_VAR}=1) or neither. Skipping \
         quietly would hide the fact that nothing ran."
    );
    (live, quota)
}

/// Authorization is required even when a caller explicitly selects ignored tests.
fn live(test: &str) -> Live {
    let (enabled, _) = gates();
    assert!(
        enabled,
        "{test}: requires ASKCODEX_LIVE=1 (real backend and credentials)"
    );
    self_check();
    Live(())
}

fn live_quota(test: &str) -> Live {
    let (enabled, quota) = gates();
    assert!(
        enabled && quota,
        "{test}: requires ASKCODEX_LIVE=1 ASKCODEX_LIVE_QUOTA=1 (spends subscription quota)"
    );
    self_check();
    Live(())
}

/// Verify this file's own safety machinery before it is relied upon.
///
/// Both checks guard something a live run cannot recover from: a broken
/// scrubber would leak identity into a failure message, and a corrupted
/// reference PNG would burn image quota on a request that was doomed. They
/// run after explicit authorization and before any backend request.
fn self_check() {
    assert_eq!(
        scrub("acct_abc123 user_xyz789 someone@example.com eyJhbGciOiJub25lIn0.e30.sig"),
        "acct_REDACTED user_REDACTED email_REDACTED token_REDACTED",
        "the redaction helper is broken — refusing to run live tests that could \
         print identity into a failure message"
    );
    assert_eq!(
        scrub("GET /codex/usage -> HTTP 401: unauthorized"),
        "GET /codex/usage -> HTTP 401: unauthorized",
        "the redaction helper mangles ordinary diagnostics"
    );

    let png = reference_png();
    assert_eq!(
        png.len(),
        REFERENCE_PNG_BYTES,
        "the embedded reference PNG does not decode to the expected byte count"
    );
    let (width, height) = png_dimensions(&png, "embedded reference PNG");
    assert_eq!(
        (width, height),
        (REFERENCE_PNG_SIDE, REFERENCE_PNG_SIDE),
        "the embedded reference PNG has unexpected dimensions"
    );
}

// ---------------------------------------------------------------------------
// redaction
// ---------------------------------------------------------------------------

/// Remove identity from text that is about to appear in a failure message.
///
/// Replaces the caller's home directory, then any word-run that is shaped
/// like an account id, a user id, an email address, or a JWT. Panic
/// messages are the one place in this file where external text is printed,
/// so everything that lands there goes through here first.
fn scrub(text: &str) -> String {
    let mut text = text.to_string();
    if let Some(home) = std::env::var_os("HOME")
        && !home.is_empty()
        && let Some(home) = home.to_str()
    {
        text = text.replace(home, "$HOME");
    }

    let mut output = String::with_capacity(text.len());
    let mut word = String::new();
    // A "word" is a maximal run of the characters identifiers, emails and
    // JWTs are built from; everything else is a separator and is copied
    // through untouched.
    let is_word_char = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '@' | '-');
    for ch in text.chars() {
        if is_word_char(ch) {
            word.push(ch);
        } else {
            output.push_str(&redact_word(&word));
            word.clear();
            output.push(ch);
        }
    }
    output.push_str(&redact_word(&word));
    output
}

fn redact_word(word: &str) -> String {
    if word.is_empty() {
        return String::new();
    }
    if word.starts_with("acct_") {
        return "acct_REDACTED".to_string();
    }
    if word.starts_with("user_") {
        return "user_REDACTED".to_string();
    }
    // Base64url of a JWT header always starts `eyJ` (`{"`).
    if word.starts_with("eyJ") {
        return "token_REDACTED".to_string();
    }
    if let Some((local, domain)) = word.split_once('@')
        && !local.is_empty()
        && domain.contains('.')
    {
        return "email_REDACTED".to_string();
    }
    word.to_string()
}

// ---------------------------------------------------------------------------
// running askcodex
// ---------------------------------------------------------------------------

/// One finished askcodex invocation.
struct Run {
    /// The argv, made of test-authored literals only (never backend data),
    /// so it is safe to name in a failure message.
    command: String,
    raw: bool,
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: String,
}

impl Live {
    /// Spawn the built `askcodex` binary with `--no-refresh` forced on.
    ///
    /// The environment is inherited on purpose (see the module docs):
    /// `CODEX_HOME`/`HOME` must resolve to the user's real credentials for
    /// a live test to mean anything.
    fn run(&self, args: &[&str]) -> Run {
        refuse_refreshing_argv(args);

        let output = Command::new(env!("CARGO_BIN_EXE_askcodex"))
            // Forced here rather than per test: a test cannot forget it,
            // and adding a new test cannot reintroduce the rotation risk.
            .arg("--no-refresh")
            .args(args)
            .output()
            .unwrap_or_else(|e| panic!("failed to spawn askcodex: {e}"));

        Run {
            command: args.join(" "),
            raw: args.iter().find(|arg| !arg.starts_with('-')) == Some(&"raw"),
            status: output.status,
            stdout: output.stdout,
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }
}

/// Reject any argv that could rotate the user's tokens.
///
/// `--no-refresh` does NOT suppress an explicit `auth refresh` (that flag
/// disables the automatic freshness check), and `raw` can post anywhere, so
/// the two doors are closed explicitly.
fn refuse_refreshing_argv(args: &[&str]) {
    for arg in args {
        assert!(
            *arg != "refresh",
            "a live test tried to run a refreshing command ({arg:?}). Refreshing \
             rotates the user's real refresh token and can lock them out of codex; \
             this suite must never do it."
        );
        assert!(
            !arg.contains("auth.openai.com") && !arg.contains("oauth"),
            "a live test tried to reach the OAuth token endpoint ({arg:?}). That \
             request carries a live refresh token; this suite must never send it."
        );
    }
}

impl Run {
    /// Assert the command succeeded. Failure output is scrubbed.
    fn ok(&self) -> &Self {
        assert!(
            self.status.success(),
            "`askcodex --no-refresh {}` exited with {:?}\nstderr (redacted): {}",
            self.command,
            self.status.code(),
            scrub(self.stderr.trim())
        );
        self
    }

    /// The single JSON document `--json` promises on stdout.
    ///
    /// The payload is never included in the panic message: it carries the
    /// caller's account data. serde_json errors report a line/column, which
    /// is enough to debug a shape change without printing the shape.
    fn document(&self) -> Value {
        self.ok();
        serde_json::from_slice(&self.stdout).unwrap_or_else(|e| {
            panic!(
                "`askcodex --no-refresh {}` did not print exactly one JSON document: {e} \
                 (payload withheld — it carries account data)",
                self.command
            )
        })
    }

    /// Semantic commands expose a versioned result; raw preserves backend JSON.
    fn json(&self) -> Value {
        let mut document = self.document();
        if self.raw {
            return document;
        }
        assert!(
            document["schema_version"] == 1,
            "unexpected JSON schema version (payload withheld)"
        );
        assert!(
            document["command"].is_string(),
            "missing command label (payload withheld)"
        );
        assert!(
            document.get("result").is_some(),
            "missing semantic result (payload withheld)"
        );
        document["result"].take()
    }

    /// Inspect original backend data when comparing transport-level shapes.
    fn backend(&self) -> Value {
        let mut document = self.document();
        assert!(
            document["schema_version"] == 1,
            "unexpected JSON schema version (payload withheld)"
        );
        assert!(
            document.get("backend").is_some(),
            "missing backend document (payload withheld)"
        );
        document["backend"].take()
    }

    /// stdout as text, for the human-rendering commands.
    fn text(&self) -> String {
        self.ok();
        String::from_utf8(self.stdout.clone()).unwrap_or_else(|e| {
            panic!(
                "`askcodex --no-refresh {}` printed non-UTF-8 on stdout: {e}",
                self.command
            )
        })
    }
}

// ---------------------------------------------------------------------------
// shape assertions (no value is ever printed)
// ---------------------------------------------------------------------------

/// Fetch a required, non-empty string field. The VALUE is never returned to
/// a panic message — only the key name and what was wrong with it.
fn required_str<'a>(doc: &'a Value, key: &str, what: &str) -> &'a str {
    let value = doc
        .get(key)
        .unwrap_or_else(|| panic!("{what}: key `{key}` is absent"));
    let text = value
        .as_str()
        .unwrap_or_else(|| panic!("{what}: key `{key}` is {}, expected a string", kind(value)));
    assert!(!text.is_empty(), "{what}: key `{key}` is an empty string");
    text
}

/// A present key whose value is either null or a non-empty string.
fn optional_str<'a>(doc: &'a Value, key: &str, what: &str) -> Option<&'a str> {
    let value = doc.get(key).unwrap_or_else(|| {
        panic!("{what}: key `{key}` is absent (absence must be a null, not a missing key)")
    });
    match value {
        Value::Null => None,
        Value::String(text) => {
            assert!(!text.is_empty(), "{what}: key `{key}` is an empty string");
            Some(text)
        }
        other => panic!(
            "{what}: key `{key}` is {}, expected a string or null",
            kind(other)
        ),
    }
}

/// The JSON type name — safe to print, unlike the value.
fn kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

/// Keys askcodex must never print, and the string shape a token would have.
const CREDENTIAL_KEYS: [&str; 5] = [
    "access_token",
    "refresh_token",
    "id_token",
    "api_key",
    "openai_api_key",
];

/// Walk a document and fail if anything credential-shaped is in it.
fn assert_no_credentials(value: &Value, what: &str) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let lowered = key.to_ascii_lowercase();
                assert!(
                    !CREDENTIAL_KEYS.contains(&lowered.as_str()),
                    "{what}: output carries a `{key}` key — askcodex must never print a credential"
                );
                assert_no_credentials(child, what);
            }
        }
        Value::Array(items) => {
            for item in items {
                assert_no_credentials(item, what);
            }
        }
        Value::String(text) => assert!(
            !text.starts_with("eyJ"),
            "{what}: output carries a JWT-shaped string — askcodex must never print a token value"
        ),
        _ => {}
    }
}

/// Decode a live document through askcodex's own typed model. This is the
/// schema-drift canary: CI cannot see the backend, so this is the only
/// place a renamed or retyped field is caught before a user hits it.
fn decode<T: serde::de::DeserializeOwned>(document: &Value, what: &str) -> T {
    serde_json::from_value(document.clone()).unwrap_or_else(|e| {
        panic!(
            "{what}: the live response no longer decodes into askcodex's typed model — \
             the backend schema changed: {}",
            scrub(&e.to_string())
        )
    })
}

/// The (width, height) an IHDR chunk declares, with the container checked
/// first. Byte values printed here are image bytes, never credentials.
fn png_dimensions(bytes: &[u8], what: &str) -> (u32, u32) {
    assert!(
        bytes.len() >= 24,
        "{what}: {} bytes is too short to be a PNG",
        bytes.len()
    );
    assert_eq!(
        &bytes[..8],
        &PNG_SIGNATURE[..],
        "{what}: wrong PNG signature (first 8 bytes: {})",
        hex(&bytes[..8])
    );
    assert_eq!(
        &bytes[8..12],
        &[0, 0, 0, 13],
        "{what}: first chunk is not a 13-byte IHDR"
    );
    assert_eq!(&bytes[12..16], b"IHDR", "{what}: first chunk is not IHDR");

    let width = u32::from_be_bytes(bytes[16..20].try_into().expect("4 bytes"));
    let height = u32::from_be_bytes(bytes[20..24].try_into().expect("4 bytes"));
    (width, height)
}

/// The color type an IHDR declares, at offset 25 (8 signature + 4 length +
/// 4 `IHDR` + 4 width + 4 height + 1 bit depth).
///
/// Callers check the container with [`png_dimensions`] first; the bounds
/// check here is a second, independent guard rather than an assumption
/// borrowed from the caller. The returned byte is image metadata — safe to
/// name in a failure message, unlike anything else in a live response.
fn png_color_type(bytes: &[u8], what: &str) -> u8 {
    assert!(
        bytes.len() >= 26,
        "{what}: {} bytes is too short to hold an IHDR color type",
        bytes.len()
    );
    bytes[25]
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn reference_png() -> Vec<u8> {
    BASE64
        .decode(REFERENCE_PNG_BASE64)
        .expect("the embedded reference PNG is not valid base64")
}

// ---------------------------------------------------------------------------
// scratch directory
// ---------------------------------------------------------------------------

/// A unique directory under the system temp dir, removed on success and
/// KEPT on failure so a bad image can be inspected instead of vanishing.
struct ScratchDir(PathBuf);

impl ScratchDir {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!("askcodex-live-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&path)
            .unwrap_or_else(|e| panic!("cannot create the scratch dir for {tag}: {e}"));
        ScratchDir(path)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    /// Every entry in the directory, sorted — used to prove a command wrote
    /// exactly one file.
    fn entries(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&self.0)
            .unwrap_or_else(|e| panic!("cannot list {}: {e}", self.0.display()))
            .map(|entry| {
                entry
                    .unwrap_or_else(|e| panic!("cannot read an entry of {}: {e}", self.0.display()))
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        names
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        // Never panic while unwinding: that aborts the process and destroys
        // the test report, so these two paths report instead of asserting.
        let mut out = std::io::stdout();
        if std::thread::panicking() {
            let _ = writeln!(
                out,
                "askcodex live: kept {} for inspection (the test failed)",
                self.0.display()
            );
            return;
        }
        if let Err(e) = std::fs::remove_dir_all(&self.0) {
            let _ = writeln!(
                out,
                "askcodex live: could not remove {}: {e}",
                self.0.display()
            );
        }
    }
}

// ---------------------------------------------------------------------------
// tier 1: read-only, quota-free (ASKCODEX_LIVE=1)
// ---------------------------------------------------------------------------

#[test]
#[ignore = "real backend and credentials; requires ASKCODEX_LIVE=1"]
fn live_auth_status_reports_claims_only_and_never_a_token() {
    let live = live("live_auth_status_reports_claims_only_and_never_a_token");

    let run = live.run(&["--json", "auth", "status"]);
    let doc = run.json();
    let what = "auth status --json";

    assert_no_credentials(&doc, what);
    required_str(&doc, "auth_file", what);
    optional_str(&doc, "auth_mode", what);
    // Present and non-empty: askcodex cannot address the backend without it.
    // Its VALUE is never read into a message, here or anywhere else.
    required_str(&doc, "account_id", what);
    optional_str(&doc, "last_refresh", what);

    // The expiry is a real timestamp, not a placeholder.
    let expires_at = required_str(&doc, "access_token_expires_at", what);
    expires_at
        .parse::<chrono::DateTime<chrono::Utc>>()
        .unwrap_or_else(|e| panic!("{what}: access_token_expires_at is not RFC3339: {e}"));

    let minutes = doc
        .get("access_token_expires_in_minutes")
        .and_then(Value::as_i64)
        .unwrap_or_else(|| {
            panic!("{what}: access_token_expires_in_minutes is absent or not an integer")
        });
    let valid = doc
        .get("access_token_valid")
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("{what}: access_token_valid is absent or not a boolean"));
    assert_eq!(
        valid,
        minutes > 0,
        "{what}: access_token_valid disagrees with the countdown it was derived from"
    );

    assert!(
        valid,
        "the stored access token has expired. This suite NEVER refreshes (a refresh \
         rotates your real refresh token and a failure there can lock you out of \
         codex), so it cannot fix this for you: run `askcodex auth refresh` yourself and \
         re-run the live tests."
    );

    // The human rendering says the same things and still no secret.
    let text = live.run(&["auth", "status"]).text();
    for label in [
        "auth file :",
        "auth_mode :",
        "account_id:",
        "last_refresh:",
        "access_token expires:",
    ] {
        assert!(
            text.contains(label),
            "auth status (text): line `{label}` is missing"
        );
    }
    assert!(
        !text.contains("eyJ"),
        "auth status (text): output contains a JWT-shaped string"
    );
}

#[test]
#[ignore = "real backend and credentials; requires ASKCODEX_LIVE=1"]
fn live_whoami_reports_a_plan_without_this_test_learning_who_you_are() {
    let live = live("live_whoami_reports_a_plan_without_this_test_learning_who_you_are");

    let doc = live.run(&["--json", "whoami"]).json();
    let what = "whoami --json";

    assert!(doc.is_object(), "{what}: expected a JSON object");
    assert_no_credentials(&doc, what);

    // Every modelled key is present; absence is a null, never a missing key.
    for key in ["email", "name", "user_id", "account_id", "plan_type"] {
        optional_str(&doc, key, what);
    }
    // The two the backend must supply for askcodex to work at all. Their values
    // are personal and are never compared to a literal or printed.
    required_str(&doc, "plan_type", what);
    required_str(&doc, "account_id", what);
}

#[test]
#[ignore = "real backend and credentials; requires ASKCODEX_LIVE=1"]
fn live_usage_decodes_into_the_typed_model_and_its_windows_parse() {
    let live = live("live_usage_decodes_into_the_typed_model_and_its_windows_parse");

    let doc = live.run(&["--json", "usage"]).json();
    let what = "usage --json";

    assert!(doc.is_object(), "{what}: expected a JSON object");
    assert_no_credentials(&doc, what);

    let usage: UsageResponse = decode(&doc, what);
    let plan = usage
        .plan_type
        .as_deref()
        .unwrap_or_else(|| panic!("{what}: plan_type is absent"));
    assert!(!plan.is_empty(), "{what}: plan_type is an empty string");

    let rate = usage
        .rate_limit
        .as_ref()
        .unwrap_or_else(|| panic!("{what}: rate_limit is absent — askcodex reports quota from it"));
    let windows = [
        ("primary_window", rate.primary_window.as_ref()),
        ("secondary_window", rate.secondary_window.as_ref()),
    ];
    assert!(
        windows.iter().any(|(_, window)| window.is_some()),
        "{what}: neither rate-limit window is present, so `askcodex usage` can report no quota at all"
    );

    for (name, window) in windows {
        let Some(window) = window else { continue };
        if let Some(percent) = window.used_percent {
            // Shape only: finite and not negative. No upper bound is
            // asserted — an account in overage may legitimately exceed 100
            // and a false failure here would waste the one live run.
            assert!(
                percent.is_finite() && percent >= 0.0,
                "{what}: {name}.used_percent is not a sane percentage"
            );
        }
        if let Some(seconds) = window.limit_window_seconds {
            assert!(seconds > 0, "{what}: {name}.limit_window_seconds is zero");
        }
        // reset_after_seconds is a u64: any value that decoded is >= 0.
    }

    // The human renderer agrees with the document it renders.
    let text = live.run(&["usage"]).text();
    assert!(
        text.starts_with("plan            :"),
        "usage (text): the first line is not the plan line"
    );
    assert!(
        text.contains(plan),
        "usage (text): does not report the plan the JSON reports"
    );
}

#[test]
#[ignore = "real backend and credentials; requires ASKCODEX_LIVE=1"]
fn live_models_lists_slugs_and_decodes_into_the_typed_catalog() {
    let live = live("live_models_lists_slugs_and_decodes_into_the_typed_catalog");

    let doc = live.run(&["--json", "models"]).json();
    let what = "models --json";

    assert_no_credentials(&doc, what);
    // The semantic catalog result retains the models array.
    let models = doc
        .get("models")
        .and_then(|value| value.as_array())
        .unwrap_or_else(|| {
            panic!(
                "{what}: expected a `models` array in the catalog envelope, got {}",
                kind(&doc)
            )
        });
    assert!(
        !models.is_empty(),
        "{what}: the catalog is empty — askcodex would offer no model at all"
    );

    let mut text_capable = 0usize;
    for (index, entry) in models.iter().enumerate() {
        let what = &format!("{what}: models[{index}]");
        assert!(entry.is_object(), "{what}: expected an object");
        // A slug is what every other command refers to a model by.
        required_str(entry, "slug", what);

        let model: ModelInfo = decode(entry, what);
        if model.input_modalities.iter().any(|m| m == "text") {
            text_capable += 1;
        }
        for level in &model.supported_reasoning_levels {
            if let Some(effort) = &level.effort {
                assert!(
                    !effort.is_empty(),
                    "{what}: a supported_reasoning_levels entry has an empty effort"
                );
            }
        }
        if let Some(visibility) = &model.visibility {
            assert!(
                !visibility.is_empty(),
                "{what}: visibility is an empty string"
            );
        }
    }

    // No specific model is asserted (the catalog changes constantly), only
    // the capability `askcodex ask` depends on.
    assert!(
        text_capable > 0,
        "{what}: no model accepts text input, so `askcodex ask` cannot work"
    );

    // The human rendering counts what the array holds.
    let text = live.run(&["models"]).text();
    assert!(
        text.starts_with(&format!("{} model(s) available:", models.len())),
        "models (text): the header does not match the number of models returned"
    );
}

#[test]
#[ignore = "real backend and credentials; requires ASKCODEX_LIVE=1"]
fn live_raw_get_codex_usage_reaches_the_same_endpoint_as_the_usage_command() {
    let live = live("live_raw_get_codex_usage_reaches_the_same_endpoint_as_the_usage_command");

    let raw = live.run(&["--json", "raw", "GET", "/codex/usage"]).json();
    let what = "raw GET /codex/usage";

    assert_no_credentials(&raw, what);
    let raw_object = raw
        .as_object()
        .unwrap_or_else(|| panic!("{what}: expected a JSON object, got {}", kind(&raw)));
    let _: UsageResponse = decode(&raw, what);

    // Same endpoint, same document shape. Only the KEY SET is compared:
    // the values (percentages, reset counters) move between two calls, and
    // asserting them would produce a flake, not a finding.
    let via_command = live.run(&["--json", "usage"]).backend();
    let command_object = via_command
        .as_object()
        .unwrap_or_else(|| panic!("usage --json: expected a JSON object"));

    let mut raw_keys: Vec<&str> = raw_object.keys().map(String::as_str).collect();
    let mut command_keys: Vec<&str> = command_object.keys().map(String::as_str).collect();
    raw_keys.sort_unstable();
    command_keys.sort_unstable();
    assert_eq!(
        raw_keys, command_keys,
        "the raw escape hatch and `usage` returned different document shapes"
    );
}

#[test]
#[ignore = "real backend and credentials; requires ASKCODEX_LIVE=1"]
fn live_read_only_suite_never_mutates_auth_json() {
    let live = live("live_read_only_suite_never_mutates_auth_json");

    // Metadata only. The file's CONTENT is never read by this suite.
    let path = config::auth_path().expect("resolve the auth file path");
    let before = auth_fingerprint(&path);

    for args in [
        vec!["--json", "auth", "status"],
        vec!["--json", "whoami"],
        vec!["--json", "usage"],
        vec!["--json", "models"],
        vec!["--json", "raw", "GET", "/codex/usage"],
    ] {
        live.run(&args).ok();
    }

    let after = auth_fingerprint(&path);
    assert_eq!(
        before, after,
        "auth.json changed while the read-only live suite ran. Nothing here may \
         refresh: a refresh rotates the real refresh token and a failure in that \
         window can lock you out of codex. (If the codex CLI ran concurrently, \
         re-run this alone before believing askcodex did it.)"
    );
}

/// Size and modification time of `auth.json` — enough to detect any write,
/// without opening the file.
fn auth_fingerprint(path: &Path) -> (u64, std::time::SystemTime) {
    let meta = std::fs::metadata(path).unwrap_or_else(|e| {
        panic!(
            "cannot stat the auth file at {}: {e}. Log in with `codex login` \
             (file credential storage) before running the live tests.",
            scrub(&path.display().to_string())
        )
    });
    let modified = meta
        .modified()
        .unwrap_or_else(|e| panic!("no modification time for the auth file: {e}"));
    (meta.len(), modified)
}

// ---------------------------------------------------------------------------
// tier 2: spends the user's quota (ASKCODEX_LIVE=1 ASKCODEX_LIVE_QUOTA=1)
// ---------------------------------------------------------------------------

#[test]
#[ignore = "real backend and credentials; requires ASKCODEX_LIVE=1 ASKCODEX_LIVE_QUOTA=1; spends quota"]
fn live_quota_image_create_writes_exactly_one_locked_size_png() {
    let live = live_quota("live_quota_image_create_writes_exactly_one_locked_size_png");

    let dir = ScratchDir::new("image-create");
    let out = dir.join("created.png");
    let out_arg = out.to_str().expect("utf-8 scratch path");

    let doc = live
        .run(&[
            "--json",
            "image",
            "create",
            "a plain slate-gray square, flat color, no text",
            "-o",
            out_arg,
        ])
        .json();
    let what = "image create --json";

    assert_eq!(
        doc["path"],
        Value::from(out_arg),
        "{what}: wrong output path"
    );
    assert_eq!(
        doc["ref_images"],
        Value::from(0),
        "{what}: create reported reference images"
    );

    assert_eq!(
        dir.entries(),
        vec!["created.png".to_string()],
        "{what}: expected exactly one file to be written"
    );

    assert_locked_png(&out, &doc, what);
}

#[test]
#[ignore = "real backend and credentials; requires ASKCODEX_LIVE=1 ASKCODEX_LIVE_QUOTA=1; spends quota"]
fn live_quota_image_edit_returns_one_locked_size_png_from_a_reference() {
    let live = live_quota("live_quota_image_edit_returns_one_locked_size_png_from_a_reference");

    let dir = ScratchDir::new("image-edit");
    let reference = match std::env::var_os(REF_IMAGE_VAR) {
        // An override that does not exist is a mistake, not a reason to
        // fall back to the embedded fixture behind the user's back.
        Some(path) if !path.is_empty() => {
            let path = PathBuf::from(path);
            assert!(
                path.is_file(),
                "{REF_IMAGE_VAR} points at something that is not a file: {}",
                scrub(&path.display().to_string())
            );
            path
        }
        _ => {
            let path = dir.join("reference.png");
            std::fs::write(&path, reference_png())
                .unwrap_or_else(|e| panic!("cannot write the reference image: {e}"));
            path
        }
    };

    let out = dir.join("edited.png");
    let out_arg = out.to_str().expect("utf-8 scratch path");
    let reference_arg = reference.to_str().expect("utf-8 reference path");

    let doc = live
        .run(&[
            "--json",
            "image",
            "edit",
            "make the palette warmer, keep the composition",
            "-i",
            reference_arg,
            "-o",
            out_arg,
        ])
        .json();
    let what = "image edit --json";

    assert_eq!(
        doc["path"],
        Value::from(out_arg),
        "{what}: wrong output path"
    );
    assert_eq!(
        doc["ref_images"],
        Value::from(1),
        "{what}: wrong reference-image count"
    );

    assert_locked_png(&out, &doc, what);
}

/// The image contract this project documents: one PNG, in the opaque color
/// type the backend locks every generation to, with the reported metadata
/// matching the bytes on disk.
///
/// The exact pixel size is deliberately NOT asserted: it is a server-chosen
/// value that varies between dates (docs/PROTOCOL.md §5 records the observed
/// values). What must hold on every call: exactly one PNG, no alpha, and an
/// envelope `size` that agrees with the pixels actually sent.
fn assert_locked_png(path: &Path, doc: &Value, what: &str) {
    let bytes = std::fs::read(path)
        .unwrap_or_else(|e| panic!("{what}: cannot read the file askcodex said it wrote: {e}"));

    let (width, height) = png_dimensions(&bytes, what);

    let color_type = png_color_type(&bytes, what);
    assert_eq!(
        color_type, PNG_COLOR_TYPE_RGB,
        "{what}: the PNG declares color type {color_type}, not {PNG_COLOR_TYPE_RGB} \
         (truecolor RGB, no alpha) — the documented opaque-image lock changed, and \
         docs/PROTOCOL.md, README.md and skill/SKILL.md all need updating"
    );

    let reported_size = required_str(doc, "size", what);
    assert_eq!(
        reported_size,
        format!("{width}x{height}"),
        "{what}: the size the backend reported disagrees with the pixels it sent"
    );

    let reported_bytes = doc
        .get("bytes")
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("{what}: `bytes` is absent or not an integer"));
    assert_eq!(
        reported_bytes,
        bytes.len() as u64,
        "{what}: the reported byte count disagrees with the file on disk"
    );
}

#[test]
#[ignore = "real backend and credentials; requires ASKCODEX_LIVE=1 ASKCODEX_LIVE_QUOTA=1; spends quota"]
fn live_quota_ask_streams_a_completed_answer() {
    let live = live_quota("live_quota_ask_streams_a_completed_answer");

    // Default model on purpose: asserting a specific slug would encode a
    // catalog that changes. What is asserted is that askcodex reports the model
    // it actually used.
    let doc = live
        .run(&[
            "--json",
            "ask",
            "Reply with exactly one short sentence confirming you received this.",
        ])
        .json();
    let what = "ask --json";

    assert_no_credentials(&doc, what);
    assert_eq!(
        doc.get("model").and_then(Value::as_str),
        Some(config::DEFAULT_ASK_MODEL),
        "{what}: askcodex did not report the model it was asked to use"
    );

    let text = required_str(&doc, "text", what);
    assert!(
        !text.trim().is_empty(),
        "{what}: the stream completed with an empty answer"
    );
    assert!(
        text.chars().any(char::is_alphanumeric),
        "{what}: the answer carries no readable characters"
    );
}
