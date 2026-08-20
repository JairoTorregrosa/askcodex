//! Black-box safety tests for `askcodex::auth` — the module that rewrites the
//! user's real credential file.
//!
//! These tests are deliberately OUTSIDE the crate: they see only the public
//! API (`load_auth`, `jwt_exp`, `needs_refresh`, `refresh_with_endpoint`,
//! `persist_atomic`, `models::AuthFile`, `config`), exactly like a
//! downstream user. The unit tests inside `src/auth.rs` drive private
//! helpers with injected paths and URLs; nothing here can do that, so every
//! property below is proven through the same surface a third party has.
//! Where a property is NOT observable from out here, the test says so
//! instead of pretending to check it.
//!
//! # Isolation: how this file is safe to run
//!
//! - `CODEX_HOME` is pointed at a FRESH, empty temp directory for every
//!   single test (even the pure ones), so the real `~/.codex` is
//!   unreachable. Each `CodexHome` asserts `config::auth_path()` actually
//!   resolves inside that directory — the isolation is proven, not assumed.
//! - The production endpoint `config::TOKEN_URL` is never contacted:
//!   `auth::refresh` (which pins it) is never called. Only
//!   `refresh_with_endpoint` is, always against a localhost httpmock
//!   server.
//! - Every token in this file is invented (hand-built unsigned JWTs and
//!   obvious placeholder strings). `account_id` is `acct_REDACTED`. No real
//!   credential value exists here and none can be printed by these tests.
//!
//! # Thread-safety of the `CODEX_HOME` mutation (the chosen approach)
//!
//! `std::env::set_var` is `unsafe` in edition 2024 and process-global: on
//! POSIX `setenv` may reallocate the whole `environ` array, so a write is
//! undefined behavior if ANY other thread touches the environment at the
//! same moment — not merely a thread reading `CODEX_HOME`.
//!
//! The approach chosen here is a **static `Mutex` held for the entire body
//! of every test**, not merely around the `set_var` call: a test acquires
//! `ENV_LOCK` first, mutates the variable second, and releases the lock
//! only once the test — including its `Drop`-based env restoration and its
//! `CODEX_HOME`-dependent cleanup — has finished. libtest still runs the
//! tests on several threads, but every line of test code in this binary
//! that reads or writes the environment runs under that lock, so no two of
//! them can overlap. (`--test-threads=1` is a valid way to run this file
//! but deliberately not a requirement: it cannot be imposed from inside a
//! test file, so relying on it would be exactly the kind of unstated
//! assumption this project refuses to make.)
//!
//! What that leaves — stated plainly instead of papered over — is threads
//! this file does not own:
//!
//! 1. httpmock's background server threads. Their one-time startup, the
//!    moment a server library would plausibly read the environment, is
//!    forced to happen under the lock and BEFORE this binary's first
//!    `set_var` (see `warm_up_mock_server`).
//! 2. libtest's own harness threads, which read the environment outside
//!    this file's control: `RUST_MIN_STACK` when spawning a test thread
//!    and `RUST_BACKTRACE` when formatting a panic. std reads both through
//!    one-shot caches, so in practice they are populated at the first test
//!    spawn (before any test body, hence before any `set_var`) and only on
//!    a run that is already failing, respectively.
//!
//! Poisoning is absorbed (`into_inner`) on purpose: one failing test must
//! not cascade into unrelated ones, and the invariant the lock protects is
//! re-established from scratch by the next test anyway.

use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, Once};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use httpmock::prelude::*;
use serde_json::{Value, json};

use askcodex::Error;
use askcodex::Secret;
use askcodex::auth::{jwt_exp, load_auth, needs_refresh, persist_atomic, refresh_with_endpoint};
use askcodex::config;
use askcodex::models::{self, AuthFile};

// ---------------------------------------------------------------------------
// Invented credentials. Nothing in this file is real.
// ---------------------------------------------------------------------------

/// The refresh token the fixture file starts with. If a code path ever
/// clears or replaces this without the server saying so, the user is
/// locked out of codex — several tests below exist only to catch that.
const OLD_REFRESH_TOKEN: &str = "askcodex-test-refresh-token-OLD";
/// The rotated refresh token a successful mock refresh hands back.
const NEW_REFRESH_TOKEN: &str = "askcodex-test-refresh-token-NEW";
/// A far-future `exp` (2100-01-01) for fixtures that must look fresh.
const FRESH_EXP: i64 = 4_102_444_800;
/// Seconds in a day, for the `last_refresh` age rule.
const SECS_PER_DAY: i64 = 86_400;

// ---------------------------------------------------------------------------
// Environment isolation
// ---------------------------------------------------------------------------

/// Serializes every test in this binary (see the module header). Held for
/// the whole test body, never just around the `set_var`.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Start (and immediately release) a mock server once, before this binary
/// has ever written to the environment, so that httpmock's background
/// threads do all of their own startup work — including any environment
/// reads — while no write can be in flight.
fn warm_up_mock_server() {
    static WARM: Once = Once::new();
    WARM.call_once(|| {
        drop(MockServer::start());
    });
}

/// A fresh, empty `CODEX_HOME` for one test, plus the lock that makes the
/// process-global mutation sound.
struct CodexHome {
    path: PathBuf,
    /// Dropped last (declared last): the directory is cleaned up and any
    /// `EnvRestore` has run before another test may touch the environment.
    _guard: MutexGuard<'static, ()>,
}

impl CodexHome {
    fn fresh(tag: &str) -> CodexHome {
        // 1. Take the lock BEFORE anything reads or writes the environment.
        let guard = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // 2. Let httpmock finish its one-time startup while no write can race it.
        warm_up_mock_server();

        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "askcodex-auth-safety-{}-{tag}-{unique}",
            std::process::id()
        ));
        // `create_dir` (not `create_dir_all`) so a leftover directory from a
        // crashed run is a loud failure instead of a silently reused,
        // non-fresh CODEX_HOME.
        fs::create_dir(&path).expect("create a fresh, previously nonexistent CODEX_HOME");

        // SAFETY: `ENV_LOCK` is held by this thread and is the only way any
        // test in this binary reaches the environment, so no other thread
        // can be reading or writing `CODEX_HOME` concurrently. See the
        // module header for the full argument.
        unsafe { std::env::set_var("CODEX_HOME", &path) };

        let home = CodexHome {
            path,
            _guard: guard,
        };
        // Prove the isolation rather than assuming it: the library must
        // resolve its credential path inside this temp directory.
        assert_eq!(
            config::auth_path().expect("auth_path resolves from CODEX_HOME"),
            home.auth(),
            "CODEX_HOME isolation failed — the library is not looking inside the temp dir"
        );
        home
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn auth(&self) -> PathBuf {
        self.path.join("auth.json")
    }

    fn backup(&self) -> PathBuf {
        self.path.join("auth.json.bak")
    }

    fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    /// Install a credential file with codex's own permissions (0600).
    fn write_auth(&self, document: &str) {
        fs::write(self.auth(), document).expect("write the fixture auth.json");
        fs::set_permissions(self.auth(), fs::Permissions::from_mode(0o600))
            .expect("set fixture mode 0600");
    }

    fn entries(&self) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(&self.path)
            .expect("read CODEX_HOME")
            .map(|entry| {
                entry
                    .expect("directory entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        names
    }

    fn assert_no_temp_files(&self) {
        for name in self.entries() {
            assert!(
                !name.contains(".tmp."),
                "a temp file survived the operation: {name}"
            );
        }
    }

    /// The postcondition EVERY failure path must satisfy: `auth.json` is
    /// still the complete previous document, still 0600, still loadable,
    /// and no temp file was left behind.
    fn assert_credentials_intact(&self, expected: &[u8]) {
        let current = fs::read(self.auth()).expect("auth.json must still exist");
        assert_eq!(
            current, expected,
            "auth.json was modified or truncated by a failing operation"
        );
        assert_eq!(
            mode_of(&self.auth()),
            0o600,
            "auth.json permissions were loosened by a failing operation"
        );
        load_auth().expect("auth.json must still parse and validate after a failure");
        self.assert_no_temp_files();
    }
}

impl Drop for CodexHome {
    fn drop(&mut self) {
        // Deliberately not asserted: `Drop` runs during unwinding, where a
        // panic would abort the process and hide the real failure. Cleanup
        // is hygiene, not a tested property. `CODEX_HOME` is left pointing
        // at this (now removed) directory on purpose — unsetting it would
        // make the next resolution fall back to the user's real ~/.codex.
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Removes an environment variable and puts it back on drop, even if the
/// test panics. Only ever constructed while `ENV_LOCK` is held.
struct EnvRestore {
    key: &'static str,
    previous: Option<OsString>,
}

impl EnvRestore {
    fn remove(key: &'static str) -> EnvRestore {
        let previous = std::env::var_os(key);
        // SAFETY: `ENV_LOCK` is held (the caller owns a `CodexHome`), so no
        // other test thread can read or write the environment concurrently.
        unsafe { std::env::remove_var(key) };
        EnvRestore { key, previous }
    }
}

impl Drop for EnvRestore {
    fn drop(&mut self) {
        // SAFETY: as in `remove` — still under `ENV_LOCK`, which the
        // `CodexHome` guard releases only after this runs.
        match self.previous.take() {
            Some(value) => unsafe { std::env::set_var(self.key, value) },
            None => unsafe { std::env::remove_var(self.key) },
        }
    }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// Build a syntactically valid but completely FAKE unsigned JWT whose
/// payload is `claims`. Segments are unpadded base64url, like the real
/// tokens (and unlike a naively padded encoder).
fn fake_jwt(claims: &str) -> String {
    format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#),
        URL_SAFE_NO_PAD.encode(claims.as_bytes()),
        URL_SAFE_NO_PAD.encode(b"not-a-signature"),
    )
}

fn jwt_expiring_at(exp: i64) -> String {
    fake_jwt(&format!(r#"{{"exp":{exp}}}"#))
}

/// A realistic auth.json: the four keys askcodex models, plus unknown keys at
/// BOTH levels, including null-valued ones. askcodex does not model these and
/// must never drop, rename, or null them out. (Their names are invented —
/// naming a real codex-internal key in askcodex's own code is exactly the
/// coupling the round-trip design avoids.)
fn auth_document(exp: i64) -> String {
    format!(
        r#"{{
  "auth_mode": "chatgpt",
  "legacy_null_key": null,
  "tokens": {{
    "id_token": "{id}",
    "access_token": "{access}",
    "refresh_token": "{OLD_REFRESH_TOKEN}",
    "account_id": "acct_REDACTED",
    "unknown_token_number": 7,
    "unknown_token_null": null,
    "unknown_token_object": {{"nested": [1, 2, 3]}}
  }},
  "last_refresh": "2026-08-07T23:32:41.615755Z",
  "unknown_top_level": {{"deep": {{"key": null}}, "list": []}}
}}
"#,
        id = jwt_expiring_at(exp),
        access = jwt_expiring_at(exp),
    )
}

fn parse_auth(document: &str) -> AuthFile {
    serde_json::from_str(document).expect("fixture parses as an auth document")
}

/// A minimal valid document with a chosen `exp` and optional `last_refresh`.
fn auth_with(exp: i64, last_refresh: Option<&str>) -> AuthFile {
    auth_with_access(&jwt_expiring_at(exp), last_refresh)
}

/// The same, with the access token given verbatim — for the branch where
/// `exp` cannot be read at all.
fn auth_with_access(access: &str, last_refresh: Option<&str>) -> AuthFile {
    let last = match last_refresh {
        Some(value) => format!(r#","last_refresh":"{value}""#),
        None => String::new(),
    };
    parse_auth(&format!(
        r#"{{"tokens":{{"access_token":"{access}","account_id":"acct_REDACTED"}}{last}}}"#
    ))
}

/// The in-memory credential state, as comparable data.
///
/// NOT `format!("{auth:?}")`: `Secret`'s Debug redacts every value
/// identically, so two different tokens render the same and a Debug
/// comparison would silently pass while the credentials changed. Serde is
/// transparent for `Secret`, so this snapshot really does compare values.
fn snapshot(auth: &AuthFile) -> Value {
    serde_json::to_value(auth).expect("auth document serializes")
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).expect("read JSON file")).expect("file contains JSON")
}

fn mode_of(path: &Path) -> u32 {
    fs::metadata(path).expect("metadata").permissions().mode() & 0o777
}

/// Identity of the file behind a path: a new inode proves the file was
/// created rather than rewritten in place (and so never existed with
/// another file's permissions).
fn inode_of(path: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt as _;
    fs::metadata(path).expect("metadata").ino()
}

fn keys_of(value: &Value) -> Vec<String> {
    let mut keys: Vec<String> = value
        .as_object()
        .expect("JSON object")
        .keys()
        .cloned()
        .collect();
    keys.sort();
    keys
}

/// The agent askcodex itself builds (`http_status_as_error(false)`).
fn test_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_connect(Some(Duration::from_secs(config::CONNECT_TIMEOUT_SECS)))
        .build()
        .into()
}

// ---------------------------------------------------------------------------
// Isolation itself
// ---------------------------------------------------------------------------

#[test]
fn codex_home_isolation_is_provable_from_outside() {
    let home = CodexHome::fresh("isolation");

    // The library resolves its path from CODEX_HOME, verbatim...
    assert_eq!(config::auth_path().unwrap(), home.auth());
    // ...and that path is nowhere near the user's real credential file.
    if let Some(real_home) = std::env::var_os("HOME") {
        let real_auth = PathBuf::from(real_home).join(".codex");
        assert!(
            !home.auth().starts_with(&real_auth),
            "a test resolved a path inside the real codex home: {}",
            home.auth().display()
        );
    }
    // A fresh CODEX_HOME really is empty, so nothing below can be reading a
    // file some earlier test left behind.
    assert!(home.entries().is_empty());
    assert!(matches!(
        load_auth().unwrap_err(),
        Error::AuthFileMissing { .. }
    ));
}

// ---------------------------------------------------------------------------
// Round-trip fidelity: askcodex must never clobber what it does not model
// ---------------------------------------------------------------------------

#[test]
fn unknown_keys_including_nulls_survive_a_load_persist_cycle() {
    let home = CodexHome::fresh("roundtrip");
    let original = auth_document(FRESH_EXP);
    home.write_auth(&original);

    let auth = load_auth().expect("fixture loads");
    persist_atomic(&auth).expect("persist succeeds");

    let before: Value = serde_json::from_str(&original).unwrap();
    let after = read_json(&home.auth());

    // Fidelity is asserted on the JSON VALUE, not on the byte string: askcodex
    // re-renders the document with serde_json's pretty printer, so the
    // input's whitespace and key order are not part of the contract. What
    // is part of the contract — every key, every value, every null — is
    // checked exhaustively here, and byte-level stability is covered by
    // `persist_is_byte_stable_and_idempotent` below.
    assert_eq!(
        before, after,
        "a load/persist cycle changed the document askcodex does not model"
    );
    assert_eq!(keys_of(&before), keys_of(&after), "top-level keys changed");
    assert_eq!(
        keys_of(&before["tokens"]),
        keys_of(&after["tokens"]),
        "keys inside tokens changed"
    );

    // Spelled out, because these are the ones a naive struct model eats:
    assert_eq!(after["legacy_null_key"], Value::Null);
    assert!(
        after.as_object().unwrap().contains_key("legacy_null_key"),
        "a null-valued unknown key was dropped instead of preserved"
    );
    assert_eq!(after["tokens"]["unknown_token_null"], Value::Null);
    assert!(
        after["tokens"]
            .as_object()
            .unwrap()
            .contains_key("unknown_token_null"),
        "a null-valued unknown key inside tokens was dropped"
    );
    assert_eq!(after["tokens"]["unknown_token_number"], json!(7));
    assert_eq!(
        after["unknown_top_level"],
        json!({"deep": {"key": null}, "list": []})
    );
    // ...and nothing was invented either.
    assert_eq!(
        keys_of(&after),
        vec![
            "auth_mode".to_string(),
            "last_refresh".to_string(),
            "legacy_null_key".to_string(),
            "tokens".to_string(),
            "unknown_top_level".to_string(),
        ]
    );
}

#[test]
fn persist_never_invents_the_optional_keys_a_document_omits() {
    let home = CodexHome::fresh("no-invention");
    // No auth_mode, no last_refresh, no id_token, no refresh_token.
    let minimal = format!(
        r#"{{"tokens":{{"access_token":"{}","account_id":"acct_REDACTED"}}}}"#,
        jwt_expiring_at(FRESH_EXP)
    );
    home.write_auth(&minimal);

    let auth = load_auth().expect("minimal document loads");
    persist_atomic(&auth).expect("persist succeeds");

    let written = read_json(&home.auth());
    assert_eq!(keys_of(&written), vec!["tokens".to_string()]);
    assert_eq!(
        keys_of(&written["tokens"]),
        vec!["access_token".to_string(), "account_id".to_string()]
    );
}

#[test]
fn persist_is_byte_stable_and_idempotent() {
    let home = CodexHome::fresh("idempotent");
    home.write_auth(&auth_document(FRESH_EXP));

    persist_atomic(&load_auth().expect("load 1")).expect("persist 1");
    let first = fs::read(home.auth()).expect("read 1");

    persist_atomic(&load_auth().expect("load 2")).expect("persist 2");
    let second = fs::read(home.auth()).expect("read 2");

    assert_eq!(first, second, "persist is not byte-stable across cycles");
    let text = String::from_utf8(first).expect("auth.json is UTF-8");
    assert!(text.ends_with("}\n"), "missing trailing newline");
    assert!(text.contains("\n  \"tokens\""), "not pretty-printed");
    home.assert_no_temp_files();
}

// ---------------------------------------------------------------------------
// File mode and backup
// ---------------------------------------------------------------------------

#[test]
fn persist_writes_0600_and_a_0600_backup_of_the_previous_document() {
    let home = CodexHome::fresh("mode-backup");
    let original = auth_document(FRESH_EXP);
    home.write_auth(&original);
    // Loosen the original deliberately: the rewrite must not inherit it.
    fs::set_permissions(home.auth(), fs::Permissions::from_mode(0o644)).unwrap();

    let auth = load_auth().expect("fixture loads");
    persist_atomic(&auth).expect("persist succeeds");

    assert_eq!(mode_of(&home.auth()), 0o600, "auth.json must be 0600");
    assert_eq!(
        mode_of(&home.backup()),
        0o600,
        "the backup carries the same credentials and must be 0600 too"
    );
    // The backup is a byte-exact copy of what was there before.
    assert_eq!(
        fs::read(home.backup()).expect("read backup"),
        original.as_bytes(),
        "the backup is not the previous document"
    );
    assert_eq!(
        home.entries(),
        vec!["auth.json".to_string(), "auth.json.bak".to_string()],
        "persist left something unexpected in CODEX_HOME"
    );
}

#[test]
fn persist_into_an_empty_codex_home_creates_no_backup() {
    let home = CodexHome::fresh("no-backup");
    let auth = parse_auth(&format!(
        r#"{{"tokens":{{"access_token":"{}","account_id":"acct_REDACTED"}}}}"#,
        jwt_expiring_at(FRESH_EXP)
    ));

    persist_atomic(&auth).expect("persist succeeds");

    assert_eq!(home.entries(), vec!["auth.json".to_string()]);
    assert_eq!(mode_of(&home.auth()), 0o600);
}

// ---------------------------------------------------------------------------
// Atomicity / crash-safety
// ---------------------------------------------------------------------------

#[test]
fn persist_into_a_read_only_directory_leaves_the_original_complete() {
    let home = CodexHome::fresh("readonly-dir");
    let original = auth_document(FRESH_EXP);
    home.write_auth(&original);
    let auth = load_auth().expect("fixture loads");

    // Make the rename target's directory unwritable: neither the temp file
    // nor the backup nor the rename can happen.
    fs::set_permissions(home.path(), fs::Permissions::from_mode(0o500)).unwrap();
    // A read-only directory only proves something if the OS enforces it for
    // this user. Probing first turns "running as root" into a loud failure
    // instead of a test that passes without verifying anything.
    let probe = fs::File::create(home.join("enforcement-probe"));
    let result = if probe.is_ok() {
        None
    } else {
        Some(persist_atomic(&auth))
    };
    // Restore before any assertion can panic, so cleanup still works.
    fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        probe.is_err(),
        "this environment does not enforce directory permissions (running as root?): \
         the crash-safety property cannot be verified here"
    );

    let err = result.expect("probe passed").expect_err(
        "persisting into an unwritable directory must fail loudly, never silently succeed",
    );
    assert!(matches!(err, Error::PersistFailed { .. }), "got {err}");
    let rendered = err.to_string();
    assert!(rendered.contains("CRITICAL"), "{rendered}");
    assert!(!rendered.contains(OLD_REFRESH_TOKEN), "{rendered}");

    home.assert_credentials_intact(original.as_bytes());
    assert_eq!(home.entries(), vec!["auth.json".to_string()]);
}

#[test]
fn persist_aborts_and_cleans_up_when_the_backup_cannot_be_written() {
    // This one fails MID-persist: the temp file has already been created,
    // written and fsynced when the backup step fails. The temp must not
    // survive and auth.json must not have been touched yet.
    let home = CodexHome::fresh("backup-blocked");
    let original = auth_document(FRESH_EXP);
    home.write_auth(&original);
    // A directory where the backup file goes makes the copy fail.
    fs::create_dir(home.backup()).unwrap();

    let mut auth = load_auth().expect("fixture loads");
    auth.last_refresh = Some("2030-01-01T00:00:00.000000Z".to_string());

    let err = persist_atomic(&auth).expect_err("a failed backup must abort the persist");
    assert!(matches!(err, Error::PersistFailed { .. }), "got {err}");

    home.assert_credentials_intact(original.as_bytes());
    assert_eq!(
        home.entries(),
        vec!["auth.json".to_string(), "auth.json.bak".to_string()],
        "no stray temp file may survive a mid-persist failure"
    );
    // The document on disk is still the OLD one — the mutation above did
    // not leak to disk through a partially completed persist.
    assert_eq!(
        read_json(&home.auth())["last_refresh"],
        json!("2026-08-07T23:32:41.615755Z")
    );
}

#[test]
fn persist_refuses_to_reuse_a_foreign_temp_file() {
    // O_EXCL: a leftover temp belongs to someone else. askcodex must fail loudly
    // rather than overwrite it, and must not delete it either.
    let home = CodexHome::fresh("foreign-temp");
    let original = auth_document(FRESH_EXP);
    home.write_auth(&original);
    let stale = home.join(&format!("auth.json.tmp.{}", std::process::id()));
    fs::write(&stale, "not ours").unwrap();

    let auth = load_auth().expect("fixture loads");
    let err = persist_atomic(&auth).expect_err("an existing temp file must abort the persist");
    assert!(matches!(err, Error::PersistFailed { .. }), "got {err}");

    assert_eq!(
        fs::read_to_string(&stale).unwrap(),
        "not ours",
        "askcodex deleted a temp file it did not create"
    );
    let current = fs::read(home.auth()).expect("auth.json must still exist");
    assert_eq!(current, original.as_bytes());
    assert_eq!(mode_of(&home.auth()), 0o600);
    load_auth().expect("auth.json must still parse and validate");
}

// ---------------------------------------------------------------------------
// A failed refresh must never cost the user their credentials
// ---------------------------------------------------------------------------

#[test]
fn refresh_without_a_usable_refresh_token_never_contacts_the_server() {
    // No usable refresh token means no request at all. Posting an empty
    // string would be a guess dressed up as a credential, and answering
    // "nothing to do" would let an expiring access token flow on silently.
    let home = CodexHome::fresh("no-refresh-token");

    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.any_request();
        then.status(200)
            .body(r#"{"access_token":"askcodex-test-must-never-be-fetched"}"#);
    });

    for document in [
        // The key is absent entirely...
        format!(
            r#"{{"tokens":{{"access_token":"{}","account_id":"acct_REDACTED"}}}}"#,
            jwt_expiring_at(FRESH_EXP)
        ),
        // ...and the key is present but empty, which is not a credential.
        format!(
            r#"{{"tokens":{{"access_token":"{}","refresh_token":"","account_id":"acct_REDACTED"}}}}"#,
            jwt_expiring_at(FRESH_EXP)
        ),
    ] {
        home.write_auth(&document);
        let mut auth = load_auth().expect("fixture loads");
        let before = snapshot(&auth);

        let err = refresh_with_endpoint(&test_agent(), &mut auth, &server.url("/oauth/token"))
            .expect_err("a refresh without a refresh token must fail loudly");

        assert!(matches!(err, Error::RefreshUnavailable), "got {err}");
        assert_eq!(
            snapshot(&auth),
            before,
            "the in-memory credentials changed although no refresh happened"
        );
        home.assert_credentials_intact(document.as_bytes());
        assert_eq!(home.entries(), vec!["auth.json".to_string()]);
    }

    assert_eq!(
        mock.calls(),
        0,
        "askcodex contacted the token endpoint although it had no refresh token to send"
    );
}

#[test]
fn refresh_http_500_touches_neither_the_file_nor_the_struct() {
    let home = CodexHome::fresh("refresh-500");
    let original = auth_document(FRESH_EXP);
    home.write_auth(&original);
    let mut auth = load_auth().expect("fixture loads");
    let before = snapshot(&auth);

    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(POST).path("/oauth/token");
        then.status(500).body("upstream is down");
    });

    let err = refresh_with_endpoint(&test_agent(), &mut auth, &server.url("/oauth/token"))
        .expect_err("a 500 must not be reported as a successful refresh");

    mock.assert_calls(1);
    assert!(
        matches!(&err, Error::RefreshFailed { status: 500, snippet } if snippet.contains("upstream is down")),
        "unexpected error: {err}"
    );
    assert_eq!(
        snapshot(&auth),
        before,
        "the in-memory credentials changed after a failed refresh"
    );
    home.assert_credentials_intact(original.as_bytes());
    assert_eq!(
        home.entries(),
        vec!["auth.json".to_string()],
        "a failed refresh must not even create a backup"
    );
}

#[test]
fn refresh_200_without_access_token_touches_neither_the_file_nor_the_struct() {
    let home = CodexHome::fresh("refresh-no-access");
    let original = auth_document(FRESH_EXP);
    home.write_auth(&original);
    let mut auth = load_auth().expect("fixture loads");
    let before = snapshot(&auth);

    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(POST).path("/oauth/token");
        // A 200 that is missing the one field askcodex requires.
        then.status(200).body(
            r#"{"error":"server_error","id_token":"askcodex-test-id-token","expires_in":600}"#,
        );
    });

    let err = refresh_with_endpoint(&test_agent(), &mut auth, &server.url("/oauth/token"))
        .expect_err("a 200 without access_token must not be treated as success");

    mock.assert_calls(1);
    match &err {
        Error::RefreshInvalidResponse { keys } => {
            assert_eq!(keys, &["error", "expires_in", "id_token"]);
        }
        other => panic!("unexpected error: {other}"),
    }
    // Key NAMES only: nothing from a 200 body may be rendered.
    let rendered = err.to_string();
    assert!(!rendered.contains("askcodex-test-id-token"), "{rendered}");
    assert!(!rendered.contains("server_error"), "{rendered}");

    assert_eq!(
        snapshot(&auth),
        before,
        "the in-memory credentials changed after an invalid refresh response"
    );
    home.assert_credentials_intact(original.as_bytes());
    assert_eq!(home.entries(), vec!["auth.json".to_string()]);
}

#[test]
fn refresh_that_omits_a_rotated_refresh_token_keeps_the_old_one() {
    // THE lockout case: the server answers 200 with a new access token but
    // no rotated refresh token. Clearing the old one here would leave the
    // user unable to refresh ever again.
    let home = CodexHome::fresh("refresh-keeps-rt");
    home.write_auth(&auth_document(FRESH_EXP));
    let mut auth = load_auth().expect("fixture loads");
    let before = snapshot(&auth);
    let new_access = jwt_expiring_at(FRESH_EXP + 3600);

    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(POST).path("/oauth/token");
        // No `refresh_token` key at all, and an EMPTY `id_token` — neither
        // is a usable replacement.
        then.status(200).body(format!(
            r#"{{"access_token":"{new_access}","id_token":"","expires_in":864000}}"#
        ));
    });

    refresh_with_endpoint(&test_agent(), &mut auth, &server.url("/oauth/token"))
        .expect("a refresh without token rotation is still a success");

    mock.assert_calls(1);
    let after = snapshot(&auth);
    assert_eq!(
        after["tokens"]["refresh_token"],
        json!(OLD_REFRESH_TOKEN),
        "the working refresh token was destroyed because the server did not rotate it"
    );
    assert_eq!(
        after["tokens"]["id_token"], before["tokens"]["id_token"],
        "an empty id_token must not overwrite a working one"
    );
    assert_eq!(after["tokens"]["access_token"], json!(new_access));

    let written = read_json(&home.auth());
    assert_eq!(
        written["tokens"]["refresh_token"],
        json!(OLD_REFRESH_TOKEN),
        "the persisted refresh token was destroyed"
    );
    assert_eq!(written["tokens"]["id_token"], before["tokens"]["id_token"]);
    assert_eq!(written["tokens"]["access_token"], json!(new_access));
    assert_eq!(mode_of(&home.auth()), 0o600);
    home.assert_no_temp_files();
}

#[test]
fn successful_rotation_persists_every_field_plus_last_refresh_in_codex_format() {
    let home = CodexHome::fresh("refresh-ok");
    let original = auth_document(1_700_000_000);
    home.write_auth(&original);
    let mut auth = load_auth().expect("fixture loads");
    let new_access = jwt_expiring_at(FRESH_EXP);
    let new_id = jwt_expiring_at(FRESH_EXP);

    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        // Asserting the request shape proves the OLD refresh token is what
        // gets sent, with no backend headers on the OAuth host.
        when.method(POST)
            .path("/oauth/token")
            .header("content-type", "application/json; charset=utf-8")
            .header("user-agent", config::USER_AGENT)
            .header_missing("authorization")
            .header_missing("chatgpt-account-id")
            .json_body(json!({
                "client_id": config::CLIENT_ID,
                "grant_type": "refresh_token",
                "refresh_token": OLD_REFRESH_TOKEN,
            }));
        then.status(200).body(format!(
            r#"{{"access_token":"{new_access}","id_token":"{new_id}",
                 "refresh_token":"{NEW_REFRESH_TOKEN}","expires_in":864000}}"#
        ));
    });

    // `format_last_refresh` truncates to microseconds; a second of slack on
    // each side keeps the window assertion honest without being flaky.
    let before = chrono::Utc::now() - chrono::Duration::seconds(1);
    refresh_with_endpoint(&test_agent(), &mut auth, &server.url("/oauth/token"))
        .expect("refresh succeeds");
    let after = chrono::Utc::now() + chrono::Duration::seconds(1);
    mock.assert_calls(1);

    // In memory and on disk must agree, field by field.
    let written = read_json(&home.auth());
    assert_eq!(written, snapshot(&auth), "the file and the struct disagree");
    assert_eq!(written["tokens"]["access_token"], json!(new_access));
    assert_eq!(written["tokens"]["id_token"], json!(new_id));
    assert_eq!(written["tokens"]["refresh_token"], json!(NEW_REFRESH_TOKEN));
    assert_eq!(written["tokens"]["account_id"], json!("acct_REDACTED"));

    // last_refresh, byte-exact in the format codex itself writes:
    // RFC3339 UTC, exactly 6 fractional digits, `Z` suffix.
    let stamp = written["last_refresh"]
        .as_str()
        .expect("last_refresh is a string");
    let parsed = models::parse_last_refresh(stamp).expect("last_refresh is RFC3339");
    assert_eq!(
        models::format_last_refresh(parsed),
        stamp,
        "last_refresh is not in codex's byte-exact format"
    );
    let (_, fraction) = stamp.split_once('.').expect("fractional seconds present");
    assert_eq!(
        fraction.len(),
        7,
        "expected 6 fractional digits + Z: {stamp}"
    );
    assert!(fraction.ends_with('Z'), "{stamp}");
    assert!(fraction[..6].chars().all(|c| c.is_ascii_digit()), "{stamp}");
    assert!(parsed >= before && parsed <= after, "{stamp} is not `now`");

    // Everything askcodex does not model rode along untouched.
    assert_eq!(
        written["unknown_top_level"],
        json!({"deep": {"key": null}, "list": []})
    );
    assert_eq!(written["tokens"]["unknown_token_number"], json!(7));
    assert_eq!(written["tokens"]["unknown_token_null"], Value::Null);
    assert_eq!(written["legacy_null_key"], Value::Null);

    // The rewritten file is still 0600, the backup holds the pre-rotation
    // document byte for byte, and nothing else was left behind.
    assert_eq!(mode_of(&home.auth()), 0o600);
    assert_eq!(mode_of(&home.backup()), 0o600);
    assert_eq!(fs::read(home.backup()).unwrap(), original.as_bytes());
    assert_eq!(
        home.entries(),
        vec!["auth.json".to_string(), "auth.json.bak".to_string()]
    );

    // And the result is a document askcodex can load again.
    let reloaded = load_auth().expect("the rotated file reloads");
    assert_eq!(snapshot(&reloaded), written);
    assert!(
        !needs_refresh(&reloaded, chrono::Utc::now()).expect("freshness check"),
        "a just-rotated document must not immediately want another refresh"
    );
}

#[test]
fn a_rotation_that_cannot_be_persisted_is_reported_as_the_critical_state_it_is() {
    // The worst reachable state: the server HAS rotated the tokens, so the
    // refresh token on disk is already dead, and the write back failed.
    // Reporting success here would hand the user a file whose credentials
    // no longer work with no hint why — the lockout with a smile.
    let home = CodexHome::fresh("rotation-unpersistable");
    let original = auth_document(1_700_000_000);
    home.write_auth(&original);
    let mut auth = load_auth().expect("fixture loads");
    // A leftover temp file from an earlier run of this process. The persist
    // therefore fails MID-write: after the current document was backed up,
    // and after the server already rotated the tokens.
    let stale_temp = home.join(&format!("auth.json.tmp.{}", std::process::id()));
    fs::write(&stale_temp, "interrupted run").unwrap();

    let new_access = jwt_expiring_at(FRESH_EXP);
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(POST).path("/oauth/token");
        then.status(200).body(format!(
            r#"{{"access_token":"{new_access}","refresh_token":"{NEW_REFRESH_TOKEN}"}}"#
        ));
    });

    let err = refresh_with_endpoint(&test_agent(), &mut auth, &server.url("/oauth/token"))
        .expect_err("a rotation askcodex could not save must never be reported as success");
    mock.assert_calls(1);

    // Loud, and specifically about the one state where credentials can be
    // lost — including where to look and what to do next.
    assert!(matches!(err, Error::PersistFailed { .. }), "got {err}");
    let rendered = err.to_string();
    assert!(rendered.contains("CRITICAL"), "{rendered}");
    assert!(rendered.contains("rotated"), "{rendered}");
    assert!(rendered.contains("codex login"), "{rendered}");
    assert!(
        rendered.contains(&home.auth().display().to_string()),
        "the error must name the file it failed to write: {rendered}"
    );
    assert!(
        rendered.contains(&home.backup().display().to_string()),
        "the error must name the backup it points the user at: {rendered}"
    );
    // ...and that backup is not a claim. It exists, and it holds the
    // document that was on disk when this refresh started — not one left
    // over from an earlier refresh, whose refresh token would be two
    // generations dead by now.
    assert!(
        home.backup().exists(),
        "the error named a backup that does not exist"
    );
    assert_eq!(
        fs::read(home.backup()).expect("read the named backup"),
        original.as_bytes(),
        "the named backup is not the document that was replaced"
    );
    assert_eq!(mode_of(&home.backup()), 0o600);
    for secret in [OLD_REFRESH_TOKEN, NEW_REFRESH_TOKEN, new_access.as_str()] {
        assert!(
            !rendered.contains(secret),
            "the CRITICAL error leaked a token value"
        );
    }

    // The caller is told loudly AND still holds the rotated tokens in
    // memory: nothing was lost silently inside the process.
    let after = snapshot(&auth);
    assert_eq!(after["tokens"]["access_token"], json!(new_access));
    assert_eq!(after["tokens"]["refresh_token"], json!(NEW_REFRESH_TOKEN));

    // On disk the PREVIOUS document is still complete and still 0600: a
    // failed persist never leaves a half-written credential file behind.
    // (Spelled out rather than `assert_credentials_intact`, whose no-temp
    // check would trip over the blocker this test planted itself.)
    assert_eq!(
        fs::read(home.auth()).expect("auth.json still exists"),
        original.as_bytes()
    );
    assert_eq!(mode_of(&home.auth()), 0o600);
    load_auth().expect("auth.json must still parse and validate after a failure");
    assert_eq!(
        read_json(&home.auth())["tokens"]["refresh_token"],
        json!(OLD_REFRESH_TOKEN)
    );
    assert_eq!(
        fs::read_to_string(&stale_temp).unwrap(),
        "interrupted run",
        "askcodex deleted a temp file it did not create"
    );
    assert_eq!(
        home.entries(),
        vec![
            "auth.json".to_string(),
            "auth.json.bak".to_string(),
            stale_temp
                .file_name()
                .expect("temp file name")
                .to_string_lossy()
                .into_owned(),
        ],
        "no stray file may survive a failed rotation"
    );
}

#[test]
fn refresh_never_contacts_the_endpoint_when_the_auth_path_cannot_be_resolved() {
    // If askcodex could not possibly persist the result, it must not ask the
    // server to rotate the token: a rotation it cannot save is a lockout.
    let home = CodexHome::fresh("unresolvable-home");
    home.write_auth(&auth_document(FRESH_EXP));
    let mut auth = load_auth().expect("fixture loads");
    let before = snapshot(&auth);

    // Start the server BEFORE touching the environment (see module header).
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.any_request();
        then.status(200).body(format!(
            r#"{{"access_token":"{}"}}"#,
            jwt_expiring_at(FRESH_EXP)
        ));
    });

    // Restored on drop, before the CodexHome guard releases ENV_LOCK.
    let _no_codex_home = EnvRestore::remove("CODEX_HOME");
    let _no_home = EnvRestore::remove("HOME");

    assert!(matches!(config::auth_path(), Err(Error::NoHomeDir)));
    let err = refresh_with_endpoint(&test_agent(), &mut auth, &server.url("/oauth/token"))
        .expect_err("an unresolvable auth path must abort the refresh");

    assert!(matches!(err, Error::NoHomeDir), "got {err}");
    assert_eq!(
        mock.calls(),
        0,
        "askcodex sent a live refresh token to the server although it could not have saved the result"
    );
    assert_eq!(snapshot(&auth), before);
}

// ---------------------------------------------------------------------------
// The keyring case and the other loud load failures
// ---------------------------------------------------------------------------

#[test]
fn auth_without_tokens_is_a_loud_named_error_about_file_based_storage() {
    let home = CodexHome::fresh("keyring");
    // Each of these parses as JSON but carries no usable credential — the
    // shape codex leaves behind when it stores credentials in the system
    // keyring instead of the file.
    for document in [
        r#"{"auth_mode":"chatgpt"}"#,
        r#"{"auth_mode":"chatgpt","tokens":null}"#,
        r#"{"tokens":{"account_id":"acct_REDACTED"}}"#,
        r#"{"tokens":{"access_token":"","account_id":"acct_REDACTED"}}"#,
    ] {
        home.write_auth(document);
        let err = load_auth()
            .err()
            .unwrap_or_else(|| panic!("{document} must not load as a usable credential"));

        assert!(
            matches!(err, Error::AuthTokensMissing { .. }),
            "unexpected error for {document}: {err}"
        );
        // Well-named: the variant, not a generic parse failure.
        assert!(
            format!("{err:?}").starts_with("AuthTokensMissing"),
            "{err:?}"
        );
        let rendered = err.to_string();
        assert!(rendered.contains("file-based"), "{rendered}");
        assert!(rendered.contains("keyring"), "{rendered}");
        assert!(rendered.contains("codex login"), "{rendered}");
        assert!(
            rendered.contains(&home.auth().display().to_string()),
            "the error must name the file it looked at: {rendered}"
        );
    }
}

#[test]
fn tokens_without_an_account_id_are_rejected_with_their_own_error() {
    let home = CodexHome::fresh("no-account-id");
    for document in [
        r#"{"tokens":{"access_token":"a.b.c"}}"#,
        r#"{"tokens":{"access_token":"a.b.c","account_id":""}}"#,
    ] {
        home.write_auth(document);
        let err = load_auth().expect_err("a document without account_id must not load");
        assert!(
            matches!(err, Error::AuthAccountIdMissing { .. }),
            "unexpected error for {document}: {err}"
        );
    }
}

#[test]
fn a_missing_or_corrupt_auth_file_is_loud_and_actionable() {
    let home = CodexHome::fresh("load-failures");

    let err = load_auth().expect_err("a missing file must not produce empty credentials");
    assert!(matches!(err, Error::AuthFileMissing { .. }), "got {err}");
    assert!(err.to_string().contains("codex login"), "{err}");

    home.write_auth("{not json");
    let err = load_auth().expect_err("a corrupt file must not produce empty credentials");
    assert!(matches!(err, Error::AuthFileInvalid { .. }), "got {err}");
    assert!(
        err.to_string().contains(&home.auth().display().to_string()),
        "{err}"
    );

    // Reading is never a write: the corrupt file is still exactly as it was.
    assert_eq!(fs::read_to_string(home.auth()).unwrap(), "{not json");
    assert_eq!(home.entries(), vec!["auth.json".to_string()]);
}

// ---------------------------------------------------------------------------
// jwt_exp / needs_refresh boundaries, through the public API
// ---------------------------------------------------------------------------

#[test]
fn jwt_exp_decodes_the_boundary_shapes_and_rejects_the_rest() {
    let _home = CodexHome::fresh("jwt-exp");

    // Unpadded base64url payload whose length is not a multiple of 3.
    let token = Secret::new(fake_jwt(r#"{"exp":1799999999,"client_id":"app_x"}"#));
    assert_eq!(jwt_exp(&token).unwrap(), 1_799_999_999);
    // Extremes and RFC 7519's non-integer NumericDate.
    assert_eq!(jwt_exp(&Secret::new(jwt_expiring_at(-5))).unwrap(), -5);
    assert_eq!(
        jwt_exp(&Secret::new(jwt_expiring_at(i64::MAX))).unwrap(),
        i64::MAX
    );
    assert_eq!(
        jwt_exp(&Secret::new(fake_jwt(r#"{"exp":1700000000.75}"#))).unwrap(),
        1_700_000_000
    );

    // Everything malformed is an error, never a silent 0 (which would
    // quietly force a refresh).
    for bad in ["", "onlyone", "two.parts", "a.b.c.d"] {
        let err = jwt_exp(&Secret::new(bad)).unwrap_err();
        assert!(
            matches!(&err, Error::JwtInvalid { reason } if reason.contains("3 dot-separated")),
            "unexpected error for {bad:?}: {err}"
        );
    }
    for claims in [
        r#"{"iat":1700000000}"#,
        r#"{"exp":"1700000000"}"#,
        r#"{"exp":null}"#,
        r#"[1,2,3]"#,
    ] {
        let err = jwt_exp(&Secret::new(fake_jwt(claims))).unwrap_err();
        assert!(
            matches!(err, Error::JwtInvalid { .. }),
            "unexpected error for {claims}: {err}"
        );
    }
    // A padded payload is malformed, not something to silently re-pad.
    let padded = format!(
        "aGVhZGVy.{}.c2ln",
        base64::engine::general_purpose::URL_SAFE.encode(br#"{"exp":10}"#)
    );
    assert!(padded.contains('='));
    assert!(matches!(
        jwt_exp(&Secret::new(padded)).unwrap_err(),
        Error::JwtInvalid { .. }
    ));
}

#[test]
fn jwt_exp_errors_never_contain_token_material() {
    let _home = CodexHome::fresh("jwt-redaction");
    let material = "ASKCODEXTESTTOKENMATERIAL";
    for raw in [
        format!("aGVhZGVy.{material}!!!.c2ln"),
        format!("{material}.{}.c2ln", URL_SAFE_NO_PAD.encode(b"[]")),
        material.to_string(),
    ] {
        let rendered = jwt_exp(&Secret::new(raw)).unwrap_err().to_string();
        assert!(
            !rendered.contains(material),
            "an error leaked token material: {rendered}"
        );
    }
}

#[test]
fn needs_refresh_expiry_window_boundary() {
    let _home = CodexHome::fresh("needs-refresh-window");
    let now = chrono::Utc::now();

    // Exactly at the window edge: `exp - now == REFRESH_WINDOW_SECS` is not
    // yet "less than the window".
    assert!(
        !needs_refresh(
            &auth_with(now.timestamp() + config::REFRESH_WINDOW_SECS, None),
            now
        )
        .unwrap()
    );
    // One second inside it.
    assert!(
        needs_refresh(
            &auth_with(now.timestamp() + config::REFRESH_WINDOW_SECS - 1, None),
            now
        )
        .unwrap()
    );
    // Already expired.
    assert!(needs_refresh(&auth_with(now.timestamp() - 1, None), now).unwrap());
    // Absurd values must not overflow into the wrong answer.
    assert!(!needs_refresh(&auth_with(i64::MAX, None), now).unwrap());
    assert!(needs_refresh(&auth_with(i64::MIN, None), now).unwrap());
}

#[test]
fn needs_refresh_last_refresh_is_the_fallback_for_an_unreadable_exp_only() {
    // codex's rule, as recorded in docs/PROTOCOL.md §6 `[verified-source]`:
    // refresh if `exp <= now + 5 min`, OR — only when `exp` is unreadable —
    // if `last_refresh` is older than 8 days. Evaluating the age rule
    // unconditionally would rotate the real credentials of anyone who left
    // askcodex alone for nine days while holding a token still valid for a day,
    // which codex itself would not do.
    let _home = CodexHome::fresh("needs-refresh-age");
    let now = chrono::Utc::now();
    let fresh_exp = now.timestamp() + 3600;

    // No last_refresh at all: the age rule is skipped, not guessed.
    let auth = auth_with(fresh_exp, None);
    assert!(auth.last_refresh.is_none());
    assert!(!needs_refresh(&auth, now).unwrap());

    // A readable exp settles it on its own, however old the timestamp is.
    let ancient = models::format_last_refresh(now - chrono::Duration::days(9));
    assert!(
        !needs_refresh(&auth_with(fresh_exp, Some(&ancient)), now).unwrap(),
        "a valid access token was rotated over last_refresh alone"
    );

    // With an unreadable exp, the age rule decides, at the same boundary.
    let at_limit = now - chrono::Duration::seconds(config::REFRESH_MAX_AGE_DAYS * SECS_PER_DAY);
    let auth = auth_with_access("not-a-jwt", Some(&models::format_last_refresh(at_limit)));
    assert!(
        !needs_refresh(&auth, now).unwrap(),
        "exactly REFRESH_MAX_AGE_DAYS old is not yet stale"
    );

    let past_limit = at_limit - chrono::Duration::seconds(2);
    let auth = auth_with_access("not-a-jwt", Some(&models::format_last_refresh(past_limit)));
    assert!(needs_refresh(&auth, now).unwrap());
}

#[test]
fn a_last_refresh_askcodex_cannot_parse_does_not_disable_every_command() {
    // `needs_refresh` runs before every backend command, so failing here on
    // a field the decision does not depend on took whoami, usage, models,
    // ask and image down together — for a user whose access token was
    // perfectly valid. The first string is codex's own format minus the
    // UTC offset.
    let _home = CodexHome::fresh("needs-refresh-tolerant");
    let now = chrono::Utc::now();
    for raw in ["2026-08-07T23:32:41.615755", "last tuesday", ""] {
        assert!(
            !needs_refresh(&auth_with(now.timestamp() + 3600, Some(raw)), now).unwrap(),
            "a valid access token was rejected over last_refresh={raw:?}"
        );
    }
}

#[test]
fn needs_refresh_is_loud_about_corruption_instead_of_guessing() {
    let _home = CodexHome::fresh("needs-refresh-loud");
    let now = chrono::Utc::now();

    // In the branch that DOES depend on last_refresh — an access token
    // whose expiry cannot be read — corruption is reported, not guessed at.
    let err = needs_refresh(&auth_with_access("not-a-jwt", Some("last tuesday")), now).unwrap_err();
    assert!(
        matches!(&err, Error::UnexpectedResponse { context } if context.contains("last_refresh")),
        "unexpected error: {err}"
    );

    // A non-JWT access token with no fallback signal propagates the decode
    // error unchanged: with neither an expiry nor a timestamp there is
    // nothing to decide on, and askcodex does not invent an answer.
    let auth =
        parse_auth(r#"{"tokens":{"access_token":"not-a-jwt","account_id":"acct_REDACTED"}}"#);
    assert!(matches!(
        needs_refresh(&auth, now).unwrap_err(),
        Error::JwtInvalid { .. }
    ));

    // No access token at all (only reachable by skipping load_auth) is an
    // error, never a default "yes, refresh".
    let auth = parse_auth(r#"{"tokens":{"account_id":"acct_REDACTED"}}"#);
    let err = needs_refresh(&auth, now).unwrap_err();
    assert!(
        matches!(&err, Error::UnexpectedResponse { context } if context.contains("access_token")),
        "unexpected error: {err}"
    );
}

// ---------------------------------------------------------------------------
// Concurrent askcodex processes must not clobber a rotated refresh token
// ---------------------------------------------------------------------------

#[test]
fn a_second_process_adopts_the_rotated_credentials_instead_of_spending_its_own() {
    // Two overlapping askcodex invocations (an agent issuing parallel tool
    // calls is the realistic case) each load auth.json and each decide a
    // refresh is due. `fs::rename` makes each write atomic, but atomicity
    // is not mutual exclusion: without a lock and a re-read, the second
    // process POSTs the SAME refresh token the first one just spent —
    // PROTOCOL.md §6 lists `refresh_token_reused` as a permanent,
    // re-login-only failure — and then writes its own snapshot over the
    // file, so the generation that survives is decided by who finishes
    // last.
    let home = CodexHome::fresh("concurrent-rotation");
    home.write_auth(&auth_document(1_700_000_000));

    // Two handles on the same document: two processes, one credential file.
    let mut first = load_auth().expect("load 1");
    let mut second = load_auth().expect("load 2");

    let server = MockServer::start();
    // Matching on the body proves WHICH generation each request carried.
    let gen1 = server.mock(|when, then| {
        when.method(POST).path("/oauth/token").json_body(json!({
            "client_id": config::CLIENT_ID,
            "grant_type": "refresh_token",
            "refresh_token": OLD_REFRESH_TOKEN,
        }));
        then.status(200).body(format!(
            r#"{{"access_token":"{}","refresh_token":"{NEW_REFRESH_TOKEN}"}}"#,
            jwt_expiring_at(FRESH_EXP)
        ));
    });

    refresh_with_endpoint(&test_agent(), &mut first, &server.url("/oauth/token"))
        .expect("the first refresh succeeds");
    gen1.assert_calls(1);
    let rotated = read_json(&home.auth());

    // The second process now refreshes while still a generation behind.
    refresh_with_endpoint(&test_agent(), &mut second, &server.url("/oauth/token"))
        .expect("the second process must not fail over a race it can resolve");

    assert_eq!(
        gen1.calls(),
        1,
        "the spent refresh token was sent to the server a second time"
    );
    assert_eq!(
        snapshot(&second)["tokens"]["refresh_token"],
        json!(NEW_REFRESH_TOKEN),
        "the lagging process kept its own retired generation in memory"
    );
    assert_eq!(
        read_json(&home.auth()),
        rotated,
        "auth.json was overwritten by the process holding the older generation"
    );
    home.assert_no_temp_files();
    assert_eq!(
        home.entries(),
        vec!["auth.json".to_string(), "auth.json.bak".to_string()],
        "the credential lock must not survive the refresh that took it"
    );
}

#[test]
fn a_lock_left_behind_by_a_crashed_run_never_makes_askcodex_unusable() {
    // SIGINT does not unwind, so a killed askcodex can leave its lock file. It
    // must be reclaimed by age, not by a support ticket.
    let home = CodexHome::fresh("stale-lock");
    home.write_auth(&auth_document(1_700_000_000));
    let mut auth = load_auth().expect("fixture loads");

    let lock = home.join("auth.json.lock");
    fs::write(&lock, "424242\n").expect("plant a lock file");
    fs::File::options()
        .write(true)
        .open(&lock)
        .expect("open the lock file")
        .set_modified(std::time::SystemTime::now() - Duration::from_secs(24 * 60 * 60))
        .expect("age the lock file");

    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(POST).path("/oauth/token");
        then.status(200).body(format!(
            r#"{{"access_token":"{}","refresh_token":"{NEW_REFRESH_TOKEN}"}}"#,
            jwt_expiring_at(FRESH_EXP)
        ));
    });

    refresh_with_endpoint(&test_agent(), &mut auth, &server.url("/oauth/token"))
        .expect("a lock nobody owns must not block a refresh forever");

    mock.assert_calls(1);
    assert_eq!(
        home.entries(),
        vec!["auth.json".to_string(), "auth.json.bak".to_string()],
        "the reclaimed lock was not released"
    );
}

// ---------------------------------------------------------------------------
// The backup, the symlink, and what a failed persist may claim
// ---------------------------------------------------------------------------

#[test]
fn a_symlinked_auth_json_keeps_receiving_updates() {
    // `rename(2)` acts on the directory entry, so writing through a
    // symlinked auth.json would replace the LINK with a regular file: the
    // user's real store silently stops being updated and freezes at a
    // refresh-token generation the server has already retired, with nothing
    // in askcodex's output ever mentioning it.
    let home = CodexHome::fresh("symlinked-auth");
    let store = home.join("real-store");
    fs::create_dir(&store).expect("create the user's real store");
    let real = store.join("credentials.json");
    let original = auth_document(FRESH_EXP);
    fs::write(&real, &original).expect("write the real credential file");
    fs::set_permissions(&real, fs::Permissions::from_mode(0o600)).expect("0600");
    std::os::unix::fs::symlink(&real, home.auth()).expect("symlink auth.json");

    let mut auth = load_auth().expect("the linked document loads");
    auth.last_refresh = Some("2030-01-01T00:00:00.000000Z".to_string());
    persist_atomic(&auth).expect("persist through the link");

    assert!(
        fs::symlink_metadata(home.auth())
            .expect("auth.json still exists")
            .file_type()
            .is_symlink(),
        "askcodex replaced the user's symlink with a regular file"
    );
    assert_eq!(
        read_json(&real)["last_refresh"],
        json!("2030-01-01T00:00:00.000000Z"),
        "the link target did not receive the update"
    );
    assert_eq!(mode_of(&real), 0o600);
    // Backup and temp belong beside the file the rename replaces (same
    // filesystem), not beside the link.
    assert_eq!(
        fs::read(store.join("credentials.json.bak")).expect("the backup sits beside the real file"),
        original.as_bytes()
    );
    assert_eq!(
        home.entries(),
        vec!["auth.json".to_string(), "real-store".to_string()]
    );
}

#[test]
fn the_backup_is_created_0600_never_widened_from_a_looser_file() {
    // `fs::copy` + `set_permissions` is the chmod-after-write pattern this
    // module forbids three steps earlier for the temp file — on a file
    // holding byte-identical credentials. Copying onto an existing backup
    // keeps that file's inode, and with it its mode, until the chmod lands.
    let home = CodexHome::fresh("backup-mode-window");
    home.write_auth(&auth_document(FRESH_EXP));
    fs::set_permissions(home.auth(), fs::Permissions::from_mode(0o644)).unwrap();
    fs::write(home.backup(), "an earlier backup").unwrap();
    fs::set_permissions(home.backup(), fs::Permissions::from_mode(0o644)).unwrap();
    let before = inode_of(&home.backup());

    persist_atomic(&load_auth().expect("fixture loads")).expect("persist succeeds");

    assert_ne!(
        inode_of(&home.backup()),
        before,
        "the backup was rewritten in place, so it existed with the source's 0644"
    );
    assert_eq!(mode_of(&home.backup()), 0o600);
    home.assert_no_temp_files();
}

#[test]
fn a_persist_failure_never_points_the_user_at_a_backup_it_did_not_write() {
    // The message states as a FACT that a backup of the previous file is at
    // the named path. An error that sends a user to a file which does not
    // exist — while telling them their credentials may be gone — is worse
    // than one that says nothing.
    let home = CodexHome::fresh("no-backup-claim");
    let original = auth_document(FRESH_EXP);
    home.write_auth(&original);
    let auth = load_auth().expect("fixture loads");

    fs::set_permissions(home.path(), fs::Permissions::from_mode(0o500)).unwrap();
    let probe = fs::File::create(home.join("enforcement-probe"));
    let result = if probe.is_ok() {
        None
    } else {
        Some(persist_atomic(&auth))
    };
    fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        probe.is_err(),
        "this environment does not enforce directory permissions (running as root?)"
    );

    let err = result
        .expect("probe passed")
        .expect_err("persist must fail");
    let rendered = err.to_string();
    assert!(rendered.contains("CRITICAL"), "{rendered}");
    assert!(
        !home.backup().exists(),
        "no backup could have been written into a read-only directory"
    );
    assert!(
        !rendered.contains("auth.json.bak"),
        "the error names a backup that was never written: {rendered}"
    );
    // What it names instead is the file that really does hold the previous
    // document, and that file is really there.
    assert!(
        rendered.contains(&home.auth().display().to_string()),
        "{rendered}"
    );
    home.assert_credentials_intact(original.as_bytes());
}

// ---------------------------------------------------------------------------
// A refresh failure body is a third party's string, not a trusted one
// ---------------------------------------------------------------------------

#[test]
fn a_refresh_error_body_is_scrubbed_of_credentials_before_it_is_quoted() {
    // README's guarantee is absolute — "a token cannot reach a log line,
    // an error message, a panic ... even by accident" — but the OAuth error
    // body is a string from a server nobody here has ever seen fail, and
    // PROTOCOL.md §6 itself names a `refresh_token_reused` error. The
    // guarantee has to hold on code, not on a belief about a third party.
    let home = CodexHome::fresh("scrubbed-refresh-error");
    let original = auth_document(FRESH_EXP);
    home.write_auth(&original);
    let mut auth = load_auth().expect("fixture loads");
    let access = jwt_expiring_at(FRESH_EXP);

    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(POST).path("/oauth/token");
        then.status(400).body(format!(
            r#"{{"error":"invalid_grant","error_description":"refresh_token {OLD_REFRESH_TOKEN} was reused","echo":"{access}"}}"#
        ));
    });

    let err = refresh_with_endpoint(&test_agent(), &mut auth, &server.url("/oauth/token"))
        .expect_err("a 400 is a failed refresh");
    mock.assert_calls(1);

    let rendered = err.to_string();
    for (name, secret) in [
        ("refresh_token", OLD_REFRESH_TOKEN),
        ("access_token", access.as_str()),
    ] {
        assert!(
            !rendered.contains(secret),
            "the {name} value reached an error message: {rendered}"
        );
    }
    assert!(rendered.contains("REDACTED"), "{rendered}");
    // Only the values are gone; the diagnosis survives.
    assert!(rendered.contains("invalid_grant"), "{rendered}");
    assert!(rendered.contains("was reused"), "{rendered}");
    home.assert_credentials_intact(original.as_bytes());
}
