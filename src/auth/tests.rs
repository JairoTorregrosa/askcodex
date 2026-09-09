const SECS_PER_DAY: i64 = 86_400;
use super::*;
use super::{
    lock::AuthLock,
    session::{refresh_inner, refresh_locked},
    store::{load_auth_from, persist_atomic_to},
};
use crate::{
    config,
    error::Error,
    models::{self, AuthFile},
    redact::Secret,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicU64, Ordering};

use httpmock::prelude::*;

// ---------------------------------------------------------------
// Test isolation
// ---------------------------------------------------------------
//
// Two independent guarantees, both required:
//
// 1. No test here calls `config::auth_path()` or `config::TOKEN_URL`.
//    Every filesystem test drives `load_auth_from` / `persist_atomic_to`
//    with a path inside a per-test temp directory, and every network
//    test drives `refresh_inner` against a localhost httpmock server.
//    The real `~/.codex` and `auth.openai.com` are unreachable from
//    this module's tests by construction.
// 2. Defense in depth: [`super::isolate_codex_home`] still points
//    `CODEX_HOME` at a scratch directory once per test process, so
//    that even a future test that DID resolve the real path would land
//    in the scratch dir. Nothing here depends on its value, which is
//    why these tests never take `super::lock_codex_home()`.

/// A unique directory under the system temp dir, removed on drop.
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> TempDir {
        isolate_codex_home();
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "askcodex-auth-test-{}-{}-{}",
            std::process::id(),
            tag,
            unique
        ));
        fs::create_dir_all(&path).expect("create temp dir");
        TempDir { path }
    }

    fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    /// The auth file path used by most tests.
    fn auth(&self) -> PathBuf {
        self.join("auth.json")
    }

    fn entries(&self) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(&self.path)
            .expect("read temp dir")
            .map(|entry| {
                entry
                    .expect("dir entry")
                    .file_name()
                    .to_string_lossy()
                    .into()
            })
            .collect();
        // The persistent lock inode is checked by the dedicated lock tests.
        names.retain(|name| name != "auth.json.lock");
        names.sort();
        names
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

// ---------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------

/// Build a syntactically valid (unsigned, FAKE) JWT whose payload is
/// `claims`. No real token value exists anywhere in these tests, and
/// fixtures are built from these plain strings so that `Secret::expose`
/// never has to be called to construct one.
fn fake_jwt(claims: &str) -> String {
    format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#),
        URL_SAFE_NO_PAD.encode(claims.as_bytes()),
        URL_SAFE_NO_PAD.encode(b"sig"),
    )
}

fn fake_jwt_expiring_at(exp: i64) -> String {
    fake_jwt(&format!(r#"{{"exp":{exp}}}"#))
}

fn jwt_with_payload(claims: &str) -> Secret {
    Secret::new(fake_jwt(claims))
}

fn jwt_expiring_at(exp: i64) -> Secret {
    Secret::new(fake_jwt_expiring_at(exp))
}

fn mode_of(path: &Path) -> u32 {
    fs::metadata(path).expect("metadata").permissions().mode() & 0o777
}

/// Identity of the file behind a path: a new inode proves the file was
/// created rather than rewritten in place.
fn inode_of(path: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt as _;
    fs::metadata(path).expect("metadata").ino()
}

/// A full auth document with an access token expiring at `exp`.
fn auth_json(exp: i64) -> String {
    format!(
        r#"{{
  "auth_mode": "chatgpt",
  "openai_api_key_placeholder": null,
  "tokens": {{
    "id_token": "{id}",
    "access_token": "{access}",
    "refresh_token": "old-refresh-token",
    "account_id": "acct_test",
    "unknown_token_key": 7
  }},
  "last_refresh": "2026-08-07T23:32:41.615755Z",
  "unknown_top_level": {{"nested": [1, 2, 3]}}
}}"#,
        id = fake_jwt_expiring_at(exp),
        access = fake_jwt_expiring_at(exp),
    )
}

fn parse_auth(text: &str) -> AuthFile {
    serde_json::from_str(text).expect("fixture parses")
}

// The three accessors below are the ONLY `Secret::expose` calls in this
// module besides the JWT decode in `jwt_exp`. They exist so the rotation
// assertions can compare values; every value they touch is a fixture
// string invented in this file, never a real credential.
fn access_token_of(auth: &AuthFile) -> String {
    auth.tokens
        .as_ref()
        .and_then(|tokens| tokens.access_token.as_ref())
        .expect("access token")
        .expose()
        .to_string()
}

fn refresh_token_of(auth: &AuthFile) -> String {
    auth.tokens
        .as_ref()
        .and_then(|tokens| tokens.refresh_token.as_ref())
        .expect("refresh token")
        .expose()
        .to_string()
}

fn id_token_of(auth: &AuthFile) -> Option<String> {
    auth.tokens
        .as_ref()
        .and_then(|tokens| tokens.id_token.as_ref())
        .map(|token| token.expose().to_string())
}

/// The agent askcodex builds in production (`http_status_as_error(false)`).
fn test_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_connect(Some(Duration::from_secs(config::CONNECT_TIMEOUT_SECS)))
        .build()
        .into()
}

// ---------------------------------------------------------------
// jwt_exp
// ---------------------------------------------------------------

#[test]
fn jwt_exp_decodes_unpadded_payload() {
    isolate_codex_home();
    // 1 byte of payload mod 3 => the base64 segment would need "==" if
    // it were padded; URL_SAFE_NO_PAD must decode it as-is.
    let token = jwt_with_payload(r#"{"exp":1799999999,"client_id":"app_x"}"#);
    assert_eq!(jwt_exp(&token).unwrap(), 1_799_999_999);
}

#[test]
fn jwt_exp_accepts_negative_and_fractional_numeric_date() {
    isolate_codex_home();
    assert_eq!(jwt_exp(&jwt_expiring_at(-5)).unwrap(), -5);
    // RFC 7519 NumericDate may be non-integer.
    let token = jwt_with_payload(r#"{"exp":1700000000.75}"#);
    assert_eq!(jwt_exp(&token).unwrap(), 1_700_000_000);
}

#[test]
fn jwt_exp_rejects_wrong_segment_count() {
    isolate_codex_home();
    for bad in ["", "onlyone", "two.parts", "a.b.c.d"] {
        let err = jwt_exp(&Secret::new(bad)).unwrap_err();
        assert!(
            matches!(&err, Error::JwtInvalid { reason } if reason.contains("3 dot-separated")),
            "unexpected error for {bad:?}: {err}"
        );
    }
}

#[test]
fn jwt_exp_rejects_bad_base64() {
    isolate_codex_home();
    let err = jwt_exp(&Secret::new("aGVhZGVy.not base64!.c2ln")).unwrap_err();
    assert!(matches!(&err, Error::JwtInvalid { reason } if reason.contains("base64url")));
}

#[test]
fn jwt_exp_rejects_padded_payload() {
    isolate_codex_home();
    // Codex/OpenAI JWTs are unpadded; a padded segment is malformed and
    // must be loud rather than silently re-padded.
    // 10 payload bytes => the padded encoding ends in "==".
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
fn jwt_exp_rejects_non_json_payload() {
    isolate_codex_home();
    let token = Secret::new(format!(
        "aGVhZGVy.{}.c2ln",
        URL_SAFE_NO_PAD.encode(b"not json at all")
    ));
    let err = jwt_exp(&token).unwrap_err();
    assert!(matches!(&err, Error::JwtInvalid { reason } if reason.contains("not JSON")));
}

#[test]
fn jwt_exp_rejects_non_object_payload() {
    isolate_codex_home();
    let token = jwt_with_payload("[1,2,3]");
    let err = jwt_exp(&token).unwrap_err();
    assert!(matches!(&err, Error::JwtInvalid { reason } if reason.contains("JSON object")));
}

#[test]
fn jwt_exp_rejects_missing_exp() {
    isolate_codex_home();
    let token = jwt_with_payload(r#"{"iat":1700000000}"#);
    let err = jwt_exp(&token).unwrap_err();
    assert!(matches!(&err, Error::JwtInvalid { reason } if reason.contains("`exp`")));
}

#[test]
fn jwt_exp_rejects_non_numeric_exp() {
    isolate_codex_home();
    for claims in [
        r#"{"exp":"1700000000"}"#,
        r#"{"exp":null}"#,
        r#"{"exp":true}"#,
        r#"{"exp":{"seconds":1}}"#,
    ] {
        let err = jwt_exp(&jwt_with_payload(claims)).unwrap_err();
        assert!(
            matches!(&err, Error::JwtInvalid { reason } if reason.contains("not a number")),
            "unexpected error for {claims}: {err}"
        );
    }
}

#[test]
fn jwt_errors_never_leak_the_token_value() {
    isolate_codex_home();
    let secret_material = "SUPERSECRETTOKENMATERIAL";
    let tokens = [
        format!("aGVhZGVy.{secret_material}!!!.c2ln"),
        format!("{secret_material}.{}.c2ln", URL_SAFE_NO_PAD.encode(b"[]")),
        secret_material.to_string(),
    ];
    for raw in tokens {
        let rendered = jwt_exp(&Secret::new(raw)).unwrap_err().to_string();
        assert!(
            !rendered.contains(secret_material),
            "error leaked token material: {rendered}"
        );
    }
}

// ---------------------------------------------------------------
// needs_refresh
// ---------------------------------------------------------------

fn auth_with(access_exp: i64, last_refresh: Option<&str>) -> AuthFile {
    auth_with_access(&fake_jwt_expiring_at(access_exp), last_refresh)
}

/// A document whose access token is `access` verbatim — for the branch
/// where `exp` cannot be read at all.
fn auth_with_access(access: &str, last_refresh: Option<&str>) -> AuthFile {
    let last = match last_refresh {
        Some(value) => format!(r#","last_refresh":"{value}""#),
        None => String::new(),
    };
    parse_auth(&format!(
        r#"{{"tokens":{{"access_token":"{access}","account_id":"acct_test"}}{last}}}"#
    ))
}

#[test]
fn needs_refresh_is_false_exactly_at_the_window_edge() {
    isolate_codex_home();
    let now = Utc::now();
    // exp - now == REFRESH_WINDOW_SECS -> NOT less than the window.
    let auth = auth_with(now.timestamp() + config::REFRESH_WINDOW_SECS, None);
    assert!(!needs_refresh(&auth, now).unwrap());
}

#[test]
fn needs_refresh_is_true_one_second_inside_the_window() {
    isolate_codex_home();
    let now = Utc::now();
    let auth = auth_with(now.timestamp() + config::REFRESH_WINDOW_SECS - 1, None);
    assert!(needs_refresh(&auth, now).unwrap());
}

#[test]
fn needs_refresh_is_true_for_an_expired_token() {
    isolate_codex_home();
    let now = Utc::now();
    let auth = auth_with(now.timestamp() - 1, None);
    assert!(needs_refresh(&auth, now).unwrap());
}

#[test]
fn needs_refresh_does_not_overflow_on_absurd_exp() {
    isolate_codex_home();
    let now = Utc::now();
    let auth = auth_with(i64::MAX, None);
    assert!(!needs_refresh(&auth, now).unwrap());
    let auth = auth_with(i64::MIN, None);
    assert!(needs_refresh(&auth, now).unwrap());
}

#[test]
fn needs_refresh_skips_the_age_rule_when_last_refresh_is_absent() {
    isolate_codex_home();
    let now = Utc::now();
    let auth = auth_with(now.timestamp() + 3600, None);
    assert!(auth.last_refresh.is_none());
    assert!(!needs_refresh(&auth, now).unwrap());
}

#[test]
fn needs_refresh_age_rule_boundaries_when_exp_is_unreadable() {
    isolate_codex_home();
    let now = Utc::now();

    let just_inside = now - chrono::Duration::seconds(config::REFRESH_MAX_AGE_DAYS * SECS_PER_DAY);
    let auth = auth_with_access("not-a-jwt", Some(&models::format_last_refresh(just_inside)));
    assert!(
        !needs_refresh(&auth, now).unwrap(),
        "exactly REFRESH_MAX_AGE_DAYS old is not yet stale"
    );

    let just_outside = just_inside - chrono::Duration::seconds(2);
    let auth = auth_with_access(
        "not-a-jwt",
        Some(&models::format_last_refresh(just_outside)),
    );
    assert!(needs_refresh(&auth, now).unwrap());
}

#[test]
fn needs_refresh_ignores_last_refresh_while_exp_is_readable() {
    // codex's rule (docs/PROTOCOL.md §6) consults `last_refresh` ONLY
    // when it cannot read `exp`. A token that is valid for another hour
    // but has not been used for nine days must not be rotated: that
    // mutates the user's real credentials for no reason, and it is the
    // state that makes concurrent rotation reachable at all.
    isolate_codex_home();
    let now = Utc::now();
    let ancient = models::format_last_refresh(now - chrono::Duration::days(9));
    assert!(!needs_refresh(&auth_with(now.timestamp() + 3600, Some(&ancient)), now).unwrap());
    // The expiry rule still fires, ancient timestamp or not.
    assert!(needs_refresh(&auth_with(now.timestamp() + 10, Some(&ancient)), now).unwrap());
}

#[test]
fn needs_refresh_does_not_brick_every_command_over_an_unparseable_last_refresh() {
    // `needs_refresh` is the first thing every backend command calls.
    // Failing here on a field the decision does not even depend on took
    // `whoami`, `usage`, `models`, `ask` and `image` down together —
    // for a user whose access token was perfectly valid. The first
    // string below is codex's own format minus the UTC offset.
    isolate_codex_home();
    let now = Utc::now();
    for raw in ["2026-08-07T23:32:41.615755", "last tuesday", ""] {
        assert!(
            !needs_refresh(&auth_with(now.timestamp() + 3600, Some(raw)), now).unwrap(),
            "a valid access token was rejected over last_refresh={raw:?}"
        );
    }
}

#[test]
fn needs_refresh_is_loud_when_the_fallback_signal_is_corrupt() {
    // The other side of the rule: in the branch that DOES depend on
    // `last_refresh`, corruption must surface rather than be guessed at.
    isolate_codex_home();
    let now = Utc::now();
    let err = needs_refresh(&auth_with_access("not-a-jwt", Some("last tuesday")), now).unwrap_err();
    assert!(
        matches!(&err, Error::UnexpectedResponse { context } if context.contains("last_refresh")),
        "unexpected error: {err}"
    );
}

#[test]
fn needs_refresh_propagates_jwt_errors_when_there_is_no_other_signal() {
    // Neither a readable expiry nor a timestamp: nothing to decide on,
    // so the decode error is the answer (deliberate divergence from
    // codex, which would treat this as "no refresh needed").
    isolate_codex_home();
    let auth = parse_auth(r#"{"tokens":{"access_token":"not-a-jwt","account_id":"a"}}"#);
    assert!(matches!(
        needs_refresh(&auth, Utc::now()).unwrap_err(),
        Error::JwtInvalid { .. }
    ));
}

#[test]
fn needs_refresh_is_loud_without_an_access_token() {
    isolate_codex_home();
    let auth = parse_auth(r#"{"tokens":{"account_id":"a"}}"#);
    let err = needs_refresh(&auth, Utc::now()).unwrap_err();
    assert!(
        matches!(&err, Error::UnexpectedResponse { context } if context.contains("access_token")),
        "unexpected error: {err}"
    );
}

// ---------------------------------------------------------------
// load_auth
// ---------------------------------------------------------------

#[test]
fn load_auth_reads_a_valid_file_and_keeps_unknown_keys() {
    let dir = TempDir::new("load-ok");
    let raw = auth_json(1_800_000_000);
    fs::write(dir.auth(), &raw).unwrap();

    let auth = load_auth_from(&dir.auth()).unwrap();
    assert_eq!(auth.auth_mode.as_deref(), Some("chatgpt"));
    assert_eq!(refresh_token_of(&auth), "old-refresh-token");
    assert_eq!(
        auth.extra.get("unknown_top_level").unwrap(),
        &serde_json::json!({"nested": [1, 2, 3]})
    );
    // Round-trip is value-identical, unknown keys included.
    let before: Value = serde_json::from_str(&raw).unwrap();
    let after: Value = super::test_document(&auth);
    assert_eq!(before, after);
}

#[test]
fn load_auth_missing_file_is_auth_file_missing() {
    let dir = TempDir::new("load-missing");
    let err = load_auth_from(&dir.auth()).unwrap_err();
    assert!(matches!(err, Error::AuthFileMissing { .. }));
    assert!(err.to_string().contains("codex login"));
}

#[test]
fn load_auth_unreadable_file_is_auth_file_unreadable() {
    let dir = TempDir::new("load-unreadable");
    // A directory where the file should be: readable path, unreadable
    // as a file (EISDIR) — distinct from "missing".
    fs::create_dir(dir.auth()).unwrap();
    assert!(matches!(
        load_auth_from(&dir.auth()).unwrap_err(),
        Error::AuthFileUnreadable { .. }
    ));
}

#[test]
fn load_auth_invalid_json_is_auth_file_invalid() {
    let dir = TempDir::new("load-invalid");
    fs::write(dir.auth(), "{not json").unwrap();
    assert!(matches!(
        load_auth_from(&dir.auth()).unwrap_err(),
        Error::AuthFileInvalid { .. }
    ));
}

#[test]
fn load_auth_missing_or_empty_tokens_is_the_keyring_message() {
    let dir = TempDir::new("load-tokens");
    for document in [
        r#"{"auth_mode":"chatgpt"}"#,
        r#"{"tokens":null}"#,
        r#"{"tokens":{"account_id":"a"}}"#,
        r#"{"tokens":{"access_token":"","account_id":"a"}}"#,
    ] {
        fs::write(dir.auth(), document).unwrap();
        let err = load_auth_from(&dir.auth()).unwrap_err();
        assert!(
            matches!(err, Error::AuthTokensMissing { .. }),
            "unexpected error for {document}: {err}"
        );
        assert!(err.to_string().contains("keyring"));
    }
}

#[test]
fn load_auth_missing_account_id_is_loud() {
    let dir = TempDir::new("load-account");
    for document in [
        r#"{"tokens":{"access_token":"a.b.c"}}"#,
        r#"{"tokens":{"access_token":"a.b.c","account_id":""}}"#,
    ] {
        fs::write(dir.auth(), document).unwrap();
        assert!(
            matches!(
                load_auth_from(&dir.auth()).unwrap_err(),
                Error::AuthAccountIdMissing { .. }
            ),
            "unexpected error for {document}"
        );
    }
}

#[test]
fn load_auth_never_writes() {
    let dir = TempDir::new("load-readonly");
    fs::write(dir.auth(), auth_json(1_800_000_000)).unwrap();
    let before = fs::read(dir.auth()).unwrap();
    let modified = fs::metadata(dir.auth()).unwrap().modified().unwrap();

    load_auth_from(&dir.auth()).unwrap();

    assert_eq!(fs::read(dir.auth()).unwrap(), before);
    assert_eq!(
        fs::metadata(dir.auth()).unwrap().modified().unwrap(),
        modified
    );
    assert_eq!(dir.entries(), vec!["auth.json".to_string()]);
}

// ---------------------------------------------------------------
// persist_atomic
// ---------------------------------------------------------------

#[test]
fn persist_writes_pretty_json_with_trailing_newline_and_keeps_unknown_keys() {
    let dir = TempDir::new("persist-roundtrip");
    let raw = auth_json(1_800_000_000);
    fs::write(dir.auth(), &raw).unwrap();
    let auth = load_auth_from(&dir.auth()).unwrap();

    persist_atomic_to(&auth, &dir.auth()).unwrap();

    let written = fs::read_to_string(dir.auth()).unwrap();
    assert!(written.ends_with("}\n"), "missing trailing newline");
    assert!(written.contains("\n  \"tokens\""), "not pretty-printed");
    let before: Value = serde_json::from_str(&raw).unwrap();
    let after: Value = serde_json::from_str(&written).unwrap();
    assert_eq!(before, after, "unknown keys must round-trip");
}

#[test]
fn persist_result_is_0600_and_backs_up_the_previous_document() {
    let dir = TempDir::new("persist-mode");
    let original = auth_json(1_800_000_000);
    fs::write(dir.auth(), &original).unwrap();
    // Deliberately loosen the original: the rewrite must not inherit it.
    fs::set_permissions(dir.auth(), fs::Permissions::from_mode(0o644)).unwrap();

    let mut auth = load_auth_from(&dir.auth()).unwrap();
    auth.last_refresh = Some("2026-08-08T00:00:00.000001Z".to_string());
    persist_atomic_to(&auth, &dir.auth()).unwrap();

    assert_eq!(mode_of(&dir.auth()), 0o600);
    assert_eq!(mode_of(&dir.join("auth.json.bak")), 0o600);

    let backup: Value =
        serde_json::from_str(&fs::read_to_string(dir.join("auth.json.bak")).unwrap()).unwrap();
    assert_eq!(backup, serde_json::from_str::<Value>(&original).unwrap());

    let current: Value = serde_json::from_str(&fs::read_to_string(dir.auth()).unwrap()).unwrap();
    assert_eq!(current["last_refresh"], "2026-08-08T00:00:00.000001Z");

    assert_eq!(
        dir.entries(),
        vec!["auth.json".to_string(), "auth.json.bak".to_string()]
    );
}

#[test]
fn persist_without_an_existing_file_creates_no_backup() {
    let dir = TempDir::new("persist-fresh");
    let auth = parse_auth(r#"{"tokens":{"access_token":"a.b.c","account_id":"acct"}}"#);

    persist_atomic_to(&auth, &dir.auth()).unwrap();

    assert_eq!(dir.entries(), vec!["auth.json".to_string()]);
    assert_eq!(mode_of(&dir.auth()), 0o600);
}

#[test]
fn persist_failure_to_create_the_temp_leaves_the_original_intact() {
    let dir = TempDir::new("persist-nodir");
    let target = dir.join("missing-subdir").join("auth.json");
    let auth = parse_auth(r#"{"tokens":{"access_token":"a.b.c","account_id":"acct"}}"#);

    let err = persist_atomic_to(&auth, &target).unwrap_err();
    match &err {
        Error::PersistFailed { path, backup, .. } => {
            assert_eq!(path, &target);
            // No backup was taken (there was no previous document to
            // back up), so the error must not name one at all. Naming
            // a path the user could go read, when nothing was written
            // there, is the failure-masking answer.
            assert_eq!(backup, &None);
        }
        other => panic!("unexpected error: {other}"),
    }
    let rendered = err.to_string();
    assert!(rendered.contains("CRITICAL"));
    assert!(!rendered.contains(".bak"), "{rendered}");
    assert!(
        rendered.contains("was not modified and still holds the previous tokens"),
        "the no-backup message must say where the previous tokens are: {rendered}"
    );
    assert!(dir.entries().is_empty());
}

#[test]
fn persist_aborts_when_the_backup_cannot_be_written() {
    let dir = TempDir::new("persist-backup-fail");
    let original = auth_json(1_800_000_000);
    fs::write(dir.auth(), &original).unwrap();
    // A directory at auth.json.bak makes `fs::copy` fail.
    fs::create_dir(dir.join("auth.json.bak")).unwrap();

    let mut auth = load_auth_from(&dir.auth()).unwrap();
    auth.last_refresh = Some("2030-01-01T00:00:00.000000Z".to_string());

    let err = persist_atomic_to(&auth, &dir.auth()).unwrap_err();
    assert!(matches!(err, Error::PersistFailed { .. }), "got {err}");

    // Postcondition: the original document is byte-identical and no
    // temp file survived.
    assert_eq!(fs::read_to_string(dir.auth()).unwrap(), original);
    assert_eq!(
        dir.entries(),
        vec!["auth.json".to_string(), "auth.json.bak".to_string()]
    );
    assert!(dir.entries().iter().all(|name| !name.contains(".tmp.")));
}

#[test]
fn persist_fails_loudly_when_a_stale_temp_file_exists() {
    // O_EXCL: askcodex refuses to overwrite a temp it did not create, and
    // must not delete it either (it may belong to another process).
    let dir = TempDir::new("persist-excl");
    let original = auth_json(1_800_000_000);
    fs::write(dir.auth(), &original).unwrap();
    let stale = dir.join(&format!("auth.json.tmp.{}", std::process::id()));
    fs::write(&stale, "stale").unwrap();

    let auth = load_auth_from(&dir.auth()).unwrap();
    assert!(matches!(
        persist_atomic_to(&auth, &dir.auth()).unwrap_err(),
        Error::PersistFailed { .. }
    ));
    assert_eq!(fs::read_to_string(&stale).unwrap(), "stale");
    assert_eq!(fs::read_to_string(dir.auth()).unwrap(), original);
}

// ---------------------------------------------------------------
// refresh
// ---------------------------------------------------------------

#[test]
fn refresh_without_a_refresh_token_makes_no_request() {
    let dir = TempDir::new("refresh-unavailable");
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.any_request();
        then.status(200).body("{}");
    });

    for document in [
        r#"{"tokens":{"access_token":"a.b.c","account_id":"acct"}}"#,
        r#"{"tokens":{"access_token":"a.b.c","refresh_token":"","account_id":"acct"}}"#,
    ] {
        let mut auth = parse_auth(document);
        let err = refresh_inner(
            &test_agent(),
            &mut auth,
            &server.url("/oauth/token"),
            &dir.auth(),
        )
        .unwrap_err();
        assert!(matches!(err, Error::RefreshUnavailable), "got {err}");
    }
    assert_eq!(mock.calls(), 0);
    assert!(dir.entries().is_empty());
}

#[test]
fn refresh_sends_the_codex_wire_shape_and_no_backend_headers() {
    let dir = TempDir::new("refresh-wire");
    fs::write(dir.auth(), auth_json(1_800_000_000)).unwrap();
    let mut auth = load_auth_from(&dir.auth()).unwrap();

    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(POST)
            .path("/oauth/token")
            .header("content-type", "application/json; charset=utf-8")
            .header("user-agent", config::USER_AGENT)
            .header_missing("authorization")
            .header_missing("chatgpt-account-id")
            .json_body(serde_json::json!({
                "client_id": config::CLIENT_ID,
                "grant_type": "refresh_token",
                "refresh_token": "old-refresh-token",
            }));
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"access_token":"new.access.token"}"#);
    });

    refresh_inner(
        &test_agent(),
        &mut auth,
        &server.url("/oauth/token"),
        &dir.auth(),
    )
    .unwrap();

    mock.assert_calls(1);
}

#[test]
fn refresh_rotates_all_present_fields_and_persists() {
    let dir = TempDir::new("refresh-ok");
    let original = auth_json(1_700_000_000);
    fs::write(dir.auth(), &original).unwrap();
    let mut auth = load_auth_from(&dir.auth()).unwrap();

    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/oauth/token");
        then.status(200).body(
            r#"{"access_token":"new.access.token","id_token":"new.id.token",
                    "refresh_token":"new-refresh-token","expires_in":864000}"#,
        );
    });

    // One second of slack on both sides: `format_last_refresh` truncates
    // to microseconds, so an exact `>=` on the raw clock is fragile.
    let before = Utc::now() - chrono::Duration::seconds(1);
    refresh_inner(
        &test_agent(),
        &mut auth,
        &server.url("/oauth/token"),
        &dir.auth(),
    )
    .unwrap();

    // In memory.
    assert_eq!(access_token_of(&auth), "new.access.token");
    assert_eq!(id_token_of(&auth).as_deref(), Some("new.id.token"));
    assert_eq!(refresh_token_of(&auth), "new-refresh-token");
    let stamp = auth.last_refresh.clone().expect("last_refresh set");
    let parsed = models::parse_last_refresh(&stamp).expect("codex-format timestamp");
    assert_eq!(
        models::format_last_refresh(parsed),
        stamp,
        "byte-exact format"
    );
    assert!(parsed >= before && parsed <= Utc::now() + chrono::Duration::seconds(1));

    // On disk: same document, 0600, backup holds the previous one.
    let written: Value = serde_json::from_str(&fs::read_to_string(dir.auth()).unwrap()).unwrap();
    assert_eq!(written["tokens"]["access_token"], "new.access.token");
    assert_eq!(written["tokens"]["refresh_token"], "new-refresh-token");
    assert_eq!(
        written["unknown_top_level"],
        serde_json::json!({"nested": [1, 2, 3]})
    );
    assert_eq!(written["tokens"]["unknown_token_key"], 7);
    assert_eq!(mode_of(&dir.auth()), 0o600);
    let backup: Value =
        serde_json::from_str(&fs::read_to_string(dir.join("auth.json.bak")).unwrap()).unwrap();
    assert_eq!(backup, serde_json::from_str::<Value>(&original).unwrap());
}

#[test]
fn refresh_keeps_the_old_refresh_token_when_the_response_omits_it() {
    let dir = TempDir::new("refresh-keep-rt");
    fs::write(dir.auth(), auth_json(1_700_000_000)).unwrap();
    let mut auth = load_auth_from(&dir.auth()).unwrap();
    let old_id = id_token_of(&auth).unwrap();

    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/oauth/token");
        // Empty strings must be treated as "not rotated", never as a
        // reason to clear a working credential.
        then.status(200)
            .body(r#"{"access_token":"new.access.token","refresh_token":"","id_token":""}"#);
    });

    refresh_inner(
        &test_agent(),
        &mut auth,
        &server.url("/oauth/token"),
        &dir.auth(),
    )
    .unwrap();

    assert_eq!(refresh_token_of(&auth), "old-refresh-token");
    assert_eq!(id_token_of(&auth), Some(old_id));
    let written: Value = serde_json::from_str(&fs::read_to_string(dir.auth()).unwrap()).unwrap();
    assert_eq!(written["tokens"]["refresh_token"], "old-refresh-token");
}

#[test]
fn refresh_non_200_leaves_memory_and_file_untouched() {
    let dir = TempDir::new("refresh-400");
    let original = auth_json(1_700_000_000);
    fs::write(dir.auth(), &original).unwrap();
    let mut auth = load_auth_from(&dir.auth()).unwrap();
    let before = format!("{auth:?}");

    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/oauth/token");
        then.status(400)
            .body(r#"{"error":"invalid_grant","error_description":"refresh_token_expired"}"#);
    });

    let err = refresh_inner(
        &test_agent(),
        &mut auth,
        &server.url("/oauth/token"),
        &dir.auth(),
    )
    .unwrap_err();

    match &err {
        Error::RefreshFailed { status, snippet } => {
            assert_eq!(*status, 400);
            assert!(snippet.contains("refresh_token_expired"), "got {snippet}");
        }
        other => panic!("unexpected error: {other}"),
    }
    assert_eq!(
        format!("{auth:?}"),
        before,
        "in-memory tokens must not change"
    );
    assert_eq!(fs::read_to_string(dir.auth()).unwrap(), original);
    assert_eq!(dir.entries(), vec!["auth.json".to_string()]);
}

#[test]
fn refresh_non_200_works_on_a_default_agent_too() {
    // The per-request `http_status_as_error(false)` override means a
    // caller-supplied default agent still yields the status + body,
    // not an opaque ureq StatusCode error.
    let dir = TempDir::new("refresh-default-agent");
    fs::write(dir.auth(), auth_json(1_700_000_000)).unwrap();
    let mut auth = load_auth_from(&dir.auth()).unwrap();

    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/oauth/token");
        then.status(403).body("forbidden");
    });

    let err = refresh_inner(
        &ureq::Agent::new_with_defaults(),
        &mut auth,
        &server.url("/oauth/token"),
        &dir.auth(),
    )
    .unwrap_err();
    assert!(
        matches!(&err, Error::RefreshFailed { status: 403, snippet } if snippet == "forbidden"),
        "unexpected error: {err}"
    );
}

#[test]
fn refresh_error_snippet_is_bounded_and_utf8_safe() {
    let dir = TempDir::new("refresh-snippet");
    fs::write(dir.auth(), auth_json(1_700_000_000)).unwrap();
    let mut auth = load_auth_from(&dir.auth()).unwrap();

    // Multibyte characters straddling the truncation point.
    let body = "é".repeat(config::ERROR_SNIPPET_BYTES);
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/oauth/token");
        then.status(500).body(body.clone());
    });

    let err = refresh_inner(
        &test_agent(),
        &mut auth,
        &server.url("/oauth/token"),
        &dir.auth(),
    )
    .unwrap_err();
    match &err {
        Error::RefreshFailed { status, snippet } => {
            assert_eq!(*status, 500);
            assert!(
                snippet.len() <= config::ERROR_SNIPPET_BYTES,
                "{}",
                snippet.len()
            );
            assert!(body.starts_with(snippet.as_str()));
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn refresh_200_without_access_token_reports_key_names_only() {
    let dir = TempDir::new("refresh-nokey");
    let original = auth_json(1_700_000_000);
    fs::write(dir.auth(), &original).unwrap();
    let mut auth = load_auth_from(&dir.auth()).unwrap();

    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/oauth/token");
        then.status(200)
            .body(r#"{"error":"server_error","id_token":"leaked.id.token","expires_in":10}"#);
    });

    let err = refresh_inner(
        &test_agent(),
        &mut auth,
        &server.url("/oauth/token"),
        &dir.auth(),
    )
    .unwrap_err();

    match &err {
        Error::RefreshInvalidResponse { keys } => {
            assert_eq!(keys, &["error", "expires_in", "id_token"]);
        }
        other => panic!("unexpected error: {other}"),
    }
    // Key NAMES only: no value from the 200 body may be rendered.
    let rendered = err.to_string();
    assert!(!rendered.contains("leaked.id.token"), "{rendered}");
    assert!(!rendered.contains("server_error"), "{rendered}");
    assert_eq!(fs::read_to_string(dir.auth()).unwrap(), original);
}

#[test]
fn refresh_200_with_empty_access_token_is_rejected() {
    let dir = TempDir::new("refresh-empty");
    fs::write(dir.auth(), auth_json(1_700_000_000)).unwrap();
    let mut auth = load_auth_from(&dir.auth()).unwrap();

    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/oauth/token");
        then.status(200).body(r#"{"access_token":""}"#);
    });

    assert!(matches!(
        refresh_inner(
            &test_agent(),
            &mut auth,
            &server.url("/oauth/token"),
            &dir.auth()
        )
        .unwrap_err(),
        Error::RefreshInvalidResponse { .. }
    ));
    assert_eq!(access_token_of(&auth), fake_jwt_expiring_at(1_700_000_000));
}

#[test]
fn refresh_200_with_a_non_json_body_never_quotes_it() {
    let dir = TempDir::new("refresh-nonjson");
    fs::write(dir.auth(), auth_json(1_700_000_000)).unwrap();
    let mut auth = load_auth_from(&dir.auth()).unwrap();

    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/oauth/token");
        then.status(200).body("access_token=live-token-material");
    });

    let err = refresh_inner(
        &test_agent(),
        &mut auth,
        &server.url("/oauth/token"),
        &dir.auth(),
    )
    .unwrap_err();
    let rendered = err.to_string();
    assert!(
        matches!(err, Error::UnexpectedResponse { .. }),
        "{rendered}"
    );
    assert!(!rendered.contains("live-token-material"), "{rendered}");
}

#[test]
fn refresh_200_with_a_json_array_body_is_loud() {
    let dir = TempDir::new("refresh-array");
    fs::write(dir.auth(), auth_json(1_700_000_000)).unwrap();
    let mut auth = load_auth_from(&dir.auth()).unwrap();

    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/oauth/token");
        then.status(200).body(r#"["nope"]"#);
    });

    assert!(matches!(
        refresh_inner(
            &test_agent(),
            &mut auth,
            &server.url("/oauth/token"),
            &dir.auth()
        )
        .unwrap_err(),
        Error::UnexpectedResponse { .. }
    ));
}

#[test]
fn refresh_propagates_persist_failure_after_rotation() {
    let dir = TempDir::new("refresh-persist-fail");
    let original = auth_json(1_700_000_000);
    fs::write(dir.auth(), &original).unwrap();
    let mut auth = load_auth_from(&dir.auth()).unwrap();
    // A leftover temp file from an earlier run of THIS process: the
    // persist gets as far as the backup and then trips O_EXCL. (An
    // unwritable directory would now abort before the token is sent —
    // the lock cannot be taken there — which is the better outcome but
    // not the state this test is about.)
    let stale = dir.join(&format!("auth.json.tmp.{}", std::process::id()));
    fs::write(&stale, "stale").unwrap();

    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/oauth/token");
        then.status(200)
            .body(r#"{"access_token":"new.access.token","refresh_token":"new-refresh-token"}"#);
    });

    let err = refresh_inner(
        &test_agent(),
        &mut auth,
        &server.url("/oauth/token"),
        &dir.auth(),
    )
    .unwrap_err();

    assert!(matches!(err, Error::PersistFailed { .. }), "got {err}");
    let rendered = err.to_string();
    assert!(rendered.contains("CRITICAL"));
    assert!(!rendered.contains("new-refresh-token"), "{rendered}");
    // The rotation DID happen in memory; the caller must not retry.
    assert_eq!(access_token_of(&auth), "new.access.token");

    // The backup the message points at is not a claim: it exists, and
    // it holds the document that was on disk when this call started —
    // not a leftover from some earlier refresh.
    let Error::PersistFailed {
        backup: Some(backup),
        ..
    } = &err
    else {
        panic!("a backup was written, so the error must name it: {err}")
    };
    assert_eq!(backup, &dir.join("auth.json.bak"));
    assert!(rendered.contains("auth.json.bak"));
    assert!(backup.exists(), "the named backup does not exist");
    assert_eq!(fs::read_to_string(backup).unwrap(), original);
    assert_eq!(mode_of(backup), 0o600);
}

// ---------------------------------------------------------------
// The credential lock (cross-process rotation safety)
// ---------------------------------------------------------------

/// The document a mock rotation hands back, with a far-future expiry so
/// that a process adopting it can see that it is fresh.
fn rotated_body(refresh: &str) -> String {
    format!(
        r#"{{"access_token":"{}","refresh_token":"{refresh}"}}"#,
        fake_jwt_expiring_at(4_102_444_800)
    )
}

#[test]
fn a_concurrent_rotation_is_adopted_instead_of_spending_the_stale_token() {
    // THE lost-update case. Two askcodex processes load the same document,
    // both decide a refresh is due. The first rotates GEN1 -> GEN2 and
    // persists. The second still holds GEN1 in memory: without the lock
    // and the re-read it POSTs GEN1 a second time (the identical token
    // the server has just retired — PROTOCOL.md §6 calls that reuse a
    // permanent, re-login-only failure) and then writes ITS snapshot
    // over the file, so whichever process finishes last decides which
    // generation survives.
    let dir = TempDir::new("refresh-concurrent");
    fs::write(dir.auth(), auth_json(1_700_000_000)).unwrap();
    let mut first = load_auth_from(&dir.auth()).unwrap();
    let mut second = load_auth_from(&dir.auth()).unwrap();
    assert_eq!(refresh_token_of(&second), "old-refresh-token");

    let server = MockServer::start();
    // Matching on the token proves WHICH generation was sent.
    let gen1 = server.mock(|when, then| {
        when.method(POST)
            .path("/oauth/token")
            .json_body(serde_json::json!({
                "client_id": config::CLIENT_ID,
                "grant_type": "refresh_token",
                "refresh_token": "old-refresh-token",
            }));
        then.status(200).body(rotated_body("refresh-GEN2"));
    });

    refresh_inner(
        &test_agent(),
        &mut first,
        &server.url("/oauth/token"),
        &dir.auth(),
    )
    .unwrap();
    gen1.assert_calls(1);

    // The second process, still a generation behind, now refreshes.
    refresh_inner(
        &test_agent(),
        &mut second,
        &server.url("/oauth/token"),
        &dir.auth(),
    )
    .unwrap();

    gen1.assert_calls(1);
    assert_eq!(
        refresh_token_of(&second),
        "refresh-GEN2",
        "the lagging process kept its own spent generation"
    );
    let written: Value = serde_json::from_str(&fs::read_to_string(dir.auth()).unwrap()).unwrap();
    assert_eq!(
        written["tokens"]["refresh_token"], "refresh-GEN2",
        "auth.json was overwritten with a retired generation"
    );
    // And nothing was left lying around.
    assert_eq!(
        dir.entries(),
        vec!["auth.json".to_string(), "auth.json.bak".to_string()]
    );
}

#[test]
fn a_refresh_blocked_by_another_process_never_sends_the_token() {
    let dir = TempDir::new("refresh-locked-out");
    let original = auth_json(1_700_000_000);
    fs::write(dir.auth(), &original).unwrap();
    let mut auth = load_auth_from(&dir.auth()).unwrap();

    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.any_request();
        then.status(200).body(rotated_body("nope"));
    });

    // A lock held by some other, live process.
    let lock = dir.join("auth.json.lock");
    fs::write(&lock, "999999\n").unwrap();
    let _held = AuthLock::acquire(&dir.auth(), Duration::ZERO).unwrap();
    fs::File::options()
        .write(true)
        .open(&lock)
        .unwrap()
        .set_modified(SystemTime::now() - Duration::from_secs(24 * 60 * 60))
        .unwrap();

    let err = refresh_locked(
        &test_agent(),
        &mut auth,
        &server.url("/oauth/token"),
        &dir.auth(),
        Duration::from_millis(80),
    )
    .unwrap_err();

    match &err {
        Error::AuthLockUnavailable { path, .. } => assert_eq!(path, &lock),
        other => panic!("unexpected error: {other}"),
    }
    // Loud, actionable, and nothing was spent or touched.
    let rendered = err.to_string();
    assert!(rendered.contains("auth.json.lock"), "{rendered}");
    assert!(rendered.contains("lock"), "{rendered}");
    assert_eq!(mock.calls(), 0);
    assert_eq!(fs::read_to_string(dir.auth()).unwrap(), original);
    assert_eq!(
        fs::read_to_string(&lock).unwrap(),
        "999999\n",
        "askcodex deleted a lock it did not own"
    );
}

#[test]
fn a_lock_left_by_a_crashed_process_is_reclaimed_and_released() {
    // A stale lock must never make askcodex permanently unusable.
    let dir = TempDir::new("refresh-stale-lock");
    fs::write(dir.auth(), auth_json(1_700_000_000)).unwrap();
    let mut auth = load_auth_from(&dir.auth()).unwrap();

    let lock = dir.join("auth.json.lock");
    fs::write(&lock, "999999\n").unwrap();
    fs::File::options()
        .write(true)
        .open(&lock)
        .unwrap()
        .set_modified(SystemTime::now() - Duration::from_secs(24 * 60 * 60))
        .unwrap();

    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(POST).path("/oauth/token");
        then.status(200).body(rotated_body("refresh-after-crash"));
    });

    refresh_locked(
        &test_agent(),
        &mut auth,
        &server.url("/oauth/token"),
        &dir.auth(),
        Duration::from_millis(80),
    )
    .unwrap();

    mock.assert_calls(1);
    assert_eq!(refresh_token_of(&auth), "refresh-after-crash");
    // Ownership is released on return; the lock inode remains reusable.
    assert!(lock.is_file());
    let _reacquired = AuthLock::acquire(&dir.auth(), Duration::ZERO).unwrap();
    assert_eq!(
        dir.entries(),
        vec!["auth.json".to_string(), "auth.json.bak".to_string()]
    );
}

#[test]
fn the_lock_is_released_even_when_the_refresh_fails() {
    let dir = TempDir::new("refresh-lock-release");
    fs::write(dir.auth(), auth_json(1_700_000_000)).unwrap();
    let mut auth = load_auth_from(&dir.auth()).unwrap();

    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/oauth/token");
        then.status(400).body("nope");
    });

    refresh_inner(
        &test_agent(),
        &mut auth,
        &server.url("/oauth/token"),
        &dir.auth(),
    )
    .unwrap_err();

    assert_eq!(dir.entries(), vec!["auth.json".to_string()]);
    let _reacquired = AuthLock::acquire(&dir.auth(), Duration::ZERO).unwrap();
}

// ---------------------------------------------------------------
// Backup and symlink handling
// ---------------------------------------------------------------

#[test]
fn the_backup_is_a_new_0600_file_never_a_looser_one_rewritten_in_place() {
    // `fs::copy` onto an existing backup keeps that file's inode AND
    // its mode until a following chmod — the chmod-after-write window
    // this module forbids for the temp file, on a file holding the
    // very same credentials. The backup must therefore be a file
    // created 0600, not a rewritten one.
    let dir = TempDir::new("persist-backup-mode");
    fs::write(dir.auth(), auth_json(1_800_000_000)).unwrap();
    fs::set_permissions(dir.auth(), fs::Permissions::from_mode(0o644)).unwrap();
    let backup = dir.join("auth.json.bak");
    fs::write(&backup, "previous backup").unwrap();
    fs::set_permissions(&backup, fs::Permissions::from_mode(0o644)).unwrap();
    let before = inode_of(&backup);

    let auth = load_auth_from(&dir.auth()).unwrap();
    persist_atomic_to(&auth, &dir.auth()).unwrap();

    assert_ne!(
        inode_of(&backup),
        before,
        "the backup was rewritten in place, so it existed with the source's mode"
    );
    assert_eq!(mode_of(&backup), 0o600);
}

#[test]
fn a_symlinked_auth_json_keeps_pointing_at_the_users_real_file() {
    // rename(2) replaces the LINK, so the user's canonical store would
    // silently stop receiving updates and freeze at a dead generation.
    let dir = TempDir::new("persist-symlink");
    let store = dir.join("real-store");
    fs::create_dir(&store).unwrap();
    let real = store.join("codex-auth.json");
    fs::write(&real, auth_json(1_800_000_000)).unwrap();
    std::os::unix::fs::symlink(&real, dir.auth()).unwrap();

    let mut auth = load_auth_from(&dir.auth()).unwrap();
    auth.last_refresh = Some("2030-01-01T00:00:00.000000Z".to_string());
    persist_atomic_to(&auth, &dir.auth()).unwrap();

    assert!(
        fs::symlink_metadata(dir.auth())
            .unwrap()
            .file_type()
            .is_symlink(),
        "askcodex replaced the symlink with a regular file"
    );
    let written: Value = serde_json::from_str(&fs::read_to_string(&real).unwrap()).unwrap();
    assert_eq!(written["last_refresh"], "2030-01-01T00:00:00.000000Z");
    assert_eq!(mode_of(&real), 0o600);
    // Backup and temp live beside the REAL file (same filesystem as the
    // rename target), not beside the link.
    assert!(store.join("codex-auth.json.bak").exists());
    assert_eq!(
        dir.entries(),
        vec!["auth.json".to_string(), "real-store".to_string()]
    );
}

#[test]
fn a_dangling_symlink_is_loud_and_creates_nothing() {
    let dir = TempDir::new("persist-dangling");
    std::os::unix::fs::symlink(dir.join("nowhere.json"), dir.auth()).unwrap();
    let auth = parse_auth(r#"{"tokens":{"access_token":"a.b.c","account_id":"acct"}}"#);

    assert!(matches!(
        persist_atomic_to(&auth, &dir.auth()).unwrap_err(),
        Error::PersistFailed { .. }
    ));
    assert_eq!(dir.entries(), vec!["auth.json".to_string()]);
}

// ---------------------------------------------------------------
// Refresh-error snippets carry no credential
// ---------------------------------------------------------------

#[test]
fn a_refresh_error_body_that_echoes_a_token_is_scrubbed_before_it_is_quoted() {
    // The OAuth error body is a string from a third party that nobody
    // in this project has ever observed, and PROTOCOL.md §6 documents a
    // `refresh_token_reused` failure — so a body that names the token
    // is exactly the shape that cannot be ruled out. The guarantee has
    // to hold on code, not on an assumption about someone else's
    // server.
    let dir = TempDir::new("refresh-scrub");
    fs::write(dir.auth(), auth_json(1_700_000_000)).unwrap();
    let mut auth = load_auth_from(&dir.auth()).unwrap();
    let access = access_token_of(&auth);
    let id = id_token_of(&auth).unwrap();

    let server = MockServer::start();
    server.mock(|when, then| {
            when.method(POST).path("/oauth/token");
            then.status(400).body(format!(
                r#"{{"error":"invalid_grant","error_description":"refresh_token old-refresh-token was reused","seen":["{access}","{id}"]}}"#
            ));
        });

    let err = refresh_inner(
        &test_agent(),
        &mut auth,
        &server.url("/oauth/token"),
        &dir.auth(),
    )
    .unwrap_err();

    let rendered = err.to_string();
    assert!(matches!(err, Error::RefreshFailed { status: 400, .. }));
    for (name, secret) in [
        ("refresh_token", "old-refresh-token"),
        ("access_token", access.as_str()),
        ("id_token", id.as_str()),
    ] {
        assert!(
            !rendered.contains(secret),
            "the {name} value reached an error message: {rendered}"
        );
    }
    assert!(rendered.contains("REDACTED"), "{rendered}");
    // Still a useful diagnostic: only the values are gone.
    assert!(rendered.contains("invalid_grant"), "{rendered}");
    assert!(rendered.contains("was reused"), "{rendered}");
}

#[test]
fn a_token_straddling_the_snippet_cut_is_scrubbed_rather_than_truncated() {
    // Scrubbing AFTER truncation would leave the head of a token that
    // begins just before the cut. Position one there deliberately.
    let dir = TempDir::new("refresh-scrub-edge");
    fs::write(dir.auth(), auth_json(1_700_000_000)).unwrap();
    let mut auth = load_auth_from(&dir.auth()).unwrap();

    let mut body = String::from(r#"{"error":"invalid_grant","d":""#);
    while body.len() < config::ERROR_SNIPPET_BYTES - 8 {
        body.push('x');
    }
    body.push_str("old-refresh-token");
    body.push_str(r#""}"#);

    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/oauth/token");
        then.status(400).body(body);
    });

    let err = refresh_inner(
        &test_agent(),
        &mut auth,
        &server.url("/oauth/token"),
        &dir.auth(),
    )
    .unwrap_err();

    let Error::RefreshFailed { snippet, .. } = &err else {
        panic!("unexpected error: {err}")
    };
    assert!(
        !snippet.contains("old-refr"),
        "the first bytes of the refresh token survived the cut: {snippet}"
    );
    assert!(snippet.contains("REDACTED"), "{snippet}");
    assert!(
        snippet.len() <= config::ERROR_SNIPPET_BYTES,
        "{}",
        snippet.len()
    );
}

#[test]
fn a_lock_symlink_is_refused_without_touching_its_target() {
    let dir = TempDir::new("lock-symlink");
    let target = dir.join("sentinel");
    fs::write(&target, b"unchanged").unwrap();
    std::os::unix::fs::symlink(&target, dir.join("auth.json.lock")).unwrap();
    assert!(matches!(
        AuthLock::acquire(&dir.auth(), Duration::ZERO),
        Err(Error::AuthLockUnavailable { .. })
    ));
    assert_eq!(fs::read(&target).unwrap(), b"unchanged");
}

#[test]
#[ignore = "subprocess helper invoked only by lock_release_on_process_death"]
fn lock_child_helper() {
    use std::io::Write;
    let path =
        std::env::var_os("ASKCODEX_TEST_LOCK_PATH").expect("parent supplies isolated fixture");
    let path = PathBuf::from(path);
    assert!(path.starts_with(std::env::temp_dir()));
    let _guard = AuthLock::acquire(&path, Duration::ZERO).unwrap();
    println!("LOCKED");
    std::io::stdout().flush().unwrap();
    loop {
        std::thread::sleep(Duration::from_secs(1));
    }
}

#[test]
fn lock_release_on_process_death() {
    use std::io::{BufRead, BufReader};
    use std::process::{Child, Command, Stdio};
    struct ChildGuard(Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let dir = TempDir::new("lock-process-death");
    let mut child = ChildGuard(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "auth::tests::lock_child_helper",
                "--ignored",
                "--nocapture",
            ])
            .env("ASKCODEX_TEST_LOCK_PATH", dir.auth())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let mut reader = BufReader::new(child.0.stdout.take().unwrap());
    let mut line = String::new();
    loop {
        assert_ne!(
            reader.read_line(&mut line).unwrap(),
            0,
            "child exited before acquiring lock"
        );
        if line.trim() == "LOCKED" {
            break;
        }
        line.clear();
    }
    assert!(matches!(
        AuthLock::acquire(&dir.auth(), Duration::ZERO),
        Err(Error::AuthLockUnavailable { .. })
    ));
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    let _guard = AuthLock::acquire(&dir.auth(), Duration::ZERO).unwrap();
    assert_eq!(mode_of(&dir.join("auth.json.lock")), 0o600);
}

#[test]
fn credential_debug_never_exposes_unknown_fields_or_identifiers() {
    let auth: AuthFile = serde_json::from_value(serde_json::json!({
        "auth_mode":"fixture-private-mode",
        "last_refresh":"fixture-private-timestamp",
        "unknown":"fixture-private-top",
        "tokens":{"access_token":"fixture-private-access",
        "account_id":"fixture-private-account",
        "future":{"value":"fixture-private-nested"}}
    }))
    .unwrap();
    assert!(!format!("{auth:?}").contains("fixture-private"));
    assert!(!format!("{:?}", auth.tokens).contains("fixture-private"));
}

#[test]
fn malformed_credential_errors_never_echo_document_values() {
    use std::error::Error as _;
    let dir = TempDir::new("parse-redaction");
    for malformed in [
        r#""fixture-private-root""#,
        r#"{"tokens":"fixture-private-token-object"}"#,
    ] {
        fs::write(dir.auth(), malformed).unwrap();
        let error = load_auth_from(&dir.auth()).unwrap_err();
        assert!(matches!(error, Error::AuthFileInvalid { .. }));
        assert!(!format!("{error}").contains("fixture-private"));
        assert!(!format!("{error:?}").contains("fixture-private"));
        assert!(
            !error
                .source()
                .unwrap()
                .to_string()
                .contains("fixture-private")
        );
        assert!(error.to_string().contains("line"));
    }
}

#[test]
fn oauth_redirects_never_reach_another_server_or_replace_credentials() {
    for status in [301, 302, 303, 307, 308] {
        let dir = TempDir::new("oauth-redirect");
        let original = auth_json(1_700_000_000);
        fs::write(dir.auth(), &original).unwrap();
        let mut document = load_auth_from(&dir.auth()).unwrap();
        let before = super::test_document(&document);
        let destination = MockServer::start();
        let poisoned = destination.mock(|when, then| {
            when.any_request();
            then.status(200).body(rotated_body("fake-redirected-token"));
        });
        let origin = MockServer::start();
        let redirect = origin.mock(|when, then| {
            when.method(POST).path("/oauth/token");
            then.status(status)
                .header("Location", destination.url("/redirected"));
        });
        // A default agent follows redirects unless this OAuth request overrides it.
        let result = refresh_inner(
            &ureq::Agent::new_with_defaults(),
            &mut document,
            &origin.url("/oauth/token"),
            &dir.auth(),
        );
        assert!(matches!(result,Err(Error::RefreshFailed{status:actual,..}) if actual==status));
        assert_eq!(redirect.calls(), 1);
        assert_eq!(
            poisoned.calls(),
            0,
            "redirect destination received a request"
        );
        assert_eq!(super::test_document(&document), before);
        assert_eq!(fs::read_to_string(dir.auth()).unwrap(), original);
    }
}

#[test]
fn constructing_client_does_not_reload_the_session_store() {
    let dir = TempDir::new("session-single-load");
    fs::write(dir.auth(), auth_json(4_102_444_800)).unwrap();
    let session = AuthSession::load(CredentialStore::from_path(dir.auth())).unwrap();
    assert_eq!(session.path(), dir.auth());
    let expected = super::test_document(session.document());
    fs::remove_file(dir.auth()).unwrap();
    let client = crate::http::Client::from_session(session, true).unwrap();
    assert_eq!(super::test_document(client.auth()), expected);
    assert!(!dir.auth().exists());
}

#[test]
fn explicit_session_refresh_uses_its_original_store_path() {
    let dir = TempDir::new("session-explicit-store");
    fs::write(dir.auth(), auth_json(1_700_000_000)).unwrap();
    let untouched = dir.join("other-auth.json");
    fs::write(&untouched, b"unrelated-store").unwrap();
    let mut session = AuthSession::load(CredentialStore::from_path(dir.auth())).unwrap();
    let server = MockServer::start();
    let refresh = server.mock(|when, then| {
        when.method(POST).path("/oauth/token");
        then.status(200).body(rotated_body("session-owned-refresh"));
    });
    session
        .refresh_with_endpoint(&test_agent(), &server.url("/oauth/token"))
        .unwrap();
    assert_eq!(refresh.calls(), 1);
    assert_eq!(
        super::test_document(session.document())["tokens"]["refresh_token"],
        "session-owned-refresh"
    );
    assert_eq!(fs::read(&untouched).unwrap(), b"unrelated-store");
    assert_eq!(
        super::test_document(session.document()),
        serde_json::from_slice::<Value>(&fs::read(dir.auth()).unwrap()).unwrap()
    );
}
