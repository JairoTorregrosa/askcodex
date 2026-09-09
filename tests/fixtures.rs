//! The sanitization and provenance gates on `docs/samples/` and `docs/captures/`.
//!
//! These directories contain redacted captures and explicitly adapted fixtures, and
//! they are published. Everything that identifies the account is supposed
//! to be replaced by the project's placeholders before the fixture is
//! committed — and until this file existed, "supposed to" was the whole
//! mechanism. `docs/TESTING.md` claimed the rendering tests enforced it;
//! an adversarial review disproved that by rewriting the placeholders in
//! `usage.json` and watching the suite stay green. Exactly one fixture's
//! placeholders were pinned, by one assertion, as a side effect of testing
//! something else.
//!
//! So this is the gate the documentation described. It reads the directory
//! at run time rather than naming files, because the fixture most likely to
//! carry an unredacted identifier is the one somebody adds next.
//!
//! It cannot prove a value is fake — only that nothing in these files has
//! the SHAPE of a live identifier. That is worth stating plainly: this
//! catches the accident (a capture committed as captured), not a
//! determined author.

use std::path::{Path, PathBuf};

/// The placeholders the project declares, in `GOVERNANCE.md`, `AGENTS.md`
/// and the pull-request template. A fixture may contain these and nothing
/// else that looks like an identifier.
const PLACEHOLDERS: &[&str] = &[
    "acct_REDACTED",
    "user_REDACTED",
    "email_REDACTED",
    "org_REDACTED",
    "resp_REDACTED",
    "msg_REDACTED",
    "session_REDACTED",
    "uuid_REDACTED",
];

fn samples_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/samples")
}

fn fixtures() -> Vec<(String, String)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs");
    let mut out: Vec<(String, String)> = ["samples", "captures"]
        .into_iter()
        .flat_map(|name| {
            std::fs::read_dir(dir.join(name)).unwrap_or_else(|e| panic!("read {name}: {e}"))
        })
        .map(|entry| entry.expect("dir entry").path())
        .filter(|path| path.is_file())
        .map(|path| {
            let name = path
                .strip_prefix(&dir)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            let body = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            (name, body)
        })
        .collect();
    out.sort();
    assert!(
        !out.is_empty(),
        "no fixtures found in {} — this gate would pass vacuously",
        dir.display()
    );
    out
}

/// Every run of `pattern` over `body` that is not a declared placeholder.
///
/// Matches are returned so the failure can name what it found. That is
/// safe precisely because anything reaching this point is, by hypothesis,
/// something that should not have been committed — and it is already in
/// the file the developer is looking at.
fn offenders(body: &str, pattern: impl Fn(&str) -> Vec<String>) -> Vec<String> {
    let mut hits: Vec<String> = pattern(body)
        .into_iter()
        .filter(|hit| !PLACEHOLDERS.iter().any(|p| hit == p))
        .collect();
    hits.sort();
    hits.dedup();
    hits
}

/// Every `prefix`-led identifier, for the `acct_`/`user_`/`org_` family.
/// Both separators: `auth.json` writes `acct_...` and the `/me` projection
/// returns `user-...`, and a scan that knew only the underscore form is
/// how a real identifier survived one earlier review.
fn prefixed(body: &str, prefix: &str) -> Vec<String> {
    let mut out = Vec::new();
    for sep in ['_', '-'] {
        let needle = format!("{prefix}{sep}");
        let mut rest = body;
        while let Some(at) = rest.find(&needle) {
            let tail = &rest[at + needle.len()..];
            let end = tail
                .find(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '-')
                .unwrap_or(tail.len());
            if end >= 4 {
                out.push(format!("{needle}{}", &tail[..end]));
            }
            rest = &rest[at + needle.len()..];
        }
    }
    out
}

fn emails(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    for token in body.split(|c: char| c.is_whitespace() || c == '"' || c == ',') {
        let token = token.trim_matches(|c: char| !c.is_ascii_alphanumeric());
        let Some((local, domain)) = token.split_once('@') else {
            continue;
        };
        // A domain has a dot and a non-numeric last label; `askcodex@0.1.0` and
        // `actions/checkout@v4.2.2` do not qualify, and neither is an
        // address.
        let Some((_, tld)) = domain.rsplit_once('.') else {
            continue;
        };
        if local.is_empty() || tld.is_empty() || tld.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        out.push(token.to_string());
    }
    out
}

/// Anything shaped `8-4-4-4-12` hex. `responses-sse.txt` carries a
/// `prompt_cache_key`, which is a session UUID: not a secret, but it is
/// stable per session and correlates a published transcript back to the
/// account that produced it.
fn uuids(body: &str) -> Vec<String> {
    const GROUPS: [usize; 5] = [8, 4, 4, 4, 12];
    body.split(|c: char| !(c.is_ascii_hexdigit() || c == '-'))
        .filter(|token| {
            let parts: Vec<&str> = token.split('-').collect();
            parts.len() == GROUPS.len()
                && parts
                    .iter()
                    .zip(GROUPS)
                    .all(|(part, want)| part.len() == want && !part.is_empty())
        })
        .map(str::to_string)
        .collect()
}

/// An OpenAI API key: `sk-` at a token boundary followed by a long run.
/// askcodex never reads one, so this can only fire on an accident — but a
/// leaked key is a live credential regardless of which tool dropped it.
///
/// The length floor is what separates a key from prose: `sk-` is also the
/// start of `sk-learn`, and a check that flags every `sk-` gets muted by
/// the first false positive and then protects nothing.
fn api_keys(body: &str) -> Vec<String> {
    body.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
        .filter(|token| token.starts_with("sk-") && token.len() >= 24)
        .map(str::to_string)
        .collect()
}

/// Three dot-separated base64url runs beginning `eyJ` — a JWT, i.e. an
/// access or id token.
fn jwts(body: &str) -> Vec<String> {
    body.split(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-'))
        .filter(|token| token.starts_with("eyJ") && token.split('.').count() == 3)
        .filter(|token| token.split('.').all(|segment| segment.len() >= 8))
        .map(str::to_string)
        .collect()
}

#[test]
fn no_fixture_carries_an_account_or_user_identifier() {
    for (name, body) in fixtures() {
        for prefix in ["acct", "user", "org", "resp", "msg", "session"] {
            let hits = offenders(&body, |body| prefixed(body, prefix));
            assert!(
                hits.is_empty(),
                "docs/{name} carries unredacted {prefix} identifier(s): {hits:?}\n\
                 Replace each with the declared placeholder ({prefix}_REDACTED). These \
                 files are published; a captured id belongs to a real account."
            );
        }
    }
}

#[test]
fn no_fixture_carries_a_session_uuid() {
    for (name, body) in fixtures() {
        let hits = offenders(&body, uuids);
        assert!(
            hits.is_empty(),
            "docs/{name} carries UUID(s): {hits:?}\n\
             Replace each with uuid_REDACTED. A session key ties a published \
             transcript to the account that produced it."
        );
    }
}

#[test]
fn no_fixture_carries_an_email_address() {
    for (name, body) in fixtures() {
        let hits = offenders(&body, emails);
        assert!(
            hits.is_empty(),
            "docs/{name} carries an email address: {hits:?}\n\
             Replace it with email_REDACTED."
        );
    }
}

#[test]
fn no_fixture_carries_a_token() {
    for (name, body) in fixtures() {
        let hits = offenders(&body, jwts);
        assert!(
            hits.is_empty(),
            "docs/{name} contains a JWT-shaped string in {} place(s).\n\
             A token must never be committed. If one was, it is not enough to \
             delete it: rotate the credential with `codex login`, because the \
             value is already in git history.",
            hits.len()
        );
        let hits = offenders(&body, api_keys);
        assert!(
            hits.is_empty(),
            "docs/{name} contains {} API-key-shaped string(s).\n\
             askcodex never reads an API key, so one here can only have arrived by \
             accident — but it is still a live credential. Revoke it at \
             https://platform.openai.com/api-keys before removing it.",
            hits.len()
        );
    }
}

#[test]
fn no_fixture_carries_an_absolute_home_path() {
    // A path under someone's home directory tells a reader about the
    // maintainer's filesystem and cites evidence nobody else can open.
    // One fixture shipped a reference to a private notes file before this
    // gate existed.
    for (name, body) in fixtures() {
        for needle in ["/Users/", "/home/"] {
            assert!(
                !body.contains(needle),
                "docs/{name} contains an absolute path under {needle}. \
                 Describe the evidence instead of pointing at a file only its \
                 author can open."
            );
        }
    }
}

#[test]
fn the_gate_would_actually_fail() {
    // A sanitization check that cannot go red is worse than none, because
    // it is read as proof. Each pattern is run against a fabricated
    // offender to show it bites. None of these values is real.
    assert_eq!(
        offenders(r#"{"account_id": "acct_9fKQ2mZzExample"}"#, |b| prefixed(
            b, "acct"
        )),
        vec!["acct_9fKQ2mZzExample".to_string()]
    );
    assert_eq!(
        offenders(r#"{"user_id": "user-s1JykExampleValue"}"#, |b| prefixed(
            b, "user"
        )),
        vec!["user-s1JykExampleValue".to_string()],
        "the `user-` spelling must be caught, not only `user_`"
    );
    assert_eq!(
        offenders(r#"{"email": "someone@example.test"}"#, emails),
        vec!["someone@example.test".to_string()]
    );
    assert_eq!(
        offenders("eyJhbGciOiJub25l.eyJzdWIiOiJmYWtl.c2lnbmF0dXJl", jwts).len(),
        1
    );
    assert_eq!(
        offenders(
            r#"{"prompt_cache_key": "0f8fad5b-d9cb-469f-a165-70867728950e"}"#,
            uuids
        ),
        vec!["0f8fad5b-d9cb-469f-a165-70867728950e".to_string()]
    );
    // Both spellings. The plain `sk-` form is the one an earlier version of
    // this check missed: it required `sk-proj` AND `sk-` together, which
    // no plain key satisfies.
    assert_eq!(
        offenders(
            "Authorization: Bearer sk-NotARealKeyJustTheShape00",
            api_keys
        ),
        vec!["sk-NotARealKeyJustTheShape00".to_string()]
    );
    assert_eq!(
        offenders("sk-proj-NotARealKeyJustTheShape00", api_keys),
        vec!["sk-proj-NotARealKeyJustTheShape00".to_string()]
    );

    // And the mirror image: the declared placeholders, and the version-pin
    // idioms that are not addresses, must pass.
    for clean in [
        r#"{"account_id": "acct_REDACTED", "user_id": "user_REDACTED"}"#,
        r#"{"email": "email_REDACTED"}"#,
        r#"{"pinned": "actions/checkout@v4.2.2", "crate": "askcodex@0.1.0"}"#,
        r#"{"prompt_cache_key": "uuid_REDACTED", "sha": "11d5960a326750d5838078e36cf38b85af677262"}"#,
        "installed scikit-learn; the sk- prefix alone is not a key",
    ] {
        assert!(
            offenders(clean, |b| prefixed(b, "acct")).is_empty(),
            "{clean}"
        );
        assert!(
            offenders(clean, |b| prefixed(b, "user")).is_empty(),
            "{clean}"
        );
        assert!(offenders(clean, emails).is_empty(), "{clean}");
        assert!(offenders(clean, jwts).is_empty(), "{clean}");
        assert!(offenders(clean, uuids).is_empty(), "{clean}");
        assert!(offenders(clean, api_keys).is_empty(), "{clean}");
    }
}

fn capture_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/captures/responses-sse-2026-08-07.txt")
}

#[test]
fn original_redacted_capture_is_the_unchanged_historical_blob() {
    let output = std::process::Command::new("git")
        .args(["hash-object", "--no-filters", "--"])
        .arg(capture_path())
        .output()
        .expect("Git is required for repository provenance verification");
    assert!(
        output.status.success(),
        "cannot fingerprint historical capture"
    );
    assert_eq!(
        std::str::from_utf8(&output.stdout).unwrap().trim(),
        "b04691041fd3cdad5b4d70ba6cb17a7ca5c40276",
        "historical capture changed; add a new dated capture instead of rewriting evidence"
    );
}

#[test]
fn adapted_sse_changes_only_the_declared_synthetic_sentinel() {
    let original = std::fs::read_to_string(capture_path()).unwrap();
    let adapted = std::fs::read_to_string(samples_dir().join("responses-sse.txt")).unwrap();
    assert!(adapted.starts_with(": Provenance:"));
    assert_eq!(original.ends_with('\n'), adapted.ends_with('\n'));
    let original: Vec<_> = original.lines().collect();
    let adapted: Vec<_> = adapted
        .lines()
        .skip_while(|line| line.starts_with(':') || line.is_empty())
        .collect();
    assert_eq!(original.len(), adapted.len(), "SSE framing changed");
    let mut substitutions = 0;
    for (original_line, adapted_line) in original.iter().zip(adapted) {
        let Some(original_json) = original_line.strip_prefix("data: ") else {
            assert_eq!(*original_line, adapted_line, "SSE event or framing changed");
            continue;
        };
        let mut expected: serde_json::Value = serde_json::from_str(original_json).unwrap();
        let actual: serde_json::Value = serde_json::from_str(
            adapted_line
                .strip_prefix("data: ")
                .expect("missing data prefix"),
        )
        .unwrap();
        match expected["type"].as_str().unwrap() {
            "response.output_text.delta" => {
                let replacement = match expected["delta"].as_str().unwrap() {
                    "CS" => Some("ASK"),
                    "UB" => Some("CODEX"),
                    _ => None,
                };
                if let Some(replacement) = replacement {
                    expected["delta"] = replacement.into();
                    substitutions += 1;
                }
            }
            "response.output_text.done"
            | "response.content_part.done"
            | "response.output_item.done" => {
                let pointer = match expected["type"].as_str().unwrap() {
                    "response.output_text.done" => "/text",
                    "response.content_part.done" => "/part/text",
                    _ => "/item/content/0/text",
                };
                let text = expected.pointer_mut(pointer).unwrap();
                assert_eq!(text.as_str(), Some("CSUB-VERIFY-OK"));
                *text = "ASKCODEX-VERIFY-OK".into();
                substitutions += 1;
            }
            _ => {}
        }
        assert_eq!(
            expected, actual,
            "adaptation changed an undeclared payload field"
        );
    }
    assert_eq!(substitutions, 5, "sentinel adaptation contract changed");
}
