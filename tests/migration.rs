//! Independent shipped-binary migration gates. No application internals imported.
use std::{
    fs,
    io::Write,
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_askcodex");
const SENTINELS: &[&str] = &[
    "migration-synthetic-signature-do-not-print",
    "migration-synthetic-refresh-do-not-print",
    "migration-synthetic-id-do-not-print",
];

struct Sandbox(PathBuf);

impl Sandbox {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "migration-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("fresh sandbox");
        Self(root)
    }

    fn auth(&self, bytes: &[u8]) {
        fs::write(self.0.join("auth.json"), bytes).unwrap();
    }

    fn valid_auth(&self) {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        let payload = URL_SAFE_NO_PAD.encode(br#"{"exp":4102444800}"#);
        self.auth(
            &serde_json::to_vec(&json!({
                "auth_mode": "chatgpt",
                "tokens": {
                    "access_token": format!("{header}.{payload}.{}", SENTINELS[0]),
                    "refresh_token": SENTINELS[1],
                    "id_token": SENTINELS[2],
                    "account_id": "acct_REDACTED"
                },
                "migration_unknown": {"preserve": [1, 2, 3]}
            }))
            .unwrap(),
        );
    }

    fn run_bin(&self, binary: &str, args: &[&str], stdin: &[u8]) -> Output {
        let before = fs::read(self.0.join("auth.json")).ok();
        let mut command = Command::new(binary);
        command
            .args(args)
            .env_clear()
            .env("HOME", &self.0)
            .env("CODEX_HOME", &self.0)
            .env("HTTP_PROXY", "http://127.0.0.1:1")
            .env("HTTPS_PROXY", "http://127.0.0.1:1")
            .env("ALL_PROXY", "http://127.0.0.1:1")
            .current_dir(&self.0)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // SAFETY: alarm is async-signal-safe and only configures this child.
        // The timer survives exec, bounding regressions that block on a FIFO.
        unsafe {
            command.pre_exec(|| {
                libc::alarm(5);
                Ok(())
            });
        }
        let mut child = command.spawn().unwrap();
        let write = child.stdin.take().unwrap().write_all(stdin);
        if let Err(error) = write {
            assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
        }
        let output = child.wait_with_output().unwrap();
        assert_eq!(before, fs::read(self.0.join("auth.json")).ok());
        for bytes in [&output.stdout, &output.stderr] {
            let text = String::from_utf8_lossy(bytes);
            for sentinel in SENTINELS {
                assert!(!text.contains(sentinel), "synthetic secret leaked");
            }
        }
        output
    }

    fn run(&self, args: &[&str], stdin: &[u8]) -> Output {
        self.run_bin(BIN, args, stdin)
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

const LEAVES: &[&[&str]] = &[
    &["whoami"],
    &["usage"],
    &["models"],
    &["transcribe"],
    &["ask"],
    &["image", "create"],
    &["image", "edit"],
    &["raw"],
    &["auth", "status"],
    &["auth", "refresh"],
];

#[test]
fn every_legacy_command_remains_available_without_auth() {
    let sandbox = Sandbox::new();
    for leaf in LEAVES {
        let mut args = leaf.to_vec();
        args.push("--help");
        let output = sandbox.run(&args, b"");
        assert!(output.status.success(), "help failed: {args:?}");
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(text.contains("--json"));
        assert!(text.contains("--no-refresh"));
    }
}

#[test]
fn generated_reference_is_complete_and_does_not_read_auth() {
    let sandbox = Sandbox::new();
    sandbox.auth(b"deliberately malformed credentials");
    let output = sandbox.run(&["reference"], b"");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let reference = String::from_utf8(output.stdout).unwrap();
    for leaf in LEAVES {
        assert!(
            reference.contains(&leaf.join(" ")),
            "generated reference omitted {leaf:?}"
        );
    }
    for flag in [
        "--json",
        "--events",
        "--no-refresh",
        "--client-version",
        "--instructions",
        "--effort",
        "--inputs",
        "--out",
        "--body",
        "--stream",
    ] {
        assert!(reference.contains(flag), "reference omitted {flag}");
    }
}

#[test]
fn legacy_flags_still_parse_in_the_shipped_binary() {
    let sandbox = Sandbox::new();
    let cases: &[&[&str]] = &[
        &["models", "--client-version", "0.150.0"],
        &[
            "ask",
            "p",
            "--model",
            "m",
            "--effort",
            "high",
            "--instructions",
            "s",
        ],
        &["image", "create", "p", "-o", "out.png"],
        &[
            "image", "edit", "p", "-i", "a.png", "b.png", "--out", "out.png",
        ],
        &["raw", "POST", "/codex/responses", "--body", "{}"],
        &["raw", "GET", "/codex/responses", "--stream"],
        &["transcribe", "input.wav"],
    ];
    for args in cases {
        let mut invocation = vec!["--no-refresh"];
        invocation.extend_from_slice(args);
        let output = sandbox.run(&invocation, b"");
        assert_ne!(
            output.status.code(),
            Some(2),
            "legacy flags rejected: {args:?}"
        );
        assert!(!output.status.success(), "missing auth/input should fail");
    }
}

#[test]
fn local_errors_win_over_broken_auth_and_never_mutate_it() {
    let sandbox = Sandbox::new();
    sandbox.auth(b"deliberately malformed credentials");
    fs::write(sandbox.0.join("broken.wav"), b"not audio").unwrap();
    let cases: &[(&[&str], &[u8])] = &[
        (&["transcribe", "missing.wav"], b""),
        (&["transcribe", "broken.wav"], b""),
        (&["image", "edit", "p", "-i", "missing.png"], b""),
        (&["image", "create", "p", "-o", "missing/out.png"], b""),
        (&["raw", "POST", "/x", "--body", "{"], b""),
        (&["raw", "POST", "/x", "--body", "-"], b"{"),
        (&["ask", "-"], b"\xff"),
    ];
    for (args, stdin) in cases {
        let mut machine_args = vec!["--json"];
        machine_args.extend_from_slice(args);
        let output = sandbox.run(&machine_args, stdin);
        assert!(
            !output.status.success(),
            "invalid input succeeded: {args:?}"
        );
        assert!(
            output.stdout.is_empty(),
            "failure emitted payload: {args:?}"
        );
        let error: Value = serde_json::from_slice(&output.stderr)
            .unwrap_or_else(|_| panic!("error is not JSON for {args:?}"));
        assert_eq!(error["schema_version"], 1);
        let code = error["error"]["code"].as_str().unwrap();
        assert!(
            matches!(code, "input_invalid" | "input_unreadable" | "io_error"),
            "local input lost precedence for {args:?}: {code}"
        );
        assert!(error["error"]["message"].is_string());
    }
}

#[test]
fn auth_status_has_versioned_success_and_events_without_secret_or_mutation() {
    let sandbox = Sandbox::new();
    sandbox.valid_auth();
    for args in [
        vec!["--json", "--no-refresh", "auth", "status"],
        vec!["auth", "status", "--json", "--no-refresh"],
    ] {
        let output = sandbox.run(&args, b"");
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["command"], "auth status");
        assert_eq!(value["result"]["access_token_valid"], true);
        assert!(value["result"].get("access_token").is_none());
    }
    let events = sandbox.run(&["auth", "status", "--events", "--no-refresh"], b"");
    assert!(events.status.success());
    assert!(events.stderr.is_empty());
    let value: Value = serde_json::from_slice(&events.stdout).unwrap();
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["event"], "result");
    assert_eq!(value["command"], "auth status");
}

#[test]
fn output_mode_conflicts_fail_locally() {
    let sandbox = Sandbox::new();
    sandbox.auth(b"deliberately malformed credentials");
    for args in [
        vec!["--json", "--events", "auth", "status"],
        vec!["--events", "raw", "GET", "/codex/usage"],
    ] {
        let output = sandbox.run(&args, b"");
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
}

#[test]
#[ignore = "requires explicit ASKCODEX_MIGRATION_BASELINE archived binary"]
fn archived_baseline_preserves_legacy_leaf_help_exit_status() {
    let baseline = std::env::var("ASKCODEX_MIGRATION_BASELINE")
        .expect("set ASKCODEX_MIGRATION_BASELINE to archived pre-refactor binary");
    let sandbox = Sandbox::new();
    for leaf in LEAVES {
        let mut args = leaf.to_vec();
        args.push("--help");
        let before = sandbox.run_bin(&baseline, &args, b"");
        let after = sandbox.run(&args, b"");
        assert_eq!(before.status.code(), after.status.code(), "{args:?}");
        assert!(after.status.success());
    }
}

fn assert_input_error(output: Output, expected: &str) {
    assert_eq!(
        output.status.code(),
        Some(1),
        "input rejection must exit promptly, not be killed"
    );
    assert!(output.stdout.is_empty());
    let value: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["error"]["code"], expected);
}

fn sparse_file(path: &Path, prefix: &[u8], length: u64) {
    let mut file = fs::File::create(path).unwrap();
    file.write_all(prefix).unwrap();
    file.set_len(length).unwrap();
}

#[test]
fn oversized_audio_and_combined_references_fail_before_auth() {
    let sandbox = Sandbox::new();
    sandbox.auth(b"deliberately malformed credentials");
    sparse_file(
        &sandbox.0.join("large.wav"),
        b"RIFFxxxxWAVE",
        25 * 1024 * 1024 + 1,
    );
    assert_input_error(
        sandbox.run(&["--json", "transcribe", "large.wav"], b""),
        "input_invalid",
    );
    for name in ["first.png", "second.png"] {
        sparse_file(
            &sandbox.0.join(name),
            b"\x89PNG\r\n\x1a\n",
            13 * 1024 * 1024,
        );
    }
    assert_input_error(
        sandbox.run(
            &[
                "--json",
                "image",
                "edit",
                "p",
                "-i",
                "first.png",
                "second.png",
            ],
            b"",
        ),
        "input_invalid",
    );
}

#[test]
fn oversized_stdin_fails_before_auth_for_ask_and_raw() {
    let sandbox = Sandbox::new();
    sandbox.auth(b"deliberately malformed credentials");
    let bytes = vec![b' '; 16 * 1024 * 1024 + 1];
    for args in [
        vec!["--json", "ask", "-"],
        vec!["--json", "raw", "POST", "/x", "--body", "-"],
    ] {
        assert_input_error(sandbox.run(&args, &bytes), "input_invalid");
    }
}

#[test]
fn devices_and_unconnected_fifo_fail_before_auth_without_blocking() {
    let sandbox = Sandbox::new();
    sandbox.auth(b"deliberately malformed credentials");
    let path = sandbox.0.join("unconnected.fifo");
    let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: c_path is NUL-terminated, remains live, and points within this sandbox.
    assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
    for args in [
        vec!["--json", "transcribe", "/dev/zero"],
        vec!["--json", "transcribe", "unconnected.fifo"],
        vec!["--json", "image", "edit", "p", "-i", "/dev/zero"],
        vec!["--json", "image", "edit", "p", "-i", "unconnected.fifo"],
    ] {
        assert_input_error(sandbox.run(&args, b""), "input_invalid");
    }
}
