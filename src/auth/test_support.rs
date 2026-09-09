//! Shared scratch-directory isolation for legacy HTTP tests.
use std::{fs, path::Path};

/// Point `CODEX_HOME` at a per-process scratch directory and return it.
///
/// Test-only, and the single place in the crate that writes that variable:
/// `set_var` is process-wide, so it runs exactly once per test process,
/// before any test can read it (every test in this crate calls this first).
/// Its purpose is defense in depth — even a test that DID let production
/// code resolve `config::auth_path()` lands in the scratch directory
/// instead of the user's real `~/.codex`.
#[cfg(test)]
pub(crate) fn isolate_codex_home() -> std::path::PathBuf {
    use std::sync::Once;

    static ONCE: Once = Once::new();
    let scratch =
        std::env::temp_dir().join(format!("askcodex-test-codex-home-{}", std::process::id()));
    ONCE.call_once(|| {
        fs::create_dir_all(&scratch).expect("create scratch CODEX_HOME");
        // SAFETY: executed exactly once per process, before any test has
        // read the environment, and never again afterwards.
        unsafe { std::env::set_var("CODEX_HOME", &scratch) };
    });
    scratch
}

/// Serialize the tests that let production code resolve AND WRITE
/// `config::auth_path()`, since they all share the one scratch
/// `CODEX_HOME` returned by [`isolate_codex_home`].
///
/// The tests in THIS module never need it (they drive `load_auth_from` /
/// `persist_atomic_to` / `refresh_inner` with their own temp paths); the
/// refresh-through-`Client` tests in http.rs do, and so does any test that
/// asserts on the CONTENTS of the scratch directory. Poisoning is ignored
/// on purpose: one failing test must not cascade into unrelated ones.
///
/// Holding it is not a convention. [`assert_codex_home_locked`] makes it
/// mechanical, because the convention already failed once: a test that
/// reached the credential lock through `Client` without taking this mutex
/// created `auth.json.lock` beside another test's assertion on the
/// directory listing, and the resulting failure surfaced on one CI runner
/// and not on the author's machine.
#[cfg(test)]
pub(crate) fn lock_codex_home() -> CodexHomeGuard {
    let inner = codex_home_mutex()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *codex_home_holder().lock().expect("holder mutex") = Some(std::thread::current().id());
    CodexHomeGuard { _inner: inner }
}

#[cfg(test)]
fn codex_home_mutex() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    &LOCK
}

#[cfg(test)]
fn codex_home_holder() -> &'static std::sync::Mutex<Option<std::thread::ThreadId>> {
    static HOLDER: std::sync::Mutex<Option<std::thread::ThreadId>> = std::sync::Mutex::new(None);
    &HOLDER
}

/// Guard for [`lock_codex_home`]. Records which thread holds the mutex so
/// that a violation can name itself instead of showing up as a mystery
/// directory listing in an unrelated test.
#[cfg(test)]
pub(crate) struct CodexHomeGuard {
    _inner: std::sync::MutexGuard<'static, ()>,
}

#[cfg(test)]
impl Drop for CodexHomeGuard {
    fn drop(&mut self) {
        *codex_home_holder().lock().expect("holder mutex") = None;
    }
}

/// Panic if `path` lives in the shared scratch `CODEX_HOME` and the calling
/// thread does not hold [`lock_codex_home`].
///
/// Called where production code is about to CREATE something there. A test
/// that reaches this point without the mutex is racing every other test
/// that reads the same directory, and the whole point of this project is
/// that a broken invariant is loud at its cause rather than silent until it
/// surfaces somewhere else.
#[cfg(test)]
pub(crate) fn assert_codex_home_locked(path: &Path) {
    let scratch =
        std::env::temp_dir().join(format!("askcodex-test-codex-home-{}", std::process::id()));
    if path.parent() != Some(scratch.as_path()) {
        return;
    }
    let holder = *codex_home_holder().lock().expect("holder mutex");
    assert_eq!(
        holder,
        Some(std::thread::current().id()),
        "this test writes {} in the shared scratch CODEX_HOME without holding \
         auth::lock_codex_home(). Take the guard for the whole test body: \
         `let _guard = auth::lock_codex_home();`",
        path.display()
    );
}
