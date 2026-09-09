//! Credential-file loading and atomic persistence. Only this module serializes stored tokens.
use crate::{
    config,
    error::Error,
    models::{AuthFile, AuthTokens},
};
use serde::Serialize;
use std::{
    fs,
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug)]
pub(crate) struct CredentialStore {
    path: PathBuf,
}
impl CredentialStore {
    pub(crate) fn configured() -> Result<Self, Error> {
        Ok(Self {
            path: config::auth_path()?,
        })
    }
    #[cfg(test)]
    pub(crate) fn from_path(path: PathBuf) -> Self {
        Self { path }
    }
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
    pub(crate) fn load(&self) -> Result<AuthFile, Error> {
        load_auth_from(&self.path)
    }
}

pub(super) fn load_auth_from(path: &Path) -> Result<AuthFile, Error> {
    // `read` + NotFound (rather than `exists()` first) keeps the
    // missing/unreadable distinction race-free.
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            return Err(Error::AuthFileMissing {
                path: path.to_path_buf(),
            });
        }
        Err(source) => {
            return Err(Error::AuthFileUnreadable {
                path: path.to_path_buf(),
                source,
            });
        }
    };

    let auth: AuthFile =
        serde_json::from_slice(&bytes).map_err(|source| Error::AuthFileInvalid {
            path: path.to_path_buf(),
            source: sanitized_parse_error(source),
        })?;

    let has_access_token = auth
        .tokens
        .as_ref()
        .and_then(|tokens| tokens.access_token.as_ref())
        .is_some_and(|token| !token.is_empty());
    if !has_access_token {
        return Err(Error::AuthTokensMissing {
            path: path.to_path_buf(),
        });
    }

    let has_account_id = auth
        .tokens
        .as_ref()
        .and_then(|tokens| tokens.account_id.as_deref())
        .is_some_and(|id| !id.is_empty());
    if !has_account_id {
        return Err(Error::AuthAccountIdMissing {
            path: path.to_path_buf(),
        });
    }

    Ok(auth)
}

pub(super) fn persist_atomic_to(auth: &AuthFile, path: &Path) -> Result<(), Error> {
    // Step 1. Serialization happens before anything touches the disk, so a
    // (practically impossible) serde failure cannot leave a temp file.
    let mut document = serialize_document(auth)?;
    document.push('\n');

    // Step 2. Follow a symlink to the real credential file. Until the
    // target is known, no sibling name can be computed and no backup can
    // exist, so a failure here names `path` itself (which is untouched).
    let target = resolve_symlink(path).map_err(|source| persist_failed(path, None, source))?;
    let path = target.as_path();

    let Some(file_name) = path.file_name() else {
        return Err(persist_failed(
            path,
            None,
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "auth file path has no file name",
            ),
        ));
    };
    // `with_file_name` keeps every sibling in the SAME directory as the
    // target, which is what makes the final rename atomic.
    let sibling = |suffix: &str| -> PathBuf {
        let mut name = file_name.to_os_string();
        name.push(suffix);
        path.with_file_name(name)
    };
    let backup = sibling(".bak");
    let backup_temp = sibling(&format!(".bak.tmp.{}", std::process::id()));
    let temp = sibling(&format!(".tmp.{}", std::process::id()));

    // Step 3. Back up the CURRENT document BEFORE anything else is written.
    // A failure here aborts and leaves the original untouched.
    let exists = path
        .try_exists()
        .map_err(|source| persist_failed(path, None, source))?;
    if exists {
        write_backup(path, &backup, &backup_temp)
            .map_err(|source| persist_failed(path, None, source))?;
    }
    // Everything from here on can name the backup, because from here on it
    // exists and holds the document `auth.json` currently has. Before this
    // point the honest answer is that no backup was taken and `auth.json`
    // itself is still the previous document — so that is what gets named.
    let named_backup: Option<&Path> = if exists { Some(&backup) } else { None };

    // Step 4. O_CREAT|O_EXCL (`create_new`) + mode 0600 applied by the
    // kernel at creation time: there is no window in which the file exists
    // with looser permissions. NOTE: the guard is armed only AFTER a
    // successful open — on EEXIST the temp belongs to someone else and
    // must not be deleted.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)
        .map_err(|source| persist_failed(path, named_backup, source))?;
    let mut guard = TempFileGuard::new(&temp);

    // Step 5.
    file.write_all(document.as_bytes())
        .map_err(|source| persist_failed(path, named_backup, source))?;
    file.flush()
        .map_err(|source| persist_failed(path, named_backup, source))?;
    file.sync_all()
        .map_err(|source| persist_failed(path, named_backup, source))?;
    drop(file);

    // Step 6. Atomic on POSIX: a concurrent reader sees either the old or
    // the new complete document, never a partial one. (The containing
    // directory is deliberately not fsynced: that would only add power-loss
    // durability, which is outside this threat model, and its failure after
    // a completed rename could not be acted on anyway.)
    fs::rename(&temp, path).map_err(|source| persist_failed(path, named_backup, source))?;
    guard.disarm();
    Ok(())
}

fn write_backup(path: &Path, backup: &Path, temp: &Path) -> std::io::Result<()> {
    // auth.json is a few KB; reading it whole keeps this a single
    // write-then-rename with no partially-copied intermediate state.
    let previous = fs::read(path)?;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(temp)?;
    let mut guard = TempFileGuard::new(temp);
    file.write_all(&previous)?;
    file.flush()?;
    file.sync_all()?;
    drop(file);

    fs::rename(temp, backup)?;
    guard.disarm();
    Ok(())
}

fn persist_failed(path: &Path, backup: Option<&Path>, source: std::io::Error) -> Error {
    Error::PersistFailed {
        path: path.to_path_buf(),
        backup: backup.map(Path::to_path_buf),
        source,
    }
}

pub(super) fn resolve_symlink(path: &Path) -> std::io::Result<PathBuf> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => fs::canonicalize(path),
        _ => Ok(path.to_path_buf()),
    }
}

struct TempFileGuard<'a> {
    path: Option<&'a Path>,
}

impl<'a> TempFileGuard<'a> {
    fn new(path: &'a Path) -> Self {
        TempFileGuard { path: Some(path) }
    }

    /// Call after a successful rename: the temp no longer exists and the
    /// path now belongs to `auth.json`'s directory entry.
    fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for TempFileGuard<'_> {
    fn drop(&mut self) {
        if let Some(path) = self.path {
            // A discarded error, because `Drop` cannot propagate. What the
            // leftover costs, stated accurately:
            //
            // - Within THIS process the failure is self-announcing: the
            //   temp name embeds `std::process::id()`, so the next persist
            //   trips O_EXCL and fails loudly rather than overwriting it.
            // - Across processes it is NOT. A different PID picks a
            //   different name and succeeds silently, and askcodex never
            //   deletes a temp it did not create. So a run killed between
            //   the fsync and the rename (SIGINT does not unwind — see
            //   `main.rs`) leaves an `auth.json.tmp.<pid>` at 0600 that may
            //   hold newer credentials than `auth.json`, and nothing points
            //   the user at it. That is a known, accepted limitation of
            //   this design, not a guarantee.
            //
            // Deliberately NOT "fixed" by a deterministic temp name: a
            // crash orphan would then block every later persist, which
            // trades a recoverable state for an unrecoverable one. Only
            // one askcodex can be inside a refresh at a time (see `AuthLock`),
            // so the same-PID collision above is the crashed-predecessor
            // case, never a live competitor.
            let _ = fs::remove_file(path);
        }
    }
}

// These borrowed adapters are deliberately private: runtime credentials do not
// implement Serialize. Exposure is permitted only at the persistence boundary.
#[derive(Serialize)]
struct StoredAuth<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_mode: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tokens: Option<StoredTokens<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_refresh: Option<&'a str>,
    #[serde(flatten)]
    extra: &'a serde_json::Map<String, serde_json::Value>,
}
#[derive(Serialize)]
struct StoredTokens<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    id_token: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    access_token: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    account_id: Option<&'a str>,
    #[serde(flatten)]
    extra: &'a serde_json::Map<String, serde_json::Value>,
}
impl<'a> From<&'a AuthTokens> for StoredTokens<'a> {
    fn from(tokens: &'a AuthTokens) -> Self {
        Self {
            id_token: tokens.id_token.as_ref().map(|token| token.expose()),
            access_token: tokens.access_token.as_ref().map(|token| token.expose()),
            refresh_token: tokens.refresh_token.as_ref().map(|token| token.expose()),
            account_id: tokens.account_id.as_deref(),
            extra: &tokens.extra,
        }
    }
}
pub(super) fn serialize_document(auth: &AuthFile) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(&StoredAuth {
        auth_mode: auth.auth_mode.as_deref(),
        tokens: auth.tokens.as_ref().map(StoredTokens::from),
        last_refresh: auth.last_refresh.as_deref(),
        extra: &auth.extra,
    })
}

fn sanitized_parse_error(source: serde_json::Error) -> serde_json::Error {
    // Serde type errors can include an entire unexpected string value. Keep only
    // the category and location, so Display, Debug and the source chain are safe.
    <serde_json::Error as serde::de::Error>::custom(format!(
        "invalid credential document ({:?}) at line {}, column {}",
        source.classify(),
        source.line(),
        source.column()
    ))
}
