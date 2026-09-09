//! Cooperative kernel-held lock. The inode is persistent and is never unlinked.
//!
//! Closing the descriptor (including process death) releases ownership. File age
//! and PID contents never grant ownership. This excludes cooperating askcodex
//! processes, not Codex or older askcodex versions using an unlink-based lock.
use crate::error::Error;
use std::{
    fs::{File, OpenOptions},
    io,
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::Path,
    time::{Duration, Instant},
};

const LOCK_POLL: Duration = Duration::from_millis(50);

pub(super) struct AuthLock {
    _file: File,
}
impl AuthLock {
    pub(super) fn acquire(auth_file: &Path, wait: Duration) -> Result<Self, Error> {
        let file_name = auth_file
            .file_name()
            .ok_or_else(|| Error::AuthLockUnavailable {
                path: auth_file.to_path_buf(),
                source: io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "auth file path has no file name",
                ),
            })?;
        let mut name = file_name.to_os_string();
        name.push(".lock");
        let path = auth_file.with_file_name(name);
        #[cfg(test)]
        super::assert_codex_home_locked(&path);
        // O_NOFOLLOW prevents a planted lock symlink from redirecting the open.
        // O_CLOEXEC prevents children from accidentally prolonging lock ownership.
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|source| Error::AuthLockUnavailable {
                path: path.clone(),
                source,
            })?;
        if !file
            .metadata()
            .map_err(|source| Error::AuthLockUnavailable {
                path: path.clone(),
                source,
            })?
            .is_file()
        {
            return Err(Error::AuthLockUnavailable {
                path,
                source: io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "credential lock is not a regular file",
                ),
            });
        }
        let started = Instant::now();
        loop {
            // SAFETY: file owns a live descriptor for the duration of this call;
            // flock does not retain pointers or read any Rust memory.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                return Ok(Self { _file: file });
            }
            let source = io::Error::last_os_error();
            if source.kind() != io::ErrorKind::WouldBlock
                && source.kind() != io::ErrorKind::Interrupted
            {
                return Err(Error::AuthLockUnavailable { path, source });
            }
            if started.elapsed() >= wait {
                return Err(Error::AuthLockUnavailable { path, source });
            }
            std::thread::sleep(LOCK_POLL.min(wait.saturating_sub(started.elapsed())));
        }
    }
}
