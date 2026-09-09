//! Bounded local input reads, shared by media preparation and stdin.

use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use crate::error::Error;

pub(crate) const MAX_MEDIA_BYTES: u64 = 25 * 1024 * 1024;
pub(crate) const MAX_TEXT_BYTES: u64 = 16 * 1024 * 1024;

pub(crate) fn read_limited(reader: &mut dyn Read, limit: u64) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    reader.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(Error::InputTooLarge { limit_bytes: limit });
    }
    Ok(bytes)
}

pub(crate) fn read_file(path: &Path, limit: u64, kind: &'static str) -> Result<Vec<u8>, Error> {
    let unreadable = |source| Error::InputFileUnreadable {
        path: path.into(),
        kind,
        source,
    };
    // Nonblocking open prevents a FIFO from hanging before its type can be checked.
    // Regular file symlinks are supported; metadata describes the opened target.
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(unreadable)?;
    let metadata = file.metadata().map_err(unreadable)?;
    if !metadata.is_file() {
        return Err(Error::InvalidInput {
            reason: "expected a regular input file",
        });
    }
    if metadata.len() > limit {
        return Err(Error::InputTooLarge { limit_bytes: limit });
    }
    read_limited(&mut file, limit).map_err(|error| match error {
        Error::Io(source) => unreadable(source),
        other => other,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn reads_at_most_limit_plus_one_and_never_returns_truncated_success() {
        let mut input = Cursor::new(vec![b'x'; 100]);
        assert!(matches!(
            read_limited(&mut input, 8),
            Err(Error::InputTooLarge { limit_bytes: 8 })
        ));
        assert_eq!(input.position(), 9);
        assert_eq!(
            read_limited(&mut Cursor::new(b"12345678"), 8).unwrap(),
            b"12345678"
        );
    }

    #[test]
    fn rejects_devices_instead_of_reading_an_infinite_byte_stream() {
        assert!(matches!(
            read_file(Path::new("/dev/zero"), 32, "test"),
            Err(Error::InvalidInput { .. })
        ));
    }
}
