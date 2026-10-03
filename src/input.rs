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

/// Why [`parse_exact_json`] refused a document.
#[derive(Debug)]
pub(crate) enum ExactJsonError {
    /// Not JSON. The serde message names a line and column, never content.
    Syntax(serde_json::Error),
    /// A number literal a `Value` cannot hold exactly: an integer outside
    /// the i64/u64 range, or a decimal with more precision than an f64.
    /// serde_json would keep the nearest f64, so a re-serialized document
    /// would carry a different number than the one written.
    LossyNumber,
}

/// Parse JSON, refusing any number literal a `Value` cannot hold exactly.
///
/// An integer must fit i64 or u64. A decimal must survive the trip through
/// f64: `0.1` and `1.50` do (they come back as the same value), while
/// `9007199254740992.5` does not (it comes back as `9007199254740992`).
/// Rounding either silently is a confident wrong answer.
pub(crate) fn parse_exact_json(text: &str) -> Result<serde_json::Value, ExactJsonError> {
    let value = serde_json::from_str(text).map_err(ExactJsonError::Syntax)?;
    // The document is valid JSON here, so a minimal scan is enough: skip
    // strings (with their escapes) and look at each bare number token.
    let bytes = text.as_bytes();
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            b'"' => {
                at += 1;
                while at < bytes.len() && bytes[at] != b'"' {
                    at += if bytes[at] == b'\\' { 2 } else { 1 };
                }
                at += 1;
            }
            b'-' | b'0'..=b'9' => {
                let start = at;
                while at < bytes.len()
                    && matches!(bytes[at], b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
                {
                    at += 1;
                }
                let token = &text[start..at];
                let exact = if token.contains(['.', 'e', 'E']) {
                    decimal_survives_f64(token)
                } else {
                    token.parse::<i64>().is_ok() || token.parse::<u64>().is_ok()
                };
                if !exact {
                    return Err(ExactJsonError::LossyNumber);
                }
            }
            _ => at += 1,
        }
    }
    Ok(value)
}

/// Whether a JSON decimal literal and the f64 serde_json keeps for it are
/// the same number. Rust prints an f64 with the fewest digits that parse
/// back to it, so comparing the two as normalized decimals catches any
/// digit the f64 could not keep.
fn decimal_survives_f64(token: &str) -> bool {
    match token.parse::<f64>() {
        Ok(f) if f.is_finite() => normalized_decimal(token) == normalized_decimal(&f.to_string()),
        _ => false,
    }
}

/// `(negative, significant digits, power of ten)` with no leading or
/// trailing zeros, so `1.50`, `15e-1` and `1.5` compare equal. Zero is
/// `(false, "", 0)` whatever its sign or spelling.
fn normalized_decimal(literal: &str) -> Option<(bool, String, i64)> {
    let (negative, unsigned) = match literal.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, literal),
    };
    let (mantissa, exponent) = match unsigned.find(['e', 'E']) {
        Some(at) => (&unsigned[..at], unsigned[at + 1..].parse::<i64>().ok()?),
        None => (unsigned, 0),
    };
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let mut digits = format!("{whole}{fraction}");
    let mut power = exponent.checked_sub(i64::try_from(fraction.len()).ok()?)?;
    let trailing = digits.len() - digits.trim_end_matches('0').len();
    digits.truncate(digits.len() - trailing);
    power = power.checked_add(i64::try_from(trailing).ok()?)?;
    let digits = digits.trim_start_matches('0').to_string();
    if digits.is_empty() {
        return Some((false, digits, 0));
    }
    Some((negative, digits, power))
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
    fn exact_json_keeps_64_bit_integers_and_refuses_wider_ones() {
        let ok = parse_exact_json(
            r#"{"id": 18446744073709551615, "n": -9223372036854775808, "x": 1.5e300}"#,
        )
        .unwrap();
        assert_eq!(ok["id"].as_u64(), Some(u64::MAX));
        assert!(matches!(
            parse_exact_json(r#"{"id": 18446744073709551616}"#),
            Err(ExactJsonError::LossyNumber)
        ));
        assert!(matches!(
            parse_exact_json("[-9223372036854775809]"),
            Err(ExactJsonError::LossyNumber)
        ));
        // Decimals that come back unchanged pass; one f64 cannot hold fails.
        assert!(parse_exact_json("[0.1, 1.50, 15e-1, -0.0, 1e300, 2.5E+3]").is_ok());
        assert!(matches!(
            parse_exact_json("[9007199254740992.5]"),
            Err(ExactJsonError::LossyNumber)
        ));
        assert!(matches!(
            parse_exact_json("[0.10000000000000000001]"),
            Err(ExactJsonError::LossyNumber)
        ));
        // Digits inside strings, escaped quotes included, are not numbers.
        assert!(
            parse_exact_json(r#"{"s": "99999999999999999999 \" 99999999999999999999"}"#).is_ok()
        );
        assert!(matches!(
            parse_exact_json("{\"a\": "),
            Err(ExactJsonError::Syntax(_))
        ));
    }

    #[test]
    fn rejects_devices_instead_of_reading_an_infinite_byte_stream() {
        assert!(matches!(
            read_file(Path::new("/dev/zero"), 32, "test"),
            Err(Error::InvalidInput { .. })
        ));
    }
}
