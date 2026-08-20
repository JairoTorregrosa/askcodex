//! Secret handling: a redacting newtype for credential values.
//!
//! CONTRACT (frozen — the whole point of this file is that it does not
//! grow a second exposure path):
//!
//! Every credential value (`access_token`, `id_token`, `refresh_token`) is
//! carried as [`Secret`], never as a bare `String`. No `*_token: String`
//! field may exist anywhere in this crate.
//!
//! Guarantees:
//! - `Debug` and `Display` NEVER print the inner value (probe-verified).
//! - Serde is a transparent passthrough, so tokens round-trip byte-exact
//!   when `auth.json` is rewritten.
//! - The only way to reach the value is the explicit [`Secret::expose`]
//!   call. Grepping for `expose(` audits every use site. `expose()` results
//!   must never be passed to any print/log/format macro — only into HTTP
//!   headers and request bodies.
//!
//! Deliberate non-goals (documented, not accidental): no memory zeroing
//! (`zeroize`). The threat model is accidental printing/logging/committing,
//! not process-memory forensics. The `secrecy` crate was evaluated and
//! rejected after a build probe: `SecretString` does not implement
//! `Serialize` (its `str` lacks `SerializableSecret`), and askcodex must write
//! rotated tokens back to `auth.json`.

use serde::{Deserialize, Serialize};

/// The placeholder printed instead of any secret value.
pub const REDACTED: &str = "REDACTED";

/// A credential value that cannot be printed by accident.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    /// Wrap a credential value.
    pub fn new(value: impl Into<String>) -> Self {
        Secret(value.into())
    }

    /// Expose the inner value. The ONLY legitimate destinations are HTTP
    /// headers (`Authorization`) and request/persist bodies. Never a
    /// print/log/format macro, never an error message.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// True when the wrapped value is the empty string.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<String> for Secret {
    fn from(value: String) -> Self {
        Secret(value)
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secret({REDACTED})")
    }
}

impl std::fmt::Display for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(REDACTED)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_and_display_redact() {
        let s = Secret::new("tok-supersecret");
        assert_eq!(format!("{s:?}"), "Secret(REDACTED)");
        assert_eq!(format!("{s}"), "REDACTED");
        let dbg = format!("{:?}", vec![s]);
        assert!(!dbg.contains("supersecret"));
    }

    #[test]
    fn serde_is_transparent_round_trip() {
        #[derive(Serialize, Deserialize)]
        struct T {
            access_token: Secret,
        }
        let t: T = serde_json::from_str(r#"{"access_token":"tok-abc"}"#).unwrap();
        assert_eq!(t.access_token.expose(), "tok-abc");
        assert_eq!(
            serde_json::to_string(&t).unwrap(),
            r#"{"access_token":"tok-abc"}"#
        );
    }
}
