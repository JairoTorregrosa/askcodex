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
//! - Deserialize accepts credentials at input boundaries. Serialize is absent;
//!   only private storage and OAuth adapters may emit an exposed value.
//! - The only way to reach the value is the explicit [`Secret::expose`]
//!   call. Grepping for `expose(` audits every use site. `expose()` results
//!   must never be passed to any print/log/format macro — only into HTTP
//!   headers and request bodies.
//!
//! Deliberate non-goals (documented, not accidental): no memory zeroing
//! (`zeroize`). The threat model is accidental printing/logging/committing,
//! not process-memory forensics. Runtime secrets cannot be serialized implicitly.

use serde::Deserialize;

/// The placeholder printed instead of any secret value.
pub const REDACTED: &str = "REDACTED";

/// A credential value that cannot be printed by accident.
#[derive(Clone, PartialEq, Eq, Deserialize)]
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
    fn deserialize_is_explicit_and_runtime_credentials_are_not_serializable() {
        let secret: Secret = serde_json::from_str("\"fixture-only\"").unwrap();
        assert_eq!(secret.expose(), "fixture-only");
        // If any runtime credential implements Serialize, type inference here
        // becomes ambiguous and the test target fails to compile.
        trait NotSerialize<A> {
            fn check() {}
        }
        impl<T: ?Sized> NotSerialize<()> for T {}
        struct Serializable;
        impl<T: ?Sized + serde::Serialize> NotSerialize<Serializable> for T {}
        let _ = <Secret as NotSerialize<_>>::check;
        let _ = <crate::models::AuthFile as NotSerialize<_>>::check;
        let _ = <crate::models::AuthTokens as NotSerialize<_>>::check;
    }
}
