//! Internal credential store and refresh session.
//!
//! The store preserves unknown JSON fields and writes mode-0600 backups and
//! atomic replacements. Sessions serialize cooperating askcodex refreshes
//! through a kernel-held lock. Codex does not participate in that lock.
mod jwt;
mod lock;
mod session;
mod store;

#[cfg(test)]
use crate::models::AuthFile;
pub(crate) use jwt::jwt_exp;
#[cfg(test)]
pub(crate) use jwt::needs_refresh;
pub(crate) use session::AuthSession;
pub(crate) use store::CredentialStore;

#[cfg(test)]
pub(crate) fn test_document(auth: &AuthFile) -> serde_json::Value {
    serde_json::from_str(&store::serialize_document(auth).expect("fixture serializes"))
        .expect("fixture JSON")
}
#[cfg(test)]
mod test_support;
#[cfg(test)]
pub(crate) use test_support::{assert_codex_home_locked, isolate_codex_home, lock_codex_home};
#[cfg(test)]
mod safety_tests;
#[cfg(test)]
mod tests;
