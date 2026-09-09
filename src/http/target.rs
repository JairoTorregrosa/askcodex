//! A destination that has passed the credential-origin policy.

use crate::error::Error;

#[derive(Debug)]
pub(super) struct Target(String);

impl Target {
    pub(super) fn resolve(path: &str) -> Result<Self, Error> {
        let url = super::resolve_target(path)?;
        super::origin_permitted(&url, cfg!(test))?;
        Ok(Self(url))
    }

    pub(super) fn as_str(&self) -> &str {
        &self.0
    }
}
