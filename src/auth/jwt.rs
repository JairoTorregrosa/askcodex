//! Pure JWT expiry and refresh-freshness decisions.
use crate::{
    config,
    error::Error,
    models::{self, AuthFile},
    redact::Secret,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use serde_json::Value;
const SECS_PER_DAY: i64 = 86_400;

pub(crate) fn jwt_exp(token: &Secret) -> Result<i64, Error> {
    // NOTE: every `reason` below names a step or a claim NAME. Nothing
    // derived from the token value (not even a base64 error offset, which
    // would disclose one character of it) may enter these strings.
    let mut segments = token.expose().split('.');
    let (Some(_), Some(payload), Some(_), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return Err(Error::JwtInvalid {
            reason: "expected 3 dot-separated segments".to_string(),
        });
    };

    let decoded = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| Error::JwtInvalid {
            reason: "payload segment is not unpadded base64url".to_string(),
        })?;

    let claims: Value = serde_json::from_slice(&decoded).map_err(|_| Error::JwtInvalid {
        reason: "payload segment is not JSON".to_string(),
    })?;
    if !claims.is_object() {
        return Err(Error::JwtInvalid {
            reason: "payload segment is not a JSON object".to_string(),
        });
    }

    let Some(exp) = claims.get("exp") else {
        return Err(Error::JwtInvalid {
            reason: "payload has no `exp` claim".to_string(),
        });
    };
    if let Some(secs) = exp.as_i64() {
        return Ok(secs);
    }
    // RFC 7519 NumericDate permits a non-integer value; truncate toward
    // zero rather than reject a spec-legal token.
    if let Some(secs) = exp.as_f64()
        && secs.is_finite()
        && secs >= i64::MIN as f64
        && secs <= i64::MAX as f64
    {
        return Ok(secs as i64);
    }
    Err(Error::JwtInvalid {
        reason: "claim `exp` is not a number".to_string(),
    })
}

pub(crate) fn needs_refresh(auth: &AuthFile, now: DateTime<Utc>) -> Result<bool, Error> {
    let Some(access_token) = auth
        .tokens
        .as_ref()
        .and_then(|tokens| tokens.access_token.as_ref())
    else {
        // Only reachable when the caller skipped `load_auth`. Loud, and
        // deliberately NOT a path error: nothing here is about paths.
        return Err(Error::UnexpectedResponse {
            context: "auth.json has no tokens.access_token (load it with load_auth first)"
                .to_string(),
        });
    };

    match jwt_exp(access_token) {
        // The expiry is the authoritative signal; when it is readable it is
        // the ONLY one, so a stale or malformed `last_refresh` can neither
        // rotate the user's credentials early nor disable every command.
        Ok(exp) => Ok(exp.saturating_sub(now.timestamp()) < config::REFRESH_WINDOW_SECS),
        // Fallback path only: `last_refresh` decides when `exp` does not.
        Err(undecodable) => match auth.last_refresh.as_deref() {
            Some(raw) => {
                let last =
                    models::parse_last_refresh(raw).map_err(|_| Error::UnexpectedResponse {
                        context: "auth.json last_refresh is not an RFC3339 timestamp".to_string(),
                    })?;
                Ok(now.timestamp().saturating_sub(last.timestamp())
                    > config::REFRESH_MAX_AGE_DAYS * SECS_PER_DAY)
            }
            None => Err(undecodable),
        },
    }
}
