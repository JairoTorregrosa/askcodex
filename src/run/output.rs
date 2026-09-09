//! Human rendering, machine output, and streaming delivery.

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Mode {
    Text,
    Json,
    Events,
}

impl From<bool> for Mode {
    fn from(json: bool) -> Self {
        if json { Self::Json } else { Self::Text }
    }
}

pub(super) fn emit_result<T: Serialize + ?Sized>(
    out: &mut dyn Write,
    mode: Mode,
    command: &str,
    result: &T,
    backend: Option<&Value>,
) -> Result<(), Error> {
    let mut envelope = json!({"schema_version": 1, "command": command, "result": result});
    if let Some(backend) = backend {
        envelope["backend"] = backend.clone();
    }
    if mode == Mode::Events {
        envelope["event"] = json!("result");
        emit_event(out, &envelope)
    } else {
        emit_json(out, &envelope)
    }
}

fn emit_event(out: &mut dyn Write, event: &Value) -> Result<(), Error> {
    let bytes = serde_json::to_vec(event)?;
    out.write_all(&bytes)?;
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}

pub(super) const ABSENT: &str = "-";

pub(super) const UNKNOWN: &str = "?";

pub(super) fn emit_human(out: &mut dyn Write, text: &str) -> Result<(), Error> {
    out.write_all(text.as_bytes())?;
    Ok(())
}

pub(super) fn emit_json<T: Serialize + ?Sized>(
    out: &mut dyn Write,
    value: &T,
) -> Result<(), Error> {
    let mut text = serde_json::to_string_pretty(value)?;
    text.push('\n');
    out.write_all(text.as_bytes())?;
    Ok(())
}

pub(super) fn advise_raw_stream_json(err: &mut dyn Write) -> Result<(), Error> {
    writeln!(
        err,
        "askcodex: note: --json does not apply to `raw --stream`; stdout carries the raw event stream"
    )?;
    Ok(())
}

pub(super) fn copy_stream(reader: &mut dyn BufRead, out: &mut dyn Write) -> Result<(), Error> {
    let mut line = Vec::new();
    loop {
        line.clear();
        if reader.read_until(b'\n', &mut line)? == 0 {
            return Ok(());
        }
        out.write_all(&line)?;
        out.flush()?;
    }
}

pub(super) fn advise_empty_answer(err: &mut dyn Write) -> Result<(), Error> {
    writeln!(
        err,
        "askcodex: note: the response completed with no output text; the model returned nothing to print"
    )?;
    Ok(())
}

pub(super) fn emit_ask<F>(
    mode: impl Into<Mode>,
    model: &str,
    effort: Option<&str>,
    out: &mut dyn Write,
    err: &mut dyn Write,
    stream: F,
) -> Result<(), Error>
where
    F: FnOnce(
        &mut dyn FnMut(&str) -> Result<(), Error>,
    ) -> Result<endpoints::responses::AskAnswer, Error>,
{
    let mode = mode.into();

    let answer = {
        let mut on_delta = |delta: &str| {
            // `--json` mode: NOTHING during the stream. The single JSON
            // document must be the only thing that reaches stdout.
            if mode == Mode::Json {
                return Ok(());
            }
            // A closed downstream consumer stops the HTTP reader immediately.
            let result = if mode == Mode::Events {
                emit_event(
                    out,
                    &json!({"schema_version": 1, "event": "text_delta", "delta": delta}),
                )
            } else {
                out.write_all(delta.as_bytes())
                    .and_then(|()| out.flush())
                    .map_err(Error::from)
            };
            result.map_err(|source| match source {
                Error::Io(source) => io_context("writing the answer to stdout", source),
                other => other,
            })
        };
        stream(&mut on_delta)?
    };

    let text = answer.text;

    // Said once, before either rendering: an empty answer is a real
    // outcome, but it must be visible as one instead of being padded into
    // something that looks like text.
    if text.is_empty() && mode == Mode::Text {
        advise_empty_answer(err)?;
    }

    if mode != Mode::Text {
        emit_result(
            out,
            mode,
            "ask",
            &AskOutput {
                model: model.to_string(),
                effort: effort.map(str::to_string),
                text,
                usage: answer.usage,
            },
            None,
        )
    } else if text.is_empty() || text.ends_with('\n') {
        // Nothing to terminate. A bare newline for an empty answer would
        // be a byte the model never sent — and a 1-byte file for anything
        // redirecting stdout.
        Ok(())
    } else {
        // Terminate the line the model left open, without adding anything
        // it did not say.
        emit_human(out, "\n")
    }
}

pub(super) fn render_whoami(who: &models::WhoamiOutput) -> String {
    let rows = [
        ("email", who.email.as_deref()),
        ("name", who.name.as_deref()),
        ("plan", who.plan_type.as_deref()),
        ("account_id", who.account_id.as_deref()),
        ("user_id", who.user_id.as_deref()),
    ];
    let mut text = String::new();
    for (key, value) in rows {
        let value = value.unwrap_or(ABSENT);
        text.push_str(&format!("{key:<10}: {value}\n"));
    }
    text
}

pub(super) fn render_usage(usage: &UsageResponse) -> String {
    let rate = usage.rate_limit.as_ref();

    let plan = usage.plan_type.as_deref().unwrap_or(ABSENT);
    let limit_reached = render_bool(rate.and_then(|r| r.limit_reached));
    let allowed = render_bool(rate.and_then(|r| r.allowed));

    let mut text = String::new();
    text.push_str(&format!("{:<16}: {plan}\n", "plan"));
    text.push_str(&format!(
        "{:<16}: {limit_reached}  allowed={allowed}\n",
        "limit_reached"
    ));

    for (key, window) in [
        (
            "primary_window",
            rate.and_then(|r| r.primary_window.as_ref()),
        ),
        (
            "secondary_window",
            rate.and_then(|r| r.secondary_window.as_ref()),
        ),
    ] {
        // A window the backend did not send gets no line at all — inventing
        // a zeroed one would read as "you have used nothing".
        let Some(window) = window else { continue };
        let used = match window.used_percent {
            Some(percent) => format!("{percent}"),
            None => UNKNOWN.to_string(),
        };
        let window_hours = render_hours(window.limit_window_seconds);
        let reset_hours = render_hours(window.reset_after_seconds);
        text.push_str(&format!(
            "{key:<16}: used {used}%  window {window_hours}h  resets in {reset_hours}h\n"
        ));
    }
    text
}

pub(super) fn render_models(models: &[ModelInfo]) -> String {
    let count = models.len();
    let mut text = format!("{count} model(s) available:\n");
    for model in models {
        let slug = &model.slug;
        // Same rule as the efforts below: a model that carries no input
        // modalities (key absent or empty array) renders as ABSENT. An
        // empty `in:` column would read as "this model accepts no input at
        // all", which is a claim the backend never made.
        let modalities = match model.input_modalities.as_slice() {
            [] => ABSENT.to_string(),
            items => items.join(","),
        };
        // Efforts come from `supported_reasoning_levels[].effort`. A model
        // that carries no levels at all (key absent or empty array) renders
        // as ABSENT: an empty `effort:` would read as "no efforts are
        // supported", which is a claim the backend never made.
        let efforts = match model.supported_reasoning_levels.as_slice() {
            [] => ABSENT.to_string(),
            levels => levels
                .iter()
                .map(|level| level.effort.as_deref().unwrap_or(ABSENT))
                .collect::<Vec<_>>()
                .join(","),
        };
        // Anything that is not the plain "list" visibility is called out;
        // a missing visibility is called out too, rather than assumed.
        let flag = match model.visibility.as_deref() {
            Some("list") => String::new(),
            Some(other) => format!("  [{other}]"),
            None => format!("  [{ABSENT}]"),
        };
        text.push_str(&format!(
            "  - {slug:<18} in:{modalities:<12} effort:{efforts}{flag}\n"
        ));
    }
    text
}

pub(super) fn render_bool(value: Option<bool>) -> String {
    match value {
        Some(value) => value.to_string(),
        None => ABSENT.to_string(),
    }
}

pub(super) fn render_hours(seconds: Option<u64>) -> String {
    match seconds {
        Some(seconds) => format!("{:.1}", seconds as f64 / 3600.0),
        None => UNKNOWN.to_string(),
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Expiry {
    /// RFC3339 UTC, e.g. `2026-08-17T23:32:41+00:00`.
    pub(super) at: String,
    /// Minutes from `now`; negative once the token has expired.
    pub(super) minutes: i64,
    pub(super) valid: bool,
}

impl Expiry {
    pub(super) fn of_access_token(
        auth: &AuthFile,
        path: &Path,
        now: DateTime<Utc>,
    ) -> Result<Self, Error> {
        let token = auth
            .tokens
            .as_ref()
            .and_then(|tokens| tokens.access_token.as_ref())
            .ok_or_else(|| Error::AuthTokensMissing {
                path: path.to_path_buf(),
            })?;
        // Loud on a malformed token (auth::jwt_exp never guesses), and the
        // error it raises names claims only.
        Self::from_exp(auth::jwt_exp(token)?, now)
    }

    pub(super) fn from_exp(exp: i64, now: DateTime<Utc>) -> Result<Self, Error> {
        let at = DateTime::from_timestamp(exp, 0).ok_or_else(|| Error::JwtInvalid {
            reason: "claim `exp` is outside the representable date range".to_string(),
        })?;
        let remaining = exp.saturating_sub(now.timestamp());
        Ok(Expiry {
            at: at.to_rfc3339(),
            // Rounded for DISPLAY only...
            minutes: round_minutes(remaining),
            // ...the verdict comes from the claim itself. Deriving it from
            // the rounded value reported a token with 20 seconds left — one
            // that still authenticates — as EXPIRED, which is exactly the
            // kind of answer that sends a script off to rotate credentials
            // it did not need to touch.
            valid: remaining > 0,
        })
    }

    pub(super) fn render(&self) -> String {
        let at = &self.at;
        let minutes = self.minutes;
        let state = if self.valid { "valid" } else { "EXPIRED" };
        format!("{at} ({minutes} min from now, {state})")
    }
}

pub(super) fn round_minutes(seconds: i64) -> i64 {
    (seconds as f64 / 60.0).round() as i64
}

#[derive(Debug)]
pub(super) struct AuthStatusView {
    auth_file: PathBuf,
    auth_mode: Option<String>,
    account_id: Option<String>,
    last_refresh: Option<String>,
    expiry: Expiry,
}

impl AuthStatusView {
    pub(super) fn new(
        auth: &AuthFile,
        auth_file: PathBuf,
        now: DateTime<Utc>,
    ) -> Result<Self, Error> {
        let expiry = Expiry::of_access_token(auth, &auth_file, now)?;
        Ok(AuthStatusView {
            auth_mode: auth.auth_mode.clone(),
            account_id: auth
                .tokens
                .as_ref()
                .and_then(|tokens| tokens.account_id.clone()),
            last_refresh: auth.last_refresh.clone(),
            auth_file,
            expiry,
        })
    }

    pub(super) fn render(&self) -> String {
        let path = self.auth_file.display();
        let mode = self.auth_mode.as_deref().unwrap_or(ABSENT);
        let account_id = self.account_id.as_deref().unwrap_or(ABSENT);
        let last_refresh = self.last_refresh.as_deref().unwrap_or(ABSENT);
        let expiry = self.expiry.render();

        // Label spelling is frozen, trailing space before the colon
        // included: users and scripts have been grepping this output, and
        // a prettier column is not worth breaking them.
        let mut text = String::new();
        text.push_str(&format!("auth file : {path}\n"));
        text.push_str(&format!("auth_mode : {mode}\n"));
        text.push_str(&format!("account_id: {account_id}\n"));
        text.push_str(&format!("last_refresh: {last_refresh}\n"));
        text.push_str(&format!("access_token expires: {expiry}\n"));
        text
    }

    pub(super) fn to_json(&self) -> Value {
        json!({
            "auth_file": self.auth_file.display().to_string(),
            "auth_mode": self.auth_mode,
            "account_id": self.account_id,
            "last_refresh": self.last_refresh,
            "access_token_expires_at": self.expiry.at,
            "access_token_expires_in_minutes": self.expiry.minutes,
            "access_token_valid": self.expiry.valid,
        })
    }
}

#[derive(Debug)]
pub(super) struct RefreshView {
    expiry: Expiry,
    last_refresh: Option<String>,
}

impl RefreshView {
    pub(super) fn new(auth: &AuthFile, path: &Path, now: DateTime<Utc>) -> Result<Self, Error> {
        Ok(RefreshView {
            expiry: Expiry::of_access_token(auth, path, now)?,
            last_refresh: auth.last_refresh.clone(),
        })
    }

    pub(super) fn render(&self) -> String {
        let minutes = self.expiry.minutes;
        let last_refresh = self.last_refresh.as_deref().unwrap_or(ABSENT);
        format!("refreshed. new access token valid ~{minutes} min; last_refresh={last_refresh}\n")
    }

    pub(super) fn to_json(&self) -> Value {
        json!({
            "refreshed": true,
            "access_token_expires_at": self.expiry.at,
            "access_token_expires_in_minutes": self.expiry.minutes,
            "access_token_valid": self.expiry.valid,
            "last_refresh": self.last_refresh,
        })
    }
}
