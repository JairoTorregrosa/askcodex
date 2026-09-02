//! Streaming text completion over `POST /codex/responses`.
//!
//! Layering: `sse.rs` (frozen) turns bytes into `data:` frames and decides
//! nothing; `models::ResponsesSseEvent::classify` (frozen) names one event;
//! THIS module owns the pipeline that sits on top — accumulate, terminate,
//! fail — and it is the only layer allowed to decide that a stream is
//! finished or broken.

use std::io::BufRead;

use serde_json::Value;
use ureq::http::Method;

use crate::config;
use crate::error::Error;
use crate::http::Client;
use crate::models::{ResponsesRequest, ResponsesSseEvent};
use crate::sse::SseParser;

/// Backend path of the responses endpoint. Relative: `Client` prefixes
/// `config::BASE_URL`, giving
/// `https://chatgpt.com/backend-api/codex/responses` (verified live
/// 2026-08-07, docs/PROTOCOL.md §3.7).
const RESPONSES_PATH: &str = "/codex/responses";

/// Detail of the "the stream stopped early" error. Byte-exact on purpose:
/// DESIGN.md makes `Display` strings part of the contract.
const NO_COMPLETED_DETAIL: &str = "stream ended without response.completed";

/// A completed answer: the accumulated text, plus the `response.usage`
/// object (token counts) from the terminal `response.completed` event when
/// the backend sent one. `usage` is kept as raw JSON so no key the backend
/// adds is ever dropped, and it is `None` — never a zeroed struct — when
/// the event carried no usage object.
#[derive(Debug, Clone, PartialEq)]
pub struct AskAnswer {
    pub text: String,
    pub usage: Option<Value>,
}

/// Stream a completion and return the full accumulated text.
///
/// Contract:
/// - `Client::request_stream(POST, "/codex/responses", body)` — that layer
///   adds `Accept: text/event-stream` and `OpenAI-Beta:
///   responses=experimental`. The request MUST have `stream: true` and
///   `store: false` (`models::ResponsesRequest::user_text` guarantees it).
/// - Frames come from `sse::SseParser`; each `data:` payload is parsed as
///   JSON (a payload that fails to parse aborts loudly — see the amendment
///   below) and classified via `models::ResponsesSseEvent::classify`:
///   - `OutputTextDelta(d)`: invoke `on_delta(&d)` IMMEDIATELY (this is
///     the live-typing UX; run.rs prints to stdout and flushes in text
///     mode, or accumulates silently in `--json` mode), and append to the
///     result.
///   - `Completed { raw }`: stop consuming, return the accumulated text
///     plus the event's `response.usage` object if present.
///   - `Error { raw }` -> `Error::SseStream` with the raw event truncated
///     to `config::ERROR_SNIPPET_BYTES`.
///   - `Other`: ignore (forward compatibility — an event type this build
///     has never seen must not break a stream that otherwise completes).
/// - Stream ends WITHOUT `Completed` -> `Error::SseStream { detail:
///   "stream ended without response.completed" }` — a truncated answer
///   must never be returned as a complete one.
///
/// AMENDED CONTRACT — a malformed `data:` payload is an ERROR, not a skip.
/// The stub of this function claimed a payload that fails to parse is
/// "SKIPPED — Python parity, declared in docs/PROTOCOL.md". docs/PROTOCOL.md
/// declares no such rule: its §4 parser spec lists accumulate / terminate /
/// raise-loudly-on-failure / ignore-unrecognized-types and says nothing
/// about malformed JSON. The frozen sse.rs states the opposite twice — a
/// payload is handed over verbatim, "malformed JSON included — so the
/// caller can fail loudly on it instead of this layer silently swallowing
/// it". Skipping a malformed payload and continuing is exactly the
/// failure masking this project forbids: the backend emits one complete
/// JSON document per `data:` line (verified live), so a payload that does
/// not parse means the wire contract is already broken and the answer being
/// assembled is no longer trustworthy. It therefore aborts.
///
/// The event type of a malformed payload is deliberately NOT sniffed:
/// `SseParser` drops `event:` lines (the type is repeated inside the JSON),
/// so "was that a delta?" is unanswerable for a payload that does not
/// parse, and a substring guess would be a heuristic dressed as a fact.
/// Ignoring unknown event types is untouched by this — that rule is about
/// well-formed JSON that `classify` files as `Other`.
pub fn ask(
    client: &mut Client,
    request: &ResponsesRequest,
    on_delta: &mut dyn FnMut(&str),
) -> Result<AskAnswer, Error> {
    ask_at(client, RESPONSES_PATH, request, on_delta)
}

/// [`ask`] against an explicit path.
///
/// The path is a parameter for exactly one reason: the tests below aim it
/// at a local httpmock server instead of the real backend. It stays private
/// and `ask` is the only caller in the shipped binary, so this is a test
/// seam, not a configuration knob that could send credentials somewhere
/// unexpected.
fn ask_at(
    client: &mut Client,
    path: &str,
    request: &ResponsesRequest,
    on_delta: &mut dyn FnMut(&str),
) -> Result<AskAnswer, Error> {
    // `store: false` and `stream: true` are structural in ResponsesRequest
    // (frozen); serialization drops `instructions`/`reasoning` when the
    // user supplied neither, so askcodex never sends a key it did not mean.
    let body = serde_json::to_value(request)?;
    // A non-2xx status is a hard error raised here, before a single stream
    // byte is read (http.rs owns that, including the one-shot 401 retry).
    let reader = client.request_stream(Method::POST, path, Some(&body))?;
    consume_stream(reader, on_delta)
}

/// The event-level pipeline: accumulate, terminate, fail.
///
/// Split from the transport so it can be driven by any `BufRead`. That is
/// what makes incremental delivery provable offline: a test can watch how
/// many bytes the reader has served at the moment each delta reaches
/// `on_delta`.
fn consume_stream<R: BufRead>(
    reader: R,
    on_delta: &mut dyn FnMut(&str),
) -> Result<AskAnswer, Error> {
    let mut text = String::new();

    for item in SseParser::new(reader) {
        // A read failure propagates verbatim as `Error::Io`: a
        // half-delivered stream must never be dressed up as a whole one,
        // and re-wrapping it would only hide which layer broke.
        let sse_frame = item?;

        let event: Value = serde_json::from_str(&sse_frame.data).map_err(|source| {
            let payload = snippet(&sse_frame.data);
            Error::SseStream {
                detail: format!("malformed JSON on a data: line ({source}): {payload}"),
            }
        })?;

        match ResponsesSseEvent::classify(&event) {
            // Handed over BEFORE the outcome of the stream is known: this
            // is the live-typing UX, and it is why nothing here buffers.
            // A delta event whose `delta` is absent classifies as an empty
            // string; it contributes nothing rather than inventing text.
            ResponsesSseEvent::OutputTextDelta(delta) => {
                on_delta(&delta);
                text.push_str(&delta);
            }
            // Terminal: stop consuming immediately. Anything the backend
            // sends after this is not part of the answer. `usage` rides
            // along raw when the event carries an object there; a missing
            // or null field stays None instead of becoming zeroes.
            ResponsesSseEvent::Completed { raw } => {
                let usage = raw
                    .get("response")
                    .and_then(|response| response.get("usage"))
                    .filter(|usage| !usage.is_null())
                    .cloned();
                return Ok(AskAnswer { text, usage });
            }
            ResponsesSseEvent::Error { raw } => {
                return Err(Error::SseStream {
                    detail: snippet(&raw.to_string()),
                });
            }
            ResponsesSseEvent::Other => {}
        }
    }

    // Frames ran out with no `response.completed`. Whatever text was
    // accumulated is a fragment, and returning it would be the exact
    // failure-masking this project forbids.
    Err(Error::SseStream {
        detail: NO_COMPLETED_DETAIL.to_string(),
    })
}

/// At most `config::ERROR_SNIPPET_BYTES` bytes of `s`, cut on a char
/// boundary.
///
/// `str::floor_char_boundary` is still unstable and slicing at a raw byte
/// index would panic mid-codepoint on the emoji these streams happily
/// carry, so the boundary is walked back by hand.
fn snippet(s: &str) -> String {
    if s.len() <= config::ERROR_SNIPPET_BYTES {
        return s.to_string();
    }
    let mut end = config::ERROR_SNIPPET_BYTES;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

// Offline isolation: every test below talks to a local `httpmock` server or
// to an in-memory `Cursor`. The credentials are invented literals held in
// memory, no test performs filesystem I/O, no test mutates `CODEX_HOME`
// (it is process-wide and the auth.rs tests rely on their own value), and
// no code path here can reach the real `~/.codex` or the real backend.
#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::io::{BufReader, Cursor, Read};
    use std::rc::Rc;

    // Only the method constant is imported: httpmock also exports a
    // `Method` type and a glob import would shadow ureq's.
    use httpmock::Method::POST;
    use httpmock::MockServer;
    use serde_json::json;

    use super::*;
    use crate::models::{AuthFile, AuthTokens};
    use crate::redact::Secret;

    /// Invented, non-functional credential values.
    const FAKE_ACCESS_TOKEN: &str = "fake.access.token-AAA";
    const FAKE_ACCOUNT_ID: &str = "acct_fake_0000";

    // -----------------------------------------------------------------
    // Fixtures
    // -----------------------------------------------------------------

    /// The REAL captured stream, verbatim. It ends at a bare
    /// `event: response.completed` line with no `data:` line because the
    /// capture was cut short — so the file as it stands is precisely the
    /// truncated-stream fixture, and the happy path is this plus the
    /// terminal payload the capture never delivered.
    const LIVE_TRACE: &str = include_str!("../../docs/samples/responses-sse.txt");

    /// SYNTHESIZED: reconstructed from docs/PROTOCOL.md §4, since the
    /// capture stops before the terminal event's `data:` line.
    const COMPLETED: &str = r#"{"type":"response.completed","response":{"id":"resp_REDACTED","object":"response","status":"completed"},"sequence_number":13}"#;

    /// The answer the live run streamed, in six deltas.
    const LIVE_ANSWER: &str = "ASKCODEX-VERIFY-OK";
    const LIVE_DELTAS: [&str; 6] = ["ASK", "CODEX", "-", "VERIFY", "-", "OK"];

    /// One wire frame: `event:` line, `data:` line, blank line.
    fn frame(event: &str, data: &str) -> String {
        format!("event: {event}\ndata: {data}\n\n")
    }

    /// A delta frame shaped like the captured ones.
    fn delta_frame(text: &str, sequence_number: u64) -> String {
        let data = json!({
            "type": "response.output_text.delta",
            "content_index": 0,
            "delta": text,
            "item_id": "msg_REDACTED",
            "logprobs": [],
            "output_index": 0,
            "sequence_number": sequence_number,
        })
        .to_string();
        frame("response.output_text.delta", &data)
    }

    fn completed_frame() -> String {
        frame("response.completed", COMPLETED)
    }

    /// The live capture completed: the raw trace (which ends with the
    /// bare `event: response.completed` line, no trailing newline) plus the
    /// `data:` line it was missing.
    fn happy_stream() -> String {
        format!("{LIVE_TRACE}\ndata: {COMPLETED}\n\n")
    }

    fn auth_file() -> AuthFile {
        AuthFile {
            auth_mode: Some("chatgpt".to_string()),
            tokens: Some(AuthTokens {
                id_token: None,
                access_token: Some(Secret::new(FAKE_ACCESS_TOKEN)),
                // No refresh token AND `no_refresh` below: a refresh is
                // doubly impossible from these tests.
                refresh_token: None,
                account_id: Some(FAKE_ACCOUNT_ID.to_string()),
                extra: serde_json::Map::new(),
            }),
            last_refresh: None,
            extra: serde_json::Map::new(),
        }
    }

    /// A client that can never refresh: `no_refresh` disables the
    /// pre-flight refresh and the 401 retry, so nothing here can reach
    /// `auth::refresh` (which would hit auth.openai.com).
    fn client() -> Client {
        Client::new(auth_file(), true).expect("the fake credentials are structurally valid")
    }

    fn prompt() -> ResponsesRequest {
        ResponsesRequest::user_text(config::DEFAULT_ASK_MODEL, "say ASKCODEX-VERIFY-OK", None, None)
    }

    /// Serve `stream` as `text/event-stream` and run `ask_at` against it.
    ///
    /// Returns the result plus one entry per `on_delta` INVOCATION (not per
    /// character), so the call pattern itself is assertable.
    fn run_ask(
        stream: &str,
        request: &ResponsesRequest,
    ) -> (Result<AskAnswer, Error>, Vec<String>) {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/codex/responses");
            then.status(200)
                .header("content-type", "text/event-stream")
                .body(stream);
        });

        let mut deltas: Vec<String> = Vec::new();
        let mut client = client();
        let result = {
            let mut on_delta = |d: &str| deltas.push(d.to_string());
            ask_at(
                &mut client,
                &server.url("/codex/responses"),
                request,
                &mut on_delta,
            )
        };
        (result, deltas)
    }

    fn expect_sse_error(result: Result<AskAnswer, Error>) -> String {
        match result {
            Ok(answer) => panic!("expected a loud error, got Ok({answer:?})"),
            Err(Error::SseStream { detail }) => detail,
            Err(other) => panic!("expected Error::SseStream, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // Happy path
    // -----------------------------------------------------------------

    #[test]
    fn happy_path_returns_the_live_answer_and_pushes_each_delta_separately() {
        let (result, deltas) = run_ask(&happy_stream(), &prompt());

        let answer = result.unwrap();
        assert_eq!(answer.text, LIVE_ANSWER);
        // The fixture's completed event carries no `usage` object, so the
        // field is absent — None, never a zeroed struct.
        assert_eq!(answer.usage, None);
        // Six invocations in wire order: a buffered implementation would
        // have produced one call with the whole answer.
        assert_eq!(deltas, LIVE_DELTAS.map(String::from).to_vec());
    }

    #[test]
    fn a_usage_object_on_the_completed_event_rides_through_verbatim() {
        // Unknown keys (`future_counter`) must survive: the object is
        // returned raw, never decoded into a struct that drops fields.
        let usage = json!({
            "input_tokens": 12,
            "output_tokens": 7,
            "total_tokens": 19,
            "future_counter": {"x": 1}
        });
        let completed = json!({
            "type": "response.completed",
            "response": {"id": "resp_REDACTED", "status": "completed", "usage": usage},
            "sequence_number": 13
        });
        let stream = format!("{LIVE_TRACE}\ndata: {completed}\n\n");

        let (result, _) = run_ask(&stream, &prompt());
        let answer = result.unwrap();
        assert_eq!(answer.text, LIVE_ANSWER);
        assert_eq!(answer.usage, Some(usage));
    }

    #[test]
    fn a_null_usage_on_the_completed_event_is_absent_not_an_object() {
        let completed = json!({
            "type": "response.completed",
            "response": {"id": "resp_REDACTED", "status": "completed", "usage": null},
            "sequence_number": 13
        });
        let stream = format!("{LIVE_TRACE}\ndata: {completed}\n\n");

        let (result, _) = run_ask(&stream, &prompt());
        assert_eq!(result.unwrap().usage, None);
    }

    #[test]
    fn the_endpoint_path_is_the_verified_one() {
        assert_eq!(RESPONSES_PATH, "/codex/responses");
        // `ask` delegates with this path; http.rs resolves it against
        // BASE_URL (it cannot be exercised live from a test — that would
        // mean a real backend call with real credentials).
        assert_eq!(
            format!("{}{RESPONSES_PATH}", config::BASE_URL),
            "https://chatgpt.com/backend-api/codex/responses"
        );
        assert_eq!(
            format!("{}/responses", config::CODEX_BASE_URL),
            "https://chatgpt.com/backend-api/codex/responses"
        );
    }

    // -----------------------------------------------------------------
    // Request shape
    // -----------------------------------------------------------------

    #[test]
    fn the_request_body_is_the_verified_wire_shape_with_store_false() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(POST)
                .path("/codex/responses")
                .header("accept", "text/event-stream")
                .header("openai-beta", "responses=experimental")
                // Exact JSON equality: any extra or missing key fails.
                .json_body(json!({
                    "model": "gpt-5.4-mini",
                    "input": [{
                        "type": "message",
                        "role": "user",
                        "content": [{"type": "input_text", "text": "say ASKCODEX-VERIFY-OK"}],
                    }],
                    "stream": true,
                    "store": false,
                }));
            then.status(200)
                .header("content-type", "text/event-stream")
                .body(happy_stream());
        });

        let mut client = client();
        let request = ResponsesRequest::user_text("gpt-5.4-mini", "say ASKCODEX-VERIFY-OK", None, None);
        let answer = ask_at(
            &mut client,
            &server.url("/codex/responses"),
            &request,
            &mut |_| {},
        )
        .unwrap();

        assert_eq!(answer.text, LIVE_ANSWER);
        mock.assert();
    }

    #[test]
    fn instructions_and_reasoning_are_absent_when_the_user_supplied_neither() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(POST).path("/codex/responses").is_true(|req| {
                let body = String::from_utf8_lossy(req.body_ref()).into_owned();
                !body.contains("instructions") && !body.contains("reasoning")
            });
            then.status(200)
                .header("content-type", "text/event-stream")
                .body(happy_stream());
        });

        let mut client = client();
        ask_at(
            &mut client,
            &server.url("/codex/responses"),
            &prompt(),
            &mut |_| {},
        )
        .unwrap();
        mock.assert();
    }

    #[test]
    fn instructions_and_reasoning_are_sent_when_the_user_supplied_them() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(POST).path("/codex/responses").json_body(json!({
                "model": "gpt-5.6-sol",
                "input": [{
                    "type": "message",
                    "role": "user",
                    "content": [{"type": "input_text", "text": "hi"}],
                }],
                "stream": true,
                "store": false,
                "instructions": "be brief",
                "reasoning": {"effort": "xhigh"},
            }));
            then.status(200)
                .header("content-type", "text/event-stream")
                .body(happy_stream());
        });

        let mut client = client();
        let request = ResponsesRequest::user_text(
            "gpt-5.6-sol",
            "hi",
            Some("be brief".to_string()),
            Some("xhigh".to_string()),
        );
        ask_at(
            &mut client,
            &server.url("/codex/responses"),
            &request,
            &mut |_| {},
        )
        .unwrap();
        mock.assert();
    }

    // -----------------------------------------------------------------
    // Incremental delivery
    // -----------------------------------------------------------------

    /// A `Read` that counts the bytes it has handed out.
    struct CountingReader<R> {
        inner: R,
        served: Rc<Cell<usize>>,
    }

    impl<R: Read> Read for CountingReader<R> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.inner.read(buf)?;
            self.served.set(self.served.get() + n);
            Ok(n)
        }
    }

    #[test]
    fn deltas_reach_the_caller_while_the_body_is_still_arriving() {
        let stream = happy_stream();
        let total = stream.len();
        let served = Rc::new(Cell::new(0usize));
        // 64-byte buffer: the reader is refilled hundreds of times, so the
        // byte counter is a fine-grained clock over the body.
        let reader = BufReader::with_capacity(
            64,
            CountingReader {
                inner: Cursor::new(stream.into_bytes()),
                served: Rc::clone(&served),
            },
        );

        let mut seen: Vec<(String, usize)> = Vec::new();
        let answer = {
            let mut on_delta = |d: &str| seen.push((d.to_string(), served.get()));
            consume_stream(reader, &mut on_delta).unwrap()
        };

        assert_eq!(answer.text, LIVE_ANSWER);
        assert_eq!(seen.len(), 6);
        // The decisive assertion: the FIRST delta was delivered while most
        // of the body had not been read yet. An implementation that
        // buffered the response before parsing could not do this.
        assert!(
            seen[0].1 < total,
            "first delta at {} bytes served of {total}",
            seen[0].1
        );
        // ...and delivery keeps pace with the reader instead of happening
        // in one burst at the end.
        assert!(seen[0].1 < seen[5].1, "deltas must not arrive together");
        assert!(
            seen[5].1 < total,
            "the last delta precedes the tail events of the stream"
        );
        assert!(seen.windows(2).all(|w| w[0].1 <= w[1].1));
    }

    // -----------------------------------------------------------------
    // Failure events
    // -----------------------------------------------------------------

    #[test]
    fn response_failed_mid_stream_aborts_loudly_after_the_deltas_were_delivered() {
        let failed = r#"{"type":"response.failed","response":{"id":"resp_REDACTED","status":"failed","error":{"code":"server_error","message":"boom"}},"sequence_number":6}"#;
        let stream = format!(
            "{}{}{}",
            delta_frame("ASK", 4),
            delta_frame("CODEX", 5),
            frame("response.failed", failed),
        );

        let (result, deltas) = run_ask(&stream, &prompt());

        let detail = expect_sse_error(result);
        assert!(detail.contains("server_error"), "detail was {detail:?}");
        assert!(detail.contains("boom"), "detail was {detail:?}");
        // Deltas were pushed before the outcome was known — and the
        // fragment is still NOT returned as an answer.
        assert_eq!(deltas, vec!["ASK".to_string(), "CODEX".to_string()]);
    }

    #[test]
    fn every_failure_event_name_aborts() {
        for name in ["response.failed", "response.error", "error"] {
            let event =
                json!({"type": name, "code": "rate_limit_exceeded", "message": "slow down"})
                    .to_string();
            let stream = format!("{}{}", delta_frame("ASK", 4), frame(name, &event));

            let detail = expect_sse_error(run_ask(&stream, &prompt()).0);
            assert!(
                detail.contains("rate_limit_exceeded"),
                "{name}: detail was {detail:?}"
            );
        }
    }

    #[test]
    fn an_oversized_failure_event_is_truncated_on_a_char_boundary() {
        // 600 two-byte characters: the raw event is far past the snippet
        // bound and byte 400 lands inside a codepoint.
        let message = "é".repeat(600);
        let event = json!({"type": "response.failed", "message": message});
        let raw = event.to_string();
        assert!(raw.len() > config::ERROR_SNIPPET_BYTES);
        let stream = frame("response.failed", &raw);

        let detail = expect_sse_error(run_ask(&stream, &prompt()).0);

        assert!(detail.len() <= config::ERROR_SNIPPET_BYTES);
        // Nothing was reshaped or re-encoded: the snippet is a genuine
        // prefix of the event, cut back to the nearest char boundary.
        assert!(raw.starts_with(&detail));
        assert!(detail.len() > config::ERROR_SNIPPET_BYTES - 4);
    }

    #[test]
    fn a_non_2xx_post_is_a_hard_error_and_never_a_stream() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(POST).path("/codex/responses");
            then.status(429).body(r#"{"error":"rate limited"}"#);
        });

        let mut client = client();
        let result = ask_at(
            &mut client,
            &server.url("/codex/responses"),
            &prompt(),
            &mut |_| panic!("no delta may be produced for a failed request"),
        );

        match result {
            Err(Error::HttpStatus {
                status, snippet, ..
            }) => {
                assert_eq!(status, 429);
                assert_eq!(snippet, r#"{"error":"rate limited"}"#);
            }
            other => panic!("expected HttpStatus, got {other:?}"),
        }
        assert_eq!(mock.calls(), 1, "no retry loop");
    }

    // -----------------------------------------------------------------
    // Truncation and malformed payloads
    // -----------------------------------------------------------------

    #[test]
    fn a_stream_that_ends_without_completed_is_an_error_not_a_short_answer() {
        // The raw capture: every delta of the live answer, then the wire
        // stops before the terminal event's payload.
        let (result, deltas) = run_ask(LIVE_TRACE, &prompt());

        assert_eq!(expect_sse_error(result), NO_COMPLETED_DETAIL);
        assert_eq!(
            "responses stream error: stream ended without response.completed",
            Error::SseStream {
                detail: NO_COMPLETED_DETAIL.to_string()
            }
            .to_string()
        );
        // The text WAS streamed to the caller, and was still not handed
        // back as a complete answer.
        assert_eq!(deltas.concat(), LIVE_ANSWER);
    }

    #[test]
    fn an_empty_stream_is_an_error() {
        let (result, deltas) = run_ask("", &prompt());
        assert_eq!(expect_sse_error(result), NO_COMPLETED_DETAIL);
        assert!(deltas.is_empty());
    }

    #[test]
    fn malformed_json_on_a_data_line_aborts_instead_of_being_skipped() {
        // A truncated delta payload: the one case where skipping would
        // silently drop part of the answer.
        let broken = r#"{"type":"response.output_text.delta","delta":"CODEX"#;
        let stream = format!(
            "{}{}{}{}",
            delta_frame("ASK", 4),
            frame("response.output_text.delta", broken),
            delta_frame("OK", 6),
            completed_frame(),
        );

        let (result, deltas) = run_ask(&stream, &prompt());

        let detail = expect_sse_error(result);
        assert!(
            detail.contains("malformed JSON on a data: line"),
            "detail was {detail:?}"
        );
        // The offending payload is quoted so the failure is diagnosable.
        assert!(detail.contains(r#""delta":"CODEX"#), "detail was {detail:?}");
        // Consumption stopped there: the later delta never reached the
        // caller and no partial answer was returned.
        assert_eq!(deltas, vec!["ASK".to_string()]);
    }

    #[test]
    fn a_malformed_payload_of_any_event_type_aborts() {
        // The event type of an unparseable payload is unknowable (the
        // `event:` line is dropped at framing), so the policy is a
        // superset: every malformed payload is loud, whatever it claims
        // to be.
        for broken in [
            r#"{"type":"response.completed""#,
            r#"{"type":"response.some.future.event","x":"#,
            "not json at all",
            "{",
        ] {
            let stream = format!(
                "{}{}{}",
                delta_frame("ASK", 4),
                frame("response.unknown", broken),
                completed_frame(),
            );
            let detail = expect_sse_error(run_ask(&stream, &prompt()).0);
            assert!(
                detail.contains("malformed JSON on a data: line"),
                "{broken:?}: detail was {detail:?}"
            );
        }
    }

    #[test]
    fn an_oversized_malformed_payload_is_quoted_within_the_snippet_bound() {
        let broken = format!(
            r#"{{"type":"response.output_text.delta","delta":"{}"#,
            "x".repeat(2000)
        );
        let stream = frame("response.output_text.delta", &broken);

        let detail = expect_sse_error(run_ask(&stream, &prompt()).0);

        assert!(detail.contains("malformed JSON on a data: line"));
        // The quoted payload is bounded even though the prefix text is not
        // part of that budget.
        assert!(detail.len() < broken.len());
        assert!(!detail.contains(&"x".repeat(500)));
    }

    // -----------------------------------------------------------------
    // Forward compatibility
    // -----------------------------------------------------------------

    #[test]
    fn unknown_event_types_are_ignored() {
        let future = r#"{"type":"response.reasoning_summary.delta","delta":"thinking out loud","sequence_number":99}"#;
        let untyped = r#"{"sequence_number":100,"delta":"no type field"}"#;
        let stream = format!(
            "{}{}{}{}{}",
            delta_frame("ASK", 4),
            frame("response.some.future.event", future),
            frame("response.weird", untyped),
            delta_frame("CODEX", 5),
            completed_frame(),
        );

        let (result, deltas) = run_ask(&stream, &prompt());

        assert_eq!(result.unwrap().text, "ASKCODEX");
        // Crucially, the unknown events' own `delta` fields were NOT
        // mistaken for answer text.
        assert_eq!(deltas, vec!["ASK".to_string(), "CODEX".to_string()]);
    }

    #[test]
    fn a_done_sentinel_is_tolerated_if_it_ever_appears() {
        // The subscription backend does not emit `[DONE]` (verified live);
        // termination never depends on it, and its presence must not break
        // a stream that completes normally.
        let stream = format!(
            "{}data: [DONE]\n\n{}",
            delta_frame("ASK", 4),
            completed_frame(),
        );

        let (result, deltas) = run_ask(&stream, &prompt());
        assert_eq!(result.unwrap().text, "ASK");
        assert_eq!(deltas, vec!["ASK".to_string()]);
    }

    #[test]
    fn nothing_after_response_completed_is_consumed() {
        let stream = format!(
            "{}{}{}",
            delta_frame("ASK", 4),
            completed_frame(),
            delta_frame("MUST NOT APPEAR", 99),
        );

        let (result, deltas) = run_ask(&stream, &prompt());
        assert_eq!(result.unwrap().text, "ASK");
        assert_eq!(deltas, vec!["ASK".to_string()]);
    }

    // -----------------------------------------------------------------
    // Payload fidelity
    // -----------------------------------------------------------------

    #[test]
    fn newlines_unicode_and_emoji_survive_byte_exact() {
        let pieces = [
            "line1\nline2\ttab \"quoted\" back\\slash",
            " café 中文 🚀 ",
            "\u{1f600}\u{0007}end\n",
        ];
        let mut stream = String::new();
        for (i, piece) in pieces.iter().enumerate() {
            stream.push_str(&delta_frame(piece, 4 + i as u64));
        }
        stream.push_str(&completed_frame());

        let (result, deltas) = run_ask(&stream, &prompt());

        assert_eq!(result.unwrap().text, pieces.concat());
        assert_eq!(deltas, pieces.map(String::from).to_vec());
    }

    // -----------------------------------------------------------------
    // Reader failures
    // -----------------------------------------------------------------

    /// A `Read` that serves its buffer and then fails, the way a dropped
    /// connection mid-stream does.
    struct BreakingReader {
        inner: Cursor<Vec<u8>>,
    }

    impl Read for BreakingReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.inner.read(buf)?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "connection reset mid-stream",
                ));
            }
            Ok(n)
        }
    }

    #[test]
    fn a_broken_connection_surfaces_as_io_and_never_as_a_finished_answer() {
        let stream = format!("{}{}", delta_frame("ASK", 4), delta_frame("CODEX", 5));
        let reader = BufReader::new(BreakingReader {
            inner: Cursor::new(stream.into_bytes()),
        });

        let mut deltas: Vec<String> = Vec::new();
        let result = {
            let mut on_delta = |d: &str| deltas.push(d.to_string());
            consume_stream(reader, &mut on_delta)
        };

        match result {
            Err(Error::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::ConnectionReset),
            other => panic!("expected Error::Io, got {other:?}"),
        }
        assert_eq!(deltas, vec!["ASK".to_string(), "CODEX".to_string()]);
    }

    // -----------------------------------------------------------------
    // snippet()
    // -----------------------------------------------------------------

    #[test]
    fn snippet_is_bounded_and_never_splits_a_codepoint() {
        assert_eq!(snippet("short"), "short");
        assert_eq!(snippet(""), "");

        let ascii = "x".repeat(config::ERROR_SNIPPET_BYTES * 2);
        assert_eq!(snippet(&ascii).len(), config::ERROR_SNIPPET_BYTES);

        // Exactly at the bound: untouched.
        let exact = "y".repeat(config::ERROR_SNIPPET_BYTES);
        assert_eq!(snippet(&exact), exact);

        // 4-byte codepoints: the cut walks back to a boundary, so the
        // result is always valid UTF-8 and a true prefix.
        let emoji = "🚀".repeat(500);
        let cut = snippet(&emoji);
        assert!(cut.len() <= config::ERROR_SNIPPET_BYTES);
        assert!(emoji.starts_with(&cut));
        assert!(cut.len() >= config::ERROR_SNIPPET_BYTES - 3);
        assert!(cut.chars().all(|c| c == '🚀'));
    }
}
