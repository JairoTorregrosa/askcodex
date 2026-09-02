//! SSE framing over any `BufRead` (transport-agnostic; http.rs provides
//! the live reader, tests provide cursors over fixture bytes).
//!
//! Framing rules (validated against the live backend, and re-verified
//! against a mocked stream):
//! - The stream is consumed line by line (`\n`; a trailing `\r` is
//!   stripped).
//! - Only lines starting with `data:` carry payloads. The payload is the
//!   rest of the line with surrounding whitespace trimmed.
//! - Empty payloads and the literal `[DONE]` are dropped (keep-alive /
//!   terminator noise, not events).
//! - `event:`, `id:`, `retry:` lines and comment lines (`:`) are ignored:
//!   the backend repeats the event type inside the JSON payload.
//! - Multi-line `data:` coalescing (SSE spec) is NOT implemented: the
//!   backend emits exactly one complete JSON document per `data:` line.
//!   VERIFIED ASSUMPTION — declared in docs/PROTOCOL.md; if a payload ever
//!   fails to parse as JSON downstream, the error must surface loudly, not
//!   be coalesced away.
//! - An I/O error from the underlying reader surfaces as `Err` — a
//!   half-delivered stream must never look like a complete one. (End-of-
//!   stream detection is the CALLER's duty: responses.rs errors loudly if
//!   the frames end without `response.completed`.)
//!
//! Scope note: this module is framing ONLY. It never parses JSON, never
//! interprets an event type, and never decides that a stream is finished.
//! Event semantics live in `models::ResponsesSseEvent::classify` (frozen)
//! and the accumulate/terminate/fail policy lives in
//! `endpoints::responses::ask`. A payload is handed to the caller exactly
//! as it arrived on the wire — malformed JSON included — so the caller can
//! fail loudly on it instead of this layer silently swallowing it.

use std::io::BufRead;

use crate::error::Error;

/// The SSE terminator sentinel of the OpenAI API-key path. The
/// subscription backend does NOT emit it (verified live 2026-08-07: absent
/// from the whole stream), but it is dropped rather than surfaced as a
/// frame so a future backend change cannot inject `[DONE]` into a caller
/// that expects JSON. Termination never depends on it.
const DONE_SENTINEL: &str = "[DONE]";

/// One SSE data frame: the payload of a single `data:` line, whitespace-
/// trimmed, guaranteed non-empty and not `[DONE]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseFrame {
    pub data: String,
}

/// Iterator of [`SseFrame`]s over a line-based reader.
pub struct SseParser<R: BufRead> {
    reader: R,
    /// Set at clean end-of-stream and on the first read error. A reader
    /// that has failed is never polled again, which is what makes the
    /// "one `Err`, then `None`" part of the contract hold instead of
    /// looping on a permanently broken reader. Private: the public surface
    /// stays `new` + `Iterator`.
    done: bool,
}

impl<R: BufRead> SseParser<R> {
    /// Wrap a reader. Consumes nothing until iteration starts.
    pub fn new(reader: R) -> Self {
        SseParser {
            reader,
            done: false,
        }
    }
}

impl<R: BufRead> Iterator for SseParser<R> {
    type Item = Result<SseFrame, Error>;

    /// Contract:
    /// - Returns `Some(Ok(frame))` for each `data:` payload that survives
    ///   the framing rules above, in stream order, as soon as its line
    ///   arrives (no buffering of the whole stream).
    /// - Returns `Some(Err(Error::Io(..)))` on a read error, then `None`.
    /// - Returns `None` at clean end-of-stream.
    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        // One heap buffer per frame, reused across the ignored lines
        // (`event:`, blank, comments) that precede the next payload.
        let mut line = String::new();
        loop {
            line.clear();
            match self.reader.read_line(&mut line) {
                // Clean end of stream. Whether ending HERE was legal is the
                // caller's judgement (responses.rs requires a preceding
                // `response.completed`), not this layer's.
                Ok(0) => {
                    self.done = true;
                    return None;
                }
                Ok(_) => {}
                // A half-delivered stream must never look like a complete
                // one: surface the error and stop. No retry, no "continue
                // with what we have" — that is exactly the failure masking
                // this project forbids.
                Err(e) => {
                    self.done = true;
                    return Some(Err(Error::Io(e)));
                }
            }

            // Strip the line terminator only: `\n`, plus a `\r` in front of
            // it if the backend ever switches to CRLF (the live trace is
            // LF). A final line without a terminator is still a line.
            let content = line.strip_suffix('\n').unwrap_or(line.as_str());
            let content = content.strip_suffix('\r').unwrap_or(content);

            // `event:`, `id:`, `retry:`, comments (`:`) and blank keep-alive
            // lines carry no payload; the event type is repeated inside the
            // JSON, so nothing is lost by ignoring them.
            let Some(payload) = content.strip_prefix("data:") else {
                continue;
            };
            let payload = payload.trim();
            if payload.is_empty() || payload == DONE_SENTINEL {
                continue;
            }

            return Some(Ok(SseFrame {
                data: payload.to_string(),
            }));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ResponsesSseEvent;
    use serde_json::Value;
    use std::cell::Cell;
    use std::io::{BufReader, Cursor, Read};
    use std::rc::Rc;

    // -----------------------------------------------------------------
    // Fixtures. Payloads below are verbatim (already-redacted) lines from
    // the live capture in docs/samples/responses-sse.txt unless a comment
    // says otherwise. Nothing here reads the filesystem, the network, or
    // any environment variable, so no test in this module can reach the
    // real ~/.codex.
    // -----------------------------------------------------------------

    /// Build one wire frame: `event:` line, `data:` line, blank line, LF.
    fn frame(event: &str, data: &str) -> String {
        format!("event: {event}\ndata: {data}\n\n")
    }

    /// Abbreviated from the capture (the real `response` object is ~1.5 KB
    /// of fields this layer never looks at); shape and key order preserved.
    const CREATED: &str = r#"{"type":"response.created","response":{"id":"resp_REDACTED","object":"response","status":"in_progress","model":"gpt-5.4-mini-2026-03-17","store":false},"sequence_number":0}"#;
    const IN_PROGRESS: &str = r#"{"type":"response.in_progress","response":{"id":"resp_REDACTED","object":"response","status":"in_progress"},"sequence_number":1}"#;
    /// Verbatim from the capture.
    const ITEM_ADDED: &str = r#"{"type":"response.output_item.added","item":{"id":"msg_REDACTED","type":"message","status":"in_progress","content":[],"phase":"final_answer","role":"assistant"},"output_index":0,"sequence_number":2}"#;
    /// Verbatim from the capture.
    const PART_ADDED: &str = r#"{"type":"response.content_part.added","content_index":0,"item_id":"msg_REDACTED","output_index":0,"part":{"type":"output_text","annotations":[],"logprobs":[],"text":""},"sequence_number":3}"#;
    /// Verbatim from the capture.
    const TEXT_DONE: &str = r#"{"type":"response.output_text.done","content_index":0,"item_id":"msg_REDACTED","logprobs":[],"output_index":0,"sequence_number":10,"text":"ASKCODEX-VERIFY-OK"}"#;
    /// Verbatim from the capture.
    const PART_DONE: &str = r#"{"type":"response.content_part.done","content_index":0,"item_id":"msg_REDACTED","output_index":0,"part":{"type":"output_text","annotations":[],"logprobs":[],"text":"ASKCODEX-VERIFY-OK"},"sequence_number":11}"#;
    /// SYNTHESIZED: the live capture stops at the bare
    /// `event: response.completed` line, so its `data:` line is
    /// reconstructed from the shape documented in PROTOCOL.md section 4.
    const COMPLETED: &str = r#"{"type":"response.completed","response":{"id":"resp_REDACTED","object":"response","status":"completed"},"sequence_number":13}"#;

    /// The six deltas of the live verify run, verbatim (they spell
    /// `ASKCODEX-VERIFY-OK`).
    const DELTAS: [(&str, &str); 6] = [
        (
            "ASK",
            r#"{"type":"response.output_text.delta","content_index":0,"delta":"ASK","item_id":"msg_REDACTED","logprobs":[],"obfuscation":"KOCSLZn8MAoh7O","output_index":0,"sequence_number":4}"#,
        ),
        (
            "CODEX",
            r#"{"type":"response.output_text.delta","content_index":0,"delta":"CODEX","item_id":"msg_REDACTED","logprobs":[],"obfuscation":"18k6sU10yv85v0","output_index":0,"sequence_number":5}"#,
        ),
        (
            "-",
            r#"{"type":"response.output_text.delta","content_index":0,"delta":"-","item_id":"msg_REDACTED","logprobs":[],"obfuscation":"iGJDgLwvN3eBMp7","output_index":0,"sequence_number":6}"#,
        ),
        (
            "VERIFY",
            r#"{"type":"response.output_text.delta","content_index":0,"delta":"VERIFY","item_id":"msg_REDACTED","logprobs":[],"obfuscation":"BPhcuaTM8N","output_index":0,"sequence_number":7}"#,
        ),
        (
            "-",
            r#"{"type":"response.output_text.delta","content_index":0,"delta":"-","item_id":"msg_REDACTED","logprobs":[],"obfuscation":"PzTmhMmZWCelzFX","output_index":0,"sequence_number":8}"#,
        ),
        (
            "OK",
            r#"{"type":"response.output_text.delta","content_index":0,"delta":"OK","item_id":"msg_REDACTED","logprobs":[],"obfuscation":"g2uYi563vB8Clu","output_index":0,"sequence_number":9}"#,
        ),
    ];

    /// The full observed event order for a short completion.
    fn happy_stream() -> String {
        let mut s = String::new();
        s.push_str(&frame("response.created", CREATED));
        s.push_str(&frame("response.in_progress", IN_PROGRESS));
        s.push_str(&frame("response.output_item.added", ITEM_ADDED));
        s.push_str(&frame("response.content_part.added", PART_ADDED));
        for (_, data) in DELTAS {
            s.push_str(&frame("response.output_text.delta", data));
        }
        s.push_str(&frame("response.output_text.done", TEXT_DONE));
        s.push_str(&frame("response.content_part.done", PART_DONE));
        s.push_str(&frame("response.completed", COMPLETED));
        s
    }

    /// Collect every frame, asserting none of them errored.
    fn frames_of(stream: &str) -> Vec<String> {
        SseParser::new(Cursor::new(stream.as_bytes().to_vec()))
            .map(|f| f.expect("framing must not fail on this fixture").data)
            .collect()
    }

    /// Classify frames the way `endpoints::responses::ask` will, so these
    /// tests prove the framing feeds the frozen classifier correctly.
    fn classify_all(stream: &str) -> Vec<ResponsesSseEvent> {
        frames_of(stream)
            .iter()
            .map(|d| {
                let v: Value = serde_json::from_str(d).expect("fixture payload must be JSON");
                ResponsesSseEvent::classify(&v)
            })
            .collect()
    }

    // -----------------------------------------------------------------
    // Happy path
    // -----------------------------------------------------------------

    #[test]
    fn happy_path_yields_every_data_payload_in_stream_order() {
        let frames = frames_of(&happy_stream());
        // 4 preamble + 6 deltas + 3 tail events, and NOT the `event:` lines.
        assert_eq!(frames.len(), 13);
        assert_eq!(frames[0], CREATED);
        assert_eq!(frames[1], IN_PROGRESS);
        assert_eq!(frames[4], DELTAS[0].1);
        assert_eq!(frames[12], COMPLETED);
        assert!(
            frames.iter().all(|f| !f.starts_with("event:")),
            "event: lines must never be framed as payloads"
        );
    }

    #[test]
    fn happy_path_feeds_the_classifier_the_live_answer() {
        let events = classify_all(&happy_stream());
        let mut text = String::new();
        let mut completed = false;
        for ev in &events {
            match ev {
                ResponsesSseEvent::OutputTextDelta(d) => text.push_str(d),
                ResponsesSseEvent::Completed { .. } => completed = true,
                ResponsesSseEvent::Error { .. } => panic!("no error event in this fixture"),
                ResponsesSseEvent::Other => {}
            }
        }
        assert_eq!(text, "ASKCODEX-VERIFY-OK");
        assert!(completed);
        assert!(matches!(
            events.last(),
            Some(ResponsesSseEvent::Completed { .. })
        ));
    }

    #[test]
    fn deltas_split_across_many_frames_stay_separate_and_ordered() {
        // 200 one-character deltas: each `data:` line is its own frame; the
        // parser never merges adjacent frames.
        let word: Vec<char> = "the quick brown fox jumps over the lazy dog"
            .chars()
            .cycle()
            .take(200)
            .collect();
        let mut stream = String::new();
        for (i, c) in word.iter().enumerate() {
            let data = serde_json::json!({
                "type": "response.output_text.delta",
                "delta": c.to_string(),
                "sequence_number": i,
            })
            .to_string();
            stream.push_str(&frame("response.output_text.delta", &data));
        }
        stream.push_str(&frame("response.completed", COMPLETED));

        let events = classify_all(&stream);
        assert_eq!(events.len(), 201);
        let joined: String = events
            .iter()
            .filter_map(|e| match e {
                ResponsesSseEvent::OutputTextDelta(d) => Some(d.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(joined, word.iter().collect::<String>());
    }

    // -----------------------------------------------------------------
    // Forward compatibility and failure events
    // -----------------------------------------------------------------

    #[test]
    fn unknown_event_types_are_framed_and_left_to_the_classifier() {
        // Framing is type-agnostic: an event type this build has never seen
        // is still delivered, and the frozen classifier files it as Other.
        let future = r#"{"type":"response.reasoning_summary.delta","delta":"thinking","sequence_number":99}"#;
        let mut stream = frame("response.created", CREATED);
        stream.push_str(&frame("response.some.future.event", future));
        stream.push_str(&frame("response.output_text.delta", DELTAS[0].1));
        stream.push_str(&frame("response.completed", COMPLETED));

        let frames = frames_of(&stream);
        assert_eq!(frames.len(), 4);
        assert_eq!(frames[1], future);
        assert_eq!(
            classify_all(&stream),
            vec![
                ResponsesSseEvent::Other,
                ResponsesSseEvent::Other,
                ResponsesSseEvent::OutputTextDelta("ASK".into()),
                ResponsesSseEvent::Completed {
                    raw: serde_json::from_str(COMPLETED).unwrap()
                },
            ]
        );
    }

    #[test]
    fn failure_event_mid_stream_is_framed_verbatim_for_a_loud_caller() {
        let failed = r#"{"type":"response.failed","response":{"id":"resp_REDACTED","status":"failed","error":{"code":"server_error","message":"boom"}},"sequence_number":5}"#;
        let mut stream = frame("response.created", CREATED);
        stream.push_str(&frame("response.output_text.delta", DELTAS[0].1));
        stream.push_str(&frame("response.failed", failed));

        let frames = frames_of(&stream);
        assert_eq!(frames.len(), 3);
        // Byte-exact: `ask` truncates this to ERROR_SNIPPET_BYTES for the
        // error message, so nothing may be reshaped here.
        assert_eq!(frames[2], failed);
        let events = classify_all(&stream);
        match &events[2] {
            ResponsesSseEvent::Error { raw } => {
                assert_eq!(raw["response"]["error"]["code"], "server_error");
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn bare_error_event_is_framed_like_any_other_payload() {
        let err = r#"{"type":"error","code":"rate_limit_exceeded","message":"slow down"}"#;
        let stream = frame("error", err);
        assert_eq!(frames_of(&stream), vec![err.to_string()]);
        assert!(matches!(
            classify_all(&stream)[0],
            ResponsesSseEvent::Error { .. }
        ));
    }

    // -----------------------------------------------------------------
    // Truncation and malformed payloads (this layer stays silent; the
    // caller is the one that must fail loudly)
    // -----------------------------------------------------------------

    #[test]
    fn stream_ending_without_completed_ends_cleanly_here() {
        // This is the literal tail of the live capture: the last thing on
        // the wire is a bare `event: response.completed` line with no
        // `data:` line and no trailing blank line. Framing reports clean
        // EOF (no Err) and never fabricates a Completed frame — detecting
        // the truncation is responses.rs's contract, not this module's.
        let mut stream = frame("response.created", CREATED);
        for (_, data) in DELTAS {
            stream.push_str(&frame("response.output_text.delta", data));
        }
        stream.push_str("event: response.completed\n");

        let mut parser = SseParser::new(Cursor::new(stream.into_bytes()));
        let mut count = 0;
        for item in parser.by_ref() {
            item.expect("truncation is not an I/O error");
            count += 1;
        }
        assert_eq!(count, 7); // created + 6 deltas, no completed payload
        assert!(parser.next().is_none(), "iterator stays exhausted");

        let events = classify_all(&{
            let mut s = frame("response.created", CREATED);
            for (_, data) in DELTAS {
                s.push_str(&frame("response.output_text.delta", data));
            }
            s.push_str("event: response.completed\n");
            s
        });
        assert!(
            !events
                .iter()
                .any(|ev| matches!(ev, ResponsesSseEvent::Completed { .. }))
        );
    }

    #[test]
    fn malformed_json_payload_is_delivered_verbatim_not_dropped() {
        // Framing does not parse JSON, so a truncated payload reaches the
        // caller unchanged instead of being silently coalesced or skipped
        // inside this layer.
        let broken = r#"{"type":"response.output_text.delta","delta":"ASK"#;
        let mut stream = frame("response.created", CREATED);
        stream.push_str(&frame("response.output_text.delta", broken));
        stream.push_str(&frame("response.completed", COMPLETED));

        let frames = frames_of(&stream);
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[1], broken);
        assert!(
            serde_json::from_str::<Value>(&frames[1]).is_err(),
            "the fixture must really be malformed"
        );
    }

    #[test]
    fn a_final_line_without_a_newline_is_still_framed() {
        let stream = format!(
            "{}event: response.completed\ndata: {}",
            frame("response.created", CREATED),
            COMPLETED
        );
        assert_eq!(
            frames_of(&stream),
            vec![CREATED.to_string(), COMPLETED.to_string()]
        );
    }

    // -----------------------------------------------------------------
    // Line-level robustness
    // -----------------------------------------------------------------

    #[test]
    fn crlf_line_endings_produce_identical_frames() {
        let lf = happy_stream();
        let crlf = lf.replace('\n', "\r\n");
        assert_eq!(frames_of(&crlf), frames_of(&lf));
        assert!(
            frames_of(&crlf).iter().all(|f| !f.ends_with('\r')),
            "a trailing CR must never survive into a payload"
        );
    }

    #[test]
    fn done_sentinel_blank_payloads_and_non_data_lines_are_dropped() {
        let stream = concat!(
            ": keep-alive comment\n",
            "\n",
            "event: response.created\n",
            "id: 42\n",
            "retry: 3000\n",
            "data: {\"type\":\"response.created\"}\n",
            "\n",
            "data:\n",
            "data:    \n",
            "data: [DONE]\n",
            "data:   [DONE]   \n",
            "\n",
            "data: {\"type\":\"response.completed\"}\n",
            "\n",
        );
        assert_eq!(
            frames_of(stream),
            vec![
                r#"{"type":"response.created"}"#.to_string(),
                r#"{"type":"response.completed"}"#.to_string(),
            ]
        );
    }

    #[test]
    fn payload_is_taken_with_or_without_a_space_after_the_colon() {
        let stream = "data:{\"a\":1}\ndata:   {\"b\":2}   \n";
        assert_eq!(
            frames_of(stream),
            vec![r#"{"a":1}"#.to_string(), r#"{"b":2}"#.to_string()]
        );
    }

    #[test]
    fn a_data_line_is_never_coalesced_with_the_next_line() {
        // Multi-line `data:` continuation is deliberately unimplemented:
        // each `data:` line is one complete document. Two consecutive
        // `data:` lines are two frames, never one concatenated payload.
        let stream = "data: {\"a\":1}\ndata: {\"b\":2}\n\n";
        let frames = frames_of(stream);
        assert_eq!(frames.len(), 2);
        assert!(frames.iter().all(|f| !f.contains("}{")));
    }

    #[test]
    fn escaped_delta_text_survives_byte_exact() {
        let tricky = "line1\nline2\ttab \"quoted\" back\\slash café 中文 🚀 \u{1f600}\u{0007}";
        let data = serde_json::json!({
            "type": "response.output_text.delta",
            "delta": tricky,
            "sequence_number": 4,
        })
        .to_string();
        assert!(
            !data.contains('\n'),
            "serialization must keep the payload on one line"
        );

        let stream = frame("response.output_text.delta", &data);
        let frames = frames_of(&stream);
        assert_eq!(frames[0], data, "payload must arrive byte-identical");
        assert_eq!(
            classify_all(&stream)[0],
            ResponsesSseEvent::OutputTextDelta(tricky.to_string())
        );
    }

    #[test]
    fn surrogate_pair_escapes_pass_through_untouched() {
        // The backend escapes astral-plane characters as UTF-16 surrogate
        // pairs; framing must not normalize or re-encode them.
        let data =
            r#"{"type":"response.output_text.delta","delta":"rocket 🚀 done","sequence_number":4}"#;
        let stream = frame("response.output_text.delta", data);
        assert_eq!(frames_of(&stream)[0], data);
        assert_eq!(
            classify_all(&stream)[0],
            ResponsesSseEvent::OutputTextDelta("rocket 🚀 done".to_string())
        );
    }

    #[test]
    fn a_payload_larger_than_the_reader_buffer_is_framed_whole() {
        let big = "x".repeat(300_000);
        let data = serde_json::json!({
            "type": "response.output_text.delta",
            "delta": big,
        })
        .to_string();
        let stream = frame("response.output_text.delta", &data);
        // 64-byte buffer: the line spans thousands of refills.
        let reader = BufReader::with_capacity(64, Cursor::new(stream.into_bytes()));
        let frames: Vec<String> = SseParser::new(reader).map(|f| f.unwrap().data).collect();
        assert_eq!(frames, vec![data]);
    }

    // -----------------------------------------------------------------
    // Laziness and I/O failure
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
    fn new_consumes_nothing_until_iteration_starts() {
        let served = Rc::new(Cell::new(0usize));
        let reader = BufReader::with_capacity(
            64,
            CountingReader {
                inner: Cursor::new(happy_stream().into_bytes()),
                served: Rc::clone(&served),
            },
        );
        let mut parser = SseParser::new(reader);
        assert_eq!(served.get(), 0, "new() must not touch the reader");
        let first = parser.next().expect("a frame").expect("no error");
        assert_eq!(first.data, CREATED);
        assert!(served.get() > 0);
    }

    /// A `Read` that serves its buffer and then fails, the way a dropped
    /// connection mid-stream does.
    struct BreakingReader {
        inner: Cursor<Vec<u8>>,
        polls_after_eof: Rc<Cell<usize>>,
    }

    impl Read for BreakingReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.inner.read(buf)?;
            if n == 0 {
                self.polls_after_eof.set(self.polls_after_eof.get() + 1);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "connection reset mid-stream",
                ));
            }
            Ok(n)
        }
    }

    #[test]
    fn io_error_surfaces_once_and_then_the_iterator_stops() {
        let mut stream = frame("response.created", CREATED);
        stream.push_str(&frame("response.output_text.delta", DELTAS[0].1));
        let polls = Rc::new(Cell::new(0usize));
        let reader = BufReader::new(BreakingReader {
            inner: Cursor::new(stream.into_bytes()),
            polls_after_eof: Rc::clone(&polls),
        });
        let mut parser = SseParser::new(reader);

        // Frames delivered BEFORE the failure prove incremental parsing:
        // a parser that buffered the whole body first could not have
        // produced them at all.
        assert_eq!(parser.next().unwrap().unwrap().data, CREATED);
        assert_eq!(parser.next().unwrap().unwrap().data, DELTAS[0].1);

        let err = parser
            .next()
            .expect("the failure must surface")
            .unwrap_err();
        match err {
            Error::Io(ref e) => assert_eq!(e.kind(), std::io::ErrorKind::ConnectionReset),
            other => panic!("expected Error::Io, got {other:?}"),
        }
        // The truncated stream must never be mistaken for a complete one:
        // the message says what happened instead of returning None.
        assert!(err.to_string().contains("connection reset mid-stream"));

        assert!(parser.next().is_none(), "one Err, then None");
        assert!(parser.next().is_none(), "and it stays None");
        assert_eq!(polls.get(), 1, "a failed reader is never polled again");
    }

    #[test]
    fn clean_eof_is_none_and_stays_none() {
        let mut parser = SseParser::new(Cursor::new(Vec::new()));
        assert!(parser.next().is_none());
        assert!(parser.next().is_none());
    }
}
