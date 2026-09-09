//! Independently authored output protocol acceptance tests; no auth or network.
use super::*;
use std::{cell::RefCell, io, rc::Rc};

#[derive(Default)]
struct Recording {
    bytes: Vec<u8>,
    flushed_lengths: Vec<usize>,
    closed: bool,
}
struct Sink(Rc<RefCell<Recording>>);
impl Write for Sink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut state = self.0.borrow_mut();
        if state.closed {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "consumer closed"));
        }
        state.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        let mut state = self.0.borrow_mut();
        if state.closed {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "consumer closed"));
        }
        let length = state.bytes.len();
        state.flushed_lengths.push(length);
        Ok(())
    }
}

fn records(state: &Rc<RefCell<Recording>>) -> Vec<Value> {
    let state = state.borrow();
    let text = std::str::from_utf8(&state.bytes).unwrap();
    if !text.is_empty() {
        assert!(text.ends_with('\n'), "incomplete event line");
    }
    text.lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn answer(text: &str) -> endpoints::responses::AskAnswer {
    endpoints::responses::AskAnswer {
        text: text.into(),
        usage: None,
    }
}

#[test]
fn events_are_flushed_incrementally_then_have_one_final_result() {
    let state = Rc::new(RefCell::new(Recording::default()));
    let mut sink = Sink(state.clone());
    let mut err = Vec::new();
    emit_ask(
        Mode::Events,
        "test-model",
        Some("high"),
        &mut sink,
        &mut err,
        |delta| {
            delta("hello ")?;
            assert_eq!(
                records(&state),
                vec![json!({"schema_version":1,"event":"text_delta","delta":"hello "})]
            );
            assert_eq!(state.borrow().flushed_lengths.len(), 1);
            delta("world\n")?;
            let halfway = records(&state);
            assert_eq!(halfway.len(), 2);
            assert_eq!(halfway[1]["delta"], "world\n");
            assert!(halfway.iter().all(|v| v["event"] == "text_delta"));
            assert_eq!(state.borrow().flushed_lengths.len(), 2);
            Ok(answer("hello world\n"))
        },
    )
    .unwrap();
    let events = records(&state);
    assert_eq!(events.len(), 3);
    assert_eq!(events[2]["schema_version"], 1);
    assert_eq!(events[2]["event"], "result");
    assert_eq!(events[2]["command"], "ask");
    assert_eq!(events[2]["result"]["text"], "hello world\n");
    assert_eq!(events[2]["result"]["model"], "test-model");
    assert_eq!(events[2]["result"]["effort"], "high");
    assert_eq!(state.borrow().flushed_lengths.len(), 3);
    assert!(err.is_empty());
}

#[test]
fn truncated_and_failed_streams_keep_deltas_without_final_result() {
    for detail in [
        "stream ended before response.completed",
        "backend response.failed",
    ] {
        let state = Rc::new(RefCell::new(Recording::default()));
        let mut sink = Sink(state.clone());
        let mut err = Vec::new();
        let result = emit_ask(Mode::Events, "m", None, &mut sink, &mut err, |delta| {
            delta("partial")?;
            Err(Error::SseStream {
                detail: detail.into(),
            })
        });
        assert!(matches!(result, Err(Error::SseStream { detail: actual }) if actual == detail));
        let events = records(&state);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["event"], "text_delta");
        assert_eq!(events[0]["delta"], "partial");
        assert!(
            err.is_empty(),
            "outer shell owns structured failure rendering"
        );
    }
}

#[test]
fn completed_empty_response_has_result_without_invented_delta() {
    let state = Rc::new(RefCell::new(Recording::default()));
    let mut sink = Sink(state.clone());
    let mut err = Vec::new();
    emit_ask(Mode::Events, "m", None, &mut sink, &mut err, |_| {
        Ok(answer(""))
    })
    .unwrap();
    let events = records(&state);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["event"], "result");
    assert_eq!(events[0]["result"]["text"], "");
    assert!(err.is_empty());
}

#[test]
fn closing_stdout_between_deltas_returns_error_and_never_result() {
    let state = Rc::new(RefCell::new(Recording::default()));
    let mut sink = Sink(state.clone());
    let mut err = Vec::new();
    let reached_after_failure = std::cell::Cell::new(false);
    let result = emit_ask(Mode::Events, "m", None, &mut sink, &mut err, |delta| {
        delta("delivered")?;
        state.borrow_mut().closed = true;
        delta("not delivered")?;
        reached_after_failure.set(true);
        delta("also not delivered")?;
        Ok(answer("deliverednot deliveredalso not delivered"))
    });
    assert!(
        !reached_after_failure.get(),
        "stream continued after sink failure"
    );
    let error = result.expect_err("closed consumer must fail");
    assert!(matches!(&error, Error::Io(source) if source.kind() == io::ErrorKind::BrokenPipe));
    assert_eq!(error.code(), "io_error");
    let events = records(&state);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["event"], "text_delta");
    assert_eq!(events[0]["delta"], "delivered");
}

#[test]
fn json_does_not_emit_partial_success_when_stream_fails() {
    let state = Rc::new(RefCell::new(Recording::default()));
    let mut sink = Sink(state.clone());
    let mut err = Vec::new();
    let result = emit_ask(Mode::Json, "m", None, &mut sink, &mut err, |delta| {
        delta("uncommitted answer")?;
        assert!(state.borrow().bytes.is_empty());
        assert!(state.borrow().flushed_lengths.is_empty());
        Err(Error::SseStream {
            detail: "stream ended early".into(),
        })
    });
    assert!(result.is_err());
    assert!(state.borrow().bytes.is_empty());
    assert!(err.is_empty());
}
