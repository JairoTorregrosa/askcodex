//! WAV transcription over the subscription backend's multipart /transcribe route.
use std::fmt;
use std::path::Path;

use serde_json::Value;

use crate::{config, error::Error, http::Client};

/// Client-side memory bound, not a claimed server upload limit.
const MAX_AUDIO_BYTES: u64 = crate::input::MAX_MEDIA_BYTES;

pub struct Upload {
    bytes: Vec<u8>,
    content_type: String,
}

impl fmt::Debug for Upload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Upload")
            .field("bytes", &self.bytes.len())
            .finish()
    }
}

impl Upload {
    /// Resolve and validate the file before any authentication refresh or upload.
    pub fn read(path: &Path) -> Result<Self, Error> {
        let audio = crate::input::read_file(path, MAX_AUDIO_BYTES, "audio")?;
        Self::from_wav(&audio)
    }

    fn from_wav(audio: &[u8]) -> Result<Self, Error> {
        if audio.len() as u64 > MAX_AUDIO_BYTES {
            return Err(Error::InvalidAudio {
                reason: "file exceeds the 25 MiB client upload limit",
            });
        }
        if audio.len() <= 12 || &audio[..4] != b"RIFF" || &audio[8..12] != b"WAVE" {
            return Err(Error::InvalidAudio {
                reason: "expected a nonempty RIFF/WAVE file; convert other formats to WAV first",
            });
        }
        // Choose a delimiter absent from the audio. Never interpolate a local filename
        // into multipart headers: a fixed filename avoids header injection and path leaks.
        // Fixed-width candidates and a bounded search keep adversarial audio linear
        // in file size instead of repeatedly extending a colliding delimiter.
        let boundary = (0..16)
            .map(|attempt| format!("askcodex-audio-boundary-{attempt:08x}"))
            .find(|candidate| {
                !audio
                    .windows(candidate.len())
                    .any(|part| part == candidate.as_bytes())
            })
            .ok_or(Error::InvalidAudio {
                reason: "audio collides with all multipart delimiters",
            })?;
        let mut bytes = format!("--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"audio.wav\"\r\nContent-Type: audio/wav\r\n\r\n").into_bytes();
        bytes.extend_from_slice(audio);
        bytes.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        Ok(Self {
            bytes,
            content_type: format!("multipart/form-data; boundary={boundary}"),
        })
    }

    pub fn transcribe(&self, client: &mut Client) -> Result<(String, Value), Error> {
        let raw =
            client.post_multipart(config::TRANSCRIBE_PATH, &self.content_type, &self.bytes)?;
        decode(raw)
    }
}

fn json_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn decode(raw: Value) -> Result<(String, Value), Error> {
    let object = raw.as_object().ok_or_else(|| Error::UnexpectedResponse {
        context: format!(
            "transcription response must be an object; got {}",
            json_kind(&raw)
        ),
    })?;
    let value = object
        .get("text")
        .ok_or_else(|| Error::UnexpectedResponse {
            context: "transcription response is missing text".into(),
        })?;
    // Report the mismatched type without echoing response values into diagnostics.
    let text = value
        .as_str()
        .ok_or_else(|| Error::UnexpectedResponse {
            context: format!(
                "transcription response text must be a string; got {}",
                json_kind(value)
            ),
        })?
        .to_owned();
    // An empty transcript is valid (e.g. silence). Preserve it and every unknown JSON field.
    Ok((text, raw))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn multipart_preserves_binary_and_avoids_boundary_collisions() {
        let audio = b"RIFF\0\0\0\0WAVEaskcodex-audio-boundary-00000000\0\xff";
        let upload = Upload::from_wav(audio).unwrap();
        assert!(
            upload
                .content_type
                .ends_with("boundary=askcodex-audio-boundary-00000001")
        );
        assert!(upload.bytes.windows(audio.len()).any(|part| part == audio));
        assert!(
            upload
                .bytes
                .ends_with(b"\r\n--askcodex-audio-boundary-00000001--\r\n")
        );
        assert!(!format!("{upload:?}").contains("WAVE"));
    }

    #[test]
    fn rejects_empty_truncated_and_mislabeled_audio() {
        for data in [b"".as_slice(), b"RIFF", b"RIFF1234WAVE", b"ID3not-a-wav"] {
            assert!(matches!(
                Upload::from_wav(data),
                Err(Error::InvalidAudio { .. })
            ));
        }
    }

    #[test]
    fn boundary_search_is_bounded_for_adversarial_content() {
        let mut audio = b"RIFF\0\0\0\0WAVEaskcodex-audio-boundary".to_vec();
        audio.extend(std::iter::repeat_n(b'-', 100_000));
        assert!(Upload::from_wav(&audio).is_ok());
        for attempt in 0..16 {
            audio.extend_from_slice(format!("askcodex-audio-boundary-{attempt:08x}").as_bytes());
        }
        assert!(matches!(
            Upload::from_wav(&audio),
            Err(Error::InvalidAudio { .. })
        ));
    }

    #[test]
    fn absent_null_and_nonstring_text_fail_but_empty_text_is_valid() {
        for raw in [
            json!({}),
            json!({"text": null}),
            json!({"text": 12}),
            json!([]),
        ] {
            assert!(decode(raw).is_err());
        }
        let raw = json!({"text": "", "future_field": {"value": 3}});
        assert_eq!(decode(raw.clone()).unwrap(), (String::new(), raw));
    }

    #[test]
    fn response_diagnostics_identify_shape_without_echoing_values() {
        for (raw, expected) in [
            (json!("private response"), "must be an object; got string"),
            (json!({}), "missing text"),
            (json!({"text": null}), "text must be a string; got null"),
            (
                json!({"text": ["private response"]}),
                "text must be a string; got array",
            ),
            (
                json!({"text": {"private response": true}}),
                "text must be a string; got object",
            ),
        ] {
            let error = decode(raw).unwrap_err().to_string();
            assert!(error.contains(expected), "{error}");
            assert!(!error.contains("private response"));
        }
    }
}
