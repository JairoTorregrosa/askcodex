//! Image generation/edit endpoints.
//!
//! Backend reality (validated live, locked server-side): output is ALWAYS
//! one opaque PNG at a size the server chooses. There are deliberately no
//! size/quality/background/format/n parameters anywhere in this module.
//!
//! Both endpoints share the same response contract, so decoding lives in
//! one place ([`decode_image`]): typed envelope, then `data[0].b64_json`,
//! then STANDARD base64, then the PNG magic. Every step that can fail
//! fails LOUDLY — this module never returns bytes it has not verified, and
//! never writes a file (the caller owns the output path).
//!
//! The same rule runs in the other direction. Every reference image is put
//! on the wire labelled `data:image/png;base64,...`, so [`PreparedEdit::read`]
//! verifies the PNG magic of the bytes it just read: askcodex does not assert a
//! content type it has not checked, on the user's credential. A reference
//! that is not a PNG is rejected locally, by path, BEFORE the (billed)
//! request — not turned into an opaque server-side error. PNG is also the
//! only reference format this project has ever validated against the live
//! backend, so accepting another one would be an unverified claim.

use std::io;
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;

use crate::config;
use crate::error::Error;
use crate::http::Client;
use crate::models::{
    ImageEditRequest, ImageGenerationRequest, ImageRef, ImageResponse, ImageResult,
};

/// Backend path for text -> image. Relative: `http::Client` resolves it
/// against `config::BASE_URL`.
const GENERATIONS_PATH: &str = "/codex/images/generations";

/// Backend path for reference-guided edits (same resolution rule).
const EDITS_PATH: &str = "/codex/images/edits";

/// Data-URL prefix every reference image is wrapped in (wire format taken
/// from codex; docs/PROTOCOL.md §3.5).
const DATA_URL_PREFIX: &str = "data:image/png;base64,";

/// PNG signature prefix (`\x89PNG`). The full 8-byte signature continues
/// `\r\n\x1a\n`; askcodex checks the same 4 bytes codex checks, and reports
/// what it saw instead.
const PNG_MAGIC: [u8; 4] = [0x89, b'P', b'N', b'G'];

/// `POST /codex/images/generations` with
/// `models::ImageGenerationRequest { prompt, model: config::IMAGE_MODEL }`.
///
/// Contract:
/// - Decode the response as `models::ImageResponse`.
/// - `data[0].b64_json` absent -> `Error::UnexpectedResponse` naming the
///   missing path and listing the response's top-level keys.
/// - base64-decode (STANDARD engine); invalid base64 ->
///   `Error::UnexpectedResponse`.
/// - Verify the PNG magic `\x89PNG`; anything else ->
///   `Error::ImageNotPng { magic_hex }` (first 4 bytes, hex). NO placeholder
///   output ever.
/// - Returns bytes + reported size; the CALLER (run.rs) writes the file.
pub fn create(client: &mut Client, prompt: &str) -> Result<ImageResult, Error> {
    // Exactly two fields on the wire. The backend accepts and then IGNORES
    // size/quality/background/output_format/n (and even model), so askcodex
    // sends none of them: an accepted-and-discarded knob is a lie.
    let request = ImageGenerationRequest {
        prompt: prompt.to_string(),
        model: config::IMAGE_MODEL,
    };

    let body = serde_json::to_value(&request)?;
    let response = client.post_json(&endpoint(GENERATIONS_PATH), &body)?;

    decode_image(response)
}

/// `POST /codex/images/edits` with `models::ImageEditRequest`.
///
/// Contract (input handling BEFORE any network call):
/// - More than `config::MAX_EDIT_IMAGES` inputs ->
///   `Error::TooManyImages { max, count }`.
/// - A missing input path -> `Error::InputImageMissing { path }`.
/// - An input file whose first bytes are not the PNG magic `\x89PNG` —
///   an empty or truncated file included -> `Error::InputImageNotPng
///   { path, magic_hex }` (the bytes it actually starts with, hex).
/// - Each accepted input file is read raw and wrapped as
///   `data:image/png;base64,<STANDARD-encoded bytes>`: askcodex verifies the
///   magic and then sends the bytes verbatim, it does not transcode or
///   resize.
/// - Response handling identical to [`create`].
///
/// Every one of those input failures happens before `post_json`, so a
/// request that was going to be refused is never billed.
#[cfg(test)]
pub fn edit(client: &mut Client, prompt: &str, inputs: &[&Path]) -> Result<ImageResult, Error> {
    PreparedEdit::read(prompt, inputs)?.send(client)
}

/// Validated reference bytes, ready to upload without rereading local files.
pub struct PreparedEdit {
    body: Value,
    count: usize,
}

impl std::fmt::Debug for PreparedEdit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedEdit")
            .field("references", &self.count)
            .finish()
    }
}

impl PreparedEdit {
    pub fn count(&self) -> usize {
        self.count
    }

    pub fn read(prompt: &str, inputs: &[&Path]) -> Result<Self, Error> {
        // Guard first, and on the count alone: rejecting six references must
        // not depend on six files being readable, and must not cost a round
        // trip the backend would refuse anyway.
        if inputs.len() > config::MAX_EDIT_IMAGES {
            return Err(Error::TooManyImages {
                max: config::MAX_EDIT_IMAGES,
                count: inputs.len(),
            });
        }

        // Every input is resolved and encoded before the request is built, so
        // a typo in the last path fails without having spent a backend call.
        // (An EMPTY input list is not rejected here: clap requires `-i` with at
        // least one value, and inventing a client-side rule the backend does
        // not have would hide whatever it actually answers.)
        let mut images = Vec::with_capacity(inputs.len());
        let mut remaining = crate::input::MAX_MEDIA_BYTES;
        for path in inputs {
            let (image_url, bytes) = reference_data(path, remaining)?;
            remaining -= bytes;
            images.push(ImageRef { image_url });
        }

        let request = ImageEditRequest {
            prompt: prompt.to_string(),
            model: config::IMAGE_MODEL,
            images,
        };

        let body = serde_json::to_value(&request)?;
        Ok(Self {
            body,
            count: inputs.len(),
        })
    }

    pub fn send(&self, client: &mut Client) -> Result<ImageResult, Error> {
        let response = client.post_json(&endpoint(EDITS_PATH), &self.body)?;

        decode_image(response)
    }
}

// ---------------------------------------------------------------------------
// internals
// ---------------------------------------------------------------------------

/// The URL handed to [`Client`] for one of the constant paths above.
///
/// Shipped builds: the identity function. The relative path is resolved
/// against `config::BASE_URL` by `http::Client`, exactly as codex does.
///
/// `cfg(test)` builds ONLY: the unit tests below point this at a local
/// httpmock server. The seam exists because the backend host is a frozen
/// const and these functions deliberately take no base URL, so without it
/// a unit test of `create`/`edit` would have to talk to chatgpt.com — which
/// is forbidden. Same pattern as `http::Client`'s `refresh_hook`. The
/// shipped binary and any `tests/` integration test compile the library
/// WITHOUT `cfg(test)` and therefore always get the constant path.
#[cfg(not(test))]
fn endpoint(path: &str) -> String {
    path.to_string()
}

#[cfg(test)]
fn endpoint(path: &str) -> String {
    tests::redirect(path)
}

/// Read one reference image, verify it IS a PNG, and wrap it as a
/// `data:image/png;base64,...` URL.
///
/// The bytes then go out exactly as they are on disk: askcodex does not
/// decode, re-encode or resize reference images. The one thing it does
/// inspect is the magic, because [`DATA_URL_PREFIX`] tells the backend
/// these bytes are `image/png` — asserting a content type nobody checked,
/// over the user's credential, is the lie this check exists to prevent.
/// The user gets "that file is not a PNG", with the path, instead of an
/// opaque server-side rejection charged to their quota.
#[cfg(test)]
fn data_url(path: &Path) -> Result<String, Error> {
    reference_data(path, crate::input::MAX_MEDIA_BYTES).map(|(url, _)| url)
}

fn reference_data(path: &Path, limit: u64) -> Result<(String, u64), Error> {
    // `try_exists`, not `exists`: the latter reports an unreadable parent
    // directory as "does not exist", which would send the user hunting for
    // a file that is right there.
    match path.try_exists() {
        Ok(true) => {}
        Ok(false) => {
            return Err(Error::InputImageMissing {
                path: path.to_path_buf(),
            });
        }
        Err(source) => return Err(io_error(path, "cannot stat reference image", source)),
    }

    let bytes = crate::input::read_file(path, limit, "reference image")?;

    // `starts_with`, so a file SHORTER than the magic — an empty one
    // included — is refused here rather than slicing out of bounds, and
    // `magic_hex` reports the bytes that are actually there.
    if !bytes.starts_with(&PNG_MAGIC) {
        return Err(Error::InputImageNotPng {
            path: path.to_path_buf(),
            magic_hex: magic_hex(&bytes),
        });
    }

    // 4 base64 chars per 3 input bytes, rounded up.
    let mut url = String::with_capacity(DATA_URL_PREFIX.len() + bytes.len().div_ceil(3) * 4);
    url.push_str(DATA_URL_PREFIX);
    STANDARD.encode_string(&bytes, &mut url);

    Ok((url, bytes.len() as u64))
}

/// Wrap a filesystem failure so the message names the offending path
/// (`Error::Io`'s Display is just the source otherwise).
fn io_error(path: &Path, what: &str, source: io::Error) -> Error {
    Error::Io(io::Error::new(
        source.kind(),
        format!("{what} {}: {source}", path.display()),
    ))
}

/// Shared response handling for both endpoints.
///
/// Takes the raw value BY VALUE: the key names needed for error messages
/// are collected first, so the (megabyte-scale) base64 payload is never
/// cloned.
fn decode_image(response: Value) -> Result<ImageResult, Error> {
    let shape = describe(&response);

    let decoded: ImageResponse =
        serde_json::from_value(response).map_err(|source| Error::UnexpectedResponse {
            context: format!(
                "image response does not match the documented envelope ({source}); {shape}"
            ),
        })?;

    let b64 = decoded
        .data
        .first()
        .and_then(|datum| datum.b64_json.as_deref())
        .ok_or_else(|| Error::UnexpectedResponse {
            context: format!("image response missing data[0].b64_json; {shape}"),
        })?;

    let png = STANDARD
        .decode(b64)
        .map_err(|source| Error::UnexpectedResponse {
            context: format!("image response data[0].b64_json is not valid base64: {source}"),
        })?;

    // The last gate before these bytes are handed to a caller that will
    // write them to the user's `--out` path: if they are not a PNG, nothing
    // is returned at all.
    if !png.starts_with(&PNG_MAGIC) {
        return Err(Error::ImageNotPng {
            magic_hex: magic_hex(&png),
        });
    }

    Ok(ImageResult {
        png,
        size: decoded.size,
    })
}

/// Describe a response for an error message: sorted top-level key NAMES,
/// or the JSON kind when the body is not an object. Values are never
/// quoted, so this can never echo payload content into an error.
fn describe(response: &Value) -> String {
    match response {
        Value::Object(map) => {
            let mut keys: Vec<&str> = map.keys().map(String::as_str).collect();
            keys.sort_unstable();
            format!("keys={keys:?}")
        }
        Value::Array(items) => format!(
            "response is a JSON array of {} item(s), not an object",
            items.len()
        ),
        Value::Null => "response is JSON null, not an object".to_string(),
        Value::Bool(_) => "response is a JSON bool, not an object".to_string(),
        Value::Number(_) => "response is a JSON number, not an object".to_string(),
        Value::String(_) => "response is a JSON string, not an object".to_string(),
    }
}

/// Lowercase hex of the first four bytes. Used for both directions — a
/// response payload that is
/// not a PNG, and a reference image that is not one. A shorter input
/// reports the bytes it does have; an EMPTY one says so, because an empty
/// hex string would read like askcodex had simply lost the value.
fn magic_hex(bytes: &[u8]) -> String {
    const HEX_DIGITS: [u8; 16] = *b"0123456789abcdef";

    if bytes.is_empty() {
        return "<empty payload>".to_string();
    }

    let mut hex = String::with_capacity(2 * PNG_MAGIC.len());
    for byte in bytes.iter().take(PNG_MAGIC.len()) {
        hex.push(HEX_DIGITS[usize::from(byte >> 4)] as char);
        hex.push(HEX_DIGITS[usize::from(byte & 0x0f)] as char);
    }
    hex
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

// Isolation guarantees for this module's tests:
// - Every HTTP call goes to a local httpmock server (see `Redirect`); no
//   test can reach chatgpt.com. Tests that must prove ZERO calls happened
//   still install the redirect, so an accidental call would be counted by
//   the mock instead of leaving the machine.
// - Credentials are invented literals built in-process; `Client::new`
//   touches the filesystem only on its error paths, so `~/.codex` is never
//   opened, and `no_refresh` is always true, so `auth::refresh` (which
//   posts to a real host) is unreachable.
// - The only filesystem writes are reference-image fixtures under
//   `std::env::temp_dir()`, removed on drop.
#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    use httpmock::Method::POST;
    use httpmock::MockServer;
    use serde_json::json;

    use super::*;
    use crate::models::{AuthFile, AuthTokens};
    use crate::redact::Secret;

    /// A real 1x1 RGBA PNG (70 bytes, valid IHDR/IDAT/IEND CRCs), embedded
    /// byte for byte. Nothing is fetched or read from the repo.
    const TINY_PNG: [u8; 70] = [
        0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44,
        0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f,
        0x15, 0xc4, 0x89, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x44, 0x41, 0x54, 0x78, 0xda, 0x63, 0xfc,
        0xcf, 0xc0, 0x50, 0x0f, 0x00, 0x04, 0x85, 0x01, 0x80, 0x84, 0xa9, 0x8c, 0x21, 0x00, 0x00,
        0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
    ];

    /// Invented, non-functional credential values.
    const FAKE_ACCESS_TOKEN: &str = "fake.access.token-images";
    const FAKE_ACCOUNT_ID: &str = "acct_fake_images";

    thread_local! {
        /// Base URL prepended to the endpoint paths on THIS thread. Each
        /// `#[test]` runs on its own thread, so parallel tests cannot see
        /// each other's redirect.
        static BASE_OVERRIDE: RefCell<Option<String>> = const { RefCell::new(None) };
    }

    /// The `cfg(test)` half of [`super::endpoint`].
    pub(super) fn redirect(path: &str) -> String {
        BASE_OVERRIDE.with(|base| match base.borrow().as_deref() {
            Some(base) => format!("{base}{path}"),
            // No guard installed: a test would be about to call the real
            // backend. Refuse loudly rather than let it out of the machine.
            None => panic!("images endpoint used without a Redirect guard (path {path})"),
        })
    }

    /// RAII guard pointing this module's endpoints at a mock server.
    struct Redirect;

    impl Redirect {
        fn to(server: &MockServer) -> Self {
            BASE_OVERRIDE.with(|base| *base.borrow_mut() = Some(server.base_url()));
            Redirect
        }
    }

    impl Drop for Redirect {
        fn drop(&mut self) {
            BASE_OVERRIDE.with(|base| *base.borrow_mut() = None);
        }
    }

    /// Throwaway directory for reference-image fixtures (the dev-dependency
    /// set is frozen, so no `tempfile`). Always under
    /// `std::env::temp_dir()`; never anywhere near `~/.codex`.
    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(tag: &str) -> Self {
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "askcodex-images-test-{tag}-{}-{unique}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).expect("create the fixture directory");
            TempDir { path }
        }

        /// Write a fixture file and return its path.
        fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
            let file = self.path.join(name);
            std::fs::write(&file, bytes).expect("write the fixture file");
            file
        }

        /// A path inside the directory that deliberately does NOT exist.
        fn absent(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            // Best-effort cleanup: `Drop` cannot report, and a leftover
            // temp directory must not turn a passing test red.
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn client() -> Client {
        Client::new(
            AuthFile {
                auth_mode: Some("chatgpt".to_string()),
                tokens: Some(AuthTokens {
                    id_token: None,
                    access_token: Some(Secret::new(FAKE_ACCESS_TOKEN)),
                    refresh_token: None,
                    account_id: Some(FAKE_ACCOUNT_ID.to_string()),
                    extra: serde_json::Map::new(),
                }),
                last_refresh: None,
                extra: serde_json::Map::new(),
            },
            // no_refresh: these tests must never reach `auth::refresh`,
            // which posts to a real host.
            true,
        )
        .expect("invented credentials are structurally valid")
    }

    /// A successful image envelope carrying `png` as `data[0].b64_json`.
    fn ok_envelope(png: &[u8]) -> Value {
        json!({
            "created": 1_754_000_000_u64,
            "data": [{ "b64_json": STANDARD.encode(png) }],
            "background": "opaque",
            "quality": "low",
            "size": "1254x1254",
            "output_format": "png",
        })
    }

    fn data_url_of(bytes: &[u8]) -> String {
        format!("{DATA_URL_PREFIX}{}", STANDARD.encode(bytes))
    }

    /// `ImageResult` carries raw PNG bytes and is deliberately not `Debug`
    /// (frozen models.rs), so `unwrap_err` is unavailable here.
    fn expect_error(result: Result<ImageResult, Error>) -> Error {
        match result {
            Ok(image) => panic!(
                "expected a loud error, got {} PNG byte(s) instead",
                image.png.len()
            ),
            Err(e) => e,
        }
    }

    // -- create ----------------------------------------------------------

    #[test]
    fn create_posts_prompt_and_model_only_and_returns_the_decoded_png() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            // Exact body match: the wire carries prompt + model and NOTHING
            // else. No size/quality/background/output_format/n — the
            // backend ignores them and askcodex must not pretend otherwise.
            when.method(POST)
                .path(GENERATIONS_PATH)
                .json_body(json!({"prompt": "a red cube", "model": config::IMAGE_MODEL}));
            then.status(200)
                .header("content-type", "application/json")
                .json_body(ok_envelope(&TINY_PNG));
        });
        let _redirect = Redirect::to(&server);

        let result = create(&mut client(), "a red cube").unwrap();

        mock.assert();
        assert_eq!(result.png, TINY_PNG);
        assert_eq!(result.size.as_deref(), Some("1254x1254"));
    }

    #[test]
    fn create_reports_a_non_2xx_loudly() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(POST).path(GENERATIONS_PATH);
            then.status(500).body(r#"{"error":"image backend down"}"#);
        });
        let _redirect = Redirect::to(&server);

        let err = expect_error(create(&mut client(), "a red cube"));

        assert_eq!(mock.calls(), 1);
        match err {
            Error::HttpStatus {
                method,
                status,
                snippet,
                ..
            } => {
                assert_eq!(method, "POST");
                assert_eq!(status, 500);
                assert_eq!(snippet, r#"{"error":"image backend down"}"#);
            }
            other => panic!("wrong error: {other:?}"),
        }
    }

    // -- edit ------------------------------------------------------------

    #[test]
    fn edit_posts_prompt_model_and_the_reference_images_as_data_urls() {
        let dir = TempDir::new("edit-happy");
        // Both references start with the PNG magic — the only bytes askcodex
        // will label `image/png`. The second is TINY_PNG plus trailing
        // junk after IEND, to show that askcodex checks the magic and NOTHING
        // else about the file: what follows goes out verbatim, unparsed,
        // untranscoded.
        let second_png = {
            let mut bytes = TINY_PNG.to_vec();
            bytes.extend_from_slice(b" trailing bytes askcodex must not touch");
            bytes
        };
        let first = dir.write("first.png", &TINY_PNG);
        let second = dir.write("second.png", &second_png);

        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(POST).path(EDITS_PATH).json_body(json!({
                "prompt": "make it bluer",
                "model": config::IMAGE_MODEL,
                "images": [
                    {"image_url": data_url_of(&TINY_PNG)},
                    {"image_url": data_url_of(&second_png)},
                ],
            }));
            then.status(200)
                .header("content-type", "application/json")
                .json_body(ok_envelope(&TINY_PNG));
        });
        let _redirect = Redirect::to(&server);

        let result = edit(
            &mut client(),
            "make it bluer",
            &[first.as_path(), second.as_path()],
        )
        .unwrap();

        mock.assert();
        assert_eq!(result.png, TINY_PNG);
        assert_eq!(result.size.as_deref(), Some("1254x1254"));
    }

    #[test]
    fn more_than_five_references_is_rejected_before_any_http_call() {
        let dir = TempDir::new("edit-too-many");
        // All six exist and are readable: the ONLY reason to refuse is the
        // count.
        let files: Vec<PathBuf> = (0..6)
            .map(|i| dir.write(&format!("ref{i}.png"), &TINY_PNG))
            .collect();
        let inputs: Vec<&Path> = files.iter().map(PathBuf::as_path).collect();

        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(POST).path(EDITS_PATH);
            then.status(200).json_body(ok_envelope(&TINY_PNG));
        });
        let _redirect = Redirect::to(&server);

        let err = expect_error(edit(&mut client(), "too many", &inputs));

        assert_eq!(mock.calls(), 0, "the guard must run before the request");
        match err {
            Error::TooManyImages { max, count } => {
                assert_eq!(max, config::MAX_EDIT_IMAGES);
                assert_eq!(count, 6);
            }
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn exactly_five_references_are_accepted() {
        let dir = TempDir::new("edit-five");
        let files: Vec<PathBuf> = (0..config::MAX_EDIT_IMAGES)
            .map(|i| dir.write(&format!("ref{i}.png"), &TINY_PNG))
            .collect();
        let inputs: Vec<&Path> = files.iter().map(PathBuf::as_path).collect();

        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(POST).path(EDITS_PATH).is_true(|req| {
                let body: Value = serde_json::from_slice(req.body_ref()).expect("json body");
                body["images"].as_array().map(Vec::len) == Some(5)
            });
            then.status(200).json_body(ok_envelope(&TINY_PNG));
        });
        let _redirect = Redirect::to(&server);

        edit(&mut client(), "five refs", &inputs).unwrap();

        mock.assert();
    }

    #[test]
    fn a_missing_reference_image_is_rejected_before_any_http_call() {
        let dir = TempDir::new("edit-missing");
        let present = dir.write("present.png", &TINY_PNG);
        let missing = dir.absent("nope.png");

        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(POST).path(EDITS_PATH);
            then.status(200).json_body(ok_envelope(&TINY_PNG));
        });
        let _redirect = Redirect::to(&server);

        let err = expect_error(edit(
            &mut client(),
            "one is missing",
            &[present.as_path(), missing.as_path()],
        ));

        assert_eq!(mock.calls(), 0, "the guard must run before the request");
        match err {
            Error::InputImageMissing { ref path } => assert_eq!(path, &missing),
            ref other => panic!("wrong error: {other:?}"),
        }
        // The message points at the offending file.
        assert!(err.to_string().contains("nope.png"), "{err}");
    }

    // -- reference images must actually BE PNGs --------------------------

    /// Write `bytes` as the single reference image of an `edit` call that a
    /// mock server would happily answer 200 to, and return the reported
    /// `magic_hex` plus the number of requests the mock actually recorded.
    ///
    /// The mock exists in the rejection cases precisely so that the "no
    /// request" claim is MEASURED: a regression that posted anyway would be
    /// counted here (and, in a shipped build, billed), instead of being
    /// waved through by a test that only reads the error.
    ///
    /// The fixture is always named `.png`: the check must look at the
    /// bytes, never at the extension.
    fn reject_non_png_reference(tag: &str, bytes: &[u8]) -> (String, usize) {
        let dir = TempDir::new(tag);
        let reference = dir.write("ref.png", bytes);

        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(POST).path(EDITS_PATH);
            then.status(200).json_body(ok_envelope(&TINY_PNG));
        });
        let _redirect = Redirect::to(&server);

        let err = expect_error(edit(&mut client(), "make it bluer", &[reference.as_path()]));
        let calls = mock.calls();

        match err {
            Error::InputImageNotPng {
                ref path,
                ref magic_hex,
            } => {
                assert_eq!(path, &reference, "the error must name the offending file");
                // The rendered message points the user at that same file.
                assert!(
                    err.to_string().contains(&reference.display().to_string()),
                    "{err}"
                );
                (magic_hex.clone(), calls)
            }
            ref other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn a_valid_png_reference_is_accepted() {
        let dir = TempDir::new("edit-valid-png");
        let reference = dir.write("ref.png", &TINY_PNG);

        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(POST).path(EDITS_PATH).json_body(json!({
                "prompt": "make it bluer",
                "model": config::IMAGE_MODEL,
                "images": [{"image_url": data_url_of(&TINY_PNG)}],
            }));
            then.status(200)
                .header("content-type", "application/json")
                .json_body(ok_envelope(&TINY_PNG));
        });
        let _redirect = Redirect::to(&server);

        let result = edit(&mut client(), "make it bluer", &[reference.as_path()]).unwrap();

        mock.assert();
        assert_eq!(result.png, TINY_PNG);
    }

    #[test]
    fn a_jpeg_reference_is_rejected_before_any_http_call() {
        // JFIF SOI + APP0. askcodex labels every reference `image/png` on the
        // wire, so these bytes must never be sent under that label.
        let (magic_hex, calls) =
            reject_non_png_reference("edit-jpeg-ref", b"\xff\xd8\xff\xe0\x00\x10JFIF\x00");

        assert_eq!(calls, 0, "a rejected input must cost no request");
        assert_eq!(magic_hex, "ffd8ffe0");
    }

    #[test]
    fn an_empty_reference_file_is_rejected_before_any_http_call() {
        // Zero bytes: the case that would slice out of bounds if the check
        // indexed instead of using `starts_with`.
        let (magic_hex, calls) = reject_non_png_reference("edit-empty-ref", b"");

        assert_eq!(calls, 0, "a rejected input must cost no request");
        assert_eq!(magic_hex, "<empty payload>");
    }

    #[test]
    fn a_reference_shorter_than_the_magic_is_rejected_before_any_http_call() {
        // Two bytes — the first two of a real PNG signature, so this fails
        // for being TRUNCATED, not for starting with something else, and
        // the report says exactly which two bytes were there.
        let (magic_hex, calls) = reject_non_png_reference("edit-short-ref", &[0x89, 0x50]);

        assert_eq!(calls, 0, "a rejected input must cost no request");
        assert_eq!(magic_hex, "8950");
    }

    #[test]
    fn a_valid_reference_followed_by_a_non_png_still_costs_no_request() {
        // Every input is verified before the request is built, so a bad
        // LAST path is caught even though the first one encoded fine.
        let dir = TempDir::new("edit-good-then-bad");
        let good = dir.write("good.png", &TINY_PNG);
        let bad = dir.write("bad.png", b"GIF89a");

        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(POST).path(EDITS_PATH);
            then.status(200).json_body(ok_envelope(&TINY_PNG));
        });
        let _redirect = Redirect::to(&server);

        let err = expect_error(edit(
            &mut client(),
            "one is not a png",
            &[good.as_path(), bad.as_path()],
        ));

        assert_eq!(mock.calls(), 0, "the guard must run before the request");
        match err {
            Error::InputImageNotPng {
                ref path,
                ref magic_hex,
            } => {
                assert_eq!(path, &bad);
                assert_eq!(magic_hex, "47494638");
            }
            ref other => panic!("wrong error: {other:?}"),
        }
        assert!(err.to_string().contains("bad.png"), "{err}");
    }

    // -- response validation (shared by both endpoints) ------------------

    #[test]
    fn a_non_png_payload_is_never_returned_to_the_caller() {
        let gif = b"GIF89a and then some bytes";
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path(GENERATIONS_PATH);
            then.status(200).json_body(ok_envelope(gif));
        });
        let _redirect = Redirect::to(&server);

        let err = expect_error(create(&mut client(), "a red cube"));

        match err {
            // "GIF8" in hex.
            Error::ImageNotPng { ref magic_hex } => assert_eq!(magic_hex, "47494638"),
            ref other => panic!("wrong error: {other:?}"),
        }
        assert!(err.to_string().contains("expected PNG payload"), "{err}");
    }

    #[test]
    fn an_empty_payload_is_reported_as_such_not_as_a_blank_magic() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path(GENERATIONS_PATH);
            then.status(200)
                .json_body(json!({"created": 1, "data": [{"b64_json": ""}], "size": "1254x1254"}));
        });
        let _redirect = Redirect::to(&server);

        let err = expect_error(create(&mut client(), "a red cube"));

        match err {
            Error::ImageNotPng { magic_hex } => assert_eq!(magic_hex, "<empty payload>"),
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn a_truncated_payload_reports_the_bytes_it_did_see() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path(EDITS_PATH);
            then.status(200).json_body(ok_envelope(&[0x89, 0x50]));
        });
        let _redirect = Redirect::to(&server);

        let dir = TempDir::new("edit-truncated");
        let reference = dir.write("ref.png", &TINY_PNG);
        let err = expect_error(edit(&mut client(), "p", &[reference.as_path()]));

        match err {
            Error::ImageNotPng { magic_hex } => assert_eq!(magic_hex, "8950"),
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn a_response_without_b64_json_names_the_keys_that_were_present() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path(GENERATIONS_PATH);
            then.status(200)
                .json_body(json!({"created": 1, "data": [{}], "size": "1254x1254"}));
        });
        let _redirect = Redirect::to(&server);

        let err = expect_error(create(&mut client(), "a red cube"));

        match err {
            Error::UnexpectedResponse { context } => {
                assert!(context.contains("data[0].b64_json"), "{context}");
                assert!(
                    context.contains(r#"keys=["created", "data", "size"]"#),
                    "{context}"
                );
            }
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn an_empty_data_array_is_unexpected_not_an_empty_image() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path(GENERATIONS_PATH);
            then.status(200)
                .json_body(json!({"created": 1, "data": [], "error": "moderation_blocked"}));
        });
        let _redirect = Redirect::to(&server);

        let err = expect_error(create(&mut client(), "a red cube"));

        match err {
            Error::UnexpectedResponse { context } => {
                assert!(context.contains("data[0].b64_json"), "{context}");
                // Key names only — an error may never echo response values.
                assert!(context.contains("error"), "{context}");
                assert!(!context.contains("moderation_blocked"), "{context}");
            }
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn an_envelope_of_the_wrong_shape_is_unexpected() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path(GENERATIONS_PATH);
            then.status(200).json_body(json!({"data": "not-an-array"}));
        });
        let _redirect = Redirect::to(&server);

        let err = expect_error(create(&mut client(), "a red cube"));

        match err {
            Error::UnexpectedResponse { context } => {
                assert!(context.contains("documented envelope"), "{context}");
                assert!(context.contains(r#"keys=["data"]"#), "{context}");
            }
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn an_undecodable_payload_is_unexpected_not_silently_dropped() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path(GENERATIONS_PATH);
            then.status(200)
                .json_body(json!({"created": 1, "data": [{"b64_json": "not base64!!"}]}));
        });
        let _redirect = Redirect::to(&server);

        let err = expect_error(create(&mut client(), "a red cube"));

        match err {
            Error::UnexpectedResponse { context } => {
                assert!(context.contains("not valid base64"), "{context}");
            }
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn a_response_that_is_not_an_object_is_described_by_its_json_kind() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path(GENERATIONS_PATH);
            then.status(200).json_body(json!([1, 2, 3]));
        });
        let _redirect = Redirect::to(&server);

        let err = expect_error(create(&mut client(), "a red cube"));

        match err {
            Error::UnexpectedResponse { context } => {
                assert!(context.contains("JSON array of 3 item(s)"), "{context}");
            }
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn a_missing_size_is_reported_as_absent_never_invented() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path(GENERATIONS_PATH);
            then.status(200)
                .json_body(json!({"data": [{"b64_json": STANDARD.encode(TINY_PNG)}]}));
        });
        let _redirect = Redirect::to(&server);

        let result = create(&mut client(), "a red cube").unwrap();

        assert_eq!(result.png, TINY_PNG);
        assert!(
            result.size.is_none(),
            "no size means no size, not '1254x1254'"
        );
    }

    // -- pure helpers ----------------------------------------------------

    #[test]
    fn data_url_wraps_the_file_bytes_verbatim() {
        let dir = TempDir::new("data-url");
        let file = dir.write("ref.png", &TINY_PNG);

        let url = data_url(&file).unwrap();

        assert!(url.starts_with(DATA_URL_PREFIX));
        let encoded = &url[DATA_URL_PREFIX.len()..];
        assert_eq!(STANDARD.decode(encoded).unwrap(), TINY_PNG);
    }

    #[test]
    fn data_url_refuses_to_label_non_png_bytes_as_a_png() {
        let dir = TempDir::new("data-url-not-png");

        for (name, bytes, expected) in [
            ("jpeg.png", b"\xff\xd8\xff\xe0".as_slice(), "ffd8ffe0"),
            ("empty.png", b"".as_slice(), "<empty payload>"),
            ("short.png", b"\x89P".as_slice(), "8950"),
            // Right magic in the wrong place is still the wrong magic.
            (
                "offset.png",
                b"\x00\x89PNG\r\n\x1a\n".as_slice(),
                "0089504e",
            ),
        ] {
            let file = dir.write(name, bytes);
            match data_url(&file) {
                Err(Error::InputImageNotPng { path, magic_hex }) => {
                    assert_eq!(path, file);
                    assert_eq!(magic_hex, expected, "{name}");
                }
                Err(other) => panic!("wrong error for {name}: {other:?}"),
                Ok(_) => panic!("{name} was labelled image/png without being one"),
            }
        }
    }

    #[test]
    fn data_url_on_a_missing_path_is_loud() {
        let dir = TempDir::new("data-url-missing");
        let missing = dir.absent("gone.png");
        assert!(matches!(
            data_url(&missing),
            Err(Error::InputImageMissing { .. })
        ));
    }

    #[test]
    fn describe_lists_sorted_key_names_only() {
        assert_eq!(
            describe(&json!({"size": "1254x1254", "created": 1, "data": []})),
            r#"keys=["created", "data", "size"]"#
        );
        assert_eq!(describe(&json!({})), "keys=[]");
        assert!(describe(&Value::Null).contains("null"));
        assert!(describe(&json!("boom")).contains("string"));
        assert!(describe(&json!(7)).contains("number"));
        assert!(describe(&json!(true)).contains("bool"));
    }

    #[test]
    fn magic_hex_renders_lowercase_hex_of_the_first_four_bytes() {
        assert_eq!(magic_hex(&TINY_PNG), "89504e47");
        assert_eq!(magic_hex(b"GIF89a"), "47494638");
        assert_eq!(magic_hex(&[0x00]), "00");
        assert_eq!(magic_hex(&[]), "<empty payload>");
    }
}
