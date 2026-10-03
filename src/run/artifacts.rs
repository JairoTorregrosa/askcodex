//! Validate output destinations and atomically publish generated files.

use super::*;

pub(super) const PNG_MAGIC: [u8; 4] = [0x89, b'P', b'N', b'G'];

pub(super) fn run_image<F>(
    path: &Path,
    ref_images: Option<usize>,
    mode: impl Into<Mode>,
    out: &mut dyn Write,
    generate: F,
) -> Result<(), Error>
where
    F: FnOnce() -> Result<ImageResult, Error>,
{
    preflight_out_path(path)?;
    let image = generate()?;
    save_image(&image, path, ref_images, mode, out)
}

pub(super) fn preflight_out_path(path: &Path) -> Result<(), Error> {
    let display = path.display();
    let temp = temp_sibling(path)?;
    ensure_replaceable(path)?;

    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .map_err(|source| io_context(&format!("preparing to write {display}"), source))?;
    std::fs::remove_file(&temp).map_err(|source| {
        io_context(
            &format!("removing the probe file {}", temp.display()),
            source,
        )
    })
}

pub(super) fn ensure_replaceable(path: &Path) -> Result<(), Error> {
    // Not there yet is the normal case, and any other `stat` failure is
    // left to the write itself, which reports the reason that actually
    // stopped it rather than a second-hand one.
    let Ok(metadata) = std::fs::metadata(path) else {
        return Ok(());
    };
    let display = path.display();
    if metadata.is_dir() {
        return Err(io_context(
            &format!("writing {display}"),
            std::io::Error::new(
                std::io::ErrorKind::IsADirectory,
                "the output path is a directory",
            ),
        ));
    }
    if metadata.permissions().readonly() {
        return Err(io_context(
            &format!("writing {display}"),
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "the output path exists and is write-protected",
            ),
        ));
    }
    Ok(())
}

pub(super) fn temp_sibling(path: &Path) -> Result<PathBuf, Error> {
    let Some(file_name) = path.file_name() else {
        return Err(io_context(
            &format!("writing {}", path.display()),
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "the output path has no file name",
            ),
        ));
    };
    Ok(path.with_file_name({
        let mut name = file_name.to_os_string();
        name.push(format!(".askcodex-tmp.{}", std::process::id()));
        name
    }))
}

pub(super) fn save_image(
    image: &ImageResult,
    path: &Path,
    ref_images: Option<usize>,
    mode: impl Into<Mode>,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let mode = mode.into();
    let bytes = write_png(&image.png, path)?;
    let size = image.size.as_deref();
    let facts = png_facts(&image.png);
    let background = image.background.as_deref();
    if mode != Mode::Text {
        let command = if ref_images.is_some() {
            "image edit"
        } else {
            "image create"
        };
        let mut result = image_json(path, size, bytes, ref_images);
        result["width"] = json!(facts.map(|f| f.width));
        result["height"] = json!(facts.map(|f| f.height));
        result["alpha_channel"] = json!(facts.map(|f| f.alpha_channel));
        result["background"] = json!(background);
        emit_result(out, mode, command, &result, None)
    } else {
        let mut text = render_image_saved(path, size, bytes, ref_images);
        text.push_str(&render_png_facts(facts, background));
        emit_human(out, &text)
    }
}

/// What the saved file itself declares, read from its IHDR (and, for a
/// palette image, whether a `tRNS` chunk precedes the image data). The
/// backend's `size` and `background` are claims; these are the bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PngFacts {
    pub width: u32,
    pub height: u32,
    /// The PNG can carry transparency (RGBA, gray+alpha, or a gray,
    /// truecolor or palette image with `tRNS`). It does not say how many
    /// pixels are actually transparent.
    pub alpha_channel: bool,
}

/// `None` when the header is not a well-formed IHDR, so nothing is guessed.
pub(super) fn png_facts(png: &[u8]) -> Option<PngFacts> {
    const SIGNATURE: usize = 8;
    let ihdr = png.get(SIGNATURE..SIGNATURE + 8 + 13)?;
    if ihdr[0..4] != [0, 0, 0, 13] || &ihdr[4..8] != b"IHDR" {
        return None;
    }
    let width = u32::from_be_bytes(ihdr[8..12].try_into().ok()?);
    let height = u32::from_be_bytes(ihdr[12..16].try_into().ok()?);
    // Gray, truecolor and palette images can all carry simple transparency
    // in a `tRNS` chunk; only gray+alpha and RGBA always have a channel.
    let alpha_channel = match ihdr[17] {
        4 | 6 => true,
        0 | 2 | 3 => has_trns(png)?,
        _ => return None,
    };
    Some(PngFacts {
        width,
        height,
        alpha_channel,
    })
}

/// Walk the chunks after IHDR until the image data starts.
fn has_trns(png: &[u8]) -> Option<bool> {
    let mut at = 8;
    loop {
        let len = u32::from_be_bytes(png.get(at..at + 4)?.try_into().ok()?) as usize;
        match png.get(at + 4..at + 8)? {
            b"tRNS" => return Some(true),
            b"IDAT" | b"IEND" => return Some(false),
            _ => at = at.checked_add(12)?.checked_add(len)?,
        }
    }
}

pub(super) fn render_png_facts(facts: Option<PngFacts>, background: Option<&str>) -> String {
    let pixels = facts.map_or(UNKNOWN.to_string(), |f| format!("{}x{}", f.width, f.height));
    let alpha = match facts {
        Some(PngFacts {
            alpha_channel: true,
            ..
        }) => "yes",
        Some(_) => "no",
        None => UNKNOWN,
    };
    let background = background.unwrap_or(ABSENT);
    format!("  pixels {pixels}, alpha channel {alpha}, backend background {background}\n")
}

pub(super) fn write_png(bytes: &[u8], path: &Path) -> Result<usize, Error> {
    if bytes.len() < PNG_MAGIC.len() || bytes[..PNG_MAGIC.len()] != PNG_MAGIC {
        return Err(Error::ImageNotPng {
            magic_hex: hex_prefix(bytes, PNG_MAGIC.len()),
        });
    }
    let display = path.display();
    let temp = temp_sibling(path)?;
    ensure_replaceable(path)?;

    // `create_new` (O_CREAT|O_EXCL): a temp that already exists belongs to
    // another process, and clobbering it is not this function's call. The
    // guard is armed only after a successful open, for that reason.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .map_err(|source| io_context(&format!("creating {}", temp.display()), source))?;
    let mut guard = TempFileGuard::new(&temp);

    let temp_display = temp.display().to_string();
    file.write_all(bytes)
        .map_err(|source| io_context(&format!("writing {temp_display}"), source))?;
    file.flush()
        .map_err(|source| io_context(&format!("flushing {temp_display}"), source))?;
    file.sync_all()
        .map_err(|source| io_context(&format!("syncing {temp_display}"), source))?;
    drop(file);

    std::fs::rename(&temp, path)
        .map_err(|source| io_context(&format!("writing {display}"), source))?;
    guard.disarm();
    Ok(bytes.len())
}

pub(super) struct TempFileGuard<'a> {
    path: Option<&'a Path>,
}

impl<'a> TempFileGuard<'a> {
    fn new(path: &'a Path) -> Self {
        TempFileGuard { path: Some(path) }
    }

    /// Call after a successful rename: the temp no longer exists under
    /// that name.
    fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for TempFileGuard<'_> {
    fn drop(&mut self) {
        if let Some(path) = self.path {
            // `Drop` cannot propagate, and this failure is self-announcing:
            // a leftover temp makes the next write fail loudly on O_EXCL
            // rather than silently overwrite anything.
            let _ = std::fs::remove_file(path);
        }
    }
}

pub(super) fn hex_prefix(bytes: &[u8], max: usize) -> String {
    bytes
        .iter()
        .take(max)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(super) fn render_image_saved(
    path: &Path,
    size: Option<&str>,
    bytes: usize,
    ref_images: Option<usize>,
) -> String {
    let path = path.display();
    let size = size.unwrap_or(ABSENT);
    let refs = match ref_images {
        Some(count) => format!(", {count} ref image(s)"),
        None => String::new(),
    };
    format!("saved {path}  ({size} PNG, {bytes} bytes{refs})\n")
}

pub(super) fn image_json(
    path: &Path,
    size: Option<&str>,
    bytes: usize,
    ref_images: Option<usize>,
) -> Value {
    json!({
        "path": path.display().to_string(),
        "size": size,
        "bytes": bytes,
        "ref_images": ref_images.unwrap_or(0),
    })
}
