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
    if mode != Mode::Text {
        let command = if ref_images.is_some() {
            "image edit"
        } else {
            "image create"
        };
        emit_result(
            out,
            mode,
            command,
            &image_json(path, size, bytes, ref_images),
            None,
        )
    } else {
        emit_human(out, &render_image_saved(path, size, bytes, ref_images))
    }
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
