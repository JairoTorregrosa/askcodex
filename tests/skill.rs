//! The installed skill must not send agents to a fixed path in the shared temp directory.
//!
//! `install.sh --skills` copies `skill/` into the host agents' skill directories,
//! so every recipe in it is a command an agent runs on the user's machine. The
//! recipes used to keep briefs, schemas, recordings, transcripts, images and
//! model answers in `/tmp/askcodex` under fixed names. On a shared host any
//! other local user can read that directory, or create it first: `mkdir -p`
//! accepts a directory someone else owns, and the recipes' shell redirections
//! and read-backs then follow whatever that user planted there.
//!
//! The recipes now keep their files in a private directory from
//! `mktemp -d "${TMPDIR:-/tmp}/askcodex.XXXXXX"` (mode 0700, unpredictable name,
//! never an existing entry). This test fails if any file under `skill/` names a
//! path inside `/tmp` again. It reads the directory at run time, so a guide
//! added later is covered too.

use std::path::{Path, PathBuf};

fn skill_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            skill_files(&path, out);
        } else {
            out.push(path);
        }
    }
}

#[test]
fn no_skill_file_names_a_fixed_path_in_the_shared_temp_dir() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    skill_files(&root.join("skill"), &mut files);
    files.sort();
    assert!(
        files.iter().any(|path| path.ends_with("SKILL.md")),
        "skill/SKILL.md not found; this gate would pass vacuously"
    );

    let mut offenders = Vec::new();
    for path in &files {
        let body = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        for (index, line) in body.lines().enumerate() {
            if line.contains("/tmp/") {
                let name = path.strip_prefix(root).unwrap().display();
                offenders.push(format!("{name}:{}: {}", index + 1, line.trim()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "skill files name a fixed path in the shared /tmp; use the private work directory \
         from `mktemp -d \"${{TMPDIR:-/tmp}}/askcodex.XXXXXX\"` (skill/SKILL.md step 4):\n{}",
        offenders.join("\n")
    );
}
