use std::path::Path;
use std::process::Command;

/// Formats a single Rust source file.
fn rustfmt_file(path: impl AsRef<Path>) -> std::io::Result<()> {
    let rustfmt_path = std::env::var("RUSTFMT").unwrap_or_else(|_| "rustfmt".to_owned());
    Command::new(rustfmt_path)
        .arg("--emit")
        .arg("files")
        .arg(path.as_ref())
        .output()?;
    Ok(())
}

/// Formats all Rust files at the specified path.
///
/// If the path is a with .rs suffix, the function formats this file.  If the
/// path is a directory, this function formats all Rust files under this
/// directory recursively.
pub fn rustfmt(path: impl AsRef<Path>) -> std::io::Result<()> {
    let path = path.as_ref();
    if path.is_dir() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            rustfmt(entry.path())?;
        }
        Ok(())
    } else if path.extension() == Some("rs".as_ref()) {
        rustfmt_file(path)
    } else {
        Ok(())
    }
}
