use anyhow::{Context, Result};
use ic_sys::fs::write_string_using_tmp_file;
use prometheus::{Encoder, Registry, TextEncoder};
use std::path::Path;

/// Encodes the given prometheus registry and atomically writes it to `path`.
///
/// The write is atomic: the content is first written to a temporary file in
/// the same directory, then renamed into place, so a partially-written file
/// is never visible to concurrent readers.
pub fn write_registry_to_file(registry: &Registry, path: &Path) -> Result<()> {
    let mut buf = Vec::new();
    TextEncoder::new()
        .encode(&registry.gather(), &mut buf)
        .context("Failed to encode metrics")?;
    let content = String::from_utf8(buf).context("Metrics output is not valid UTF-8")?;
    write_string_using_tmp_file(path, &content).context("Failed to write metrics to file")
}
