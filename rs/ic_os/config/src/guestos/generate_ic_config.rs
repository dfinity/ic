use anyhow::{Context, Result};
use config_types::HostOSConfig;
use std::fs::{read_to_string, write};
use std::path::Path;

/// Generate IC configuration from template and guestos config
pub fn generate_ic_config(
    guestos_config_json_path: &Path,
    template_path: &Path,
    output_path: &Path,
) -> Result<()> {
    Ok(())
}
