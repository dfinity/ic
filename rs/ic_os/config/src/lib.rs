use std::collections::HashMap;
use std::fs::read_to_string;
use std::path::Path;

use anyhow::{Context, Result};

pub type ConfigMap = HashMap<String, String>;

pub static DEFAULT_SETUPOS_CONFIG_FILE_PATH: &str = "/var/ic/config/config.ini";
pub static DEFAULT_SETUPOS_DEPLOYMENT_JSON_PATH: &str = "/data/deployment.json";

pub static DEFAULT_HOSTOS_CONFIG_FILE_PATH: &str = "/boot/config/config.ini";
pub static DEFAULT_HOSTOS_DEPLOYMENT_JSON_PATH: &str = "/boot/config/deployment.json";

fn parse_config_line(line: &str) -> Option<(String, String)> {
    // Skip blank lines and comments
    if line.is_empty() || line.trim().starts_with('#') {
        return None;
    }

    let parts: Vec<&str> = line.splitn(2, '=').collect();
    if parts.len() == 2 {
        Some((parts[0].trim().into(), parts[1].trim().into()))
    } else {
        eprintln!("Warning: skipping config line due to unrecognized format: \"{line}\"");
        eprintln!("Expected format: \"<key>=<value>\"");
        None
    }
}

pub fn config_map_from_path(config_file_path: &Path) -> Result<ConfigMap> {
    let file_contents = read_to_string(config_file_path)
        .with_context(|| format!("Error reading file: {}", config_file_path.display()))?;
    Ok(file_contents
        .lines()
        .filter_map(parse_config_line)
        .collect())
}
