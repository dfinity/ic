pub mod guestos;
pub mod hostos;
pub mod setupos;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{File, create_dir_all};
use std::io::Write;
use std::path::Path;

pub static DEFAULT_SETUPOS_CONFIG_OBJECT_PATH: &str = "/var/ic/config/config.json";
pub static DEFAULT_SETUPOS_CONFIG_INI_FILE_PATH: &str = "/config/config.ini";
pub static DEFAULT_SETUPOS_DEPLOYMENT_JSON_PATH: &str = "/data/deployment.json";

pub static DEFAULT_SETUPOS_HOSTOS_CONFIG_OBJECT_PATH: &str = "/var/ic/config/config-hostos.json";

pub static DEFAULT_HOSTOS_CONFIG_INI_FILE_PATH: &str = "/boot/config/config.ini";
pub static DEFAULT_HOSTOS_DEPLOYMENT_JSON_PATH: &str = "/boot/config/deployment.json";
pub static DEFAULT_HOSTOS_CONFIG_OBJECT_PATH: &str = "/boot/config/config.json";
pub static DEFAULT_HOSTOS_GUESTOS_CONFIG_OBJECT_PATH: &str = "/boot/config/config-guestos.json";
pub static DEFAULT_GUESTOS_CONFIG_OBJECT_PATH: &str = "/run/config/config.json";
pub static DEFAULT_BOOTSTRAP_DIR: &str = "/run/config/bootstrap";
pub static DEFAULT_IC_JSON5_OUTPUT_PATH: &str = "/run/ic-node/config/ic.json5";

pub fn serialize_and_write_config<T: Serialize>(path: &Path, config: &T) -> Result<()> {
    let serialized_config =
        serde_json::to_string_pretty(config).expect("Failed to serialize configuration");

    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
    }

    let mut file = File::create(path)?;
    file.write_all(serialized_config.as_bytes())?;
    Ok(())
}

pub fn deserialize_config<T: for<'de> Deserialize<'de>, P: AsRef<Path>>(file_path: P) -> Result<T> {
    let file =
        File::open(&file_path).context(format!("Failed to open file: {:?}", file_path.as_ref()))?;
    serde_json::from_reader(file).context(format!(
        "Failed to deserialize JSON from file: {:?}",
        file_path.as_ref()
    ))
}
