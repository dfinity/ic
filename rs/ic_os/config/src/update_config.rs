//! This module is for updating existing config.json files.
//! The deserialize-then-serialize-and-write operation ensures that if new
//! fields with `#[serde(default)]` are added to the configuration structs, they
//! are written to the config.json file on disk with their default values.

use std::path::PathBuf;

use anyhow::Result;

use crate::{deserialize_config, serialize_and_write_config};
use config_types::*;

pub fn update_guestos_config(guestos_config_json_path: &PathBuf) -> Result<()> {
    if let Ok(existing_config) = deserialize_config::<GuestOSConfig, _>(&guestos_config_json_path) {
        serialize_and_write_config(guestos_config_json_path, &existing_config)?;
    }

    Ok(())
}

pub fn update_hostos_config(hostos_config_json_path: &PathBuf) -> Result<()> {
    if let Ok(existing_config) = deserialize_config::<HostOSConfig, _>(hostos_config_json_path) {
        serialize_and_write_config(hostos_config_json_path, &existing_config)?;
    }

    Ok(())
}
