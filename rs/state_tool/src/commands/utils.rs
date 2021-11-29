//! Utility functions shared across commands.

use ic_config::{config_parser::ConfigSource, ConfigOptional};
use ic_logger::replica_logger::no_op_logger;
use ic_state_layout::StateLayout;
use std::path::PathBuf;

/// Loads the location of the state root from the given `replica` configuration
/// file.
pub fn locate_state_root(config_path: PathBuf) -> Result<StateLayout, String> {
    let config: ConfigOptional = ConfigSource::File(config_path.clone())
        .load()
        .map_err(|e| e.to_string())?;

    let state_root = config
        .state_manager
        .ok_or_else(|| {
            format!(
                "Configuration {} doesn't specify state_manager.state_root option",
                config_path.display()
            )
        })?
        .state_root();

    Ok(StateLayout::new(no_op_logger(), state_root))
}
