//! Helper functions calling the `ic-replay` library.
use crate::RecoveryResult;
use ic_base_types::CanisterId;
use ic_base_types::SubnetId;
use ic_replay::{
    cmd::{ClapSubnetId, ReplayToolArgs, SubCommand},
    player::{ReplayError, StateParams},
};
use std::path::PathBuf;
use std::str::FromStr;

use crate::error::RecoveryError;
use crate::file_sync_helper::{read_file, write_file};

pub const OUTPUT_FILE_NAME: &str = "replay_result.txt";

/// Basic blocking call of `ic-replay` for the given subnet id and config.
/// Output is stored in the given file in JSON format
pub async fn replay(
    subnet_id: SubnetId,
    config: PathBuf,
    canister_caller_id: Option<CanisterId>,
    subcmd: Option<SubCommand>,
    output: PathBuf,
) -> RecoveryResult<StateParams> {
    let args = ReplayToolArgs {
        subnet_id: ClapSubnetId::from_str(&subnet_id.to_string()).unwrap(),
        config,
        canister_caller_id,
        replay_until_height: None,
        subcmd,
    };
    // Since replay output needs to be persisted anyway in case the recovery process
    // is restarted, we avoid declaring a return value and moving out of the
    // closure, and instead directly write to file.
    let output_file = output.clone();
    tokio::task::spawn_blocking(move || match ic_replay::replay(args) {
        Ok(state_params) | Err(ReplayError::UpgradeDetected(state_params)) => {
            let json = serde_json::to_string(&state_params).map_err(|e| {
                RecoveryError::invalid_output_error(format!(
                    "failed to serialize ic-replay output: {}",
                    e
                ))
            })?;
            println!("{:?}", state_params);
            write_file(&output_file, json)
        }
        Err(err) => Err(RecoveryError::invalid_output_error(format!(
            "Unexpected response: {:?}",
            err
        ))),
    })
    .await
    .map_err(|e| {
        RecoveryError::invalid_output_error(format!("failed to join ic-replay thread: {}", e))
    })??;

    read_output(output)
}

/// Read the replay output written to the given file.
/// File content is expected to be JSON format
pub fn read_output(output_file: PathBuf) -> RecoveryResult<StateParams> {
    let content = read_file(&output_file)?;
    let state_params: StateParams = serde_json::from_str(&content).map_err(|e| {
        RecoveryError::invalid_output_error(format!(
            "Failed to deserialize ic-replay output: {}",
            e
        ))
    })?;
    Ok(state_params)
}
