//! Helper functions calling the `ic-replay` library.
use crate::RecoveryResult;
use crate::{
    error::RecoveryError,
    file_sync_helper::{read_file, write_file},
};
use ic_base_types::{CanisterId, SubnetId};
use ic_replay::{
    cmd::{ClapSubnetId, ReplayToolArgs, SubCommand},
    player::{ReplayError, ReplayOutput},
};
use ic_types::ReplicaVersion;
use std::{path::PathBuf, str::FromStr};

pub const OUTPUT_FILE_NAME: &str = "replay_result.txt";

/// Basic blocking call of `ic-replay` for the given subnet id and config.
/// Output is stored in the given file in JSON format
pub async fn replay(
    subnet_id: SubnetId,
    config: PathBuf,
    canister_caller_id: Option<CanisterId>,
    data_root: PathBuf,
    subcmd: Option<SubCommand>,
    replay_until_height: Option<u64>,
    output: PathBuf,
    skip_prompts: bool,
    create_checkpoint: bool,
    replica_version: Option<ReplicaVersion>,
) -> RecoveryResult<ReplayOutput> {
    let args = ReplayToolArgs {
        subnet_id: Some(ClapSubnetId::from_str(&subnet_id.to_string()).unwrap()),
        config: Some(config),
        canister_caller_id,
        replay_until_height,
        subcmd,
        data_root: Some(data_root),
        skip_prompts,
        create_checkpoint,
        replica_version,
    };
    // Since replay output needs to be persisted anyway in case the recovery process
    // is restarted, we avoid declaring a return value and moving out of the
    // closure, and instead directly write to file.
    let output_file = output.clone();
    tokio::task::spawn_blocking(move || match ic_replay::replay(args) {
        Ok(replay_output) | Err(ReplayError::UpgradeDetected(replay_output)) => {
            store_replay_output(replay_output, output_file)
        }
        Err(ReplayError::ManualInspectionRequired(replay_output)) => {
            store_replay_output(replay_output, output_file)?;
            Err(RecoveryError::OutputError(
                "Replay finished successfully, but manual inspection and/or re-run is recommended."
                    .into(),
            ))
        }
        Err(err) => Err(RecoveryError::invalid_output_error(format!(
            "Unexpected response: {err:?}"
        ))),
    })
    .await
    .map_err(|e| {
        RecoveryError::invalid_output_error(format!("failed to join ic-replay thread: {e}"))
    })??;

    read_output(output)
}

pub fn store_replay_output(
    replay_output: ReplayOutput,
    output_file: PathBuf,
) -> RecoveryResult<()> {
    let json = serde_json::to_string(&replay_output).map_err(|e| {
        RecoveryError::invalid_output_error(format!("failed to serialize ic-replay output: {e}"))
    })?;
    println!("{replay_output:?}");
    write_file(&output_file, json)
}

/// Read the replay output written to the given file.
/// File content is expected to be JSON format
pub fn read_output(output_file: PathBuf) -> RecoveryResult<ReplayOutput> {
    let content = read_file(&output_file)?;
    let replay_output: ReplayOutput = serde_json::from_str(&content).map_err(|e| {
        RecoveryError::invalid_output_error(format!("Failed to deserialize ic-replay output: {e}"))
    })?;
    Ok(replay_output)
}
