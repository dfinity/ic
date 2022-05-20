//! Helper functions calling the `ic-replay` library.
use crate::RecoveryResult;
use ic_base_types::SubnetId;
use ic_replay::{
    cmd::{ClapSubnetId, ReplayToolArgs},
    player::{ReplayError, StateParams},
};
use ic_types::Height;
use std::path::PathBuf;
use std::str::FromStr;

use crate::error::RecoveryError;
use crate::file_sync_helper::{read_file, write_file};

pub const OUTPUT_FILE_NAME: &str = "replay_result.txt";

/// Basic blocking call of `ic-replay` for the given subnet id and config
/// without any subcommands. Output is stored in the given file as a single,
/// space-separated line of <`replay_height` `state_hash`>
pub async fn replay(
    subnet_id: SubnetId,
    config: PathBuf,
    output: PathBuf,
) -> RecoveryResult<StateParams> {
    let args = ReplayToolArgs {
        subnet_id: ClapSubnetId::from_str(&subnet_id.to_string()).unwrap(),
        config,
        canister_caller_id: None,
        replay_until_height: None,
        subcmd: None,
    };
    // Since replay output needs to be persisted anyway in case the recovery process
    // is restarted, we avoid declaring a return value and moving out of the
    // closure, and instead directly write to file.
    let output_file = output.clone();
    tokio::task::spawn_blocking(move || match ic_replay::replay(args) {
        Ok((height, hash)) | Err(ReplayError::UpgradeDetected((height, hash))) => {
            write_file(&output_file, format!("{} {}", height, hash))
                .expect("failed to write ic-replay output")
        }
        err => panic!("Unexpected response: {:?}", err),
    })
    .await
    .map_err(|e| {
        RecoveryError::invalid_output_error(format!("Execution of ic-replay failed: {}", e))
    })?;

    read_output(output)
}

/// Read the replay output written to the given file.
/// File content is expected to be a single line of <`replay_height` `state_hash`>
pub fn read_output(output_file: PathBuf) -> RecoveryResult<StateParams> {
    let content = read_file(&output_file)?;
    let vec = content.split(' ').collect::<Vec<&str>>();
    Ok((
        Height::from(vec[0].parse::<u64>().unwrap()),
        vec[1].to_string(),
    ))
}
