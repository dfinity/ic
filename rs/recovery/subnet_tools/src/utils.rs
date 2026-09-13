use ic_protobuf::types::v1 as pb;
use ic_recovery::error::{RecoveryError, RecoveryResult};
use ic_state_manager::manifest::{manifest_from_path, manifest_hash};
use ic_types::{Time, consensus::CatchUpPackage};

use std::{fmt::Display, path::Path};

/// Reads and deserializes the CUP at `cup_path`.
pub fn get_cup(cup_path: &Path) -> RecoveryResult<CatchUpPackage> {
    let cup_proto = pb::CatchUpPackage::read_from_file(cup_path)
        .map_err(|err| cup_error("Failed to decode the CUP file", cup_path, err))?;

    CatchUpPackage::try_from(&cup_proto)
        .map_err(|err| cup_error("Failed to deserialize the CUP file", cup_path, err))
}

/// The block time of the CUP at `cup_path`, i.e. the IC time the subnet had
/// reached when it halted at that CUP.
pub fn get_batch_time_from_cup(cup_path: &Path) -> RecoveryResult<Time> {
    get_cup(cup_path).map(|cup| cup.content.block.as_ref().context.time)
}

fn cup_error(message: impl Display, cup_path: &Path, error: impl Display) -> RecoveryError {
    RecoveryError::UnexpectedError(format!("{} ({}): {}", message, cup_path.display(), error))
}

/// Computes the state hash of the given checkpoint.
pub fn get_state_hash(checkpoint_dir: impl AsRef<Path>) -> RecoveryResult<String> {
    let manifest = manifest_from_path(checkpoint_dir.as_ref()).map_err(|e| {
        RecoveryError::CheckpointError(
            format!(
                "Failed to read the manifest from path {}",
                checkpoint_dir.as_ref().display()
            ),
            e,
        )
    })?;

    Ok(hex::encode(manifest_hash(&manifest)))
}
