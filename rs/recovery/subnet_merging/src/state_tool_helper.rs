use ic_recovery::{
    error::{RecoveryError, RecoveryResult},
    file_sync_helper::write_file,
};

use std::{fs::File, path::Path};

/// Computes manifest of a checkpoint at `dir` and writes it to `output_path`.
pub(crate) fn compute_manifest(dir: &Path, output_path: &Path) -> RecoveryResult<()> {
    ic_state_tool::commands::manifest::compute_manifest(dir)
        .map_err(|err| {
            RecoveryError::StateToolError(format!("Failed to compute the state manifest: {err}"))
        })
        .and_then(|manifest| write_file(output_path, manifest))
}

/// Verifies whether the textual representation of a manifest matches its root hash, and
/// returns the root hash.
pub(crate) fn verify_manifest(manifest_path: &Path) -> RecoveryResult<String> {
    let manifest_file =
        File::open(manifest_path).map_err(|err| RecoveryError::file_error(manifest_path, err))?;

    ic_state_tool::commands::verify_manifest::verify_manifest(manifest_file)
        .map_err(|err| {
            RecoveryError::StateToolError(format!("Failed to verify the state manifest: {err}"))
        })
        .map(hex::encode)
}

/// Assembles the checkpoint at `output` from the checkpoints at `base` (the
/// state of the destination subnet) and `source` (the state of the subnet that
/// is merged away): it holds everything of `base`, with the canisters and
/// canister snapshots of `source` added to those of `base`, and is marked as
/// the product of a subnet merge.
pub(crate) fn merge_checkpoints(base: &Path, source: &Path, output: &Path) -> RecoveryResult<()> {
    ic_state_tool::commands::merge::do_merge(
        base.to_path_buf(),
        source.to_path_buf(),
        output.to_path_buf(),
    )
    .map_err(|err| RecoveryError::StateToolError(format!("Failed to merge the states: {err}")))
}

/// The batch time of the checkpoint at `path`, in nanoseconds since the Epoch,
/// i.e. the IC time the subnet had reached when it wrote the checkpoint.
pub(crate) fn checkpoint_time_nanos(path: &Path) -> RecoveryResult<u64> {
    ic_state_tool::commands::checkpoint_time::batch_time_nanos(path.to_path_buf()).map_err(|err| {
        RecoveryError::StateToolError(format!(
            "Failed to read the batch time of the checkpoint {}: {err}",
            path.display()
        ))
    })
}
