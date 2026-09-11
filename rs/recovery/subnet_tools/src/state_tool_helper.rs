//! Wrappers around the `state_tool` commands these tools run on the states
//! they download and produce.

use ic_base_types::SubnetId;
use ic_recovery::{
    error::{RecoveryError, RecoveryResult},
    file_sync_helper::write_file,
};
use ic_registry_routing_table::CanisterIdRange;
use ic_registry_subnet_type::SubnetType;
use ic_types::Time;

use std::{fs::File, path::Path};

/// Computes manifest of a checkpoint at `dir` and writes it to `output_path`.
pub fn compute_manifest(dir: &Path, output_path: &Path) -> RecoveryResult<()> {
    ic_state_tool::commands::manifest::compute_manifest(dir)
        .map_err(|err| {
            RecoveryError::StateToolError(format!("Failed to compute the state manifest: {err}"))
        })
        .and_then(|manifest| write_file(output_path, manifest))
}

/// Verifies whether the textual representation of a manifest matches its root hash, and
/// returns the root hash.
pub fn verify_manifest(manifest_path: &Path) -> RecoveryResult<String> {
    let manifest_file =
        File::open(manifest_path).map_err(|err| RecoveryError::file_error(manifest_path, err))?;

    ic_state_tool::commands::verify_manifest::verify_manifest(manifest_file)
        .map_err(|err| {
            RecoveryError::StateToolError(format!("Failed to verify the state manifest: {err}"))
        })
        .map(hex::encode)
}

/// Splits a manifest, to verify the manifests resulting from a subnet split.
pub fn split_manifest(
    manifest_path: &Path,
    source_subnet: SubnetId,
    destination_subnet: SubnetId,
    batch_time: Time,
    canister_id_ranges: &[CanisterIdRange],
    subnet_type: SubnetType,
    output_path: &Path,
) -> RecoveryResult<()> {
    let mut output_file =
        File::create(output_path).map_err(|err| RecoveryError::file_error(output_path, err))?;

    ic_state_tool::commands::split_manifest::do_split_manifest(
        manifest_path.to_path_buf(),
        source_subnet,
        destination_subnet,
        subnet_type,
        batch_time,
        canister_id_ranges.to_vec(),
        &mut output_file,
    )
    .map_err(|err| RecoveryError::StateToolError(format!("Failed to split the manifest: {err}")))?;

    Ok(())
}

/// Assembles the checkpoint at `output` from the checkpoints at `base` (the
/// state of the destination subnet of a merge) and `source` (the state of the
/// subnet that is merged away): it holds everything of `base`, with the
/// canisters and canister snapshots of `source` added to those of `base`, and
/// is marked as the product of a subnet merge.
pub fn merge_checkpoints(base: &Path, source: &Path, output: &Path) -> RecoveryResult<()> {
    ic_state_tool::commands::merge::do_merge(
        base.to_path_buf(),
        source.to_path_buf(),
        output.to_path_buf(),
    )
    .map_err(|err| RecoveryError::StateToolError(format!("Failed to merge the states: {err}")))
}

/// The batch time of the checkpoint at `path`, in nanoseconds since the Epoch,
/// i.e. the IC time the subnet had reached when it wrote the checkpoint.
pub fn checkpoint_time_nanos(path: &Path) -> RecoveryResult<u64> {
    ic_state_tool::commands::checkpoint_time::batch_time_nanos(path.to_path_buf()).map_err(|err| {
        RecoveryError::StateToolError(format!(
            "Failed to read the batch time of the checkpoint {}: {err}",
            path.display()
        ))
    })
}
