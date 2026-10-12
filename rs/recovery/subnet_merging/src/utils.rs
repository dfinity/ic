use ic_base_types::{RegistryVersion, SubnetId};
use ic_protobuf::registry::subnet::v1::SubnetRecord;
use ic_recovery::{
    error::{RecoveryError, RecoveryResult},
    file_sync_helper::{read_file, write_file},
    registry_helper::RegistryHelper,
};
use ic_registry_client_helpers::subnet::SubnetRegistry;

use std::path::Path;

/// Returns the record of the given subnet as of `registry_version`, rather
/// than as of the latest version `RegistryHelper::get_subnet_record` reads.
///
/// Polls the `RegistryReplicator` first, as every getter of `RegistryHelper`
/// does: a version the local store has not caught up with yet is not readable,
/// and the merge may well be asking about one that was just created.
pub(crate) fn get_subnet_record_at_version(
    registry_helper: &RegistryHelper,
    subnet_id: SubnetId,
    registry_version: RegistryVersion,
) -> RecoveryResult<Option<SubnetRecord>> {
    let _ = registry_helper.latest_registry_version()?;

    registry_helper
        .registry_client()
        .get_subnet_record(subnet_id, registry_version)
        .map_err(|err| {
            RecoveryError::RegistryError(format!(
                "Failed to get the record of subnet {subnet_id} at registry version \
                 {registry_version}: {err}"
            ))
        })
}

/// The lowest registry version at which `predicate` holds, in a registry whose
/// history has it hold from some version onwards -- e.g. "the subnet is labeled
/// cooling down", which a single proposal of this tool brings about and nothing
/// here undoes.
///
/// Found by binary search, i.e. in a logarithmic number of (local) registry
/// reads rather than by scanning the whole history. Fails if the predicate does
/// not hold at the latest registry version; if the property was turned on and
/// off repeatedly, the version returned is the start of one of the stretches it
/// held in, which is why the callers log it for the operator to confirm.
pub(crate) fn first_registry_version_where(
    registry_helper: &RegistryHelper,
    predicate: impl Fn(RegistryVersion) -> RecoveryResult<bool>,
) -> RecoveryResult<RegistryVersion> {
    let latest = registry_helper.latest_registry_version()?;
    if !predicate(latest)? {
        return Err(RecoveryError::ValidationFailed(format!(
            "The expected registry state has not been reached at the latest registry version \
             {latest}"
        )));
    }

    // Invariant: the predicate does not hold at `low` and holds at `high`. The
    // registry starts at version 1, whose predecessor 0 is the empty registry,
    // where nothing holds.
    let mut low = RegistryVersion::from(0);
    let mut high = latest;
    while high > low + RegistryVersion::from(1) {
        let middle = RegistryVersion::from((low.get() + high.get()) / 2);
        if predicate(middle)? {
            high = middle;
        } else {
            low = middle;
        }
    }

    Ok(high)
}

pub(crate) fn write_registry_version(path: &Path, version: u64) -> RecoveryResult<()> {
    write_file(path, version.to_string())
}

pub(crate) fn read_registry_version(path: &Path) -> RecoveryResult<u64> {
    let contents = read_file(path)?;
    contents.trim().parse().map_err(|err| {
        RecoveryError::UnexpectedError(format!(
            "Failed to parse the registry version {contents:?} at {}: {err}",
            path.display()
        ))
    })
}
