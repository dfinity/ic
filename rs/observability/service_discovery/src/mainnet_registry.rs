use std::path::Path;

use ic_registry_local_store::{compact_delta_to_changelog, Changelog, LocalStoreImpl};

pub fn get_mainnet_delta_6d_c1() -> Changelog {
    compact_delta_to_changelog(ic_registry_local_store_artifacts::MAINNET_DELTA_00_6D_C1)
        .expect("Could not read mainnet delta 00-6d-c1")
        .1
}

/// this method uses unsafe writes. as a result, after a power outage, it is
/// possible that the latest version is lower than the highest version in
/// `changelog`, even if the call returned successfully. we deem this acceptable
/// in this particular case, as this method is only used on startup and the
/// missing versions will be fetched through subsequent updates of the local
/// store.
pub fn create_local_store_from_changelog<P: AsRef<Path>>(
    path: P,
    changelog: Changelog,
) -> LocalStoreImpl {
    let store = LocalStoreImpl::new(path.as_ref());
    for (v, changelog_entry) in changelog.into_iter().enumerate() {
        store
            .write_changelog_entry_unsafe((v + 1) as u64, changelog_entry)
            .unwrap();
    }
    store
}
