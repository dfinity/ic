use std::path::Path;

use ic_registry_common::local_store::{
    compact_delta_to_changelog, Changelog, LocalStoreImpl, LocalStoreWriter,
};
use ic_types::RegistryVersion;

pub fn get_mainnet_delta_6d_c1() -> Changelog {
    let mainnet_delta_raw =
        include_bytes!("../../../registry/common/artifacts/mainnet_delta_00-6d-c1.pb");
    compact_delta_to_changelog(&mainnet_delta_raw[..])
        .expect("Could not read mainnet delta 00-6d-c1")
        .1
}

pub fn create_local_store_from_changelog<P: AsRef<Path>>(
    path: P,
    changelog: Changelog,
) -> LocalStoreImpl {
    let store = LocalStoreImpl::new(path.as_ref());
    for (v, changelog_entry) in changelog.into_iter().enumerate() {
        let v = RegistryVersion::from((v + 1) as u64);
        store.store(v, changelog_entry).unwrap();
    }
    store
}
