//! This is just used by a test (to wit, rs/nervous_system/canisters/tests/registry.rs).
//!
//! Our job is just to call the registry_get_changes_since method. For that
//! test, this is the code under test.

use ic_cdk::update;
use ic_crypto_sha2::Sha256;
use ic_nervous_system_canisters::registry::{Registry, RegistryCanister};
use ic_registry_fetch_large_record_test_canister::{
    CallRegistryGetChangesSinceRequest, ContentSummary,
};
use ic_registry_transport::pb::v1::RegistryDelta;
use ic_types::RegistryVersion;

#[update]
async fn call_registry_get_changes_since(
    _: CallRegistryGetChangesSinceRequest,
) -> Option<ContentSummary> {
    let registry_canister = RegistryCanister::new();

    let latest_version: RegistryVersion = registry_canister.get_latest_version().await.unwrap();

    let mut deltas: Vec<RegistryDelta> = registry_canister
        .registry_changes_since(latest_version - RegistryVersion::from(1))
        .await
        .unwrap();

    assert_eq!(deltas.len(), 1);
    let RegistryDelta { key, mut values } = deltas.pop().unwrap();

    assert_eq!(values.len(), 1);
    let value = values.pop().unwrap();
    if value.deletion_marker {
        return None;
    }

    let value = value.value;
    let result = ContentSummary {
        key,
        len: u64::try_from(value.len()).unwrap(),
        sha256: Sha256::hash(&value).to_vec(),
    };
    Some(result)
}

fn main() {
    // Intentionally left blank.
}
