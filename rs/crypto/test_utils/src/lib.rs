//! Utilities for testing crypto code.
pub mod canister_signatures;
pub mod ed25519_utils;

use ic_types::NodeId;

use ic_interfaces_registry::RegistryClient;
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

pub use ic_crypto_internal_csp_test_utils::files;

pub fn crypto_for<T>(node_id: NodeId, crypto_components: &BTreeMap<NodeId, T>) -> &T {
    crypto_components
        .get(&node_id)
        .unwrap_or_else(|| panic!("missing crypto component for {node_id:?}"))
}

pub fn empty_fake_registry() -> Arc<dyn RegistryClient> {
    Arc::new(FakeRegistryClient::new(Arc::new(
        ProtoRegistryDataProvider::new(),
    )))
}

/// returns a `BTreeSet` of the items provided as array.
pub fn set_of<T: Ord + Clone>(items: &[T]) -> BTreeSet<T> {
    let mut set = BTreeSet::new();
    for item in items {
        assert!(set.insert(item.clone()));
    }
    set
}

pub fn map_of<K: Ord, V>(entries: Vec<(K, V)>) -> BTreeMap<K, V> {
    let mut map = BTreeMap::new();
    for (key, value) in entries {
        assert!(map.insert(key, value).is_none());
    }
    map
}
