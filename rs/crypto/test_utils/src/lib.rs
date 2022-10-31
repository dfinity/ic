//! Utilities for testing crypto code.
pub mod canister_signatures;
pub mod dkg;
pub mod ed25519_utils;
pub mod tls;

use ic_types::NodeId;

use ic_interfaces_registry::RegistryClient;
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

pub use ic_crypto_internal_csp_test_utils::files;
use ic_protobuf::crypto::v1::NodePublicKeys;
use ic_types::crypto::CurrentNodePublicKeys;

pub fn crypto_for<T>(node_id: NodeId, crypto_components: &BTreeMap<NodeId, T>) -> &T {
    crypto_components
        .get(&node_id)
        .unwrap_or_else(|| panic!("missing crypto component for {:?}", node_id))
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

//TODO CRP-1738: should no longer be needed when get_node_keys_or_generate_if_missing also returns CurrentNodePublicKeys
pub fn assert_public_keys_eq(
    node_public_keys: &NodePublicKeys,
    expected_current_node_public_keys: &CurrentNodePublicKeys,
) {
    assert_eq!(
        node_public_keys.node_signing_pk,
        expected_current_node_public_keys.node_signing_public_key
    );
    assert_eq!(
        node_public_keys.committee_signing_pk,
        expected_current_node_public_keys.committee_signing_public_key
    );
    assert_eq!(
        node_public_keys.tls_certificate,
        expected_current_node_public_keys.tls_certificate
    );
    assert_eq!(
        node_public_keys.dkg_dealing_encryption_pk,
        expected_current_node_public_keys.dkg_dealing_encryption_public_key
    );
    assert_eq!(
        node_public_keys.idkg_dealing_encryption_pk,
        expected_current_node_public_keys.idkg_dealing_encryption_public_key
    );
}
