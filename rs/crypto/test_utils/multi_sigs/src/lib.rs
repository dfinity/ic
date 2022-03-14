//! Utilities for testing multisignature operations.

use ic_crypto::utils::{NodeKeysToGenerate, TempCryptoComponent};
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_keys::make_crypto_node_key;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_types::crypto::KeyPurpose;
use ic_types::{NodeId, PrincipalId, RegistryVersion};
use rand::prelude::*;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

pub struct MultiSigTestEnvironment {
    pub crypto_components: BTreeMap<NodeId, TempCryptoComponent>,
    pub registry_data: Arc<ProtoRegistryDataProvider>,
    pub registry: Arc<FakeRegistryClient>,
    pub registry_version: RegistryVersion, // NOTE: We just pin the version upon creation
}

impl MultiSigTestEnvironment {
    /// Creates a new test environment with the given number of nodes.
    pub fn new(num_of_nodes: usize) -> Self {
        let registry_data = Arc::new(ProtoRegistryDataProvider::new());
        let registry = Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));

        let registry_version = { RegistryVersion::new(thread_rng().gen_range(1, u32::MAX) as u64) };

        let mut env = Self {
            crypto_components: BTreeMap::new(),
            registry_data,
            registry,
            registry_version,
        };

        let node_ids = Self::n_random_node_ids(num_of_nodes);

        for node_id in node_ids {
            env.create_crypto_component_with_key_in_registry(node_id);
        }
        env.registry.update_to_latest_version();

        env
    }

    /// Returns a node (Id and reference-to-CryptoComponent) chosen randomly
    /// from this environment.
    pub fn random_node(&self) -> (NodeId, &TempCryptoComponent) {
        self.random_node_excluding(&[])
    }

    /// Returns a node (Id and reference-to-CryptoComponent) chosen randomly
    /// from this environment's nodes exclusive of the given exclusions.
    pub fn random_node_excluding(&self, exclusions: &[NodeId]) -> (NodeId, &TempCryptoComponent) {
        self.choose_multiple_excluding(1, exclusions)
            .into_iter()
            .next()
            .expect("no available nodes")
    }

    /// Returns `num_of_nodes` nodes (Id and reference-to-CryptoComponent)
    /// chosen randomly from this environment's nodes exclusive of the given
    /// exclusions.
    pub fn choose_multiple_excluding(
        &self,
        num_of_nodes: usize,
        exclusions: &[NodeId],
    ) -> BTreeMap<NodeId, &TempCryptoComponent> {
        let rng = &mut thread_rng();

        self.crypto_components
            .iter()
            .filter(|(id, _)| !exclusions.contains(id))
            .choose_multiple(rng, num_of_nodes)
            .into_iter()
            .map(|(k, v)| (*k, v))
            .collect()
    }

    fn n_random_node_ids(n: usize) -> BTreeSet<NodeId> {
        let rng = &mut thread_rng();
        let mut node_ids = BTreeSet::new();
        while node_ids.len() < n {
            node_ids.insert(NodeId::from(PrincipalId::new_node_test_id(rng.gen())));
        }
        node_ids
    }

    fn create_crypto_component_with_key_in_registry(&mut self, node_id: NodeId) {
        let registry = Arc::clone(&self.registry) as Arc<_>;
        let (temp_crypto, node_keys) = {
            let keys_to_gen = NodeKeysToGenerate::only_committee_signing_key();

            TempCryptoComponent::new_with_node_keys_generation(registry, node_id, keys_to_gen)
        };
        self.crypto_components.insert(node_id, temp_crypto);

        let committee_pubkey = node_keys
            .committee_signing_pk
            .expect("failed to generate committee key");
        self.registry_data
            .add(
                &make_crypto_node_key(node_id, KeyPurpose::CommitteeSigning),
                self.registry_version,
                Some(committee_pubkey),
            )
            .expect("failed to add committee public key to registry");
    }
}
