use super::{
    ComponentModifier, ConsensusDependencies, ConsensusInstance, ConsensusRunner,
    ConsensusRunnerConfig, StopPredicate, setup_subnet, test_master_public_key_ids,
};
use ic_consensus_utils::pool_reader::PoolReader;
use ic_interfaces::{consensus_pool::ConsensusPool, messaging::MessageRouting};
use ic_interfaces_registry::RegistryClient;
use ic_management_canister_types_private::MasterPublicKeyId;
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_test_utilities_time::FastForwardTimeSource;
use ic_test_utilities_types::ids::{node_test_id, subnet_test_id, test_replica_version};
use ic_types::{Height, batch::BatchContent, crypto::CryptoHash, replica_config::ReplicaConfig};
use rand_chacha::{ChaChaRng, rand_core::SeedableRng};
use std::{cell::RefCell, rc::Rc, sync::Arc};

/// Helper type for additional mutations to the registry that a test may want to perform after the
/// initial setup of the subnet.
pub type RegistryMutations = Box<dyn FnOnce(&ProtoRegistryDataProvider, &FakeRegistryClient)>;

pub struct TestRunner {
    config: ConsensusRunnerConfig,
    finish: bool,
    modifiers: Vec<ComponentModifier>,
    stop_predicate: Option<StopPredicate>,
    additional_registry_mutations: Option<RegistryMutations>,
    chain_key_ids: Vec<MasterPublicKeyId>,
}

impl TestRunner {
    pub fn new(config: ConsensusRunnerConfig, finish: bool) -> Self {
        Self {
            config,
            finish,
            modifiers: vec![],
            stop_predicate: None,
            additional_registry_mutations: None,
            chain_key_ids: test_master_public_key_ids(),
        }
    }

    pub fn with_modifiers(mut self, modifiers: Vec<ComponentModifier>) -> Self {
        self.modifiers = modifiers;
        self
    }

    pub fn with_stop_predicate(mut self, stop_predicate: StopPredicate) -> Self {
        self.stop_predicate = Some(stop_predicate);
        self
    }

    pub fn with_additional_registry_mutations(
        mut self,
        additional_registry_mutations: RegistryMutations,
    ) -> Self {
        self.additional_registry_mutations = Some(additional_registry_mutations);
        self
    }

    /// Set up the subnet without any chain keys.
    ///
    /// Generating chain key transcripts, dealings and pre-signatures with real crypto dominates
    /// the runtime of the simulation, so tests that don't exercise chain keys should switch them
    /// off to keep their runtime (and the timeout of the target they live in) modest.
    pub fn without_chain_keys(mut self) -> Self {
        self.chain_key_ids.clear();
        self
    }

    pub fn run_test(mut self) {
        let stop_predicate = self
            .stop_predicate
            .expect("Stop predicate must be set before running the test");

        let rng = &mut ChaChaRng::seed_from_u64(self.config.random_seed);
        let nodes = self.config.num_nodes;
        ic_test_utilities::artifact_pool_config::with_test_pool_configs(
            nodes,
            move |pool_configs| {
                let time_source = FastForwardTimeSource::new();
                let subnet_id = subnet_test_id(0);
                let replica_configs: Vec<_> = vec![(); nodes]
                    .iter()
                    .enumerate()
                    .map(|(index, _)| ReplicaConfig {
                        node_id: node_test_id(index as u64),
                        subnet_id,
                        replica_version: test_replica_version(),
                    })
                    .collect();
                let node_ids: Vec<_> = replica_configs
                    .iter()
                    .map(|config| config.node_id)
                    .collect();
                let (data_provider, registry_client, cup, cryptos) = setup_subnet(
                    subnet_id,
                    &node_ids,
                    self.config.dkg_interval_length,
                    &self.chain_key_ids,
                    rng,
                );
                if let Some(additional_registry_mutations) = self.additional_registry_mutations {
                    additional_registry_mutations(&data_provider, &registry_client);
                }
                let inst_deps: Vec<_> = replica_configs
                    .iter()
                    .zip(pool_configs.iter())
                    .map(|(replica_config, pool_config)| {
                        ConsensusDependencies::new(
                            replica_config.clone(),
                            pool_config.clone(),
                            Arc::clone(&registry_client) as Arc<dyn RegistryClient>,
                            cup.clone(),
                            time_source.clone(),
                        )
                    })
                    .collect();

                let mut runner = ConsensusRunner::new_with_config(self.config, time_source);

                for ((pool_config, deps), crypto) in pool_configs
                    .iter()
                    .zip(inst_deps.iter())
                    .zip(cryptos.iter())
                {
                    let modifier = self.modifiers.pop();
                    runner.add_instance(
                        deps.consensus_pool.read().unwrap().get_cache(),
                        crypto.clone(),
                        crypto.clone(),
                        modifier,
                        deps,
                        pool_config.clone(),
                        &PoolReader::new(&*deps.consensus_pool.read().unwrap()),
                    );
                }
                assert_eq!(runner.run_until(stop_predicate), self.finish);
            },
        )
    }

    pub fn run_n_rounds_and_collect_hashes(self) -> Vec<CryptoHash> {
        let rounds = self.config.num_rounds;
        let hashes = Rc::new(RefCell::new(Vec::new()));
        let hashes_clone = hashes.clone();
        let reach_n_rounds = move |inst: &ConsensusInstance<'_>| {
            let pool = inst.driver.consensus_pool.write().unwrap();
            for nota in pool.validated().notarization().get_highest_iter() {
                let hash = ic_types::crypto::crypto_hash(&nota);
                let hash = hash.get_ref();
                if !hashes_clone.borrow().contains(hash) {
                    hashes_clone.borrow_mut().push(hash.clone());
                }
            }
            inst.deps.message_routing.expected_batch_height() >= Height::from(rounds)
        };
        self.with_stop_predicate(Box::new(reach_n_rounds))
            .run_test();
        hashes.as_ref().take()
    }

    pub fn run_n_rounds_and_check_pubkeys(self) -> bool {
        assert!(
            !self.chain_key_ids.is_empty(),
            "Checking for chain key public keys requires chain keys to be configured"
        );
        let rounds = self.config.num_rounds;
        let key_ids = self.chain_key_ids.clone();
        let pubkey_exists = Rc::new(RefCell::new(false));
        let pubkey_exists_clone = pubkey_exists.clone();
        let got_pubkey = move |inst: &ConsensusInstance<'_>| {
            let batches = inst.deps.message_routing.as_ref().batches.read().unwrap();
            let Some(batch) = batches.last() else {
                return false;
            };

            let mut found_keys = 0;
            for key_id in &key_ids {
                if let BatchContent::Data { chain_key_data, .. } = &batch.content
                    && chain_key_data.master_public_keys.contains_key(key_id)
                {
                    found_keys += 1
                }
            }
            if found_keys == key_ids.len() {
                *pubkey_exists_clone.borrow_mut() = true;
            }
            *pubkey_exists_clone.borrow()
                || inst.deps.message_routing.expected_batch_height() >= Height::from(rounds)
        };
        self.with_stop_predicate(Box::new(got_pubkey)).run_test();

        *pubkey_exists.borrow()
    }
}
