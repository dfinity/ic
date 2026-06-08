//! # Traceability
//! Spec: openspec/capabilities/consensus/spec.md
//!
//! REQ-CONS-001: Subcomponent Execution Order
//!   SCENARIO-CONS-001: Round-robin invocation
//!   SCENARIO-CONS-002: DKG key manager runs first
//!   SCENARIO-CONS-003: Subnet halt by registry record
//!
//! REQ-CONS-002: Block Maker Election
//!   SCENARIO-CONS-004: Node elected as block maker
//!   SCENARIO-CONS-005: Duplicate proposal prevention
//!   SCENARIO-CONS-006: Better block suppression
//!
//! REQ-CONS-004: Notarization
//!   SCENARIO-CONS-011: Notarization share creation
//!   SCENARIO-CONS-012: Notarization aggregate creation
//!
//! REQ-CONS-005: Finalization
//!   SCENARIO-CONS-013: Finalization share creation
//!   SCENARIO-CONS-014: Finalization aggregate creation
//!
//! REQ-CONS-010: Batch Delivery
//!   SCENARIO-CONS-022: Deliver finalized block as batch

#[cfg(test)]
mod framework;

use crate::framework::{
    ComponentModifier, ConsensusDependencies, ConsensusInstance, ConsensusRunner,
    ConsensusRunnerConfig, StopPredicate, malicious, setup_subnet,
};
use framework::test_master_public_key_ids;
use ic_consensus::consensus::ACCEPTABLE_NOTARIZATION_CERTIFICATION_GAP;
use ic_consensus_utils::pool_reader::PoolReader;
use ic_interfaces::{consensus_pool::ConsensusPool, messaging::MessageRouting};
use ic_interfaces_registry::RegistryClient;
use ic_protobuf::registry::subnet::v1::SubnetRecord;
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_test_utilities_time::FastForwardTimeSource;
use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
use ic_types::{
    Height, batch::BatchContent, crypto::CryptoHash, malicious_flags::MaliciousFlags,
    replica_config::ReplicaConfig,
};
use rand::Rng;
use rand_chacha::{ChaChaRng, rand_core::SeedableRng};
use std::{cell::RefCell, cmp::Ordering, rc::Rc, sync::Arc};

#[test]
fn multiple_nodes_are_live() -> Result<(), String> {
    // allow settings to be customized when running from commandline
    ConsensusRunnerConfig::new_from_env(4, 0)
        .and_then(|config| config.parse_extra_config())
        .map(|config| {
            TestRunner::new(config, true).run_n_rounds_and_collect_hashes();
        })
}

#[test]
fn single_node_is_live() {
    let config = ConsensusRunnerConfig {
        num_nodes: 1,
        num_rounds: 126,
        ..Default::default()
    };
    TestRunner::new(config, true).run_n_rounds_and_collect_hashes();
}

#[test]
fn master_pubkeys_are_produced() -> Result<(), String> {
    ConsensusRunnerConfig::new_from_env(4, 0)
        .and_then(|config| config.parse_extra_config())
        .map(|mut config| {
            // make sure we run at least 60 rounds
            if config.num_rounds < 60 {
                config.num_rounds = 60;
            }
            assert!(TestRunner::new(config, true).run_n_rounds_and_check_pubkeys());
        })
}

#[ignore]
#[test]
fn multiple_nodes_are_deterministic() {
    let run = || {
        let config = ConsensusRunnerConfig {
            num_nodes: 4,
            num_rounds: 10,
            ..Default::default()
        };
        TestRunner::new(config, true).run_n_rounds_and_collect_hashes()
    };
    assert_eq!(run(), run());
}

#[test]
fn minority_invalid_notary_share_signature_would_pass() -> Result<(), String> {
    ConsensusRunnerConfig::new_from_env(4, 0)
        .and_then(|config| config.parse_extra_config())
        .map(|config| {
            let mut rng = ChaChaRng::seed_from_u64(config.random_seed);
            let f = (config.num_nodes - 1) / 3;
            assert!(f > 0, "This test requires NUM_NODES >= 4");
            let mut malicious: Vec<ComponentModifier> = Vec::new();
            for _ in 0..rng.gen_range(1..=f) {
                malicious.push(malicious::invalid_notary_share_signature())
            }
            TestRunner::new(config, true)
                .with_modifiers(malicious)
                .run_n_rounds_and_collect_hashes();
        })
}

#[test]
fn majority_invalid_notary_share_signature_would_stuck() -> Result<(), String> {
    ConsensusRunnerConfig::new_from_env(4, 0)
        .and_then(|config| config.parse_extra_config())
        .map(|config| {
            let mut malicious: Vec<ComponentModifier> = Vec::new();
            for _ in 0..(config.num_nodes / 3 + 1) {
                malicious.push(malicious::invalid_notary_share_signature())
            }
            TestRunner::new(config, false)
                .with_modifiers(malicious)
                .run_n_rounds_and_collect_hashes();
        })
}

#[test]
fn minority_absent_notary_share_would_pass() -> Result<(), String> {
    ConsensusRunnerConfig::new_from_env(4, 0)
        .and_then(|config| config.parse_extra_config())
        .map(|config| {
            let mut rng = ChaChaRng::seed_from_u64(config.random_seed);
            let f = (config.num_nodes - 1) / 3;
            assert!(f > 0, "This test requires NUM_NODES >= 4");
            let mut malicious: Vec<ComponentModifier> = Vec::new();
            for _ in 0..rng.gen_range(1..=f) {
                malicious.push(malicious::absent_notary_share());
            }
            TestRunner::new(config, true)
                .with_modifiers(malicious)
                .run_n_rounds_and_collect_hashes();
        })
}

#[test]
fn majority_absent_notary_share_signature_would_stuck() -> Result<(), String> {
    ConsensusRunnerConfig::new_from_env(4, 0)
        .and_then(|config| config.parse_extra_config())
        .map(|config| {
            let mut malicious: Vec<ComponentModifier> = Vec::new();
            for _ in 0..(config.num_nodes / 3 + 1) {
                malicious.push(malicious::absent_notary_share());
            }
            TestRunner::new(config, false)
                .with_modifiers(malicious)
                .run_n_rounds_and_collect_hashes();
        })
}

#[test]
fn minority_maliciouly_notarize_all_would_pass() -> Result<(), String> {
    ConsensusRunnerConfig::new_from_env(4, 0)
        .and_then(|config| config.parse_extra_config())
        .map(|config| {
            let mut rng = ChaChaRng::seed_from_u64(config.random_seed);
            let f = (config.num_nodes - 1) / 3;
            assert!(f > 0, "This test requires NUM_NODES >= 4");
            let mut malicious: Vec<ComponentModifier> = Vec::new();
            for _ in 0..rng.gen_range(1..=f) {
                let malicious_flags = MaliciousFlags {
                    maliciously_notarize_all: true,
                    ..MaliciousFlags::default()
                };
                malicious.push(malicious::with_malicious_flags(malicious_flags));
            }
            TestRunner::new(config, true)
                .with_modifiers(malicious)
                .run_n_rounds_and_collect_hashes();
        })
}

#[test]
fn minority_maliciouly_finalize_all_would_pass() -> Result<(), String> {
    ConsensusRunnerConfig::new_from_env(4, 0)
        .and_then(|config| config.parse_extra_config())
        .map(|config| {
            let mut rng = ChaChaRng::seed_from_u64(config.random_seed);
            let f = (config.num_nodes - 1) / 3;
            assert!(f > 0, "This test requires NUM_NODES >= 4");
            let mut malicious: Vec<ComponentModifier> = Vec::new();
            for _ in 0..rng.gen_range(1..=f) {
                let malicious_flags = MaliciousFlags {
                    maliciously_finalize_all: true,
                    ..MaliciousFlags::default()
                };
                malicious.push(malicious::with_malicious_flags(malicious_flags));
            }
            TestRunner::new(config, true)
                .with_modifiers(malicious)
                .run_n_rounds_and_collect_hashes();
        })
}

/*
 * FIXME: This may fail when multiple blocks are finalized at a given round,
 * but not always. So it is still probabilistic.
 *
 * Also when it fails, it may exhibit unexpected behavior (e.g. panic) because
 * the invariant of having at most one finalized block each round is broken.
 * So we don't have a good way to reliably catch this.
 */
#[ignore]
#[test]
fn majority_maliciouly_finalize_all_would_diverge() -> Result<(), String> {
    ConsensusRunnerConfig::new_from_env(4, 0)
        .and_then(|config| config.parse_extra_config())
        .map(|config| {
            let mut malicious: Vec<ComponentModifier> = Vec::new();
            for _ in 0..((config.num_nodes - 1) / 3 * 2 + 1) {
                let malicious_flags = MaliciousFlags {
                    maliciously_notarize_all: true, // to create more than 1 branches
                    maliciously_finalize_all: true, // to finalize more than 1 branches
                    ..MaliciousFlags::default()
                };
                malicious.push(malicious::with_malicious_flags(malicious_flags));
            }
            TestRunner::new(config, false)
                .with_modifiers(malicious)
                .run_n_rounds_and_collect_hashes();
        })
}

#[test]
fn minority_maliciouly_idkg_dealers_would_pass() -> Result<(), String> {
    ConsensusRunnerConfig::new_from_env(4, 0)
        .and_then(|config| config.parse_extra_config())
        .map(|mut config| {
            // make sure we run at least 60 rounds
            if config.num_rounds < 60 {
                config.num_rounds = 60;
            }
            let mut rng = ChaChaRng::seed_from_u64(config.random_seed);
            let f = (config.num_nodes - 1) / 3;
            assert!(f > 0, "This test requires NUM_NODES >= 4");
            let mut malicious: Vec<ComponentModifier> = Vec::new();
            for _ in 0..rng.gen_range(1..=f) {
                let malicious_flags = MaliciousFlags {
                    maliciously_corrupt_idkg_dealings: true,
                    ..MaliciousFlags::default()
                };
                malicious.push(malicious::with_malicious_flags(malicious_flags));
            }
            assert!(
                TestRunner::new(config, true)
                    .with_modifiers(malicious)
                    .run_n_rounds_and_check_pubkeys()
            )
        })
}

#[test]
fn stalled_clocks_with_f_malicious_would_pass() -> Result<(), String> {
    ConsensusRunnerConfig::new_from_env(4, 0)
        .and_then(|config| config.parse_extra_config())
        .map(|mut config| {
            config.stall_clocks = true;
            let f = (config.num_nodes - 1) / 3;
            assert!(f > 0, "This test requires NUM_NODES >= 4");
            let mut malicious: Vec<ComponentModifier> = Vec::new();
            for _ in 0..f {
                malicious.push(malicious::absent_notary_share())
            }
            TestRunner::new(config, true)
                .with_modifiers(malicious)
                .run_n_rounds_and_collect_hashes();
        })
}

// Helper type for additional mutations to the registry that a test may want to perform after the
// initial setup of the subnet.
type RegistryMutations = Box<dyn FnOnce(&ProtoRegistryDataProvider, &FakeRegistryClient)>;
struct TestRunner {
    config: ConsensusRunnerConfig,
    finish: bool,
    modifiers: Vec<ComponentModifier>,
    stop_predicate: Option<StopPredicate>,
    additional_registry_mutations: Option<RegistryMutations>,
}

impl TestRunner {
    fn new(config: ConsensusRunnerConfig, finish: bool) -> Self {
        Self {
            config,
            finish,
            modifiers: vec![],
            stop_predicate: None,
            additional_registry_mutations: None,
        }
    }

    fn with_modifiers(mut self, modifiers: Vec<ComponentModifier>) -> Self {
        self.modifiers = modifiers;
        self
    }

    fn with_stop_predicate(mut self, stop_predicate: StopPredicate) -> Self {
        self.stop_predicate = Some(stop_predicate);
        self
    }

    fn with_additional_registry_mutations(
        mut self,
        additional_registry_mutations: RegistryMutations,
    ) -> Self {
        self.additional_registry_mutations = Some(additional_registry_mutations);
        self
    }

    fn run_test(mut self) {
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
                    })
                    .collect();
                let node_ids: Vec<_> = replica_configs
                    .iter()
                    .map(|config| config.node_id)
                    .collect();
                let (data_provider, registry_client, cup, cryptos) =
                    setup_subnet(subnet_id, &node_ids, self.config.dkg_interval_length, rng);
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

    fn run_n_rounds_and_collect_hashes(self) -> Vec<CryptoHash> {
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

    fn run_n_rounds_and_check_pubkeys(self) -> bool {
        let rounds = self.config.num_rounds;
        let pubkey_exists = Rc::new(RefCell::new(false));
        let pubkey_exists_clone = pubkey_exists.clone();
        let got_pubkey = move |inst: &ConsensusInstance<'_>| {
            let batches = inst.deps.message_routing.as_ref().batches.read().unwrap();
            let Some(batch) = batches.last() else {
                return false;
            };

            let mut found_keys = 0;
            for key_id in test_master_public_key_ids() {
                if let BatchContent::Data { chain_key_data, .. } = &batch.content
                    && chain_key_data.master_public_keys.contains_key(&key_id)
                {
                    found_keys += 1
                }
            }
            if found_keys == test_master_public_key_ids().len() {
                *pubkey_exists_clone.borrow_mut() = true;
            }
            *pubkey_exists_clone.borrow()
                || inst.deps.message_routing.expected_batch_height() >= Height::from(rounds)
        };
        self.with_stop_predicate(Box::new(got_pubkey)).run_test();

        *pubkey_exists.borrow()
    }
}

/// Run a test subnets with `num_nodes` many nodes, out of which there are `num_nodes_equivocating` many equivocating blockmaker
fn equivocating_block_maker_test(
    num_nodes: usize,
    num_nodes_equivocating: usize,
    finish: bool,
) -> Result<(), String> {
    ConsensusRunnerConfig::new_from_env(num_nodes, 0)
        .and_then(|config| config.parse_extra_config())
        .map(|config| {
            let mut malicious: Vec<ComponentModifier> = Vec::new();
            let malicious_flags = MaliciousFlags {
                maliciously_propose_equivocating_blocks: true,
                ..MaliciousFlags::default()
            };
            for _ in 0..num_nodes_equivocating {
                malicious.push(malicious::with_malicious_flags(malicious_flags.clone()));
            }
            TestRunner::new(config, finish)
                .with_modifiers(malicious)
                .run_n_rounds_and_collect_hashes();
        })
}

/// Tests that as long as there is a single block maker that does not equivocate, we will occasionally
/// have a block that gets finalized
#[test]
fn one_node_equivocating_passes() -> Result<(), String> {
    equivocating_block_maker_test(4, 1, true)
}

/// Tests that if all blockmakers are equivocating, we will not be able to finalize any block ever
#[test]
fn all_nodes_equivocating_fail() -> Result<(), String> {
    equivocating_block_maker_test(4, 4, false)
}

/// Regression test for ICSUP-XXX stalling subnet `3hhby` on 2026-05-22.
/// Tests that if checkpointing is slow at an upgrade boundary, i.e. consensus reaches hard bound
/// `ACCEPTABLE_NOTARIZATION_CERTIFICATION_GAP` before the upgrade height is certified, then
/// consensus still creates a CUP.
/// This used not to be the case because CUP shares were only created when the finalized tip's
/// certified height reached the upgrade height, which would never happen because consensus had
/// reached the hard bound.
/// This was fixed by ignoring this condition when the subnet is halting.
///
/// Steps of the test:
/// 1. Certified height is frozen at the upgrade height minus 1 (simulating a slow checkpoint).
/// 2. Consensus advances with empty blocks until the bound
///    `ACCEPTABLE_NOTARIZATION_CERTIFICATION_GAP` is reached, then stops creating more blocks.
/// 3. The certified-height override is released; consensus resumes and a CUP should be created at
///    the upgrade height, even though there exists no finalized block whose certified height
///    reached the upgrade height.
#[test]
fn slow_checkpointing_at_upgrade_boundary() {
    const DKG_INTERVAL_LENGTH: u64 = 74; // On purpose larger than `ACCEPTABLE_NOTARIZATION_CERTIFICATION_GAP`
    // We need to execute one first interval to trigger the upgrade at the end of the second.
    let upgrade_height = Height::from(2 * (DKG_INTERVAL_LENGTH + 1));

    let config = ConsensusRunnerConfig {
        num_nodes: 4,
        dkg_interval_length: DKG_INTERVAL_LENGTH,
        ..Default::default()
    };

    // Make the subnet upgrade at `upgrade_height`
    let additional_registry_mutations =
        |data_provider: &ProtoRegistryDataProvider, registry_client: &FakeRegistryClient| {
            let latest_version = data_provider.latest_version();
            let subnet_record = registry_client
                .get_subnet_record(subnet_test_id(0), latest_version)
                .unwrap()
                .unwrap();
            data_provider
                .add(
                    &ic_registry_keys::make_subnet_record_key(subnet_test_id(0)),
                    latest_version + 1.into(),
                    Some(SubnetRecord {
                        replica_version_id: "upgrade_version".to_string(),
                        ..subnet_record
                    }),
                )
                .unwrap();
            registry_client.reload();
        };

    let frozen_state_height = upgrade_height - 1.into();
    let mut is_checkpointing = true;
    let stop = move |inst: &ConsensusInstance<'_>| {
        let pool = inst.driver.consensus_pool.read().unwrap();
        let reader = PoolReader::new(&*pool);
        let finalized_height = reader.get_finalized_height();

        // As long as we are checkpointing, we should not have a CUP at the upgrade height yet.
        if is_checkpointing {
            let cup_height = reader.get_catch_up_height();
            assert_ne!(
                cup_height, upgrade_height,
                "Should not have created a CUP at the upgrade height {} before finishing checkpointing",
                upgrade_height,
            );
        }

        let stall_height = frozen_state_height.get() + ACCEPTABLE_NOTARIZATION_CERTIFICATION_GAP;
        match Ord::cmp(&finalized_height.get(), &stall_height) {
            Ordering::Less => {
                // Freeze the certified height at `frozen_state_height` on all nodes to simulate a
                // slow checkpoint at the upgrade boundary, so that consensus reaches the hard
                // bound `ACCEPTABLE_NOTARIZATION_CERTIFICATION_GAP` before the upgrade height is
                // certified.
                *inst
                    .deps
                    .state_manager
                    .override_max_state_height
                    .write()
                    .unwrap() = Some(frozen_state_height);
            }
            Ordering::Equal => {
                // Until the stall height, every block should still carry `certified_height ==
                // frozen_state_height` (the cap is still active).
                let finalized_certified_height = reader
                    .get_finalized_block(finalized_height)
                    .unwrap()
                    .context
                    .certified_height;
                assert_eq!(
                    finalized_certified_height, frozen_state_height,
                    "finalized block at height {} should have certified_height == {}, but got {}",
                    finalized_height, frozen_state_height, finalized_certified_height
                );

                // Now, simulate that checkpointing has finished by releasing the override
                *inst
                    .deps
                    .state_manager
                    .override_max_state_height
                    .write()
                    .unwrap() = None;
                is_checkpointing = false;
            }
            Ordering::Greater => {
                // This should happen only after we have released the override. In this case, we
                // should only have created a single block past the upgrade height, and its
                // certified height should still be equal to the frozen height.
                // Note: It is possible not to enter that branch at all if the CUP was created
                // before making a new block.
                assert!(
                    !is_checkpointing,
                    "finalized height should not have exceeded the stall point before finishing checkpointing"
                );
                assert_eq!(
                    finalized_height.get(),
                    frozen_state_height.get() + ACCEPTABLE_NOTARIZATION_CERTIFICATION_GAP + 1,
                    "finalized height should only exceed the bound by 1, but got {}",
                    finalized_height
                );
                let finalized_certified_height = reader
                    .get_finalized_block(finalized_height)
                    .unwrap()
                    .context
                    .certified_height;
                assert_eq!(
                    finalized_certified_height, frozen_state_height,
                    "finalized block at height {} should still have certified_height == {}, but got {}",
                    finalized_height, frozen_state_height, finalized_certified_height
                );
            }
        }

        let cup_height = reader.get_catch_up_height();
        // Success condition is to have been able to create a CUP at the upgrade height.
        cup_height == upgrade_height
    };

    TestRunner::new(config, true)
        .with_stop_predicate(Box::new(stop))
        .with_additional_registry_mutations(Box::new(additional_registry_mutations))
        .run_test();
}
