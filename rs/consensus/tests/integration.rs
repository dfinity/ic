#[cfg(test)]
mod framework;

use crate::framework::{
    ComponentModifier, ConsensusDependencies, ConsensusInstance, ConsensusRunner,
    ConsensusRunnerConfig, StopPredicate, malicious, setup_subnet,
};
use framework::test_master_public_key_ids;
use ic_consensus_utils::pool_reader::PoolReader;
use ic_interfaces::{consensus_pool::ConsensusPool, messaging::MessageRouting};
use ic_interfaces_registry::RegistryClient;
use ic_test_utilities_time::FastForwardTimeSource;
use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
use ic_types::{
    Height, crypto::CryptoHash, malicious_flags::MaliciousFlags, replica_config::ReplicaConfig,
};
use rand::Rng;
use rand_chacha::{ChaChaRng, rand_core::SeedableRng};
use std::{cell::RefCell, rc::Rc, sync::Arc};

#[test]
fn multiple_nodes_are_live() -> Result<(), String> {
    // allow settings to be customized when running from commandline
    ConsensusRunnerConfig::new_from_env(4, 0)
        .and_then(|config| config.parse_extra_config())
        .map(|config| {
            run_n_rounds_and_collect_hashes(config, Vec::new(), true);
        })
}

#[test]
fn single_node_is_live() {
    let config = ConsensusRunnerConfig {
        num_nodes: 1,
        num_rounds: 126,
        ..Default::default()
    };
    run_n_rounds_and_collect_hashes(config, Vec::new(), true);
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
            assert!(run_n_rounds_and_check_pubkeys(config, Vec::new(), true));
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
        run_n_rounds_and_collect_hashes(config, Vec::new(), true)
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
            for _ in 0..rng.random_range(1..=f) {
                malicious.push(malicious::invalid_notary_share_signature())
            }
            run_n_rounds_and_collect_hashes(config, malicious, true);
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
            run_n_rounds_and_collect_hashes(config, malicious, false);
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
            for _ in 0..rng.random_range(1..=f) {
                malicious.push(malicious::absent_notary_share());
            }
            run_n_rounds_and_collect_hashes(config, malicious, true);
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
            run_n_rounds_and_collect_hashes(config, malicious, false);
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
            for _ in 0..rng.random_range(1..=f) {
                let malicious_flags = MaliciousFlags {
                    maliciously_notarize_all: true,
                    ..MaliciousFlags::default()
                };
                malicious.push(malicious::with_malicious_flags(malicious_flags));
            }
            run_n_rounds_and_collect_hashes(config, malicious, true);
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
            for _ in 0..rng.random_range(1..=f) {
                let malicious_flags = MaliciousFlags {
                    maliciously_finalize_all: true,
                    ..MaliciousFlags::default()
                };
                malicious.push(malicious::with_malicious_flags(malicious_flags));
            }
            run_n_rounds_and_collect_hashes(config, malicious, true);
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
            run_n_rounds_and_collect_hashes(config, malicious, false);
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
            for _ in 0..rng.random_range(1..=f) {
                let malicious_flags = MaliciousFlags {
                    maliciously_corrupt_idkg_dealings: true,
                    ..MaliciousFlags::default()
                };
                malicious.push(malicious::with_malicious_flags(malicious_flags));
            }
            assert!(run_n_rounds_and_check_pubkeys(config, malicious, true))
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
            run_n_rounds_and_collect_hashes(config, malicious, true);
        })
}

fn run_test(
    config: ConsensusRunnerConfig,
    mut modifiers: Vec<ComponentModifier>,
    stop_predicate: StopPredicate,
    finish: bool,
) {
    let rng = &mut ChaChaRng::seed_from_u64(config.random_seed);
    let nodes = config.num_nodes;
    ic_test_utilities::artifact_pool_config::with_test_pool_configs(nodes, move |pool_configs| {
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
        let (registry_client, cup, cryptos) = setup_subnet(subnet_id, &node_ids, rng);
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

        let mut runner = ConsensusRunner::new_with_config(config, time_source);

        for ((pool_config, deps), crypto) in pool_configs
            .iter()
            .zip(inst_deps.iter())
            .zip(cryptos.iter())
        {
            let modifier = modifiers.pop();
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
        assert_eq!(runner.run_until(stop_predicate), finish);
    })
}

fn run_n_rounds_and_collect_hashes(
    config: ConsensusRunnerConfig,
    modifiers: Vec<ComponentModifier>,
    finish: bool,
) -> Vec<CryptoHash> {
    let rounds = config.num_rounds;
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
    run_test(config, modifiers, Box::new(reach_n_rounds), finish);
    hashes.as_ref().take()
}

fn run_n_rounds_and_check_pubkeys(
    config: ConsensusRunnerConfig,
    modifiers: Vec<ComponentModifier>,
    finish: bool,
) -> bool {
    let rounds = config.num_rounds;
    let pubkey_exists = Rc::new(RefCell::new(false));
    let pubkey_exists_clone = pubkey_exists.clone();
    let got_pubkey = move |inst: &ConsensusInstance<'_>| {
        let batches = inst.deps.message_routing.as_ref().batches.read().unwrap();
        let Some(batch) = batches.last() else {
            return false;
        };

        let mut found_keys = 0;
        for key_id in test_master_public_key_ids() {
            if batch
                .chain_key_data
                .master_public_keys
                .contains_key(&key_id)
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
    run_test(config, modifiers, Box::new(got_pubkey), finish);

    *pubkey_exists.borrow()
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
            run_n_rounds_and_collect_hashes(config, malicious, finish);
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
