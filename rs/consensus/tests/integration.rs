mod framework;
use crate::framework::{
    ConsensusDependencies, ConsensusInstance, ConsensusRunner, ConsensusRunnerConfig,
};
use ic_consensus::consensus::Membership;
use ic_interfaces::{consensus_pool::ConsensusPool, registry::RegistryClient};
use ic_test_utilities::{
    consensus::make_catch_up_package_with_empty_transcript,
    crypto::CryptoReturningOk,
    registry::{setup_registry_non_final, SubnetRecordBuilder},
    types::ids::{node_test_id, subnet_test_id},
    FastForwardTimeSource,
};
use ic_types::{crypto::CryptoHash, replica_config::ReplicaConfig, Height, RegistryVersion};
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

#[test]
fn multiple_nodes_are_live() -> Result<(), String> {
    // allow settings to be customized when running from commandline
    ConsensusRunnerConfig::new_from_env(4, 0)
        .and_then(|config| config.parse_extra_config())
        .map(|config| {
            run_n_rounds_and_collect_hashes(config);
        })
}

#[test]
fn single_node_is_live() {
    let config = ConsensusRunnerConfig {
        num_nodes: 1,
        num_rounds: 126,
        ..Default::default()
    };
    run_n_rounds_and_collect_hashes(config);
}

#[test]
fn multiple_nodes_are_deterministic() {
    let run = || {
        let config = ConsensusRunnerConfig {
            num_nodes: 4,
            num_rounds: 10,
            ..Default::default()
        };
        run_n_rounds_and_collect_hashes(config)
    };
    assert_eq!(run(), run());
}

fn run_n_rounds_and_collect_hashes(config: ConsensusRunnerConfig) -> Rc<RefCell<Vec<CryptoHash>>> {
    let nodes = config.num_nodes;
    ic_test_utilities::artifact_pool_config::with_test_pool_configs(nodes, |pool_configs| {
        let rounds = config.num_rounds;
        let hashes = Rc::new(RefCell::new(Vec::new()));
        let hashes_clone = hashes.clone();
        let reach_n_rounds = move |inst: &ConsensusInstance<'_>| {
            let pool = inst.driver.consensus_pool.write().unwrap();
            for nota in pool.validated().notarization().get_highest_iter() {
                let hash = ic_crypto::crypto_hash(&nota);
                let hash = hash.get_ref();
                if !hashes_clone.borrow().contains(hash) {
                    hashes_clone.borrow_mut().push(hash.clone());
                }
            }
            inst.deps.message_routing.expected_batch_height() >= Height::from(rounds)
        };
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
        let crypto = Arc::new(CryptoReturningOk::default());
        let initial_version = 1;
        let (data_provider, registry_client) = setup_registry_non_final(
            subnet_id,
            vec![(
                initial_version,
                SubnetRecordBuilder::from(&node_ids).build(),
            )],
        );
        // This is required by the XNet payload builder.
        for node in node_ids.iter() {
            data_provider
                .add(
                    &ic_registry_keys::make_node_record_key(*node),
                    RegistryVersion::from(initial_version),
                    Some(ic_protobuf::registry::node::v1::NodeRecord::default()),
                )
                .expect("Could not add node record.");
        }
        registry_client.update_to_latest_version();
        let cup = make_catch_up_package_with_empty_transcript(registry_client.clone(), subnet_id);
        let inst_deps: Vec<_> = replica_configs
            .iter()
            .zip(pool_configs.iter())
            .map(|(replica_config, pool_config)| {
                ConsensusDependencies::new(
                    replica_config.clone(),
                    pool_config.clone(),
                    Arc::clone(&registry_client) as Arc<dyn RegistryClient>,
                    cup.clone(),
                )
            })
            .collect();

        let mut framework = ConsensusRunner::new_with_config(config, time_source);

        for (pool_config, deps) in pool_configs.iter().zip(inst_deps.iter()) {
            let membership = Membership::new(
                deps.consensus_pool.read().unwrap().get_cache(),
                Arc::clone(&registry_client) as Arc<dyn RegistryClient>,
                subnet_id,
            );
            let membership = Arc::new(membership);
            framework.add_instance(
                membership.clone(),
                crypto.clone(),
                deps,
                pool_config.clone(),
            );
        }
        assert!(framework.run_until(&reach_n_rounds));
        hashes
    })
}
