/* tag::catalog[]
Title:: Removing nodes to a subnet running canister threshold signing

Goal:: Test whether removing subnet nodes impacts the threshold signature feature

Runbook::
. Setup:
    . System subnet comprising N nodes, necessary NNS canisters, and with chain key feature enabled.
. Removing N/3 + 1 nodes from the subnet via proposal.
. Assert that node membership has changed.
. Assert that chain key signing continues to work with the same public keys as before.

Success::
. Status endpoints of removed nodes are unreachable.
. Chain key signature succeeds with the same public keys as before.

end::catalog[] */

use std::collections::BTreeMap;

use anyhow::Result;

use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;

use canister_test::Canister;
use ic_base_types::NodeId;
use ic_consensus_threshold_sig_system_test_utils::{
    DKG_INTERVAL, enable_chain_key_signing, get_public_key_and_test_signature,
    get_public_key_with_logger, make_key_ids_for_all_schemes,
};
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    HasPublicApiUrl, HasTopologySnapshot, HasVm, IcNodeContainer, NnsInstallationBuilder,
};
use ic_system_test_driver::nns::remove_nodes_via_endpoint;
use ic_system_test_driver::util::*;
use ic_types::Height;
use rand::seq::SliceRandom;
use rand_chacha::ChaCha8Rng;
use slog::info;

const NODES_COUNT: usize = 4;
const REMOVE_NODES_COUNT: usize = (NODES_COUNT / 3) + 1;
// Seed for a random generator
const RND_SEED: u64 = 42;

fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .add_nodes(NODES_COUNT),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
}

fn test(env: TestEnv) {
    let log = env.logger();
    let nns_subnet = env.topology_snapshot().root_subnet();
    let mut nns_nodes: Vec<_> = nns_subnet.nodes().collect();
    let (nns_node, nns_nodes_to_remove) = {
        let mut rng: ChaCha8Rng = rand::SeedableRng::seed_from_u64(RND_SEED);
        nns_nodes.shuffle(&mut rng);
        (&nns_nodes[0], &nns_nodes[1..REMOVE_NODES_COUNT + 1])
    };
    info!(log, "Setup: install all necessary NNS canisters");
    let nns_agent = nns_node.with_default_agent(|agent| async move { agent });
    NnsInstallationBuilder::new()
        .install(nns_node, &env)
        .expect("Could not install NNS canisters");
    let key_ids = make_key_ids_for_all_schemes();
    let (canister_id, public_keys) = block_on(async {
        let nns = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
        let governance = Canister::new(&nns, GOVERNANCE_CANISTER_ID);
        info!(log, "Enable chain key signing");
        enable_chain_key_signing(&governance, nns_subnet.subnet_id, key_ids.clone(), &log).await;
        let msg_can = MessageCanister::new(&nns_agent, nns_node.effective_canister_id()).await;
        info!(log, "Getting public keys");
        let mut public_keys = BTreeMap::new();
        for key_id in &key_ids {
            let public_key = get_public_key_with_logger(key_id, &msg_can, &log)
                .await
                .unwrap();
            public_keys.insert(key_id.clone(), public_key);
        }

        (msg_can.canister_id(), public_keys)
    });
    info!(
        log,
        "Assert nodes are healthy before their removal from subnet"
    );
    assert_nodes_health_statuses(
        log.clone(),
        nns_nodes_to_remove,
        EndpointsStatus::AllHealthy,
    );
    info!(
        log,
        "Remove X=floor(N/3)+1=floor({NODES_COUNT}/3+1)={REMOVE_NODES_COUNT} nodes via proposal",
    );
    block_on(async {
        let node_ids: Vec<NodeId> = nns_nodes_to_remove.iter().map(|n| n.node_id).collect();
        remove_nodes_via_endpoint(nns_node.get_public_url(), node_ids.as_slice())
            .await
            .unwrap();
    });
    info!(
        log,
        "Assert nodes are unhealthy after their removal from subnet"
    );
    assert_nodes_health_statuses(
        log.clone(),
        nns_nodes_to_remove,
        EndpointsStatus::AllUnhealthy,
    );
    info!(log, "Kill nodes after removal (last shot to the victims)");
    nns_nodes_to_remove.iter().for_each(|node| node.vm().kill());
    info!(log, "Verify signature");
    block_on(async {
        let msg_can = MessageCanister::from_canister_id(&nns_agent, canister_id);
        for (key_id, public_key) in public_keys {
            let public_key_ = get_public_key_and_test_signature(&key_id, &msg_can, true, &log)
                .await
                .unwrap();
            assert_eq!(public_key, public_key_);
        }
    });
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}
