/* tag::catalog[]
Title:: Removing nodes to a subnet running threshold ECDSA

Goal:: Test whether removing subnet nodes impacts the threshold ECDSA feature

Runbook::
. Setup:
    . System subnet comprising N nodes, necessary NNS canisters, and with ecdsa feature featured.
. Removing N/3 + 1 nodes from the subnet via proposal.
. Assert that node membership has changed.
. Assert that ecdsa signing continues to work with the same public key as before.

Success::
. Status endpoints of removed nodes are unreachable.
. ECDSA signature succeeds with the same public key as before.

end::catalog[] */

use super::DKG_INTERVAL;
use crate::driver::ic::{InternetComputer, Subnet};
use crate::driver::test_env::TestEnv;
use crate::driver::test_env_api::{
    HasPublicApiUrl, HasTopologySnapshot, HasVm, IcNodeContainer, NnsInstallationBuilder,
};
use crate::nns::remove_nodes_via_endpoint;
use crate::tecdsa::{
    enable_chain_key_signing, get_public_key_with_logger, get_signature_with_logger, make_key,
};
use crate::{
    tecdsa::{verify_signature, KEY_ID1},
    util::*,
};
use canister_test::{Canister, Cycles};
use ic_base_types::NodeId;
use ic_management_canister_types::MasterPublicKeyId;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_registry_subnet_type::SubnetType;
use ic_types::Height;
use rand::seq::SliceRandom;
use rand_chacha::ChaCha8Rng;
use slog::info;

const NODES_COUNT: usize = 4;
const REMOVE_NODES_COUNT: usize = (NODES_COUNT / 3) + 1;
// Seed for a random generator
const RND_SEED: u64 = 42;

pub fn config(env: TestEnv) {
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

pub fn test(env: TestEnv) {
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
    let message_hash = vec![0xabu8; 32];
    let key_id = MasterPublicKeyId::Ecdsa(make_key(KEY_ID1));
    let (canister_id, public_key) = block_on(async {
        let nns = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
        let governance = Canister::new(&nns, GOVERNANCE_CANISTER_ID);
        info!(log, "Enable ECDSA signing");
        enable_chain_key_signing(
            &governance,
            nns_subnet.subnet_id,
            vec![key_id.clone()],
            &log,
        )
        .await;
        let msg_can = MessageCanister::new(&nns_agent, nns_node.effective_canister_id()).await;
        info!(log, "Getting public key");
        let public_key = get_public_key_with_logger(&key_id, &msg_can, &log)
            .await
            .unwrap();
        (msg_can.canister_id(), public_key)
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
        let public_key_ = get_public_key_with_logger(&key_id, &msg_can, &log)
            .await
            .unwrap();
        assert_eq!(public_key, public_key_);
        let signature = get_signature_with_logger(
            message_hash.clone(),
            Cycles::zero(),
            &key_id,
            &msg_can,
            &log,
        )
        .await
        .unwrap();
        verify_signature(&key_id, &message_hash, &public_key, &signature);
    });
}
