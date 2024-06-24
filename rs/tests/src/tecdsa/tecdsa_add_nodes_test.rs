/* tag::catalog[]
Title:: Adding nodes to a subnet running canister threshold signing

Goal:: Test whether removing subnet nodes impacts the threshold signature feature

Runbook::
. Setup:
    . System subnet comprising N nodes, necessary NNS canisters, and with chain key feature featured.
    . X unassigned nodes.
. Enable chain key signing.
. Get public keys for all supported schemes.
. Add all X unassigned nodes to System subnet via proposal.
. Assert that node membership has changed.
. Assert that chain key signing continues to work with the same public key as before.

Success::
. System subnet contains N + X nodes.
. Chain key signature succeeds with the same public key as before.

end::catalog[] */

use std::collections::BTreeMap;

use super::DKG_INTERVAL;
use crate::driver::ic::{InternetComputer, Subnet};
use crate::driver::test_env::TestEnv;
use crate::driver::test_env_api::{
    HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, NnsInstallationBuilder,
};
use crate::tecdsa::{
    enable_chain_key_signing, get_public_key_and_test_signature, get_public_key_with_logger,
    make_key_ids_for_all_schemes,
};
use crate::{
    nns::{submit_external_proposal_with_test_id, vote_execute_proposal_assert_executed},
    util::*,
};
use canister_test::Canister;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_governance::pb::v1::NnsFunction;
use ic_registry_subnet_type::SubnetType;
use ic_types::Height;
use registry_canister::mutations::do_add_nodes_to_subnet::AddNodesToSubnetPayload;
use slog::info;

const NODES_COUNT: usize = 4;
const UNASSIGNED_NODES_COUNT: usize = 3;

pub fn config(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .add_nodes(NODES_COUNT),
        )
        .with_unassigned_nodes(UNASSIGNED_NODES_COUNT)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    // Check all subnet nodes are healthy.
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
    // Check all unassigned nodes are ready.
    env.topology_snapshot().unassigned_nodes().for_each(|node| {
        node.await_can_login_as_admin_via_ssh()
            .expect("Timeout while waiting for all unassigned nodes to be ready.");
    });
}

pub fn test(env: TestEnv) {
    let log = env.logger();
    let topology_snapshot = env.topology_snapshot();
    let (nns_subnet, nns_node, unassigned_node_ids) = {
        let subnet = topology_snapshot.root_subnet();
        let node = subnet.nodes().next().unwrap();
        (
            subnet,
            node,
            topology_snapshot
                .unassigned_nodes()
                .map(|ep| ep.node_id)
                .collect::<Vec<_>>(),
        )
    };
    assert_eq!(unassigned_node_ids.len(), UNASSIGNED_NODES_COUNT);
    info!(log, "Installing nns canisters.");
    NnsInstallationBuilder::new()
        .install(&nns_node, &env)
        .expect("Could not install NNS canisters.");
    info!(log, "Enabling chain key signatures.");
    let nns_runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance = Canister::new(&nns_runtime, GOVERNANCE_CANISTER_ID);
    let key_ids = make_key_ids_for_all_schemes();
    block_on(async {
        enable_chain_key_signing(&governance, nns_subnet.subnet_id, key_ids.clone(), &log).await;
    });
    info!(log, "Initial run to get public key.");
    let agent = nns_node.with_default_agent(|agent| async move { agent });
    let msg_can =
        block_on(async { MessageCanister::new(&agent, nns_node.effective_canister_id()).await });
    let mut public_keys = BTreeMap::new();
    for key_id in &key_ids {
        let public_key = block_on(async {
            get_public_key_with_logger(key_id, &msg_can, &log)
                .await
                .unwrap()
        });
        public_keys.insert(key_id.clone(), public_key);
    }
    info!(
        log,
        "Sending a proposal for the nodes to join NNS subnet via the governance canister."
    );
    let proposal_payload = AddNodesToSubnetPayload {
        subnet_id: nns_subnet.subnet_id.get(),
        node_ids: unassigned_node_ids,
    };
    let proposal_id = block_on(submit_external_proposal_with_test_id(
        &governance,
        NnsFunction::AddNodeToSubnet,
        proposal_payload,
    ));
    info!(
        log,
        "Explicitly voting for the proposal to add nodes to NNS subnet."
    );
    block_on(vote_execute_proposal_assert_executed(
        &governance,
        proposal_id,
    ));
    info!(log, "Waiting for registry update.");
    block_on(async {
        topology_snapshot
            .block_for_newer_registry_version()
            .await
            .expect("Could not block for newer registry version");
        info!(log, "Asserting nodes membership has changed.");
        // Get a new snapshot.
        let topology_snapshot = env.topology_snapshot();
        assert!(topology_snapshot.unassigned_nodes().next().is_none());
        assert_eq!(
            topology_snapshot.root_subnet().nodes().count(),
            UNASSIGNED_NODES_COUNT + NODES_COUNT
        );
        info!(log, "Run through signature test.");
        let msg_can = MessageCanister::from_canister_id(&agent, msg_can.canister_id());
        for (key_id, public_key) in public_keys {
            let public_key_ = get_public_key_and_test_signature(&key_id, &msg_can, true, &log)
                .await
                .unwrap();
            assert_eq!(public_key, public_key_);
        }
    });
}
