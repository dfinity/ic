/* tag::catalog[]
Title:: Adding nodes to a subnet running threshold ECDSA

Goal:: Test whether removing subnet nodes impacts the threshold ECDSA feature

Runbook::
. Setup:
    . System subnet comprising N nodes, necessary NNS canisters, and with ecdsa feature featured.
    . X unassigned nodes.
. Enable ecdsa signing.
. Get public key.
. Add all X unassigned nodes to System subnet via proposal.
. Assert that node membership has changed.
. Assert that ecdsa signing continues to work with the same public key as before.

Success::
. System subnet contains N + X nodes.
. ECDSA signature succeeds with the same public key as before.

end::catalog[] */

use crate::driver::ic::{InternetComputer, Subnet};
use crate::driver::pot_dsl::get_ic_handle_and_ctx;
use crate::driver::test_env::{SshKeyGen, TestEnv};
use crate::driver::test_env_api::{
    HasGroupSetup, HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, NnsInstallationExt, ADMIN,
};
use crate::tecdsa::tecdsa_signature_test::{enable_ecdsa_signing, make_key};
use crate::{
    nns::{submit_external_proposal_with_test_id, vote_execute_proposal_assert_executed},
    tecdsa::tecdsa_signature_test::{get_public_key, get_signature, verify_signature, KEY_ID1},
    util::*,
};
use canister_test::{Canister, Cycles};
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_governance::pb::v1::NnsFunction;
use ic_registry_subnet_type::SubnetType;
use ic_types::Height;
use registry_canister::mutations::do_add_nodes_to_subnet::AddNodesToSubnetPayload;
use slog::info;

use super::tecdsa_signature_test::DKG_INTERVAL;

const NODES_COUNT: usize = 4;
const UNASSIGNED_NODES_COUNT: i32 = 3;

pub fn config(env: TestEnv) {
    env.ensure_group_setup_created();
    env.ssh_keygen(ADMIN).expect("ssh-keygen failed");

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
    // TODO: refactor functions accepting Context to Logger (e.g. get_public_key)
    let (_, ref ctx) = get_ic_handle_and_ctx(env.clone());
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
    assert_eq!(unassigned_node_ids.len(), UNASSIGNED_NODES_COUNT as usize);
    info!(log, "Installing nns canisters.");
    nns_node
        .install_nns_canisters()
        .expect("Could not install NNS canisters.");
    info!(log, "Enabling ECDSA signatures.");
    let nns_runtime = runtime_from_url(nns_node.get_public_url());
    let governance = Canister::new(&nns_runtime, GOVERNANCE_CANISTER_ID);
    block_on(async {
        enable_ecdsa_signing(&governance, nns_subnet.subnet_id, make_key(KEY_ID1)).await;
    });
    info!(log, "Initial run to get public key.");
    let agent = nns_node.with_default_agent(|agent| async move { agent });
    let (canister_id, public_key) = block_on(async {
        let msg_can = MessageCanister::new(&agent, nns_node.effective_canister_id()).await;
        let public_key = get_public_key(make_key(KEY_ID1), &msg_can, ctx)
            .await
            .unwrap();
        (msg_can.canister_id(), public_key)
    });
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
            UNASSIGNED_NODES_COUNT as usize + NODES_COUNT
        );
        info!(log, "Run through ecdsa signature test.");
        let message_hash = [0xabu8; 32];
        let msg_can = MessageCanister::from_canister_id(&agent, canister_id);
        let public_key_ = get_public_key(make_key(KEY_ID1), &msg_can, ctx)
            .await
            .unwrap();
        assert_eq!(public_key, public_key_);
        let signature = get_signature(
            &message_hash,
            Cycles::zero(),
            make_key(KEY_ID1),
            &msg_can,
            ctx,
        )
        .await
        .unwrap();
        verify_signature(&message_hash, &public_key, &signature);
    });
}
