/* tag::catalog[]
Title:: Adding nodes to a subnet running threshold ECDSA

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

use crate::{
    nns::{submit_external_proposal_with_test_id, vote_execute_proposal_assert_executed, NnsExt},
    tecdsa_signature_test::{get_public_key, get_signature, verify_signature},
    util::*,
};
use canister_test::Cycles;
use ic_fondue::{
    ic_manager::IcHandle,
    prod_tests::ic::{InternetComputer, Subnet},
};
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_governance::pb::v1::NnsFunction;
use ic_registry_subnet_features::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
use ic_types::Height;
use registry_canister::mutations::do_add_nodes_to_subnet::AddNodesToSubnetPayload;
use std::time::{Duration, Instant};

const DKG_INTERVAL: u64 = 29;
const NODES_COUNT: usize = 4;
const UNASSIGNED_NODES_COUNT: i32 = 3;

pub fn config() -> InternetComputer {
    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .add_nodes(NODES_COUNT)
                .with_features(SubnetFeatures {
                    ecdsa_signatures: true,
                    ..SubnetFeatures::default()
                }),
        )
        .with_unassigned_nodes(UNASSIGNED_NODES_COUNT)
}

pub fn test(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    // Setup: install all necessary NNS canisters.
    ctx.install_nns_canisters(&handle, true);

    // Make sure unassigned nodes are ready
    let unassigned_nodes_endpoints = get_unassinged_nodes_endpoints(&handle);
    assert_eq!(
        unassigned_nodes_endpoints.len(),
        UNASSIGNED_NODES_COUNT as usize
    );
    let unassigned_node_ids: Vec<_> = unassigned_nodes_endpoints
        .iter()
        .map(|ep| ep.node_id)
        .collect();
    block_on(assert_all_ready(unassigned_nodes_endpoints.as_slice(), ctx));

    // Initial run to get public key
    let mut rng = ctx.rng.clone();
    let nns_endpoint = get_random_nns_node_endpoint(&handle, &mut rng);
    let message_hash = [0xabu8; 32];
    // Assert all nodes are reachable via http:://[IPv6]:8080/api/v2/status
    let (canister_id, public_key) = block_on(async {
        nns_endpoint.assert_ready(ctx).await;
        let agent = assert_create_agent(nns_endpoint.url.as_str()).await;
        let uni_can = UniversalCanister::new(&agent).await;
        let public_key = get_public_key(&uni_can, ctx).await;
        (uni_can.canister_id(), public_key)
    });

    // Send a proposal for the nodes to join NNS subnet via the governance canister.
    let nns_runtime = runtime_from_url(nns_endpoint.url.clone());
    let governance_canister = canister_test::Canister::new(&nns_runtime, GOVERNANCE_CANISTER_ID);
    let proposal_payload = AddNodesToSubnetPayload {
        subnet_id: nns_endpoint.subnet_id().unwrap().get(),
        node_ids: unassigned_node_ids,
    };
    let proposal_id = block_on(submit_external_proposal_with_test_id(
        &governance_canister,
        NnsFunction::AddNodeToSubnet,
        proposal_payload,
    ));
    // Explicitly vote for the proposal to add nodes to NNS subnet.
    block_on(vote_execute_proposal_assert_executed(
        &governance_canister,
        proposal_id,
    ));
    let newly_assigned_nodes: Vec<_> = unassigned_nodes_endpoints
        .iter()
        .map(|ep| ep.recreate_with_subnet(nns_endpoint.clone().subnet.unwrap()))
        .collect();

    // Sleep and assert that new nodes are reachable (via http call).
    block_on(async {
        tokio::time::sleep(Duration::from_secs(80)).await;
        for ep in newly_assigned_nodes.iter() {
            ep.assert_ready_with_start(Instant::now(), ctx).await;
        }
    });

    // Run through ecdsa signature test
    block_on(async {
        let agent = assert_create_agent(nns_endpoint.url.as_str()).await;
        let uni_can = UniversalCanister::from_canister_id(&agent, canister_id);
        let public_key_ = get_public_key(&uni_can, ctx).await;
        assert_eq!(public_key, public_key_);
        let signature = get_signature(&message_hash, Cycles::zero(), &uni_can, ctx)
            .await
            .unwrap();
        verify_signature(&message_hash, &public_key, &signature);
    });
}
