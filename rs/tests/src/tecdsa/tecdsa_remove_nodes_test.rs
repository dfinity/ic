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

use crate::driver::ic::{InternetComputer, Subnet};
use crate::driver::pot_dsl::get_ic_handle_and_ctx;
use crate::driver::test_env::TestEnv;
use crate::driver::test_env_api::{HasTopologySnapshot, IcNodeContainer, NnsInstallationExt};
use crate::driver::vm_control::IcControl;
use crate::tecdsa::tecdsa_signature_test::{enable_ecdsa_signing, make_key};
use crate::{
    nns::NnsExt,
    tecdsa::tecdsa_signature_test::{get_public_key, get_signature, verify_signature, KEY_ID1},
    util::*,
};
use canister_test::{Canister, Cycles};
use ic_fondue::ic_manager::IcEndpoint;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_registry_subnet_type::SubnetType;
use ic_types::Height;
use slog::info;

use super::tecdsa_signature_test::DKG_INTERVAL;

const NODES_COUNT: usize = 4;
const REMOVE_NODES_COUNT: usize = (NODES_COUNT / 3) + 1;

pub fn config(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .add_nodes(NODES_COUNT),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

pub fn test(env: TestEnv) {
    let logger = env.logger();
    let (handle, ref ctx) = get_ic_handle_and_ctx(env.clone());

    info!(logger, "Setup: install all necessary NNS canisters");
    env.topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .unwrap()
        .install_nns_canisters()
        .expect("Could not install NNS canisters");

    let mut rng = ctx.rng.clone();
    let mut endpoints: Vec<_> = handle.as_permutation(&mut rng).collect();
    let message_hash = [0xabu8; 32];

    info!(
        logger,
        "Assert all nodes are reachable via http:://[IPv6]:8080/api/v2/status"
    );
    let (canister_id, public_key) = block_on(async {
        let nns_endpoint = get_random_nns_node_endpoint(&handle, &mut rng);
        nns_endpoint.assert_ready(ctx).await;
        let nns = runtime_from_url(nns_endpoint.url.clone());
        let governance = Canister::new(&nns, GOVERNANCE_CANISTER_ID);
        info!(logger, "Enable ECDSA signing");
        enable_ecdsa_signing(
            &governance,
            nns_endpoint.subnet.as_ref().unwrap().id,
            make_key(KEY_ID1),
        )
        .await;

        info!(logger, "Asserting endpoint reachability");
        assert_endpoints_health(endpoints.as_slice(), EndpointsStatus::AllHealthy).await;
        let agent = assert_create_agent(endpoints[0].url.as_str()).await;
        let msg_can = MessageCanister::new(&agent, endpoints[0].effective_canister_id()).await;
        info!(logger, "Getting public key");
        let public_key = get_public_key(make_key(KEY_ID1), &msg_can, ctx)
            .await
            .unwrap();
        (msg_can.canister_id(), public_key)
    });

    info!(logger, "Randomly select X=floor(N/3)+1 nodes for removal");
    let mut endpoints_to_remove: Vec<&IcEndpoint> = Vec::new();
    for _ in 0..REMOVE_NODES_COUNT {
        endpoints_to_remove.push(endpoints.pop().unwrap());
    }

    info!(logger, "Remove the nodes via proposal");
    let node_ids = endpoints_to_remove
        .iter()
        .map(|ep| ep.node_id)
        .collect::<Vec<_>>();
    ctx.remove_nodes(&handle, node_ids.as_slice());

    info!(
        logger,
        "Assert all nodes are now unreachable via http:://[IPv6]:8080/api/v2/status"
    );
    block_on(async {
        assert_endpoints_health(
            endpoints_to_remove.as_slice(),
            EndpointsStatus::AllUnhealthy,
        )
        .await
    });

    info!(
        logger,
        "Kill nodes after removal (last shot to the victims)"
    );
    for ep in endpoints_to_remove {
        ep.kill_node(ctx.logger.clone());
    }

    info!(logger, "Verify signature");
    block_on(async {
        let agent = assert_create_agent(endpoints[0].url.as_str()).await;
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
