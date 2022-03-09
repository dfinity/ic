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

use crate::{
    nns::NnsExt,
    tecdsa_signature_test::{get_public_key, get_signature, verify_signature},
    util::*,
};
use ic_fondue::{
    ic_manager::{IcControl, IcEndpoint, IcHandle},
    prod_tests::ic::{InternetComputer, Subnet},
};
use ic_protobuf::registry::subnet::v1::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
use ic_types::Height;

const DKG_INTERVAL: u64 = 14;
const NODES_COUNT: usize = 4;
const REMOVE_NODES_COUNT: usize = (NODES_COUNT / 3) + 1;

pub fn config() -> InternetComputer {
    InternetComputer::new().add_subnet(
        Subnet::new(SubnetType::System)
            .with_dkg_interval_length(Height::from(DKG_INTERVAL))
            .add_nodes(NODES_COUNT)
            .with_features(SubnetFeatures {
                ecdsa_signatures: true,
                ..SubnetFeatures::default()
            }),
    )
}

pub fn test(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    // Setup: install all necessary NNS canisters.
    ctx.install_nns_canisters(&handle, true);
    let mut rng = ctx.rng.clone();
    let mut endpoints: Vec<_> = handle.as_permutation(&mut rng).collect();
    let message_hash = [0xabu8; 32];
    // Assert all nodes are reachable via http:://[IPv6]:8080/api/v2/status
    let (canister_id, public_key) = block_on(async {
        assert_endpoints_reachability(endpoints.as_slice(), EndpointsStatus::AllReachable).await;
        let agent = assert_create_agent(endpoints[0].url.as_str()).await;
        let uni_can = UniversalCanister::new(&agent).await;
        let public_key = get_public_key(&uni_can, ctx).await;
        (uni_can.canister_id(), public_key)
    });
    // Randomly select X=floor(N/3)+1 nodes for removal.
    let mut endpoints_to_remove: Vec<&IcEndpoint> = Vec::new();
    for _ in 0..REMOVE_NODES_COUNT {
        endpoints_to_remove.push(endpoints.pop().unwrap());
    }
    // Remove the nodes via proposal.
    let node_ids = endpoints_to_remove
        .iter()
        .map(|ep| ep.node_id)
        .collect::<Vec<_>>();
    ctx.remove_nodes(&handle, node_ids.as_slice());
    // Assert all nodes are now unreachable via http:://[IPv6]:8080/api/v2/status
    block_on(async {
        assert_endpoints_reachability(
            endpoints_to_remove.as_slice(),
            EndpointsStatus::AllUnreachable,
        )
        .await
    });
    // Kill nodes after removal (last shot to the victims).
    for ep in endpoints_to_remove {
        ep.kill_node(ctx.logger.clone());
    }

    block_on(async {
        let agent = assert_create_agent(endpoints[0].url.as_str()).await;
        let uni_can = UniversalCanister::from_canister_id(&agent, canister_id);
        let public_key_ = get_public_key(&uni_can, ctx).await;
        assert_eq!(public_key, public_key_);
        let signature = get_signature(&message_hash, &uni_can, ctx).await;
        verify_signature(&message_hash, &public_key, &signature);
    });
}
