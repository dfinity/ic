/* tag::catalog[]
Title:: Subnet Addition Test

Goal:: asdf

Coverage::
. Root and secondary subnets can be created


end::catalog[] */

use crate::{
    nns::{
        get_governance_canister, submit_external_proposal_with_test_id,
        vote_execute_proposal_assert_failed, NnsExt,
    },
    util::{get_random_nns_node_endpoint, runtime_from_url},
};

use ic_fondue::{ic_instance::InternetComputer, ic_manager::IcHandle};
use ic_nns_governance::pb::v1::NnsFunction;
use ic_registry_subnet_features::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
use ic_types::ReplicaVersion;
use registry_canister::mutations::do_create_subnet::CreateSubnetPayload;

use futures::Future;

pub fn config() -> InternetComputer {
    InternetComputer::new().add_fast_single_node_subnet(SubnetType::System)
}

/// Simply tests
pub fn create_subnet_with_assigned_nodes_fails(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    // Install NNS canisters
    ctx.install_nns_canisters(&handle, true);

    let mut rng = ctx.rng.clone();

    // choose a random node from the nns subnet
    let endpoint = get_random_nns_node_endpoint(&handle, &mut rng);
    block_on(endpoint.assert_ready(ctx));
    let node_ids = ctx.initial_node_ids(&handle);

    // values copied from bootstrap script.
    let payload = CreateSubnetPayload {
        node_ids,
        subnet_id_override: None,
        ingress_bytes_per_block_soft_cap: 2_097_152,
        max_ingress_bytes_per_message: 2_097_152,
        max_ingress_messages_per_block: 1_000,
        max_block_payload_size: 2 * 2_097_152,
        replica_version_id: ReplicaVersion::default().to_string(),
        unit_delay_millis: 2_000,
        initial_notary_delay_millis: 2_500,
        dkg_interval_length: 99,
        dkg_dealings_per_block: 1_000,
        gossip_max_artifact_streams_per_peer: 20,
        gossip_max_chunk_wait_ms: 15_000,
        gossip_max_duplicity: 1,
        gossip_max_chunk_size: 4_096,
        gossip_receive_check_cache_size: 5_000,
        gossip_pfn_evaluation_period_ms: 3_000,
        gossip_registry_poll_period_ms: 3_000,
        gossip_retransmission_request_ms: 60_000,
        advert_best_effort_percentage: None,
        start_as_nns: false,
        subnet_type: SubnetType::Application,
        is_halted: false,
        max_instructions_per_message: 5_000_000_000,
        max_instructions_per_round: 7_000_000_000,
        max_instructions_per_install_code: 200_000_000_000,
        features: SubnetFeatures::default(),
        max_number_of_canisters: 0,
        ssh_readonly_access: vec![],
        ssh_backup_access: vec![],
    };
    // All nodes in the initial registry are already registered.
    block_on(async move {
        let r = runtime_from_url(endpoint.url.clone());
        let gov_can = get_governance_canister(&r);

        let proposal_id =
            submit_external_proposal_with_test_id(&gov_can, NnsFunction::CreateSubnet, payload)
                .await;

        vote_execute_proposal_assert_failed(&gov_can, proposal_id, "already members of subnets")
            .await;
    });
}

fn block_on<F>(f: F)
where
    F: Future<Output = ()>,
{
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on(f);
}
