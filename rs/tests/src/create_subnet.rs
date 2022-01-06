/* tag::catalog[]
Title:: Create Subnet

Goal:: Ensure that a subnet can be created from unassigned nodes

Runbook::
. set up the NNS subnet and check that we have unassigned nodes
. submit a proposal for creating a subnet based on those unassigned nodes
. validate proposal execution by checking if the new subnet has been registered as expected
. validate that the new subnet is operational by installing and querying a universal canister

Success::
. subnet creation proposal is adopted and executed
. registry subnet list equals OldSubnetIDs ∪ { new_subnet_id }
. newly created subnet endpoint comes to life within 2 minutes
. universal canister can be installed onto the new subnet
. universal canister is responsive

end::catalog[] */

use std::collections::HashSet;
use std::iter::FromIterator;
use std::time::Duration;

use ic_base_types::NodeId;
use ic_fondue::ic_manager::IcSubnet;
use ic_fondue::internet_computer::Subnet;
use ic_fondue::log::info;
use ic_fondue::util::PermOf;
use ic_fondue::{
    ic_manager::IcHandle,                // we run the test on the IC
    internet_computer::InternetComputer, // which is declared through these types
};

use ic_registry_common::registry::RegistryCanister;
use ic_registry_subnet_type::SubnetType;
use ic_types::Height;

use crate::nns::{
    self, get_software_version, submit_create_application_subnet_proposal,
    vote_execute_proposal_assert_executed,
};
use crate::nns::{get_subnet_list_from_registry, NnsExt};

use crate::util::{
    assert_create_agent, block_on, get_random_nns_node_endpoint, runtime_from_url,
    UniversalCanister,
};

pub fn config() -> InternetComputer {
    InternetComputer::new()
        .add_subnet(Subnet::fast(SubnetType::System, 2).with_dkg_interval_length(Height::from(19)))
        .with_unassigned_nodes(4)
}

pub fn create_subnet_test(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    // [Phase I] Prepare NNS
    ctx.install_nns_canisters(&handle, true);
    let mut rng = ctx.rng.clone();
    let endpoint = get_random_nns_node_endpoint(&handle, &mut rng);
    block_on(endpoint.assert_ready(ctx));

    // get IDs of (1) all nodes (2) unassigned nodes
    let node_ids = ctx.initial_node_ids(&handle);
    let unassigned_endpoints = ctx.initial_unassigned_node_endpoints(&handle);
    let unassigned_nodes: Vec<NodeId> = unassigned_endpoints.iter().map(|ep| ep.node_id).collect();

    // check that (1) unassigned nodes are a subset of all the nodes and (2) there
    // is at least one unassigned node
    assert!(
        set(&unassigned_nodes).is_subset(&set(&node_ids)),
        "could not obtain unassigned nodes"
    );
    assert!(
        !unassigned_nodes.is_empty(),
        "there must be at least one unassigned node for creating a subnet"
    );

    // [Phase II] Execute and validate the testnet change

    let client = RegistryCanister::new_with_query_timeout(
        vec![endpoint.url.clone()],
        Duration::from_secs(10),
    );

    let new_subnet: IcSubnet = block_on(async move {
        // get original subnet ids
        let original_subnets = get_subnet_list_from_registry(&client).await;
        assert!(!original_subnets.is_empty(), "registry contains no subnets");
        info!(ctx.logger, "original subnets: {:?}", original_subnets);

        // get current replica version and Governance canister
        let version = get_software_version(endpoint)
            .await
            .expect("could not obtain replica software version");
        let nns = runtime_from_url(endpoint.url.clone());
        let governance = nns::get_governance_canister(&nns);

        let proposal_id =
            submit_create_application_subnet_proposal(&governance, unassigned_nodes, version).await;

        vote_execute_proposal_assert_executed(&governance, proposal_id).await;

        // Check that the registry indeed contains the data
        let final_subnets = get_subnet_list_from_registry(&client).await;
        info!(ctx.logger, "final subnets: {:?}", final_subnets);

        // check that there is exactly one added subnet
        assert_eq!(
            original_subnets.len() + 1,
            final_subnets.len(),
            "final number of subnets should be one above number of original subnets"
        );
        let original_subnet_set = set(&original_subnets);
        let final_subnet_set = set(&final_subnets);
        assert!(
            original_subnet_set.is_subset(&final_subnet_set),
            "final number of subnets should be a superset of the set of original subnets"
        );

        // Return the newly created subnet
        let new_subnet_id = original_subnet_set
            .symmetric_difference(&final_subnet_set)
            .collect::<HashSet<_>>()
            .iter()
            .next()
            .unwrap()
            .to_owned()
            .to_owned();
        IcSubnet {
            id: new_subnet_id,
            type_of: SubnetType::Application,
        }
    });

    info!(
        ctx.logger,
        "created application subnet with ID {}", new_subnet.id
    );

    // get some endpoint of an originally unassigned node.
    let some_unassigned_endpoint = PermOf::new(&unassigned_endpoints, &mut rng)
        .find(|_ep| true)
        .unwrap();

    // [Phase III] install a canister onto that subnet and check that it is
    // operational
    block_on(async move {
        let newly_assigned_endpoint = some_unassigned_endpoint.recreate_with_subnet(new_subnet);

        newly_assigned_endpoint.assert_ready(ctx).await;

        let agent = assert_create_agent(newly_assigned_endpoint.url.as_str()).await;
        info!(
            ctx.logger,
            "successfully created agent for endpoint of an originally unassigned node"
        );

        let universal_canister = UniversalCanister::new(&agent).await;
        info!(
            ctx.logger,
            "successfully created a universal canister instance"
        );

        const UPDATE_MSG_1: &[u8] =
            b"This beautiful prose should be persisted for future generations";

        universal_canister.store_to_stable(0, UPDATE_MSG_1).await;
        info!(
            ctx.logger,
            "successfully saved message in the universal canister"
        );

        assert_eq!(
            universal_canister
                .try_read_stable(0, UPDATE_MSG_1.len() as u32)
                .await,
            UPDATE_MSG_1.to_vec(),
            "could not validate that subnet is healty: universal canister is broken"
        );
    })
}

fn set<H: Clone + std::cmp::Eq + std::hash::Hash>(data: &[H]) -> HashSet<H> {
    HashSet::from_iter(data.iter().cloned())
}
