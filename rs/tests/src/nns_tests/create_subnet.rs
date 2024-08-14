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

use ic_base_types::{NodeId, SubnetId};
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use slog::info;

use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_registry_subnet_type::SubnetType;
use ic_types::Height;

use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, NnsInstallationBuilder,
};
use ic_system_test_driver::nns::get_subnet_list_from_registry;
use ic_system_test_driver::nns::{
    self, get_software_version_from_snapshot, submit_create_application_subnet_proposal,
    vote_execute_proposal_assert_executed,
};

use ic_system_test_driver::util::{
    assert_create_agent, block_on, runtime_from_url, UniversalCanister,
};

const NNS_PRE_MASTER: usize = 4;
const APP_PRE_MASTER: usize = 4;

// Small IC for correctness test pre-master
pub fn pre_master_config(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(
            Subnet::fast(SubnetType::System, NNS_PRE_MASTER)
                .with_dkg_interval_length(Height::from(NNS_PRE_MASTER as u64 * 2)),
        )
        .with_unassigned_nodes(APP_PRE_MASTER)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
    env.topology_snapshot()
        .unassigned_nodes()
        .for_each(|node| node.await_can_login_as_admin_via_ssh().unwrap());
}

pub fn test(env: TestEnv) {
    let log = &env.logger();

    // [Phase I] Prepare NNS
    install_nns_canisters(&env);
    let topology_snapshot = &env.topology_snapshot();
    let subnet = topology_snapshot.root_subnet();
    let endpoint = subnet.nodes().next().unwrap();

    // get IDs of all unassigned nodes
    let unassigned_nodes: Vec<NodeId> = topology_snapshot
        .unassigned_nodes()
        .map(|n| n.node_id)
        .collect();

    // check that there is at least one unassigned node
    assert!(
        !unassigned_nodes.is_empty(),
        "there must be at least one unassigned node for creating a subnet"
    );

    // [Phase II] Execute and validate the testnet change

    let client = RegistryCanister::new_with_query_timeout(
        vec![endpoint.get_public_url()],
        Duration::from_secs(10),
    );

    let new_subnet_id: SubnetId = block_on(async move {
        // get original subnet ids
        let original_subnets = get_subnet_list_from_registry(&client).await;
        assert!(!original_subnets.is_empty(), "registry contains no subnets");
        info!(log, "original subnets: {:?}", original_subnets);

        // get current replica version and Governance canister
        let version = get_software_version_from_snapshot(&endpoint)
            .await
            .expect("could not obtain replica software version");
        let nns = runtime_from_url(endpoint.get_public_url(), endpoint.effective_canister_id());
        let governance = nns::get_governance_canister(&nns);

        let proposal_id =
            submit_create_application_subnet_proposal(&governance, unassigned_nodes, version).await;

        vote_execute_proposal_assert_executed(&governance, proposal_id).await;

        // Check that the registry indeed contains the data
        let final_subnets = get_subnet_list_from_registry(&client).await;
        info!(log, "final subnets: {:?}", final_subnets);

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
        original_subnet_set
            .symmetric_difference(&final_subnet_set)
            .collect::<HashSet<_>>()
            .iter()
            .next()
            .unwrap()
            .to_owned()
            .to_owned()
    });

    info!(log, "created application subnet with ID {}", new_subnet_id);

    // [Phase III] install a canister onto that subnet and check that it is
    // operational
    block_on(async move {
        topology_snapshot
            .block_for_newer_registry_version()
            .await
            .expect("Could not obtain updated registry.");
    });

    let new_subnet = topology_snapshot
        .subnets()
        .find(|subnet| subnet.subnet_id == new_subnet_id)
        .expect("Could not find newly created subnet.");
    new_subnet
        .nodes()
        .for_each(|node| node.await_status_is_healthy().unwrap());
    let newly_assigned_endpoint = new_subnet
        .nodes()
        .next()
        .expect("Could not find any node in newly created subnet.");

    block_on(async move {
        let agent = assert_create_agent(newly_assigned_endpoint.get_public_url().as_str()).await;
        info!(
            log,
            "successfully created agent for endpoint of an originally unassigned node"
        );

        let universal_canister = UniversalCanister::new_with_retries(
            &agent,
            newly_assigned_endpoint.effective_canister_id(),
            log,
        )
        .await;
        info!(log, "successfully created a universal canister instance");

        const UPDATE_MSG_1: &[u8] =
            b"This beautiful prose should be persisted for future generations";

        universal_canister.store_to_stable(0, UPDATE_MSG_1).await;
        info!(log, "successfully saved message in the universal canister");

        assert_eq!(
            universal_canister
                .try_read_stable(0, UPDATE_MSG_1.len() as u32)
                .await,
            UPDATE_MSG_1.to_vec(),
            "could not validate that subnet is healthy: universal canister is broken"
        );
    });

    info!(
        log,
        "Successfully created an app subnet of size {} from an NNS subnet of size {}",
        APP_PRE_MASTER,
        NNS_PRE_MASTER
    );
}

fn set<H: Clone + std::cmp::Eq + std::hash::Hash>(data: &[H]) -> HashSet<H> {
    HashSet::from_iter(data.iter().cloned())
}

pub fn install_nns_canisters(env: &TestEnv) {
    let nns_node = env
        .topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .expect("there is no NNS node");
    NnsInstallationBuilder::new()
        .install(&nns_node, env)
        .expect("NNS canisters not installed");
    info!(&env.logger(), "NNS canisters installed");
}
