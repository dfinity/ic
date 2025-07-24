/* tag::catalog[]
Title:: Rent Subnet

Goal:: Ensure that a rented subnet can be created.

Runbook::
. set up the NNS subnet and unassigned nodes
. enough ICP is sent to the Subnet Rental canister.
. submit ??? proposal This results in a so-called SubnetRentalRequest (whatever that means) in the Subnet Rental canister.
. validate proposal execution by checking if the new subnets have been registered as expected
. validate that all subnets are operational by installing and querying a universal canister

Success::
. subnet creation proposal is adopted and executed
. registry subnet list equals OldSubnetIDs ∪ NewSubnetIDs
. newly created subnet endpoints come to life within 2 minutes
. universal canisters can be installed onto all subnets
. universal canisters are responsive

end::catalog[] */

use anyhow::Result;
use ic_base_types::{SubnetId, PrincipalId};
// DO NOT MERGE use ic_nns_governance_api::{ProposalStatus, NnsFunction};
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        ic::{InternetComputer, Subnet},
        test_env::TestEnv,
        test_env_api::{
            HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, NnsInstallationBuilder, TopologySnapshot,
        },
    },
    nns::{
        get_subnet_list_from_registry, execute_subnet_rental_request,
    },
    systest,
    util::{
        assert_create_agent, block_on, UniversalCanister,
    },
};
use ic_types::{Height, RegistryVersion};
use slog::info;
use std::{
    collections::HashSet,
    iter::FromIterator,
    time::Duration,
};

const NNS_SUBNET_NODE_COUNT: usize = 4;
const APPLICATION_SUBNET_NODE_COUNT: usize = 4;
const DKG_INTERVAL_LENGTH: u64 = 29;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}

pub fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(
            Subnet::fast(SubnetType::System, NNS_SUBNET_NODE_COUNT)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL_LENGTH)),
        )
        .with_unassigned_nodes(APPLICATION_SUBNET_NODE_COUNT)
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
    let an_nns_subnet_node = topology_snapshot
        .root_subnet()
        .nodes()
        .next()
        .unwrap();

    // get IDs of all unassigned nodes
    let unassigned_nodes = topology_snapshot
        .unassigned_nodes()
        .map(|node| node.node_id)
        .collect
        ::<Vec<_>> // DO NOT MERGE
        ();

    // [Phase II] Execute and validate the testnet changes

    // This is the principal that will be able to create canisters in the
    // "rented" subnet once it gets created. This principal is required to
    // supply enough ICP to the Subnet Rental canister.
    let subnet_user = PrincipalId::new_user_test_id(42);

    let client = RegistryCanister::new_with_query_timeout(
        vec![an_nns_subnet_node.get_public_url()],
        Duration::from_secs(10),
    );

    block_on(async move {
        let original_subnets = get_subnet_list_from_registry(&client).await;
        // Not sure why the NNS subnet is not in original_subnets...
        assert!(!original_subnets.is_empty(), "registry contains no subnets");
        info!(log, "original subnets: {:?}", original_subnets);

        execute_subnet_rental_request(&an_nns_subnet_node, subnet_user).await;

        let new_topology_snapshot = topology_snapshot
            .block_for_min_registry_version(RegistryVersion::new(2))
            .await
            .expect("Could not obtain updated registry.");

        // Check that the registry indeed contains the data
        let mut final_subnets = get_subnet_list_from_registry(&client).await;
        info!(log, "final subnets: {:?}", final_subnets);

        /* DO NOT MERGE
        let original_subnet_set = set(&original_subnets);
        let final_subnet_set = set(&final_subnets);
        // check that there is exactly 1 additional subnet.
        assert_eq!(
            original_subnet_set.len() + 1,
            final_subnet_set.len(),
            "final number of subnets should be 1 above number of original subnets"
        );
        assert!(
            original_subnet_set.is_subset(&final_subnet_set),
            "final number of subnets should be a superset of the set of original subnets"
        );
        */

        // [Phase III]: Verify that the the CreateSubnet proposal resulted in a
        // working subnet.
        assert_eq!(final_subnets.len(), 1, "{:?} vs. original, {:?}", final_subnets, original_subnets);
        let subnet_id = final_subnets.pop().unwrap();
        info!(log, "Asserting healthy status of subnet {subnet_id}");

        assert_subnet_works(subnet_id, new_topology_snapshot, log).await;
    });
}

/// Verifies the following:
///
///     1. All nodes in the subnet are healthy.
///
///     2. Can create a canister in the subnet.
///
///     3. Can install code into the canister.
///
///     4. Can call the canister.
///
///     5. The call has the correct effect.
///
/// (The universal canister is used.)
async fn assert_subnet_works(
    subnet_id: SubnetId,
    network_topology: TopologySnapshot,
    log: &slog::Logger,
) {
    let subnet = network_topology
        .subnets()
        .find(|subnet| subnet.subnet_id == subnet_id)
        .expect("Could not find newly created subnet.");

    // Verify 1: all nodes are healthy.
    subnet
        .nodes()
        .for_each(|node| {
            node.await_status_is_healthy()
                .unwrap_or_else(|err| {
                    panic!(
                        "Node {:?} in subnet {:?} did not reach healthy state: {}",
                        node.node_id, subnet_id, err,
                    );
                })
        });

    let node = subnet
        .nodes()
        .next()
        .expect("Could not find any node in newly created subnet.");
    let agent = assert_create_agent(node.get_public_url().as_str()).await;

    // Verify 2 & 3: Can create a canister, and install code into it.
    let universal_canister =
        UniversalCanister::new_with_retries(&agent, node.effective_canister_id(), log)
        .await;

    // Verify 4: Can call the canister.
    const UPDATE_MSG_1: &[u8] =
        b"This beautiful prose should be persisted for future generations";
    universal_canister.store_to_stable(0, UPDATE_MSG_1).await;

    // Verify 5: The previous call had the intended effect.
    assert_eq!(
        universal_canister
            .try_read_stable(0, UPDATE_MSG_1.len() as u32)
            .await,
        UPDATE_MSG_1.to_vec(),
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
    let root_subnet_id = env.topology_snapshot().root_subnet().subnet_id; println!("\n\n DO NOT MERGE - E1 {:} \n\n", root_subnet_id);
    NnsInstallationBuilder::new()
        .with_mock_exchange_rate_canister()
        .with_subnet_rental_canister()
        .install(&nns_node, env)
        .expect("NNS canisters not installed");
    info!(&env.logger(), "NNS canisters installed");
}
