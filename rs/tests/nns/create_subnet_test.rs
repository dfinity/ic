/* tag::catalog[]
Title:: Create Subnet

Goal:: Ensure that subnets can be created from unassigned nodes

Runbook::
. set up the NNS subnet and unassigned nodes
. submit and adopt multiple proposals for creating subnets at the same time
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
use ic_nns_governance_api::ProposalStatus;
use ic_nns_test_utils::governance::wait_for_final_state;
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, NnsInstallationBuilder,
};
use ic_system_test_driver::nns::{
    self, get_software_version_from_snapshot, submit_create_application_subnet_proposal,
};
use ic_system_test_driver::nns::{get_subnet_list_from_registry, vote_on_proposal};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::{
    UniversalCanister, assert_create_agent, block_on, runtime_from_url,
};
use ic_types::{Height, RegistryVersion};
use registry_canister::mutations::do_create_subnet::CanisterCyclesCostSchedule;
use slog::info;
use std::collections::HashSet;
use std::iter::FromIterator;
use std::time::Duration;

const NNS_PRE_MASTER: usize = 4;
const APP_PRE_MASTER: usize = 4;
const DKG_INTERVAL_LENGTH: u64 = 29;
const APP_SUBNETS: usize = 5;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}

// Small IC for correctness test pre-master
pub fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(
            Subnet::fast(SubnetType::System, NNS_PRE_MASTER)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL_LENGTH)),
        )
        .with_unassigned_nodes(APP_PRE_MASTER * APP_SUBNETS)
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
    let mut unassigned_nodes = topology_snapshot
        .unassigned_nodes()
        .map(|node| node.node_id);

    // [Phase II] Execute and validate the testnet changes

    let client = RegistryCanister::new_with_query_timeout(
        vec![endpoint.get_public_url()],
        Duration::from_secs(10),
    );

    let (subnet_ids, topology_snapshot) = block_on(async move {
        let original_subnets = get_subnet_list_from_registry(&client).await;
        assert!(!original_subnets.is_empty(), "registry contains no subnets");
        info!(log, "original subnets: {:?}", original_subnets);

        // get current replica version and Governance canister
        let version = get_software_version_from_snapshot(&endpoint)
            .await
            .expect("could not obtain replica software version");
        let nns = runtime_from_url(endpoint.get_public_url(), endpoint.effective_canister_id());
        let governance = nns::get_governance_canister(&nns);

        // Submit and adopt the configured number of create subnet proposals
        let mut proposal_ids = vec![];
        for _ in 0..APP_SUBNETS {
            let nodes = unassigned_nodes.by_ref().take(APP_PRE_MASTER).collect();
            info!(
                log,
                "Submitting proposal to create subnet with nodes: {nodes:?}"
            );
            let proposal_id = submit_create_application_subnet_proposal(
                &governance,
                nodes,
                version.clone(),
                Some(CanisterCyclesCostSchedule::Normal),
            )
            .await;
            info!(log, "Voting on proposal {proposal_id}");
            vote_on_proposal(&governance, proposal_id).await;
            proposal_ids.push(proposal_id);
        }

        // Wait until all proposals are executed
        for proposal_id in proposal_ids {
            info!(log, "Waiting on proposal {proposal_id}");
            let proposal_info = wait_for_final_state(&governance, proposal_id).await;
            assert_eq!(
                proposal_info.status,
                ProposalStatus::Executed as i32,
                "proposal {proposal_id} did not execute: {proposal_info:?}"
            );
        }

        let new_topology_snapshot = topology_snapshot
            .block_for_min_registry_version(RegistryVersion::new(APP_SUBNETS as u64 + 1))
            .await
            .expect("Could not obtain updated registry.");

        // Check that the registry indeed contains the data
        let final_subnets = get_subnet_list_from_registry(&client).await;
        info!(log, "final subnets: {:?}", final_subnets);

        let original_subnet_set = set(&original_subnets);
        let final_subnet_set = set(&final_subnets);
        // check that there are exactly APP_SUBNETS added subnets
        assert_eq!(
            original_subnet_set.len() + APP_SUBNETS,
            final_subnet_set.len(),
            "final number of subnets should be {APP_SUBNETS} above number of original subnets"
        );
        assert!(
            original_subnet_set.is_subset(&final_subnet_set),
            "final number of subnets should be a superset of the set of original subnets"
        );

        // Return all subnet IDs
        (final_subnets, new_topology_snapshot)
    });

    // [Phase III] install a canister onto ALL subnets and check that they are
    // operational
    for subnet_id in subnet_ids {
        info!(log, "Asserting healthy status of subnet {subnet_id}");
        let subnet = topology_snapshot
            .subnets()
            .find(|subnet| subnet.subnet_id == subnet_id)
            .expect("Could not find newly created subnet.");
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap());
        let endpoint = subnet
            .nodes()
            .next()
            .expect("Could not find any node in newly created subnet.");

        block_on(async move {
            let agent = assert_create_agent(endpoint.get_public_url().as_str()).await;
            info!(
                log,
                "successfully created agent for endpoint of subnet node"
            );

            let universal_canister =
                UniversalCanister::new_with_retries(&agent, endpoint.effective_canister_id(), log)
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
    }
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
