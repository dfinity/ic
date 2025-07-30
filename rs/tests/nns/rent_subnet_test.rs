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
use candid::{Encode, Principal};
use canister_test::{RemoteTestRuntime, Runtime, Canister};
use dfn_candid::candid_multi_arity; // DO NOT MERGE
use ic_base_types::{CanisterId, SubnetId, PrincipalId};
use ic_canister_client::{Agent, Sender};
use ic_ledger_core::Tokens;
// DO NOT MERGE use ic_nns_governance_api::{ProposalStatus, NnsFunction};
use ic_nns_constants::{
    GOVERNANCE_CANISTER_ID, REGISTRY_CANISTER_ID, EXCHANGE_RATE_CANISTER_ID,
    SUBNET_RENTAL_CANISTER_ID, LEDGER_CANISTER_ID,
};
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_registry_routing_table::CanisterIdRange;
use ic_registry_subnet_features::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        ic::{InternetComputer, Subnet},
        test_env::TestEnv,
        test_env_api::{
            self,
            HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, NnsInstallationBuilder, TopologySnapshot,
            IcNodeSnapshot, SubnetSnapshot,
        },
    },
    ledger::{
        BasicIcrc1Transfer,
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
use icp_ledger::{AccountIdentifier, Subaccount};
use icrc_ledger_types::icrc1::account::Account;
use lazy_static::lazy_static;
use registry_canister::mutations::reroute_canister_ranges::RerouteCanisterRangesPayload;
use slog::info;
use std::{
    collections::HashSet,
    iter::FromIterator,
    time::Duration,
};

const DKG_INTERVAL_LENGTH: u64 = 29;
const PRICE_OF_ICP_IN_XDR_CENTS: u64 = 314;

lazy_static! {
    // This is the principal that will be able to create canisters in the
    // "rented" subnet once it gets created. This principal is required to
    // supply enough ICP to the Subnet Rental canister.
    static ref SUBNET_USER_PRINCIPAL_ID: PrincipalId = PrincipalId::new_user_test_id(153_288_198);
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}

pub fn setup(env: TestEnv) {
    let mut ic = InternetComputer::new();

    // This hack is needed so that we can install a (mock) Exchange Rate
    // canister at its usual canister ID. This hack is copied from
    // rs/tests/testnets/src_testing.rs. What this does is ensure that there is
    // a system subnet that is assigned a canister ID range containing the usual
    // Exchange Rate canister ID (uf6dk-hyaaa-aaaaq-qaaaq-cai).
    for _ in 0..32 {
        ic = ic.add_subnet(Subnet::new(SubnetType::Application).add_nodes(1));
    }
    ic = ic.add_subnet(
        Subnet::new(SubnetType::System)
            .with_features(SubnetFeatures {
                http_requests:true,
                ..SubnetFeatures::default()
            })
            .add_nodes(1),
    );
    ic = ic.add_subnet(
        Subnet::fast(
            SubnetType::System,
            1, // Node count.
        )
        .with_dkg_interval_length(Height::from(DKG_INTERVAL_LENGTH))
    );

    ic
        .with_unassigned_nodes(1)
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

    let client = RegistryCanister::new_with_query_timeout(
        vec![an_nns_subnet_node.get_public_url()],
        Duration::from_secs(10),
    );

    block_on(async move {
        let runtime = new_node_runtime(&an_nns_subnet_node);

        let original_subnets = get_subnet_list_from_registry(&client).await;
        // Not sure why the NNS subnet is not in original_subnets...
        assert!(!original_subnets.is_empty(), "registry contains no subnets");

        // The (prospective) subnet user sends an adequate amount of ICP to the
        // Subnet Rental canister (to rent the subnet that is being offerred).
        let icp_ledger = Canister::new(&runtime, LEDGER_CANISTER_ID);
        let request = BasicIcrc1Transfer {
            source: Account {
                owner: Principal::from(*SUBNET_USER_PRINCIPAL_ID),
                subaccount: None,
            },

            destination: Account {
                owner: Principal::from(SUBNET_RENTAL_CANISTER_ID),
                subaccount: Some(Subaccount::from(&*SUBNET_USER_PRINCIPAL_ID).0),
            },

            amount: Tokens::new(50_000, 0).unwrap(),
        };
        println!("\n\n DO NOT MERGE - Sending ICP to the Subnet Rental canister...\n\n");
        let _block_index = request.execute_on(&icp_ledger).await;
        println!("\n\n DO NOT MERGE - Success! ICP sent to the Subnet Rental canister.\n\n");

        execute_subnet_rental_request(&an_nns_subnet_node, *SUBNET_USER_PRINCIPAL_ID).await;

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
    let root_subnet = env.topology_snapshot().root_subnet();
    let other_system_subnet = env.topology_snapshot()
        .subnets()
        .find(|subnet| subnet.subnet_id != root_subnet.subnet_id)
        .unwrap();

    let nns_node = root_subnet
        .nodes()
        .next()
        .expect("there is no NNS node");

    let mut installer = NnsInstallationBuilder::new()
        .with_subnet_rental_canister();

    // Give SUBNET user an initial amount of ICP.
    const DEFAULT_FEE: u64 = 10_000; // DO NOT MERGE
    installer = installer.with_balance(
        AccountIdentifier::new(
            *SUBNET_USER_PRINCIPAL_ID,
            None, // subaccount
        ),
        // This is slightly more than what's needed to pay for the subnet that
        // is being offered for rent.
        Tokens::new(50_000, DEFAULT_FEE).unwrap(),
    );

    installer
        .install(&nns_node, env)
        .expect("NNS canisters not installed");

    create_and_install_mock_exchange_rate_canister(env.topology_snapshot());
}

fn new_node_runtime(node: &IcNodeSnapshot) -> Runtime {
    let agent = Agent::new(
        node.get_public_url(),
        Sender::from_principal_id(PrincipalId::from(GOVERNANCE_CANISTER_ID)),
    );

    Runtime::Remote(RemoteTestRuntime {
        agent,
        effective_canister_id: PrincipalId::from(REGISTRY_CANISTER_ID),
    })
}

fn create_and_install_mock_exchange_rate_canister(topology_snapshot: TopologySnapshot) {
    let exchange_rate_canister_subnet = find_subnet_that_hosts_canister_id(
        &topology_snapshot,
        EXCHANGE_RATE_CANISTER_ID,
    );
    assert_eq!(
        exchange_rate_canister_subnet.subnet_type(), SubnetType::System,
        "{}", exchange_rate_canister_subnet.subnet_id,
    );

    let exchange_rate_canister_subnet_node = exchange_rate_canister_subnet.nodes().next().unwrap();
    block_on(test_env_api::create_and_install_mock_exchange_rate_canister(
        &exchange_rate_canister_subnet_node,
        PRICE_OF_ICP_IN_XDR_CENTS,
    ));
}

/// Panics if not found.
fn find_subnet_that_hosts_canister_id(topology_snapshot: &TopologySnapshot, canister_id: CanisterId) -> SubnetSnapshot {
    // Scan for subnet
    let mut subnets = topology_snapshot
        .subnets()
        .filter(|subnet| {
            subnet.subnet_canister_ranges()
                .into_iter()
                .any(|canister_id_range| canister_id_range.contains(&canister_id))
        })
        .collect::<Vec<_>>();

    // Only one subnet.
    assert_eq!(
        subnets.len(), 1,
        "{:#?}\n\n{:#?}",
        subnets
            .into_iter()
            .map(|subnet| subnet.subnet_id)
            .collect::<Vec<_>>(),
        topology_snapshot
            .subnets()
            .into_iter()
            .map(|subnet| (
                subnet.subnet_id,
                subnet.subnet_canister_ranges(),
            ))
            .collect::<Vec<_>>(),
    );

    subnets.pop().unwrap()
}
