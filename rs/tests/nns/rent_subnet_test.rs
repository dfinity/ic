/* tag::catalog[]
Title:: Rent Subnet

Goal:: Go through the subnet rental life cycle. (Currently, we do not have a story for how to stop renting a subnet though.)

Runbook::
. Have some unassigned nodes, which will end up constituting the rented subnet.
. (Future) user (a principal) of the rented subnet sends ICP to the Subnet Rental canister (SRC).
. Adopt a rental request proposal. This results in a so-called SubnetRentalRequest in the SRC.
. Adopt a FulfillSubnetRentalRequest proposal. This (nominally) results in the creation of a new subnet, the "rented" subnet.
. User creates a canister. It lands in the rented subnet. The canister can serve requests, but crucially, is not charged cycles. It can run on 0 cycles.
. Another principal (i.e. besides the user) tries to create a canister in the rented subnet, but they are not allowed to do that.

Success::
. Proposals execute successfully.
. Rented subnet gets created.
. User principal can create canisters in the rented subnet.
. The user's canisters can serve traffic.
. Other users CANNOT create canisters in the rented subnet.

end::catalog[] */

use anyhow::Result;
use candid::Principal;
use canister_test::Canister;
use cycles_minting_canister::{
    IcpXdrConversionRateCertifiedResponse, NotifyError, SubnetSelection,
};
use dfn_candid::{candid, candid_one};
use ic_agent::identity::BasicIdentity;
use ic_base_types::{CanisterId, PrincipalId, SubnetId};
use ic_canister_client::{Ed25519KeyPair, Sender};
use ic_ledger_core::Tokens;
use ic_nervous_system_common::E8;
use ic_nervous_system_common_test_keys::{TEST_USER1_KEYPAIR, TEST_USER2_KEYPAIR};
use ic_nns_constants::{
    CYCLES_MINTING_CANISTER_ID, EXCHANGE_RATE_CANISTER_ID, LEDGER_CANISTER_ID,
    REGISTRY_CANISTER_ID, SUBNET_RENTAL_CANISTER_ID,
};
use ic_nns_test_utils::{
    cycles_minting::cycles_minting_create_canister, ledger::BasicIcrc1Transfer,
};
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_registry_subnet_features::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        ic::{InternetComputer, Subnet},
        test_env::TestEnv,
        test_env_api::{
            find_subnet_that_hosts_canister_id, new_subnet_runtime, HasPublicApiUrl,
            HasRegistryVersion, HasTopologySnapshot, IcNodeContainer, NnsInstallationBuilder,
            SubnetSnapshot, TopologySnapshot,
        },
    },
    nns::{
        execute_subnet_rental_request, get_software_version_from_snapshot,
        get_subnet_list_from_registry,
    },
    systest,
    types::{CanisterIdRecord, CanisterStatusResult},
    util::{assert_create_agent, block_on, UniversalCanister, UNIVERSAL_CANISTER_WASM},
};
use ic_types::RegistryVersion;
use ic_universal_canister::wasm as universal_canister_argument_builder;
use ic_utils::interfaces::ManagementCanister;
use icp_ledger::{AccountIdentifier, Subaccount};
use icrc_ledger_types::icrc1::account::Account;
use lazy_static::lazy_static;
use registry_canister::pb::v1::{GetSubnetForCanisterRequest, SubnetForCanister};
use slog::info;
use std::{
    collections::HashSet,
    iter::FromIterator,
    str::FromStr,
    thread::sleep,
    time::{Duration, SystemTime},
};

const PRICE_OF_ICP_IN_XDR_CENTS: u64 = 314;
const SUBNET_RENTAL_PAYMENT_AMOUNT_ICP: u64 = 49_000;

lazy_static! {
    // This is the principal that will be able to create canisters in the
    // "rented" subnet once it gets created. This principal is required to
    // supply enough ICP to the Subnet Rental canister.
    static ref SUBNET_USER_KEYPAIR: Ed25519KeyPair = TEST_USER1_KEYPAIR.clone();

    static ref SUBNET_USER_SENDER: Sender = Sender::from_keypair(&*SUBNET_USER_KEYPAIR);

    static ref SUBNET_USER_PRINCIPAL_ID: PrincipalId = SUBNET_USER_SENDER.get_principal_id();

    static ref NON_SUBNET_USER_KEYPAIR: Ed25519KeyPair = {
        let result = TEST_USER2_KEYPAIR.clone();

        // assert_ne is not used, because the type does not implement Debug,
        // which is required by assert_ne.
        assert!(result != *SUBNET_USER_KEYPAIR);

        result
    };

    static ref NON_SUBNET_USER_SENDER: Sender = Sender::from_keypair(&*NON_SUBNET_USER_KEYPAIR);

    static ref NON_SUBNET_USER_PRINCIPAL_ID: PrincipalId = NON_SUBNET_USER_SENDER.get_principal_id();
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
                http_requests: true,
                ..SubnetFeatures::default()
            })
            .add_nodes(1),
    );
    ic = ic.add_subnet(Subnet::fast(
        SubnetType::System,
        1, // Node count.
    ));

    ic.with_unassigned_nodes(1)
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

    install_nns_canisters(&env);
}

pub fn test(env: TestEnv) {
    let topology_snapshot = env.topology_snapshot();

    block_on(async move {
        // A pre-flight check. Not sure why this is necessary. This was probably
        // cargo culted this from ./create_subnet_test.rs
        let registry_canister = RegistryCanister::new_with_query_timeout(
            vec![topology_snapshot
                .root_subnet()
                .nodes()
                .next()
                .unwrap()
                .get_public_url()],
            Duration::from_secs(10),
        );
        let original_subnets = get_subnet_list_from_registry(&registry_canister)
            .await
            // Convert to HashSet
            .into_iter()
            .collect::<HashSet<SubnetId>>();
        assert!(!original_subnets.is_empty(), "registry contains no subnets");

        subnet_user_sends_icp_to_the_subnet_rental_canister(&topology_snapshot).await;

        execute_subnet_rental_request(&topology_snapshot, *SUBNET_USER_PRINCIPAL_ID).await;

        let topology_snapshot = execute_fulfill_subnet_rental_request(&topology_snapshot).await;
        let new_subnet_id = assert_new_subnet(&topology_snapshot, &original_subnets).await;

        assert_rented_subnet_works(new_subnet_id, &topology_snapshot).await;
    });
}

async fn subnet_user_sends_icp_to_the_subnet_rental_canister(topology_snapshot: &TopologySnapshot) {
    let runtime = new_subnet_runtime(&topology_snapshot.root_subnet());
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

        amount: Tokens::new(SUBNET_RENTAL_PAYMENT_AMOUNT_ICP, 0).unwrap(),
    };

    let _block_index = request.execute_on(&icp_ledger, &*SUBNET_USER_SENDER).await;
}

#[must_use]
async fn execute_fulfill_subnet_rental_request(
    topology_snapshot: &TopologySnapshot,
) -> TopologySnapshot {
    let previous_registry_version = topology_snapshot.get_registry_version();

    let an_nns_subnet_node = topology_snapshot.root_subnet().nodes().next().unwrap();

    let node_ids = topology_snapshot
        .unassigned_nodes()
        .map(|node| node.node_id.get())
        .collect();
    let replica_version_id = get_software_version_from_snapshot(&an_nns_subnet_node)
        .await
        .unwrap();
    let replica_version_id = String::from(replica_version_id);
    let proposal_id = ic_system_test_driver::nns::execute_fulfill_subnet_rental_request(
        &an_nns_subnet_node,
        *SUBNET_USER_PRINCIPAL_ID,
        node_ids,
        replica_version_id,
    )
    .await;
    println!("FulfillSubnetRentalRequest executed: {:?}", proposal_id);

    // Wait for us to find out about the latest Registry data.
    let min_registry_version = previous_registry_version.get() + 1;
    topology_snapshot
        .block_for_min_registry_version(RegistryVersion::new(min_registry_version))
        .await
        .expect("Could not obtain updated registry.")
}

async fn assert_new_subnet(
    topology_snapshot: &TopologySnapshot,
    original_subnets: &HashSet<SubnetId>,
) -> SubnetId {
    // What subnets did we end up with?
    let an_nns_subnet_node = topology_snapshot.root_subnet().nodes().next().unwrap();
    let registry_canister = RegistryCanister::new_with_query_timeout(
        vec![an_nns_subnet_node.get_public_url()],
        Duration::from_secs(10),
    );
    let final_subnets = HashSet::from_iter(get_subnet_list_from_registry(&registry_canister).await);

    // Assert that final_subnet == original_subnets + {new_subnet}.
    assert!(
        original_subnets.is_subset(&final_subnets),
        "final number of subnets should be a superset of the set of original subnets"
    );
    let new_subnet_ids = final_subnets
        .difference(original_subnets)
        .cloned()
        .collect::<HashSet<SubnetId>>();
    assert_eq!(new_subnet_ids.len(), 1, "{:#?}", new_subnet_ids);

    // Return the ID of the new subnet.
    new_subnet_ids.into_iter().next().unwrap()
}

/// Verifies the following:
///
///     1. All nodes in the subnet are healthy.
///
///     2. Can create a canister in the subnet.
///
///     3. Can install code into the canister.
///
///     4. Canister can be called.
///
///     5. Call affects the canister's (stable) memory.
///
///     6. The canister is NOT charged cycles.
///
///     7. Principals other than SUBNET_USER are NOT allowed to create canisters
///        in the rented subnet.
///
/// (The universal canister is used.)
async fn assert_rented_subnet_works(
    rented_subnet_id: SubnetId,
    topology_snapshot: &TopologySnapshot,
) {
    let rented_subnet = topology_snapshot
        .subnets()
        .find(|subnet| subnet.subnet_id == rented_subnet_id)
        .expect("Could not find newly created subnet.");

    // Verify 1: all nodes are healthy.
    rented_subnet.nodes().for_each(|node| {
        node.await_status_is_healthy().unwrap_or_else(|err| {
            panic!(
                "Node {:?} in subnet {:?} did not reach healthy state: {}",
                node.node_id, rented_subnet_id, err,
            );
        })
    });

    let a_rented_subnet_node = rented_subnet
        .nodes()
        .next()
        .expect("Could not find any node in newly created subnet.");
    let mut agent = assert_create_agent(a_rented_subnet_node.get_public_url().as_str()).await;
    agent.set_identity(
        BasicIdentity::from_pem(std::io::Cursor::new(SUBNET_USER_KEYPAIR.to_pem())).unwrap(),
    );

    // Verify 2: Can create a canister. Unlike the usual case, this requires 0
    // ICP. The reason for this special exception is that in subnet rental,
    // everything is paid for up front.
    let nns_subnet_runtime = new_subnet_runtime(&topology_snapshot.root_subnet());
    let new_canister = cycles_minting_create_canister(
        &nns_subnet_runtime,
        &*SUBNET_USER_SENDER,
        0, // amount_e8s
        |_| (),
    )
    .await
    .unwrap();
    let new_canister_principal_id =
        CanisterId::unchecked_from_principal(PrincipalId::from(new_canister.canister_id()));

    // Verify 2.1: The created canister is actually IN the rented subnet, due to
    // it being created by the rented subnet's user.
    assert_canister_belongs_to_subnet(
        &topology_snapshot,
        new_canister_principal_id,
        rented_subnet_id,
    )
    .await;

    // This will be used later to verify 6: the canister does not charged cycles.
    let original_cycles_balance =
        get_cycles_balance(new_canister_principal_id, &rented_subnet).await;

    // Verify 3: Can install code into the new canister.
    ManagementCanister::create(&agent)
        .install_code(
            &Principal::from(PrincipalId::from(new_canister_principal_id)),
            &UNIVERSAL_CANISTER_WASM,
        )
        .with_raw_arg(universal_canister_argument_builder().stable_grow(1).build())
        .call_and_wait()
        .await
        .unwrap();

    // Verify 4: Canister can be called.
    const POETRY: &[u8] = b"This beautiful poetry should be persisted for posterity.";
    agent
        .update(
            &Principal::from(PrincipalId::from(new_canister_principal_id)),
            "update",
        )
        .with_arg(UniversalCanister::stable_writer(0, POETRY))
        .call_and_wait()
        .await
        .unwrap();

    // Verify 5: Call affects the canister's (stable) memory.
    assert_eq!(
        agent
            .query(
                &Principal::from(PrincipalId::from(new_canister_principal_id)),
                "query"
            )
            .with_arg(
                universal_canister_argument_builder()
                    .stable_read(0, POETRY.len() as u32)
                    .reply_data_append()
                    .reply()
                    .build(),
            )
            .call()
            .await
            .unwrap(),
        POETRY.to_vec(),
    );

    // Verify 6: The canister was not charged for the previous two operations.
    let later_cycles_balance = get_cycles_balance(new_canister_principal_id, &rented_subnet).await;
    assert_eq!(
        later_cycles_balance - original_cycles_balance,
        0,
        "{original_cycles_balance}",
    );

    // Verify 7: Other principals are NOT allowed to create canisters in the
    // rented subnet.

    // As another user, try to create a canister in the rented subnet. This is supposed to get blocked.
    assert_that_non_subnet_user_gets_blocked_if_they_try_to_create_a_canister_in_the_rented_subnet(
        &topology_snapshot,
        rented_subnet_id,
    )
    .await;
}

async fn assert_canister_belongs_to_subnet(
    topology_snapshot: &TopologySnapshot,
    canister_id: CanisterId,
    expected_subnet_id: SubnetId,
) {
    // Prepare to call the Registry canister.
    let runtime = new_subnet_runtime(&topology_snapshot.root_subnet());

    // Call Registry's get_subnet_for_canister method.
    let get_subnet_for_canister_result: Result<SubnetForCanister, String> =
        Canister::new(&runtime, REGISTRY_CANISTER_ID)
            .update_from_sender(
                "get_subnet_for_canister",
                candid_one,
                GetSubnetForCanisterRequest {
                    principal: Some(PrincipalId::from(canister_id)),
                },
                &*SUBNET_USER_SENDER,
            )
            .await
            .unwrap();

    // Compare result from get_subnet_for_canister with the required subnet ID.
    let new_canister_subnet_id = get_subnet_for_canister_result.unwrap().subnet_id.unwrap();
    assert_eq!(new_canister_subnet_id, expected_subnet_id.get(),);
}

async fn get_cycles_balance(canister_id: CanisterId, subnet: &SubnetSnapshot) -> u128 {
    // Prepare to call the management canister...
    let runtime = new_subnet_runtime(&subnet);
    let management_canister = Canister::new(
        &runtime,
        CanisterId::unchecked_from_principal(PrincipalId::from_str("aaaaa-aa").unwrap()),
    );

    // Prepare the canister_status request that we are about to send.
    let request = CanisterIdRecord {
        canister_id: Principal::from(canister_id),
    };

    // Call the canister_status method (of the Management pseudo-canister).
    let result: CanisterStatusResult = management_canister
        .update_from_sender("canister_status", candid_one, request, &*SUBNET_USER_SENDER)
        .await
        .unwrap();

    // Pluck out the one field that we care about from the canister_status
    // result.
    u128::try_from(result.cycles.0).unwrap()
}

async fn assert_that_non_subnet_user_gets_blocked_if_they_try_to_create_a_canister_in_the_rented_subnet(
    topology_snapshot: &TopologySnapshot,
    rented_subnet_id: SubnetId,
) {
    let err = cycles_minting_create_canister(
        &new_subnet_runtime(&topology_snapshot.root_subnet()),
        &*NON_SUBNET_USER_SENDER,
        10 * E8, // amount_e8s
        |notify_create_canister| {
            notify_create_canister.subnet_selection = Some(SubnetSelection::Subnet {
                subnet: rented_subnet_id,
            });
        },
    )
    .await
    .unwrap_err();

    match err {
        NotifyError::Refunded {
            reason,
            block_index,
        } => {
            for key_word in [
                "not authorized".to_string(),
                format!("{}", rented_subnet_id).to_lowercase(),
                format!("{}", *NON_SUBNET_USER_PRINCIPAL_ID).to_lowercase(),
            ] {
                assert!(
                    reason.contains(&key_word),
                    "({:?}) {:?} not in {:?}",
                    block_index,
                    key_word,
                    reason,
                );
            }
        }
        _ => panic!("{:?}", err),
    }
}

fn install_nns_canisters(env: &TestEnv) {
    let topology_snapshot = env.topology_snapshot();
    let root_subnet = topology_snapshot.root_subnet();

    let nns_node = root_subnet.nodes().next().expect("there is no NNS node");

    let mut installer = NnsInstallationBuilder::new()
        .with_subnet_rental_canister()
        .with_exchange_rate_canister();

    // Give subnet user an initial amount of ICP, which they will use to pay to
    // rent a new subnet.
    installer = installer.with_balance(
        AccountIdentifier::new(
            *SUBNET_USER_PRINCIPAL_ID,
            None, // subaccount
        ),
        // This is slightly more than what's needed to pay for the subnet that
        // is being offered for rent in order to cover "incidentals" (i.e. the
        // transfer fee).
        Tokens::new(SUBNET_RENTAL_PAYMENT_AMOUNT_ICP + 100, 0).unwrap(),
    );

    // Give a bit of "pocket money" to the NON_SUBNET_USER principal, for canister creation.
    installer = installer.with_balance(
        AccountIdentifier::new(
            *NON_SUBNET_USER_PRINCIPAL_ID,
            None, // subaccount
        ),
        Tokens::new(50, 0).unwrap(),
    );

    installer
        .install(&nns_node, env)
        .expect("NNS canisters not installed");

    create_and_install_mock_exchange_rate_canister(&topology_snapshot);
    wait_for_cycles_minting_to_get_price_of_icp(&topology_snapshot);

    info!(&env.logger(), "NNS canisters installed");
}

fn create_and_install_mock_exchange_rate_canister(topology_snapshot: &TopologySnapshot) {
    let exchange_rate_canister_subnet =
        find_subnet_that_hosts_canister_id(&topology_snapshot, EXCHANGE_RATE_CANISTER_ID);
    assert_eq!(
        exchange_rate_canister_subnet.subnet_type(),
        SubnetType::System,
        "{}",
        exchange_rate_canister_subnet.subnet_id,
    );

    let runtime = new_subnet_runtime(&exchange_rate_canister_subnet);

    block_on(
        ic_nns_test_utils::itest_helpers::create_and_install_mock_exchange_rate_canister(
            &runtime,
            PRICE_OF_ICP_IN_XDR_CENTS,
        ),
    );
}

fn wait_for_cycles_minting_to_get_price_of_icp(topology_snapshot: &TopologySnapshot) {
    let nns_subnet = topology_snapshot.root_subnet();
    let runtime = new_subnet_runtime(&nns_subnet);
    let cycles_minting = Canister::new(&runtime, CYCLES_MINTING_CANISTER_ID);

    fn age_s(timestamp_seconds: u64) -> u64 {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        now - timestamp_seconds
    }

    let mut err_budget = 30;
    for i in 1..=120 {
        let result: Result<IcpXdrConversionRateCertifiedResponse, _> =
            block_on(cycles_minting.query_("get_icp_xdr_conversion_rate", candid, ()));

        let reply = match result {
            Ok(ok) => ok,
            Err(err) => {
                if err_budget == 0 {
                    panic!(
                        "Giving up on calling the Cycles Minting canister: {:?}",
                        err
                    );
                }

                println!(
                    "The Cycles Minting canister is not responsive (yet): {:?}",
                    err
                );
                err_budget -= 1;
                sleep(Duration::from_secs(1));
                continue;
            }
        };

        if age_s(reply.data.timestamp_seconds) < 600 {
            assert_eq!(
                reply.data.xdr_permyriad_per_icp,
                PRICE_OF_ICP_IN_XDR_CENTS * 100,
            );
            println!(
                "Yay! Updated ICP price found in the Cycles Minting canister \
                 after {} attempts.",
                i,
            );
            return;
        }

        sleep(Duration::from_secs(1));
    }

    panic!(
        "The Cycles Minting canister did not update its price of ICP from \
         the (mock) Exchange Rate canister within a reasonable amount of time."
    );
}
