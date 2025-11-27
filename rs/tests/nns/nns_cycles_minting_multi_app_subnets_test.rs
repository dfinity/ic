use anyhow::Result;
use cycles_minting::{TestAgent, UserHandle, make_user_ed25519};
use cycles_minting_canister::{CREATE_CANISTER_REFUND_FEE, SubnetFilter, SubnetSelection};
use dfn_candid::candid_one;
use ic_canister_client::{HttpClient, Sender};
use ic_management_canister_types_private::{CanisterIdRecord, CanisterStatusResultV2};
use ic_nervous_system_common_test_keys::{TEST_USER1_KEYPAIR, TEST_USER1_PRINCIPAL};
use ic_nns_constants::{CYCLES_MINTING_CANISTER_ID, LEDGER_CANISTER_ID};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::InternetComputer;
use ic_system_test_driver::systest;
use ic_system_test_driver::{
    driver::{
        test_env::TestEnv,
        test_env_api::{
            HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, NnsInstallationBuilder,
        },
    },
    nns::{
        change_subnet_type_assignment, change_subnet_type_assignment_with_failure,
        set_authorized_subnetwork_list, set_authorized_subnetwork_list_with_failure,
        update_subnet_type,
    },
    util::{block_on, runtime_from_url},
};
use icp_ledger::Tokens;
use slog::info;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(create_canister_on_specific_subnet_type))
        .execute_from_args()?;
    Ok(())
}

pub fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .add_fast_single_node_subnet(SubnetType::Application)
        .add_fast_single_node_subnet(SubnetType::Application)
        .add_fast_single_node_subnet(SubnetType::Application)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
}

pub fn create_canister_on_specific_subnet_type(env: TestEnv) {
    let logger = env.logger();
    let topology = env.topology_snapshot();
    let nns_node = topology.root_subnet().nodes().next().unwrap();
    let nns = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    NnsInstallationBuilder::new()
        .install(&nns_node, &env)
        .expect("Could not install NNS canisters");
    block_on(async move {
        let agent_client = HttpClient::new();
        let tst = TestAgent::new(&nns_node.get_public_url(), &agent_client);
        let user1 = UserHandle::new(
            &nns_node.get_public_url(),
            &agent_client,
            &TEST_USER1_KEYPAIR,
            LEDGER_CANISTER_ID,
            CYCLES_MINTING_CANISTER_ID,
        );

        let (controller_user_keypair, _controller_pid) = make_user_ed25519(7);
        let controller_user = UserHandle::new(
            &nns_node.get_public_url(),
            &agent_client,
            &controller_user_keypair,
            LEDGER_CANISTER_ID,
            CYCLES_MINTING_CANISTER_ID,
        );

        // The first attempt to create a canister should fail because we
        // haven't registered any subnets with the cycles minting canister.
        info!(logger, "creating canister (no subnets)");

        let send_amount = Tokens::new(2, 0).unwrap();

        let (err, refund_block) = user1
            .create_canister_cmc(send_amount, None, &controller_user, None, None)
            .await
            .unwrap_err();

        info!(logger, "error: {}", err);
        assert!(err.contains("No subnets in which to create a canister"));

        // Check that the funds for the failed creation attempt are returned to use
        // (minus the fees).
        let refund_block = refund_block.unwrap();
        tst.check_refund(
            refund_block,
            send_amount,
            CREATE_CANISTER_REFUND_FEE,
            *TEST_USER1_PRINCIPAL,
        )
        .await;

        // Register an authorized subnet and additionally assign a subnet to a type.
        info!(logger, "registering subnets");
        let app_subnet_ids: Vec<_> = topology
            .subnets()
            .filter_map(|s| (s.subnet_type() == SubnetType::Application).then_some(s.subnet_id))
            .collect();
        let type1 = "Type1".to_string();
        let authorized_subnet = app_subnet_ids[0];
        let subnet_of_type1 = app_subnet_ids[1];

        set_authorized_subnetwork_list(&nns, None, vec![authorized_subnet])
            .await
            .unwrap();

        update_subnet_type(&nns, type1.clone()).await.unwrap();
        change_subnet_type_assignment(&nns, type1.clone(), vec![subnet_of_type1])
            .await
            .unwrap();

        // Cannot add a subnet that has a type assigned as an authorized subnet
        // and also cannot assign a type to a subnet that is already authorized.
        set_authorized_subnetwork_list_with_failure(
            &nns,
            None,
            vec![subnet_of_type1],
            format!(
                "Subnets {:?} are already assigned to a type and cannot be authorized",
                vec![subnet_of_type1]
            ),
        )
        .await;

        change_subnet_type_assignment_with_failure(
            &nns,
            type1.clone(),
            vec![authorized_subnet],
            format!(
                "The provided subnets {:?} are authorized for public access and cannot be assigned a type",
                vec![authorized_subnet]
            ),
        )
        .await;

        // Create canisters with sufficient funds on
        //  - an authorized subnet
        //  - a subnet with a specified type via subnet_type
        //  - a subnet with a specified type via subnet_selection
        //  - a specific authorized subnet
        //  - a specific subnet of another type
        // and confirm the canisters are created on the expected subnet on each case.
        info!(logger, "creating canisters");
        let initial_amount = Tokens::new(50, 0).unwrap();

        let canister_on_authorized_subnet = user1
            .create_canister_cmc(initial_amount, None, &controller_user, None, None)
            .await
            .unwrap();

        let canister_on_type1_subnet = user1
            .create_canister_cmc(
                initial_amount,
                None,
                &controller_user,
                Some(type1.clone()),
                None,
            )
            .await
            .unwrap();

        let canister_on_type1_subnet_2 = user1
            .create_canister_cmc(
                initial_amount,
                None,
                &controller_user,
                None,
                Some(SubnetSelection::Filter(SubnetFilter {
                    subnet_type: Some(type1),
                })),
            )
            .await
            .unwrap();

        let canister_on_specific_subnet_authorized = user1
            .create_canister_cmc(
                initial_amount,
                None,
                &controller_user,
                None,
                Some(SubnetSelection::Subnet {
                    subnet: authorized_subnet,
                }),
            )
            .await
            .unwrap();

        let canister_on_specific_subnet_type1 = user1
            .create_canister_cmc(
                initial_amount,
                None,
                &controller_user,
                None,
                Some(SubnetSelection::Subnet {
                    subnet: subnet_of_type1,
                }),
            )
            .await
            .unwrap();

        let node_on_authorized_subnet = topology
            .subnets()
            .find_map(|s| (s.subnet_id == authorized_subnet).then_some(s.nodes().next().unwrap()))
            .unwrap();
        let node_on_type1_subnet = topology
            .subnets()
            .find_map(|s| (s.subnet_id == subnet_of_type1).then_some(s.nodes().next().unwrap()))
            .unwrap();

        let authorized_runtime = runtime_from_url(
            node_on_authorized_subnet.get_public_url(),
            node_on_authorized_subnet.effective_canister_id(),
        );
        let type1_runtime = runtime_from_url(
            node_on_type1_subnet.get_public_url(),
            node_on_type1_subnet.effective_canister_id(),
        );

        let _status: CanisterStatusResultV2 = authorized_runtime
            .get_management_canister_with_effective_canister_id(
                canister_on_authorized_subnet.into(),
            )
            .update_from_sender(
                "canister_status",
                candid_one,
                CanisterIdRecord::from(canister_on_authorized_subnet),
                &Sender::from_keypair(&controller_user_keypair),
            )
            .await
            .unwrap();

        let _status: CanisterStatusResultV2 = type1_runtime
            .get_management_canister_with_effective_canister_id(canister_on_type1_subnet.into())
            .update_from_sender(
                "canister_status",
                candid_one,
                CanisterIdRecord::from(canister_on_type1_subnet),
                &Sender::from_keypair(&controller_user_keypair),
            )
            .await
            .unwrap();

        let _status: CanisterStatusResultV2 = type1_runtime
            .get_management_canister_with_effective_canister_id(canister_on_type1_subnet_2.into())
            .update_from_sender(
                "canister_status",
                candid_one,
                CanisterIdRecord::from(canister_on_type1_subnet_2),
                &Sender::from_keypair(&controller_user_keypair),
            )
            .await
            .unwrap();

        let _status: CanisterStatusResultV2 = authorized_runtime
            .get_management_canister_with_effective_canister_id(
                canister_on_specific_subnet_authorized.into(),
            )
            .update_from_sender(
                "canister_status",
                candid_one,
                CanisterIdRecord::from(canister_on_specific_subnet_authorized),
                &Sender::from_keypair(&controller_user_keypair),
            )
            .await
            .unwrap();

        let _status: CanisterStatusResultV2 = type1_runtime
            .get_management_canister_with_effective_canister_id(
                canister_on_specific_subnet_type1.into(),
            )
            .update_from_sender(
                "canister_status",
                candid_one,
                CanisterIdRecord::from(canister_on_specific_subnet_type1),
                &Sender::from_keypair(&controller_user_keypair),
            )
            .await
            .unwrap();
    });
}
