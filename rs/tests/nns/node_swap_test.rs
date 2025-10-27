use std::time::Duration;

use anyhow::Result;
use candid::Encode;
use ic_canister_client::{Agent, Sender};
use ic_consensus_system_test_utils::rw_message::install_nns_with_customizations_and_check_progress;
use ic_nervous_system_common_test_keys::{TEST_USER1_KEYPAIR, TEST_USER1_PRINCIPAL};
use ic_nns_constants::REGISTRY_CANISTER_ID;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    HasTopologySnapshot, IcNodeContainer, NnsCustomizations,
};
use ic_system_test_driver::util::block_on;
use registry_canister::init::RegistryCanisterInitPayloadBuilder;
use registry_canister::mutations::do_swap_node_in_subnet_directly::SwapNodeInSubnetDirectlyPayload;

const OVERALL_TIMEOUT: Duration = Duration::from_secs(60 * 60);

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_timeout_per_test(OVERALL_TIMEOUT)
        .with_setup(setup)
        .add_test(ic_system_test_driver::driver::dsl::TestFunction::new(
            "node_swaps",
            test,
        ))
        .execute_from_args()
}

fn setup(env: TestEnv) {
    let caller = *TEST_USER1_PRINCIPAL;
    let mut ic = InternetComputer::new()
        .add_subnet(Subnet::new(ic_registry_subnet_type::SubnetType::System).add_nodes(3))
        .with_node_operator(caller)
        .with_node_provider(caller)
        .with_unassigned_nodes(1);

    ic.setup_and_start(&env)
        .expect("Failed to start IC under test");

    let snapshot = env.topology_snapshot();
    let subnet = snapshot.root_subnet();

    let customizations = NnsCustomizations {
        registry_canister_init_payload: RegistryCanisterInitPayloadBuilder::new()
            .enable_swapping_feature_globally()
            .enable_swapping_feature_for_subnet(subnet.subnet_id)
            .whitelist_swapping_feature_caller(caller)
            .build(),
        ..Default::default()
    };

    install_nns_with_customizations_and_check_progress(env.topology_snapshot(), customizations);
}

fn test(env: TestEnv) {
    let snapshot = env.topology_snapshot();

    let unassigned_node = snapshot.unassigned_nodes().next().unwrap();
    let subnet = snapshot.subnets().next().unwrap();
    let mut nodes_iter = subnet.nodes();

    let assigned_node = nodes_iter.next().unwrap();

    let payload = SwapNodeInSubnetDirectlyPayload {
        old_node_id: Some(assigned_node.node_id.get()),
        new_node_id: Some(unassigned_node.node_id.get()),
    };

    let next_nns_node = nodes_iter.next().unwrap();
    let url = format!("http://[{}]:8080", next_nns_node.get_ip_addr())
        .parse()
        .unwrap();
    let sender = Sender::from_keypair(&TEST_USER1_KEYPAIR.clone());
    let agent = Agent::new(url, sender);

    block_on(async move {
        agent.root_key().await.unwrap();

        let response = agent
            .execute_update(
                &REGISTRY_CANISTER_ID,
                &REGISTRY_CANISTER_ID,
                "swap_node_in_subnet_directly",
                Encode!(&payload).unwrap(),
                vec![],
            )
            .await;

        assert!(
            response.as_ref().is_ok(),
            "Expected the call to swap node in subnet directly to be ok but got: {response:?}"
        );

        snapshot.block_for_newer_registry_version().await.unwrap();

        let new_unassigned_node = snapshot.unassigned_nodes().next().unwrap();
        // Expect the new unassigned node to be the previously assigned one
        // which should happen if the canister didn't return any errors.
        assert_eq!(new_unassigned_node.node_id, assigned_node.node_id);

        // Expect the previously unassigned node to be a member of
        // a subnet it was directly swapped into.
        assert!(
            snapshot
                .subnets()
                .next()
                .unwrap()
                .nodes()
                .any(|node| node.node_id == unassigned_node.node_id)
        );
    });
}
