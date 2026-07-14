/* tag::catalog[]
Title:: Delete Subnet

Goal:: Ensure that governance can delete non-System subnets (CloudEngine, Application, and
VerifiedApplication subnets), and that System subnets cannot be deleted.

end::catalog[] */

use anyhow::Result;
use candid::{Decode, Encode};
use ic_consensus_system_test_utils::node::assert_node_is_unassigned;
use ic_nns_constants::REGISTRY_CANISTER_ID;
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, IcNodeSnapshot,
    install_registry_canister_with_testnet_topology,
};
use ic_system_test_driver::nns::get_subnet_list_from_registry;
use ic_system_test_driver::systest;
use ic_system_test_driver::util::{UniversalCanister, assert_create_agent, block_on};
use ic_types::{Height, RegistryVersion, SubnetId};
use registry_canister::init::RegistryCanisterInitPayloadBuilder;
use registry_canister::mutations::do_delete_subnet::DeleteSubnetPayload;
use std::collections::BTreeSet;
use std::time::Duration;

const NUM_NODES: usize = 1;
const NUM_ENGINE_NODES: usize = 4;
const DKG_INTERVAL_LENGTH: u64 = 29;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .add_unallowed_log_pattern_except(
            "panicked",
            "rs/consensus/src/consensus/allowed_panics.rs",
        )
        .execute_from_args()?;
    Ok(())
}

pub fn setup(env: TestEnv) {
    InternetComputer::new()
        .with_api_boundary_nodes_playnet(1)
        .add_subnet(
            Subnet::fast(SubnetType::System, NUM_NODES)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL_LENGTH)),
        )
        .add_subnet(
            Subnet::fast(SubnetType::Application, NUM_NODES)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL_LENGTH)),
        )
        .add_subnet(
            Subnet::fast(SubnetType::VerifiedApplication, NUM_NODES)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL_LENGTH)),
        )
        .add_subnet(
            Subnet::fast(SubnetType::CloudEngine, NUM_ENGINE_NODES)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL_LENGTH)),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
}

pub fn test(env: TestEnv) {
    install_registry_canister_with_testnet_topology(
        &env,
        None::<fn(&mut RegistryCanisterInitPayloadBuilder)>,
    );

    let topology_snapshot = &env.topology_snapshot();
    let nns_subnet = topology_snapshot.root_subnet();
    let nns_node = nns_subnet.nodes().next().unwrap();
    let app_subnet = topology_snapshot
        .subnets()
        .filter(|s| s.subnet_type() == SubnetType::Application)
        .collect::<Vec<_>>();
    let app_subnet = app_subnet.first().unwrap();
    let app_nodes: Vec<IcNodeSnapshot> = app_subnet.nodes().collect();
    let app_node = app_nodes
        .first()
        .expect("expected the Application subnet to have at least one node");
    let app_node_ids = BTreeSet::from_iter(app_nodes.iter().map(|x| x.node_id));
    let vapp_subnet = topology_snapshot
        .subnets()
        .filter(|s| s.subnet_type() == SubnetType::VerifiedApplication)
        .collect::<Vec<_>>();
    let vapp_subnet = vapp_subnet.first().unwrap();
    let vapp_node_ids = BTreeSet::from_iter(vapp_subnet.nodes().map(|x| x.node_id));
    let engine_subnet = topology_snapshot
        .subnets()
        .filter(|s| s.subnet_type() == SubnetType::CloudEngine)
        .collect::<Vec<_>>();
    let engine_subnet = engine_subnet.first().unwrap();
    let engine_nodes: Vec<IcNodeSnapshot> = engine_subnet.nodes().collect();
    let engine_node = engine_nodes
        .first()
        .expect("expected the CloudEngine subnet to have at least one node");
    let engine_node_ids = BTreeSet::from_iter(engine_nodes.iter().map(|x| x.node_id));
    assert!(
        topology_snapshot
            .unassigned_nodes()
            .collect::<Vec<_>>()
            .is_empty()
    );

    let registry_client = RegistryCanister::new_with_query_timeout(
        vec![nns_node.get_public_url()],
        Duration::from_secs(10),
    );

    block_on(async move {
        let nns_agent = assert_create_agent(nns_node.get_public_url().as_str()).await;
        let engine_agent = assert_create_agent(engine_node.get_public_url().as_str()).await;
        let app_agent = assert_create_agent(app_node.get_public_url().as_str()).await;
        let original_subnets = get_subnet_list_from_registry(&registry_client).await;
        assert_eq!(original_subnets.len(), 4);

        // Install a universal canister with the governance canister's canister ID
        let governance_canister =
            UniversalCanister::new(&nns_agent, nns_node.effective_canister_id()).await;

        // Install a canister each on the engine subnet and on the app subnet.
        let _canister_eng =
            UniversalCanister::new(&engine_agent, engine_node.effective_canister_id()).await;
        let _canister_app =
            UniversalCanister::new(&app_agent, app_node.effective_canister_id()).await;

        // Governance may delete any non-System subnet.

        // Deleting the CloudEngine subnet should work.
        try_delete_subnet(&engine_subnet.subnet_id, &governance_canister, None).await;

        // Deleting the Application subnet should work.
        try_delete_subnet(&app_subnet.subnet_id, &governance_canister, None).await;

        // Deleting the VerifiedApplication subnet should work.
        try_delete_subnet(&vapp_subnet.subnet_id, &governance_canister, None).await;

        // Deleting the System subnet should not work.
        try_delete_subnet(
            &nns_subnet.subnet_id,
            &governance_canister,
            Some("System subnets may not be deleted".to_string()),
        )
        .await;

        // Wait until the local registry reflects all three subnet deletions.
        let latest_version = registry_client
            .get_latest_version()
            .await
            .expect("failed to get the latest registry version");
        let new_topology_snapshot = topology_snapshot
            .block_for_min_registry_version(RegistryVersion::new(latest_version))
            .await
            .expect("Could not obtain updated registry.");

        // The deleted subnets should no longer be in the subnet list; only the
        // System (NNS) subnet should remain.
        let final_subnets = get_subnet_list_from_registry(&registry_client).await;
        assert_eq!(final_subnets, vec![nns_subnet.subnet_id]);

        // The subnet records and routing table entries of the deleted subnets should be gone.
        for deleted_subnet_id in [
            engine_subnet.subnet_id,
            app_subnet.subnet_id,
            vapp_subnet.subnet_id,
        ] {
            assert!(
                new_topology_snapshot
                    .subnet_canister_ranges(deleted_subnet_id)
                    .is_empty()
            );
        }

        // The nodes from the deleted subnets should be unassigned.
        let expected_unassigned_node_ids: BTreeSet<_> = engine_node_ids
            .iter()
            .chain(app_node_ids.iter())
            .chain(vapp_node_ids.iter())
            .copied()
            .collect();
        let unassigned_node_ids = new_topology_snapshot
            .unassigned_nodes()
            .map(|x| x.node_id)
            .collect::<BTreeSet<_>>();
        assert_eq!(unassigned_node_ids, expected_unassigned_node_ids);

        // The nodes' states should be wiped.
        for node in new_topology_snapshot.unassigned_nodes() {
            assert_node_is_unassigned(&node, &env.logger());
        }
    });
}

/// Attempt to delete the given subnet. Expect it to fail with the given error message if given, or
/// to succeed if None.
async fn try_delete_subnet<'a>(
    subnet_id: &SubnetId,
    governance_canister: &UniversalCanister<'a>,
    expected_error: Option<String>,
) {
    let arg = DeleteSubnetPayload {
        subnet_id: subnet_id.get().into(),
    };
    let result_bytes = governance_canister
        .forward_to(
            &REGISTRY_CANISTER_ID.get().0,
            "delete_subnet",
            Encode!(&arg).unwrap(),
        )
        .await
        .unwrap();
    if let Some(expected_err) = expected_error {
        let err_str = Decode!(&result_bytes, Result<(), String>)
            .unwrap()
            .unwrap_err();
        assert!(err_str.contains(&expected_err));
    } else {
        Decode!(&result_bytes, Result<(), String>).unwrap().unwrap();
    }
}
