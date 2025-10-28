use std::time::Duration;

use anyhow::Result;
use ic_consensus_system_test_utils::rw_message::install_nns_with_customizations_and_check_progress;
use ic_nervous_system_common_test_keys::{TEST_USER1_KEYPAIR, TEST_USER1_PRINCIPAL};
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    HasTopologySnapshot, IcNodeContainer, IcNodeSnapshot, NnsCustomizations,
};
use ic_system_test_driver::retry_with_msg_async;
use ic_system_test_driver::util::block_on;
use ic_types::{NodeId, SubnetId};
use registry_canister::init::RegistryCanisterInitPayloadBuilder;
use slog::{Logger, info};

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
    // Ensure that the variable is set so that the test panics early
    // if ic-admin isn't setup correctly.
    fetch_ic_admin_path();

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

fn fetch_ic_admin_path() -> String {
    std::env::var("IC_ADMIN_PATH").expect(
        "IC admin isn't present in the environment variables and is required for this test to run",
    )
}

fn test(env: TestEnv) {
    block_on(test_inner(env))
}

async fn test_inner(env: TestEnv) {
    let snapshot = env.topology_snapshot();

    let unassigned_node = snapshot.unassigned_nodes().next().unwrap();
    let subnet = snapshot.subnets().next().unwrap();
    let mut nodes_iter = subnet.nodes();

    let assigned_node = nodes_iter.next().unwrap();

    let next_nns_node = nodes_iter.next().unwrap();
    let url = format!("http://[{}]:8080", next_nns_node.get_ip_addr());
    ic_admin_swap_nodes(
        &url,
        &TEST_USER1_KEYPAIR.to_pem(),
        assigned_node.node_id,
        unassigned_node.node_id,
        &env,
    )
    .await
    .unwrap();

    snapshot.block_for_newer_registry_version().await.unwrap();

    let new_unassigned_node = snapshot.unassigned_nodes().next().unwrap();
    // Expect the new unassigned node to be the previously assigned one
    // which should happen if the canister didn't return any errors.
    assert_eq!(new_unassigned_node.node_id, assigned_node.node_id);

    // Expect the previously unassigned node to be a member of
    // a subnet it was directly swapped into.
    let new_node_in_subnet = snapshot
        .subnets()
        .next()
        .unwrap()
        .nodes()
        .find(|node| node.node_id == unassigned_node.node_id)
        .expect("Expected the unassigned node to become a member of a subnet");
    let subnet_id = subnet.subnet_id;

    retry_with_msg_async!(
        "Check that the node joined the subnt",
        &env.logger(),
        Duration::from_secs(600),
        Duration::from_secs(5),
        || async {
            ensure_node_in_subnet(new_node_in_subnet.clone(), subnet_id, env.logger()).await
        }
    )
    .await
    .unwrap()
}

async fn ensure_node_in_subnet(
    node: IcNodeSnapshot,
    subnet_id: SubnetId,
    logger: Logger,
) -> Result<()> {
    let dashboard_url = format!("http://[{}]:7070", node.get_ip_addr());
    info!(
        logger,
        "Will fetch information about the node from the dashboard at: {dashboard_url}"
    );

    let response = reqwest::get(dashboard_url)
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    let prefix = "subnet id: ";

    let subnet_from_dashboard = response
        .lines()
        .find(|l| l.starts_with(prefix))
        .map(|s| s.strip_prefix(prefix).unwrap())
        .unwrap()
        .trim();

    if subnet_from_dashboard != subnet_id.to_string() {
        return Err(anyhow::anyhow!(
            "Expected subnet to be {subnet_id} but got: {subnet_from_dashboard}"
        ));
    }

    Ok(())
}

async fn ic_admin_swap_nodes(
    nns_url: &str,
    key_content: &str,
    old_node: NodeId,
    new_node: NodeId,
    env: &TestEnv,
) -> Result<()> {
    let logger = env.logger();
    let ic_admin_bin_path = fetch_ic_admin_path();

    info!(logger, "IC admin path: {ic_admin_bin_path}");

    let key_path = env.get_path("test_operator_key.pem");
    info!(logger, "Storing key contents to: {}", key_path.display());

    std::fs::write(&key_path, key_content).map_err(anyhow::Error::from)?;

    let args: Vec<_> = [
        "--nns-urls",
        nns_url,
        "--secret-key-pem",
        &key_path.display().to_string(),
        "swap-node-in-subnet-directly",
        "--old-node-id",
        &old_node.get().to_string(),
        "--new-node-id",
        &new_node.get().to_string(),
    ]
    .into_iter()
    .map(|a| a.to_string())
    .collect();

    info!(
        logger,
        "Running the following command with ic-admin: {ic_admin_bin_path} {}",
        args.join(" ")
    );

    let result = tokio::process::Command::new(ic_admin_bin_path)
        .args(args)
        .status()
        .await
        .map_err(anyhow::Error::from)?;

    if !result.success() {
        return Err(anyhow::anyhow!(
            "ic-admin call failed with exit code: {:?}",
            result.code()
        ));
    }

    Ok(())
}
