use std::time::Duration;

use futures::future::join_all;
use anyhow::Result;
use slog::Logger;
use tokio::runtime::{Builder, Runtime};

use ic_consensus_system_test_upgrade_common::{
    bless_branch_version, get_chain_key_canister_and_public_key, upgrade,
};
use ic_consensus_system_test_utils::rw_message::{
    can_read_msg_with_retries, install_nns_and_check_progress,
};
use ic_consensus_threshold_sig_system_test_utils::{
    make_key_ids_for_all_schemes, ChainSignatureRequest,
};
use ic_registry_subnet_features::{ChainKeyConfig, KeyConfig, DEFAULT_ECDSA_MAX_QUEUE_SIZE};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::canister_agent::HasCanisterAgentCapability;
use ic_system_test_driver::generic_workload_engine::engine::Engine;
use ic_system_test_driver::canister_requests;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::generic_workload_engine::metrics::{LoadTestMetricsProvider, RequestOutcome};
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    read_dependency_to_string, GetFirstHealthyNodeSnapshot, HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, SubnetSnapshot
};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::{block_on, get_app_subnet_and_node, MessageCanister};
use ic_types::Height;

const SCHNORR_MSG_SIZE_BYTES: usize = 32;
const DKG_INTERVAL: u64 = 9;
const ALLOWED_FAILURES: usize = 1;
const SUBNET_SIZE: usize = 3 * ALLOWED_FAILURES + 1; // 4 nodes
const UP_DOWNGRADE_OVERALL_TIMEOUT: Duration = Duration::from_secs(25 * 60);
const UP_DOWNGRADE_PER_TEST_TIMEOUT: Duration = Duration::from_secs(20 * 60);
const REQUESTS_DISPATCH_EXTRA_TIMEOUT: Duration = Duration::from_secs(1);

fn setup(env: TestEnv) {
    let subnet_under_test = Subnet::new(SubnetType::Application)
        .add_nodes(SUBNET_SIZE)
        .with_dkg_interval_length(Height::from(DKG_INTERVAL))
        .with_chain_key_config(ChainKeyConfig {
            key_configs: make_key_ids_for_all_schemes()
                .into_iter()
                .map(|key_id| KeyConfig {
                    max_queue_size: DEFAULT_ECDSA_MAX_QUEUE_SIZE,
                    pre_signatures_to_create_in_advance: 5,
                    key_id,
                })
                .collect(),
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: None,
        });

    InternetComputer::new()
        .with_mainnet_config()
        .add_subnet(Subnet::fast_single_node(SubnetType::System))
        .add_subnet(subnet_under_test)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    install_nns_and_check_progress(env.topology_snapshot());
}

// Tests an upgrade of the app subnet to the branch version and a downgrade back to the mainnet version
fn upgrade_downgrade_app_subnet(env: TestEnv) {
    let nns_node = env.get_first_healthy_system_node_snapshot();
    let branch_version = bless_branch_version(&env, &nns_node);
    let agent = nns_node.with_default_agent(|agent| async move { agent });
    let key_ids = make_key_ids_for_all_schemes();
    get_chain_key_canister_and_public_key(
        &env,
        &nns_node,
        &agent,
        SubnetType::Application,
        key_ids.clone(),
    );

    let logger = env.logger();
    let (app_subnet, app_node) = get_app_subnet_and_node(&env.topology_snapshot());
    let app_agent = app_node.with_default_agent(|agent| async move { agent });

    let principal = block_on(MessageCanister::new_with_cycles(
        &app_agent,
        app_node.effective_canister_id(),
        u128::MAX,
    ))
    .canister_id();

    let requests = key_ids
        .iter()
        .map(|key_id| ChainSignatureRequest::new(principal, key_id.clone(), SCHNORR_MSG_SIZE_BYTES))
        .collect::<Vec<_>>();

    let rt: Runtime = Builder::new_multi_thread()
        .worker_threads(16)
        .max_blocking_threads(16)
        .enable_all()
        .build()
        .unwrap();

    rt.spawn(start_workload(app_subnet, requests, logger));

    let (faulty_node, can_id, msg) = upgrade(
        &env,
        &nns_node,
        &branch_version,
        SubnetType::Application,
        None,
    );
    let mainnet_version = read_dependency_to_string("testnet/mainnet_nns_revision.txt").unwrap();
    upgrade(
        &env,
        &nns_node,
        &mainnet_version,
        SubnetType::Application,
        None,
    );
    // Make sure we can still read the message stored before the first upgrade
    assert!(can_read_msg_with_retries(
        &env.logger(),
        &faulty_node.get_public_url(),
        can_id,
        &msg,
        /*retries=*/ 3
    ));
}

async fn start_workload(subnet: SubnetSnapshot, requests: Vec<ChainSignatureRequest>, log: Logger) {
    let agents = join_all(
        subnet
        .nodes()
        .map(|n| async move { n.build_canister_agent().await }),
        )
        .await;

    let generator = move |idx: usize| {
        let request = requests[idx % requests.len()].clone();
        let agent = agents[idx % agents.len()].clone();
        async move {
            let request_outcome = canister_requests![
                idx,
                1 * agent => request,
            ];
            request_outcome.into_test_outcome()
        }
    };

    Engine::new(log.clone(), generator, 4.0, UP_DOWNGRADE_OVERALL_TIMEOUT)
        .increase_dispatch_timeout(REQUESTS_DISPATCH_EXTRA_TIMEOUT)
        .execute_simply(log.clone())
        .await;
}



fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_overall_timeout(UP_DOWNGRADE_OVERALL_TIMEOUT)
        .with_timeout_per_test(UP_DOWNGRADE_PER_TEST_TIMEOUT)
        .with_setup(setup)
        .add_test(systest!(upgrade_downgrade_app_subnet))
        .execute_from_args()?;
    Ok(())
}
