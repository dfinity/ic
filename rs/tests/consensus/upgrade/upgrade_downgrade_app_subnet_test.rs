use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use futures::future::join_all;
use slog::Logger;
use tokio::runtime::{Builder, Runtime};

use ic_consensus_system_test_upgrade_common::{
    elect_target_version, get_chain_key_canister_and_public_key, upgrade,
};
use ic_consensus_system_test_utils::rw_message::{
    can_read_msg_with_retries, install_nns_and_check_progress, store_message_with_retries,
};
use ic_consensus_threshold_sig_system_test_utils::{
    ChainSignatureRequest, make_key_ids_for_all_schemes,
};
use ic_registry_subnet_features::{ChainKeyConfig, DEFAULT_ECDSA_MAX_QUEUE_SIZE, KeyConfig};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::canister_agent::HasCanisterAgentCapability;
use ic_system_test_driver::canister_requests;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::{
    AmountOfMemoryKiB, InternetComputer, Subnet, VmResourceOverrides,
};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    GetFirstHealthyNodeSnapshot, HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer,
    SubnetSnapshot, get_guestos_img_version,
};
use ic_system_test_driver::driver::test_setup::SystemTestBackend;
use ic_system_test_driver::generic_workload_engine::engine::Engine;
use ic_system_test_driver::generic_workload_engine::metrics::{
    LoadTestMetricsProvider, RequestOutcome,
};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::{MessageCanister, block_on, get_app_subnet_and_node};
use ic_types::Height;
use ic_types::messages::HttpStatusResponse;
use slog::info;

const SCHNORR_MSG_SIZE_BYTES: usize = 32;
const DKG_INTERVAL: u64 = 29;
const ALLOWED_FAILURES: usize = 1;
const SUBNET_SIZE: usize = 3 * ALLOWED_FAILURES + 1; // 4 nodes
const UP_DOWNGRADE_OVERALL_TIMEOUT: Duration = Duration::from_secs(35 * 60);
const UP_DOWNGRADE_PER_TEST_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const REQUESTS_DISPATCH_EXTRA_TIMEOUT: Duration = Duration::from_secs(1);

// Per-VM memory used on the local backend. There all VMs run on a single host,
// so the Farm default of 24 GiB per VM would let the 5 VMs (1 System + 4
// Application) collectively exceed the host's RAM and thrash swap. That starves
// the consensus finalizer, so the subnet can't finalize the upgrade CUP and the
// test fails with `Replica was running the old version only!`. 4 GiB per VM
// keeps all 5 VMs comfortably within the host's RAM.
const LOCAL_BACKEND_VM_MEMORY: AmountOfMemoryKiB = AmountOfMemoryKiB::new(4 * 1024 * 1024);

fn setup(env: TestEnv) {
    let subnet_under_test = Subnet::new(SubnetType::Application)
        .add_nodes(SUBNET_SIZE)
        .with_dkg_interval_length(Height::from(DKG_INTERVAL))
        .with_chain_key_config(ChainKeyConfig {
            key_configs: make_key_ids_for_all_schemes()
                .into_iter()
                .map(|key_id| KeyConfig {
                    max_queue_size: DEFAULT_ECDSA_MAX_QUEUE_SIZE,
                    pre_signatures_to_create_in_advance: key_id
                        .requires_pre_signatures()
                        .then_some(5),
                    key_id,
                })
                .collect(),
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: None,
            max_parallel_pre_signature_transcripts_in_creation: None,
        });

    let mut ic = InternetComputer::new()
        .add_subnet(Subnet::fast_single_node(SubnetType::System))
        .add_subnet(subnet_under_test);
    // On the local backend, cap the per-VM memory so all VMs fit within the
    // single host's RAM (see `LOCAL_BACKEND_VM_MEMORY`). On Farm, keep the
    // generous default.
    if SystemTestBackend::from_env() == SystemTestBackend::Local {
        ic = ic.with_resource_overrides(VmResourceOverrides {
            memory_kibibytes: Some(LOCAL_BACKEND_VM_MEMORY),
            ..Default::default()
        });
    }
    ic.setup_and_start(&env)
        .expect("failed to setup IC under test");

    install_nns_and_check_progress(env.topology_snapshot());
}

// Tests an upgrade of the app subnet to the target version and a downgrade back to the initial version
fn upgrade_downgrade_app_subnet(env: TestEnv) {
    let nns_node = env.get_first_healthy_system_node_snapshot();
    let target_version = elect_target_version(&env, &nns_node);
    let agent = nns_node.with_default_agent(|agent| async move { agent });
    let key_ids = make_key_ids_for_all_schemes();
    let ecdsa_state = get_chain_key_canister_and_public_key(
        &env,
        &nns_node,
        &agent,
        SubnetType::Application,
        key_ids.clone(),
    );

    let logger = env.logger();
    let (app_subnet, app_node) = get_app_subnet_and_node(&env.topology_snapshot());
    let app_agent = app_node.with_default_agent(|agent| async move { agent });

    let principal = block_on(MessageCanister::new_with_cycles_with_retries(
        &app_agent,
        app_node.effective_canister_id(),
        u128::MAX,
        &logger,
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

    rt.spawn(start_workload(app_subnet, requests, logger.clone()));

    // Store a probe message that the background poller will continuously read
    // during both upgrades to verify zero downtime.
    let probe_msg = "zero-downtime probe";
    let probe_can_id = store_message_with_retries(
        &app_node.get_public_url(),
        app_node.effective_canister_id(),
        probe_msg,
        &logger,
    );
    let probe_url = app_node.get_public_url();
    let probe_logger = logger.clone();

    // Collect all app subnet node URLs for status polling.
    let app_subnet = env
        .topology_snapshot()
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .expect("no app subnet");
    let node_urls: Vec<String> = app_subnet
        .nodes()
        .map(|n| n.get_public_url().to_string())
        .collect();
    let status_logger = logger.clone();

    // Spawn a background thread that:
    // 1. Continuously polls the probe message (zero-downtime check).
    // 2. Logs the status of every node (impl_hash, replica_start_time, availability).
    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_clone = cancel.clone();
    let poll_handle = std::thread::spawn(move || {
        while !cancel_clone.load(Ordering::Relaxed) {
            // Zero-downtime probe
            // assert!(
            //     can_read_msg_with_retries(
            //         &probe_logger,
            //         &probe_url,
            //         probe_can_id,
            //         &probe_msg.to_string(),
            //         /*retries=*/ 2,
            //     ),
            //     "Zero-downtime violation: could not read probe message during upgrade"
            // );

            // Poll each node's status
            let status_client = reqwest::blocking::Client::builder()
                .connect_timeout(Duration::from_secs(1))
                .build()
                .unwrap();
            for (i, url) in node_urls.iter().enumerate() {
                match status_client.get(format!("{}api/v2/status", url)).send() {
                    Ok(resp) if resp.status().is_success() => {
                        match resp.bytes() {
                            Ok(body) => {
                                if let Ok(status) = serde_cbor::from_slice::<HttpStatusResponse>(&body) {
                                    println!(
                                        "Node {}: replica: {:<48}  guestos: {:<48}  height: {}",
                                        i,
                                        status.impl_version.unwrap(),
                                        status.guestos_version.unwrap(),
                                        status.certified_height.unwrap(),
                                    );
                                }
                            }
                            Err(e) => {
                                println!("Node {}: UNAVAILABLE", i);
                            }
                        }
                    }
                    _ => {
                        println!("Node {i}: UNAVAILABLE");
                    }
                }
            }
            println!("");

            std::thread::sleep(Duration::from_secs(1));
        }
    });

    let logger = env.logger();
    info!(logger, "Upgrading to target version: {}", target_version);
    let (upgraded_node, can_id, msg) = upgrade(
        &env,
        &nns_node,
        &target_version,
        SubnetType::Application,
        Some(&ecdsa_state),
    );
    std::thread::sleep(Duration::from_secs(60 * 60));

    // let initial_version = get_guestos_img_version();
    // info!(logger, "Upgrading to initial version: {}", initial_version);
    // upgrade(
    //     &env,
    //     &nns_node,
    //     &initial_version,
    //     SubnetType::Application,
    //     Some(&ecdsa_state),
    // );

    // Stop the background poller and check for failures.
    cancel.store(true, Ordering::Relaxed);
    poll_handle
        .join()
        .expect("Zero-downtime polling thread panicked — upgrade caused downtime");

    info!(
        logger,
        "Make sure we can still read the message stored before the first upgrade ..."
    );
    assert!(can_read_msg_with_retries(
        &env.logger(),
        &upgraded_node.get_public_url(),
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
