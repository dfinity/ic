use crate::canister_agent::HasCanisterAgentCapability;
use crate::canister_api::{CallMode, GenericRequest};
use crate::canister_requests;
use crate::driver::{
    farm::HostFeature,
    ic::{AmountOfMemoryKiB, ImageSizeGiB, InternetComputer, NrOfVCPUs, Subnet, VmResources},
    prometheus_vm::{HasPrometheus, PrometheusVm},
    test_env::TestEnv,
    test_env_api::{
        HasTopologySnapshot, IcNodeContainer, NnsCanisterWasmStrategy, NnsCustomizations,
    },
};
use crate::generic_workload_engine::engine::Engine;
use crate::generic_workload_engine::metrics::{LoadTestMetricsProvider, RequestOutcome};
use crate::nns_dapp::set_authorized_subnets;
use crate::orchestrator::utils::rw_message::install_nns_with_customizations_and_check_progress;
use crate::util::{assert_canister_counter_with_retries, block_on};
use crate::workload_counter_canister_test::install_counter_canister;

use futures::future::join_all;
use ic_registry_subnet_type::SubnetType;
use ic_types::Height;
use slog::info;
use std::time::Duration;

const NODES_COUNT: usize = 25;
const MAX_RETRIES: u32 = 10;
const RETRY_WAIT: Duration = Duration::from_secs(10);
const SUCCESS_THRESHOLD: f32 = 0.33; // If more than 33% of the expected calls are successful the test passes
const REQUESTS_DISPATCH_EXTRA_TIMEOUT: Duration = Duration::from_secs(1);
const TESTING_PERIOD: Duration = Duration::from_secs(300);
const DKG_INTERVAL: u64 = 999;

pub fn setup(env: TestEnv) {
    PrometheusVm::default()
        .with_required_host_features(vec![HostFeature::Performance])
        .start(&env)
        .expect("Failed to start prometheus VM");
    InternetComputer::new()
        .with_required_host_features(vec![HostFeature::Performance])
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_default_vm_resources(VmResources {
                    vcpus: Some(NrOfVCPUs::new(64)),
                    memory_kibibytes: Some(AmountOfMemoryKiB::new(512142680)),
                    boot_image_minimal_size_gibibytes: Some(ImageSizeGiB::new(500)),
                })
                .add_nodes(1),
        )
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_default_vm_resources(VmResources {
                    vcpus: Some(NrOfVCPUs::new(64)),
                    memory_kibibytes: Some(AmountOfMemoryKiB::new(512142680)),
                    boot_image_minimal_size_gibibytes: Some(ImageSizeGiB::new(500)),
                })
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .add_nodes(NODES_COUNT),
        )
        .setup_and_start(&env)
        .expect("Failed to setup IC under test");
    install_nns_with_customizations_and_check_progress(
        env.topology_snapshot(),
        NnsCanisterWasmStrategy::TakeBuiltFromSources,
        NnsCustomizations::default(),
    );
    set_authorized_subnets(&env);
    env.sync_prometheus_config_with_topology();
}

pub fn test_small_messages(env: TestEnv) {
    test(env, 12, 1000)
}

pub fn test_large_messages(env: TestEnv) {
    test(env, 300000, 20)
}

pub fn custom_message_test(env: TestEnv) {
    test(env, 6000, 1000)
}

fn test(env: TestEnv, message_size: usize, rps: usize) {
    let log = env.logger();

    let canister_count: usize = 2;
    let duration: Duration = TESTING_PERIOD;

    let app_node = env
        .topology_snapshot()
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .unwrap()
        .nodes()
        .next()
        .unwrap();

    block_on(async move {
        info!(
            log,
            "Step 1: Install {} canisters on the subnet..", canister_count
        );
        let mut canisters = Vec::new();
        let agent = app_node.build_canister_agent().await;

        let agents = join_all(
            env.topology_snapshot()
                .subnets()
                .find(|s| s.subnet_type() == SubnetType::Application)
                .unwrap()
                .nodes()
                .map(|n| async move { n.build_canister_agent().await }),
        )
        .await;

        for _ in 0..canister_count {
            canisters.push(
                install_counter_canister(&agent.get(), app_node.effective_canister_id()).await,
            );
        }
        info!(log, "{} canisters installed successfully.", canisters.len());
        assert_eq!(
            canisters.len(),
            canister_count,
            "Not all canisters deployed successfully, installed {:?} expected {:?}",
            canisters.len(),
            canister_count
        );
        info!(log, "Step 2: Instantiate and start the workload..");
        let payload: Vec<u8> = vec![0; message_size];
        let generator = {
            let (agents, canisters, payload) = (agents.clone(), canisters.clone(), payload.clone());
            move |idx: usize| {
                let (agents, canisters, payload) =
                    (agents.clone(), canisters.clone(), payload.clone());
                async move {
                    let (agents, canisters, payload) =
                        (agents.clone(), canisters.clone(), payload.clone());
                    let request_outcome = canister_requests![
                        idx,
                        1 * agents[idx%agents.len()] => GenericRequest::new(canisters[0], "write".to_string(), payload.clone(), CallMode::Update),
                        1 * agents[idx%agents.len()] => GenericRequest::new(canisters[1], "write".to_string(), payload.clone(), CallMode::Update),
                    ];
                    request_outcome.into_test_outcome()
                }
            }
        };
        let metrics = Engine::new(log.clone(), generator, rps, duration)
            .increase_dispatch_timeout(REQUESTS_DISPATCH_EXTRA_TIMEOUT)
            .execute_simply(log.clone())
            .await;
        info!(log, "Reporting workload execution results ...");
        env.emit_report(format!("{}", metrics));
        info!(
            log,
            "Step 3: Assert expected number of success update calls on each canister.."
        );
        let requests_count = rps * duration.as_secs() as usize;
        let min_expected_success_calls = (SUCCESS_THRESHOLD * requests_count as f32) as usize;
        info!(
            log,
            "Minimal expected number of success calls {}", min_expected_success_calls,
        );
        info!(
            log,
            "Number of success calls {}, failure calls {}",
            metrics.success_calls(),
            metrics.failure_calls()
        );

        let min_expected_canister_counter = min_expected_success_calls / canister_count;
        info!(
            log,
            "Minimal expected counter value on canisters {}", min_expected_canister_counter
        );
        for canister in canisters.iter() {
            assert_canister_counter_with_retries(
                &log,
                &agent.get(),
                canister,
                payload.clone(),
                min_expected_canister_counter,
                MAX_RETRIES,
                RETRY_WAIT,
            )
            .await;
        }
    });
}
