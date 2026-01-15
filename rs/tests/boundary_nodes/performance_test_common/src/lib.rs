use std::net::{Ipv6Addr, SocketAddrV6};
use std::time::{Duration, Instant};

use anyhow::anyhow;
use candid::Principal;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    canister_agent::CanisterAgent,
    canister_api::{CallMode, GenericRequest},
    driver::{
        farm::HostFeature,
        ic::{AmountOfMemoryKiB, ImageSizeGiB, InternetComputer, NrOfVCPUs, Subnet, VmResources},
        test_env::TestEnv,
        test_env_api::{
            HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, NnsInstallationBuilder,
        },
    },
    generic_workload_engine::{
        engine::Engine,
        metrics::{LoadTestMetrics, RequestOutcome},
    },
    util::{block_on, create_agent_mapping, spawn_round_robin_workload_engine},
};
use rand::Rng;
use rand::RngCore;
use rand::SeedableRng;
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::thread_rng;
use slog::info;
use tokio::runtime::{Builder, Runtime};

const COUNTER_CANISTER_WAT: &str = "rs/tests/counter.wat";
// Size of the payload sent to the counter canister in update("write") call.
const PAYLOAD_SIZE_BYTES: usize = 1024;
// Parameters related to workload creation.
const REQUESTS_DISPATCH_EXTRA_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_RUNTIME_THREADS: usize = 64;
const MAX_RUNTIME_BLOCKING_THREADS: usize = MAX_RUNTIME_THREADS;

pub fn setup(env: TestEnv) {
    InternetComputer::new()
        .with_required_host_features(vec![HostFeature::Performance])
        .add_subnet(Subnet::new(SubnetType::System).add_nodes(1))
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_default_vm_resources(VmResources {
                    vcpus: Some(NrOfVCPUs::new(64)),
                    memory_kibibytes: Some(AmountOfMemoryKiB::new(512_142_680)),
                    boot_image_minimal_size_gibibytes: Some(ImageSizeGiB::new(500)),
                })
                .add_nodes(1),
        )
        .with_api_boundary_nodes(1)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    let nns_node = env
        .topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .unwrap();
    NnsInstallationBuilder::new()
        .install(&nns_node, &env)
        .expect("Could not install NNS canisters");
}

// Execute update calls (without polling) with an increasing req/s rate, against a counter canister via the boundary node agent.
pub fn update_calls_test(env: TestEnv) {
    let rps_min = 50;
    let rps_max = 450;
    let rps_step = 50;
    let workload_per_step_duration = Duration::from_secs(60 * 4);
    let log: slog::Logger = env.logger();
    let subnet_app = env
        .topology_snapshot()
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .unwrap();
    let canister_app = subnet_app
        .nodes()
        .next()
        .unwrap()
        .create_and_install_canister_with_arg(COUNTER_CANISTER_WAT, None);

    let api_bn_agent = env
        .topology_snapshot()
        .api_boundary_nodes()
        .next()
        .expect("No API boundary node found")
        .build_default_agent();

    let payload: Vec<u8> = vec![0; PAYLOAD_SIZE_BYTES];
    for rps in (rps_min..=rps_max).rev().step_by(rps_step) {
        let agent = api_bn_agent.clone();
        info!(
            log,
            "Starting workload with rps={rps} for {} sec",
            workload_per_step_duration.as_secs()
        );
        let handle_workload = {
            let requests = vec![GenericRequest::new(
                canister_app,
                "write".to_string(),
                payload.clone(),
                CallMode::UpdateNoPolling,
            )];
            spawn_round_robin_workload_engine(
                log.clone(),
                requests,
                vec![agent.clone()],
                rps,
                workload_per_step_duration,
                REQUESTS_DISPATCH_EXTRA_TIMEOUT,
                vec![],
            )
        };
        let metrics = handle_workload.join().expect("Workload execution failed.");
        info!(&log, "Workload metrics for rps={rps}: {metrics}");
        info!(
            log,
            "Failed/successful requests count {}/{}",
            metrics.failure_calls(),
            metrics.success_calls()
        );
        let expected_requests_count = rps * workload_per_step_duration.as_secs() as usize;
        assert_eq!(metrics.success_calls(), expected_requests_count);
        assert_eq!(metrics.failure_calls(), 0);
    }
}

// Execute query calls with an increasing req/s rate, against a counter canister via the boundary node agent.
pub fn query_calls_test(env: TestEnv) {
    let rps_min = 500;
    let rps_max = 6500;
    let rps_step = 500;
    let workload_per_step_duration = Duration::from_secs(60 * 4);
    let log: slog::Logger = env.logger();
    let subnet_app = env
        .topology_snapshot()
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .unwrap();
    let canister_app = subnet_app
        .nodes()
        .next()
        .unwrap()
        .create_and_install_canister_with_arg(COUNTER_CANISTER_WAT, None);

    let api_bn_agent = env
        .topology_snapshot()
        .api_boundary_nodes()
        .next()
        .expect("No API boundary node found")
        .build_default_agent();

    let payload: Vec<u8> = vec![0; PAYLOAD_SIZE_BYTES];
    for rps in (rps_min..=rps_max).rev().step_by(rps_step) {
        let agent = api_bn_agent.clone();
        info!(
            log,
            "Starting workload with rps={rps} for {} sec",
            workload_per_step_duration.as_secs()
        );
        let handle_workload = {
            let requests = vec![GenericRequest::new(
                canister_app,
                "read".to_string(),
                payload.clone(),
                CallMode::Query,
            )];
            spawn_round_robin_workload_engine(
                log.clone(),
                requests,
                vec![agent.clone()],
                rps,
                workload_per_step_duration,
                REQUESTS_DISPATCH_EXTRA_TIMEOUT,
                vec![],
            )
        };
        let metrics = handle_workload.join().expect("Workload execution failed.");
        info!(&log, "Workload metrics for rps={rps}: {metrics}");
        info!(
            log,
            "Failed/successful requests count {}/{}",
            metrics.failure_calls(),
            metrics.success_calls()
        );
        let expected_requests_count = rps * workload_per_step_duration.as_secs() as usize;
        assert_eq!(metrics.success_calls(), expected_requests_count);
        assert_eq!(metrics.failure_calls(), 0);
    }
}

pub fn mainnet_query_calls_test(env: TestEnv, bn_ipv6: Ipv6Addr) {
    const DOMAIN_URL: &str = "https://testic0.app";
    // id of the counter-canister on the application subnet in mainnet
    const MAINNET_COUNTER_CANISTER_ID: &str = "3muos-6yaaa-aaaaa-qaaua-cai";
    let rps_min = 50;
    let rps_max = 150;
    let rps_step = 50;
    let workload_per_step_duration = Duration::from_secs(60);

    // Reuse this runtime for all async executions.
    let rt: Runtime = Builder::new_multi_thread()
        .worker_threads(MAX_RUNTIME_THREADS)
        .max_blocking_threads(MAX_RUNTIME_BLOCKING_THREADS)
        .enable_all()
        .build()
        .unwrap();
    let log: slog::Logger = env.logger();
    let canister_app = Principal::from_text(MAINNET_COUNTER_CANISTER_ID).unwrap();
    let bn_agent = block_on(async { create_agent_mapping(DOMAIN_URL, bn_ipv6.into()).await })
        .expect("failed to create an agent");
    let payload: Vec<u8> = vec![0; PAYLOAD_SIZE_BYTES];
    for rps in (rps_min..=rps_max).step_by(rps_step) {
        let agents = vec![bn_agent.clone()];
        info!(
            &log,
            "Starting workload with rps={rps} for {} sec",
            workload_per_step_duration.as_secs()
        );
        let requests = [GenericRequest::new(
            canister_app,
            "read".to_string(),
            payload.clone(),
            CallMode::Query,
        )];
        let agents: Vec<CanisterAgent> = agents.into_iter().map(CanisterAgent::from).collect();
        let generator = move |idx: usize| {
            // Round Robin distribution over both requests and agents.
            let request = requests[idx % requests.len()].clone();
            let agent = agents[idx % agents.len()].clone();
            async move {
                agent
                    .call(&request)
                    .await
                    .map(|_| ()) // drop non-error responses
                    .into_test_outcome()
            }
        };
        // Don't log intermediate metrics during workload execution.
        let log_null = slog::Logger::root(slog::Discard, slog::o!());
        let aggregator = LoadTestMetrics::new(log_null);
        let engine = Engine::new(
            log.clone(),
            generator,
            rps as f64,
            workload_per_step_duration,
        )
        .increase_dispatch_timeout(REQUESTS_DISPATCH_EXTRA_TIMEOUT);
        let metrics_result =
            rt.block_on(engine.execute(aggregator, LoadTestMetrics::aggregator_fn));
        match metrics_result {
            Ok(metrics) => {
                info!(&log, "Workload metrics for rps={rps}: {metrics}");
                info!(
                    &log,
                    "Failed/successful requests count {}/{}",
                    metrics.failure_calls(),
                    metrics.success_calls()
                );
            }
            Err(err) => {
                info!(&log, "Workload execution failed with err={:?}", err);
            }
        }
    }
}

pub fn mainnet_query_calls_ic_gateway_test(env: TestEnv, bn_ipv6: Ipv6Addr) {
    const ROOT_HOST: &str = "icp0.io";
    const MAINNET_STREAMING_CANISTER_ID: &str = "4evdk-jqaaa-aaaan-qel6q-cai";
    const MAINNET_COUNTER_CANISTER_ID: &str = "3muos-6yaaa-aaaaa-qaaua-cai";
    let streaming_canister_host = format!("{MAINNET_STREAMING_CANISTER_ID}.{ROOT_HOST}");

    const RPS_MIN: usize = 600;
    const RPS_MAX: usize = 1400;
    const RPS_STEP: usize = 200;
    const WORKLOAD_PER_STEP_DURATION: Duration = Duration::from_secs(60 * 5);

    const NUM_AGENTS: usize = 100;

    // The amount of traffic that will be HTTP, the remaining traffic will be direct canister query calls.
    const HTTP_TRAFFIC_PERCENTAGE: f64 = 20.0;
    // HTTP traffic will be distributed among these requests according to their weights.
    let weighted_http_requests = [
        (format!("https://{streaming_canister_host}/1mb.json"), 25),
        (format!("https://{streaming_canister_host}/2mb.json"), 30),
        (format!("https://{streaming_canister_host}/4mb.json"), 30),
        (format!("https://{streaming_canister_host}/8mb.json"), 15),
    ];

    // Reuse this runtime for all async executions.
    let rt: Runtime = Builder::new_multi_thread()
        .worker_threads(MAX_RUNTIME_THREADS)
        .max_blocking_threads(MAX_RUNTIME_BLOCKING_THREADS)
        .enable_all()
        .build()
        .unwrap();
    let logger = env.logger();

    let bn_addr = SocketAddrV6::new(bn_ipv6, 0, 0, 0).into();

    let mut http_clients = vec![];
    for _ in 0..NUM_AGENTS {
        let http_client_builder = reqwest::ClientBuilder::new();
        let http_client_builder = http_client_builder
            .danger_accept_invalid_certs(true)
            .resolve(&streaming_canister_host, bn_addr);
        let http_client = http_client_builder.build().unwrap();

        http_clients.push(http_client);
    }

    let counter_canister_principal = Principal::from_text(MAINNET_COUNTER_CANISTER_ID).unwrap();

    let canister_agents = block_on(async {
        let mut canister_agents = vec![];
        for _ in 0..NUM_AGENTS {
            canister_agents.push(CanisterAgent::from(
                create_agent_mapping(&format!("https://{ROOT_HOST}"), bn_ipv6.into())
                    .await
                    .expect("failed to create an agent"),
            ));
        }
        canister_agents
    });

    let mut rng = thread_rng();
    let http_requests = weighted_http_requests
        .choose_multiple_weighted(&mut rng, 100, |item| item.1)
        .unwrap()
        .map(|item| item.0.clone())
        .collect::<Vec<String>>();

    for rps in (RPS_MIN..=RPS_MAX).step_by(RPS_STEP) {
        let (http_requests, http_clients, canister_agents) = (
            http_requests.clone(),
            http_clients.clone(),
            canister_agents.clone(),
        );

        info!(
            &logger,
            "Starting workload with rps={rps} for {} sec",
            WORKLOAD_PER_STEP_DURATION.as_secs()
        );

        let generator = move |idx: usize| {
            // Round Robin distribution over both requests and agents.
            let http_request = http_requests[idx % http_requests.len()].clone();
            let http_client = http_clients[idx % http_clients.len()].clone();
            let canister_agent = canister_agents[idx % canister_agents.len()].clone();

            async move {
                let mut rng = StdRng::from_entropy();
                let prob = rng.r#gen::<f64>() * 100.0;

                let mut payload = [0u8; 8];
                rng.fill_bytes(&mut payload);
                let canister_request = GenericRequest::new(
                    counter_canister_principal,
                    "read".to_string(),
                    payload.to_vec(),
                    CallMode::Query,
                );

                if prob < HTTP_TRAFFIC_PERCENTAGE {
                    let start_time = Instant::now();

                    let result = http_client
                        .get(&http_request)
                        .send()
                        .await
                        .map_err(|err| anyhow!("HTTP request failed with err: {:?}", err))
                        .and_then(|response| {
                            if response.status().is_success()
                                || response.status().is_informational()
                            {
                                Ok(())
                            } else {
                                Err(anyhow!(
                                    "HTTP request failed with status code {}",
                                    response.status().as_str()
                                ))
                            }
                        });

                    RequestOutcome::new(
                        result,
                        format!("GET@{http_request}"),
                        start_time.elapsed(),
                        1,
                    )
                    .into_test_outcome()
                } else {
                    canister_agent
                        .call(&canister_request)
                        .await
                        .map(|_| ())
                        .into_test_outcome()
                }
            }
        };

        // Don't log intermediate metrics during workload execution.
        let log_null = slog::Logger::root(slog::Discard, slog::o!());
        let aggregator = LoadTestMetrics::new(log_null);
        let engine = Engine::new(
            logger.clone(),
            generator,
            rps as f64,
            WORKLOAD_PER_STEP_DURATION,
        )
        .increase_dispatch_timeout(REQUESTS_DISPATCH_EXTRA_TIMEOUT);
        let metrics_result =
            rt.block_on(engine.execute(aggregator, LoadTestMetrics::aggregator_fn));
        match metrics_result {
            Ok(metrics) => {
                info!(&logger, "Workload metrics for rps={rps}: {metrics}");
                info!(
                    &logger,
                    "Failed/successful requests count {}/{}",
                    metrics.failure_calls(),
                    metrics.success_calls()
                );
            }
            Err(err) => {
                info!(&logger, "Workload execution failed with err={:?}", err);
            }
        }
    }
}

pub fn empty_setup(_: TestEnv) {}
