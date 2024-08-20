use std::net::{Ipv6Addr, SocketAddrV6};
use std::time::{Duration, Instant};

use crate::boundary_nodes::{constants::BOUNDARY_NODE_NAME, helpers::BoundaryNodeHttpsConfig};
use anyhow::anyhow;
use anyhow::Context;
use candid::Principal;
use ic_protobuf::registry::routing_table::v1::RoutingTable as PbRoutingTable;
use ic_registry_keys::make_routing_table_record_key;
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_registry_routing_table::RoutingTable;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::canister_agent::CanisterAgent;
use ic_system_test_driver::driver::farm::HostFeature;
use ic_system_test_driver::driver::ic::{AmountOfMemoryKiB, ImageSizeGiB, NrOfVCPUs, VmResources};
use ic_system_test_driver::generic_workload_engine::engine::Engine;
use ic_system_test_driver::generic_workload_engine::metrics::LoadTestMetrics;
use ic_system_test_driver::generic_workload_engine::metrics::RequestOutcome;
use ic_system_test_driver::util::{block_on, create_agent_mapping};
use ic_system_test_driver::{
    canister_api::{CallMode, GenericRequest},
    driver::{
        boundary_node::{BoundaryNode, BoundaryNodeVm},
        ic::{InternetComputer, Subnet},
        prometheus_vm::{HasPrometheus, PrometheusVm},
        test_env::TestEnv,
        test_env_api::{
            HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, NnsInstallationBuilder,
            RetrieveIpv4Addr, READY_WAIT_TIMEOUT, RETRY_BACKOFF,
        },
    },
    util::spawn_round_robin_workload_engine,
};
use prost::Message;
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::thread_rng;
use rand::Rng;
use rand::RngCore;
use rand::SeedableRng;
use slog::info;
use tokio::runtime::{Builder, Runtime};

const COUNTER_CANISTER_WAT: &str = "rs/tests/src/counter.wat";
// Size of the payload sent to the counter canister in update("write") call.
const PAYLOAD_SIZE_BYTES: usize = 1024;
// Parameters related to workload creation.
const REQUESTS_DISPATCH_EXTRA_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_RUNTIME_THREADS: usize = 64;
const MAX_RUNTIME_BLOCKING_THREADS: usize = MAX_RUNTIME_THREADS;

pub fn setup(bn_https_config: BoundaryNodeHttpsConfig, env: TestEnv) {
    let logger = env.logger();
    PrometheusVm::default()
        .with_required_host_features(vec![HostFeature::Performance])
        .start(&env)
        .expect("failed to start prometheus VM");
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
    let bn = BoundaryNode::new(String::from(BOUNDARY_NODE_NAME))
        .with_required_host_features(vec![HostFeature::Performance])
        .with_vm_resources(VmResources {
            // We actually use 15 vCPUs in prod, but Farm complains about CPU topology when this number is not 2^N.
            vcpus: Some(NrOfVCPUs::new(16)),
            memory_kibibytes: Some(AmountOfMemoryKiB::new(16777216)),
            boot_image_minimal_size_gibibytes: None,
        })
        .allocate_vm(&env)
        .unwrap()
        .for_ic(&env, "");
    let bn = match bn_https_config {
        BoundaryNodeHttpsConfig::UseRealCertsAndDns => bn.use_real_certs_and_dns(),
        BoundaryNodeHttpsConfig::AcceptInvalidCertsAndResolveClientSide => bn,
    };
    bn.start(&env).expect("failed to setup BoundaryNode VM");
    // Await Replicas
    info!(&logger, "Checking readiness of all replica nodes...");
    for subnet in env.topology_snapshot().subnets() {
        for node in subnet.nodes() {
            node.await_status_is_healthy()
                .expect("Replica did not come up healthy.");
        }
    }
    info!(&logger, "Polling registry");
    let registry = RegistryCanister::new(bn.nns_node_urls);
    let (latest, routes) = block_on(ic_system_test_driver::retry_with_msg_async!(
        "polling registry",
        &logger,
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
        || async {
            let (bytes, latest) = registry.get_value(make_routing_table_record_key().into(), None).await
                .context("Failed to `get_value` from registry")?;
            let routes = PbRoutingTable::decode(bytes.as_slice())
                .context("Failed to decode registry routes")?;
            let routes = RoutingTable::try_from(routes)
                .context("Failed to convert registry routes")?;
            Ok((latest, routes))
        }
    ))
    .expect("Failed to poll registry. This is not a Boundary Node error. It is a test environment issue.");
    info!(&logger, "Latest registry {latest}: {routes:?}");
    // Await Boundary Node
    let boundary_node = env
        .get_deployed_boundary_node(BOUNDARY_NODE_NAME)
        .unwrap()
        .get_snapshot()
        .unwrap();
    info!(
        &logger,
        "Boundary node {BOUNDARY_NODE_NAME} has IPv6 {:?}",
        boundary_node.ipv6()
    );
    info!(
        &logger,
        "Boundary node {BOUNDARY_NODE_NAME} has IPv4 {:?}",
        boundary_node.block_on_ipv4().unwrap()
    );
    info!(&logger, "Checking BN health");
    boundary_node
        .await_status_is_healthy()
        .expect("Boundary node did not come up healthy.");
    env.sync_with_prometheus();
}

// Execute update calls (without polling) with an increasing req/s rate, against a counter canister via the boundary node agent.
// At the moment 300 req/s is the maximum defined by the rate limiter in 000-nginx-global.conf

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
    let bn_agent = {
        let boundary_node = env
            .get_deployed_boundary_node(BOUNDARY_NODE_NAME)
            .unwrap()
            .get_snapshot()
            .unwrap();
        boundary_node.build_default_agent()
    };
    let payload: Vec<u8> = vec![0; PAYLOAD_SIZE_BYTES];
    for rps in (rps_min..=rps_max).rev().step_by(rps_step) {
        let agent = bn_agent.clone();
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
// In order to observe rates>1 req/s on the replica, caching should be disabled in 002-mainnet-nginx.conf

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
    let bn_agent = {
        let boundary_node = env
            .get_deployed_boundary_node(BOUNDARY_NODE_NAME)
            .unwrap()
            .get_snapshot()
            .unwrap();
        boundary_node.build_default_agent()
    };
    let payload: Vec<u8> = vec![0; PAYLOAD_SIZE_BYTES];
    for rps in (rps_min..=rps_max).rev().step_by(rps_step) {
        let agent = bn_agent.clone();
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

pub fn mainnet_query_calls_icx_proxy_test(env: TestEnv, bn_ipv6: Ipv6Addr) {
    const ROOT_HOST: &str = "icp0.io";
    const MAINNET_STREAMING_CANISTER_ID: &str = "4evdk-jqaaa-aaaan-qel6q-cai";
    const MAINNET_COUNTER_CANISTER_ID: &str = "3muos-6yaaa-aaaaa-qaaua-cai";
    let streaming_canister_host = format!("{MAINNET_STREAMING_CANISTER_ID}.{ROOT_HOST}");

    const RPS_MIN: usize = 600;
    const RPS_MAX: usize = 1400;
    const RPS_STEP: usize = 200;
    const WORKLOAD_PER_STEP_DURATION: Duration = Duration::from_secs(60 * 5);

    const NUM_AGENTS: usize = 100;

    // The amount of traffic that will be directed to ICX Proxy, the remaining traffic will be direct canister query calls.
    const ICX_PROXY_TRAFFIC_PERCENTAGE: f64 = 20.0;
    // ICX Proxy traffic will be distributed among these requests according to their weights.
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

    let bn_addr = SocketAddrV6::new(bn_ipv6, 443, 0, 0).into();

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
                let prob = rng.gen::<f64>() * 100.0;

                let mut payload = [0u8; 8];
                rng.fill_bytes(&mut payload);
                let canister_request = GenericRequest::new(
                    counter_canister_principal,
                    "read".to_string(),
                    payload.to_vec(),
                    CallMode::Query,
                );

                if prob < ICX_PROXY_TRAFFIC_PERCENTAGE {
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
                        format!("GET@{}", http_request),
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
