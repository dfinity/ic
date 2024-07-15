/* tag::catalog[]

Title:: Subnet handles update workloads.

Goal:: Ensure IC responds to update calls of a given size in a timely manner.

Runbook::
0. Instantiate an IC with one System and one Application subnet.
   - Optionally install one boundary node.
1. Install NNS canisters on the System subnet.
2. Build and install counter canister on each subnet.
3. Instantiate and simultaneously start two workloads (one per subnet).
   Workloads send update[canister_id, "write"] requests.
   If the boundary node option is used, all requests are dispatched to the subnets via the boundary node,
   otherwise requests are directly dispatched to all the nodes of the subnets in a round-robin fashion.
4. Collect metrics from both workloads and assert:
   - Ratio of requests with duration below DURATION_THRESHOLD should exceed MIN_REQUESTS_RATIO_BELOW_THRESHOLD.
   - Ratio of successful requests should exceed the min_success_ratio threshold.
5. Perform assertions on the counter canisters (via query `read` call)
   - Counter value on the canister should exceed the threshold = min_success_ratio * total_requests_count.

end::catalog[] */

use ic_system_test_driver::{
    canister_api::{CallMode, GenericRequest},
    driver::{
        boundary_node::{BoundaryNode, BoundaryNodeVm},
        ic::{ImageSizeGiB, InternetComputer, NrOfVCPUs, Subnet, VmResources},
        prometheus_vm::{HasPrometheus, PrometheusVm},
        test_env::TestEnv,
        test_env_api::{
            HasPublicApiUrl, HasTopologySnapshot, HasVmName, IcNodeContainer,
            NnsInstallationBuilder, RetrieveIpv4Addr, SubnetSnapshot, READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
        },
    },
    util::{
        agent_observes_canister_module, assert_canister_counter_with_retries, block_on,
        spawn_round_robin_workload_engine,
    },
};

use std::time::Duration;

use anyhow::{bail, Context};
use ic_agent::Agent;
use ic_interfaces_registry::RegistryValue;
use ic_protobuf::registry::routing_table::v1::RoutingTable as PbRoutingTable;
use ic_registry_keys::make_routing_table_record_key;
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_registry_routing_table::RoutingTable;
use ic_registry_subnet_type::SubnetType;
use slog::{debug, info, Logger};

const BOUNDARY_NODE_NAME: &str = "boundary-node-1";
const COUNTER_CANISTER_WAT: &str = "rs/tests/src/counter.wat";
const CANISTER_METHOD: &str = "write";
// Duration of each request is placed into one of the two categories - below or above this threshold.
const APP_DURATION_THRESHOLD: Duration = Duration::from_secs(30);
const NNS_DURATION_THRESHOLD: Duration = Duration::from_secs(20);
// Parameters related to reading/asserting counter values of the canisters.
const MAX_CANISTER_READ_RETRIES: u32 = 4;
const CANISTER_READ_RETRY_WAIT: Duration = Duration::from_secs(10);
// Parameters related to workload creation.
const REQUESTS_DISPATCH_EXTRA_TIMEOUT: Duration = Duration::from_secs(2); // This param can be slightly tweaked (1-2 sec), if the workload fails to dispatch requests precisely on time.

// Create an IC with two subnets, with variable number of nodes and boundary nodes
// Install NNS canister on system subnet
pub fn config(
    env: TestEnv,
    nodes_app_subnet: usize,
    use_boundary_node: bool,
    boot_image_minimal_size_gibibytes: Option<ImageSizeGiB>,
) {
    let logger = env.logger();
    PrometheusVm::default()
        .start(&env)
        .expect("failed to start prometheus VM");
    let vm_resources = VmResources {
        vcpus: Some(NrOfVCPUs::new(8)),
        memory_kibibytes: None,
        boot_image_minimal_size_gibibytes,
    };
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .with_default_vm_resources(vm_resources)
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_default_vm_resources(vm_resources)
                .add_nodes(nodes_app_subnet),
        )
        .setup_and_start(&env)
        .expect("Failed to setup IC under test.");
    env.sync_with_prometheus();
    info!(logger, "Step 1: Installing NNS canisters ...");
    let nns_node = env
        .topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .unwrap();
    NnsInstallationBuilder::new()
        .install(&nns_node, &env)
        .expect("Could not install NNS canisters.");

    let bn = if use_boundary_node {
        info!(&logger, "Installing a boundary node ...");

        let bn = BoundaryNode::new(String::from(BOUNDARY_NODE_NAME))
            .allocate_vm(&env)
            .unwrap()
            .for_ic(&env, "");

        bn.start(&env).expect("Failed to setup a universal VM.");
        info!(&logger, "Installation of the boundary nodes succeeded.");
        Some(bn)
    } else {
        None
    };

    // Await Replicas
    info!(&logger, "Checking readiness of all replica nodes...");
    for subnet in env.topology_snapshot().subnets() {
        for node in subnet.nodes() {
            node.await_status_is_healthy()
                .expect("Replica did not come up healthy.");
        }
    }

    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");

    if let Some(bn) = bn {
        info!(&logger, "Polling registry");
        let registry = RegistryCanister::new(bn.nns_node_urls);
        let (latest, routes) = rt.block_on(ic_system_test_driver::retry_with_msg_async!(
            "checking registry",
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
        let boundary_node_vm = env
            .get_deployed_boundary_node(BOUNDARY_NODE_NAME)
            .unwrap()
            .get_snapshot()
            .unwrap();

        info!(
            &logger,
            "Boundary node {BOUNDARY_NODE_NAME} has IPv4 {:?} and IPv6 {:?}",
            boundary_node_vm.block_on_ipv4().unwrap(),
            boundary_node_vm.ipv6()
        );

        info!(&logger, "Checking BN health");
        boundary_node_vm
            .await_status_is_healthy()
            .expect("Boundary node did not come up healthy.");
    }
}

// Run a test with configurable number of update requests per second,
// size of the payload, duration of the test, the requests can be sent
// to replica or boundary nodes and the required success ratio can be
// adjusted.
pub fn test(
    env: TestEnv,
    rps: usize,
    payload_size_bytes: usize,
    duration: Duration,
    use_boundary_node: bool,
) {
    let log = env.logger();
    info!(
        &log,
        "Checking readiness of all nodes after the IC setup ..."
    );
    let top_snapshot = env.topology_snapshot();
    top_snapshot.subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
    info!(&log, "All nodes are ready, IC setup succeeded.");
    info!(
        &log,
        "Step 2: Build and install one counter canisters on each subnet ..."
    );
    let app_subnet = top_snapshot
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .unwrap();
    let nns_subnet = top_snapshot
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::System)
        .unwrap();
    let app_canister = app_subnet
        .nodes()
        .next()
        .unwrap()
        .create_and_install_canister_with_arg(COUNTER_CANISTER_WAT, None);
    let nns_canister = nns_subnet
        .nodes()
        .next()
        .unwrap()
        .create_and_install_canister_with_arg(COUNTER_CANISTER_WAT, None);
    info!(
        &log,
        "Installation of counter canisters on both subnets has succeeded."
    );
    info!(&log, "Step 3: Instantiate and start workloads.");
    // Workload sends messages to canisters via node agents, so we create them.
    let app_agents = create_agents_for_subnet(&log, use_boundary_node, &env, &app_subnet);
    let nns_agents = create_agents_for_subnet(&log, use_boundary_node, &env, &nns_subnet);
    info!(
        &log,
        "Asserting all agents observe the installed canister ..."
    );
    block_on(async {
        for agent in nns_agents.iter() {
            ic_system_test_driver::retry_with_msg_async!(
                format!("observing NNS canister module {}", nns_canister.to_string()),
                &log,
                READY_WAIT_TIMEOUT,
                RETRY_BACKOFF,
                || async {
                    match agent_observes_canister_module(agent, &nns_canister).await {
                        true => Ok(()),
                        false => bail!("Canister module not available yet"),
                    }
                }
            )
            .await
            .unwrap();
        }
        for agent in app_agents.iter() {
            ic_system_test_driver::retry_with_msg_async!(
                format!("observing app canister module {}", app_canister.to_string()),
                &log,
                READY_WAIT_TIMEOUT,
                RETRY_BACKOFF,
                || async {
                    match agent_observes_canister_module(agent, &app_canister).await {
                        true => Ok(()),
                        false => bail!("Canister module not available yet"),
                    }
                }
            )
            .await
            .unwrap();
        }
    });
    info!(&log, "All agents observe the installed canister module.");
    // Spawn one workload per subnet against the counter canister.
    let payload: Vec<u8> = vec![0; payload_size_bytes];
    let handle_nns_workload = {
        let requests = vec![GenericRequest::new(
            nns_canister,
            CANISTER_METHOD.to_string(),
            payload.clone(),
            CallMode::Update,
        )];
        spawn_round_robin_workload_engine(
            log.clone(),
            requests,
            nns_agents,
            rps,
            duration,
            REQUESTS_DISPATCH_EXTRA_TIMEOUT,
            vec![NNS_DURATION_THRESHOLD],
        )
    };
    let handle_app_workload = {
        let requests = vec![GenericRequest::new(
            app_canister,
            CANISTER_METHOD.to_string(),
            payload.clone(),
            CallMode::Update,
        )];
        spawn_round_robin_workload_engine(
            log.clone(),
            requests,
            app_agents,
            rps,
            duration,
            REQUESTS_DISPATCH_EXTRA_TIMEOUT,
            vec![APP_DURATION_THRESHOLD],
        )
    };
    let load_metrics_nns = handle_nns_workload
        .join()
        .expect("Workload execution against System subnet failed.");
    let load_metrics_app = handle_app_workload
        .join()
        .expect("Workload execution against Application subnet failed.");
    info!(
        &log,
        "Step 4: Collect metrics from the workloads and perform assertions ..."
    );
    info!(&log, "System subnet metrics {load_metrics_nns}");
    info!(&log, "App subnet metrics {load_metrics_app}");
    let requests_count_below_threshold_nns =
        load_metrics_nns.requests_count_below_threshold(NNS_DURATION_THRESHOLD);
    let requests_count_below_threshold_app =
        load_metrics_app.requests_count_below_threshold(APP_DURATION_THRESHOLD);
    info!(
        &log,
        "System subnet: requests below {} sec: requests_count={:?}",
        NNS_DURATION_THRESHOLD.as_secs(),
        requests_count_below_threshold_nns,
    );
    info!(
        &log,
        "Application subnet: requests below {} sec: requests_count={:?}",
        APP_DURATION_THRESHOLD.as_secs(),
        requests_count_below_threshold_app,
    );
    assert_eq!(
        load_metrics_nns.failure_calls(),
        0,
        "Requests failed on the System subnet."
    );
    assert_eq!(
        load_metrics_app.failure_calls(),
        0,
        "Requests failed on the Application subnet."
    );
    let min_expected_counter = rps * duration.as_secs() as usize;
    assert!(requests_count_below_threshold_nns
        .iter()
        .all(|(_, count)| *count as usize == min_expected_counter));
    assert!(requests_count_below_threshold_app
        .iter()
        .all(|(_, count)| *count as usize == min_expected_counter));
    info!(
        &log,
        "Step 5: Assert min counter value={} on the canisters has been reached ... ",
        min_expected_counter
    );
    let nns_agent = nns_subnet
        .nodes()
        .next()
        .map(|node| node.with_default_agent(|agent| async move { agent }))
        .unwrap();
    let app_agent = app_subnet
        .nodes()
        .next()
        .map(|node| node.with_default_agent(|agent| async move { agent }))
        .unwrap();
    block_on(async {
        assert_canister_counter_with_retries(
            &log,
            &nns_agent,
            &nns_canister,
            payload.clone(),
            min_expected_counter,
            MAX_CANISTER_READ_RETRIES,
            CANISTER_READ_RETRY_WAIT,
        )
        .await;
    });
    block_on(async {
        assert_canister_counter_with_retries(
            &log,
            &app_agent,
            &app_canister,
            payload.clone(),
            min_expected_counter,
            MAX_CANISTER_READ_RETRIES,
            CANISTER_READ_RETRY_WAIT,
        )
        .await;
    });
}

fn create_agents_for_subnet(
    log: &Logger,
    use_boundary_node: bool,
    env: &TestEnv,
    subnet: &SubnetSnapshot,
) -> Vec<Agent> {
    if use_boundary_node {
        let deployed_boundary_node = env.get_deployed_boundary_node(BOUNDARY_NODE_NAME).unwrap();
        let boundary_node_vm = deployed_boundary_node.get_snapshot().unwrap();
        info!(
            &env.logger(),
            "Agent for the boundary node with name={:?} will be used for the {:?} subnet workload.",
            boundary_node_vm.vm_name(),
            subnet.subnet_type()
        );
        vec![boundary_node_vm.build_default_agent()]
    } else {
        subnet
            .nodes()
            .map(|node| {
                debug!(
                    &log,
                    "Agent for the node with id={} from the {:?} subnet will be used for the workload.",
                    node.node_id,
                    subnet.subnet_type()
                );
                node.build_default_agent()
            })
            .collect::<_>()
    }
}
