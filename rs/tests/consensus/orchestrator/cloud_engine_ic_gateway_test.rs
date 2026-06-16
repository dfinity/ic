/* tag::catalog[]
Title:: Cloud engine nodes are healthy on port 80 (served by ic-gateway).

Goal::
Verify that, for a cloud engine subnet, every node can be asserted healthy by
querying its public API status endpoint (`/api/v2/status`) on port 80 instead of
the replica's own port 8080.

Background::
Unlike regular subnets, cloud engine nodes are self-contained: in addition to the
replica, the orchestrator spawns an `ic-gateway` process next to it on the very
same node, which forwards requests from port 80 to the replica's port 8080.

Runbook::
0. Set up an IC with one System (NNS) subnet and one cloud engine.
1. For each node in the cloud engine subnet, query `/api/v2/status` on port 80
   and assert that the replica reports `Healthy`.

Success::
Every cloud engine node reports a healthy status on port 80.

end::catalog[] */

use anyhow::{Context, Result, bail};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, IcNodeSnapshot, READY_WAIT_TIMEOUT,
    RETRY_BACKOFF,
};
use ic_system_test_driver::util::block_on;
use ic_system_test_driver::{retry_with_msg_async, systest};
use ic_types::messages::{HttpStatusResponse, ReplicaHealthStatus};
use slog::{Logger, info};
use std::time::Duration;

/// Port on which `ic-gateway` exposes the public API of a cloud engine node.
///
/// Regular replicas serve their public API on port 8080. On cloud engine nodes
/// the orchestrator additionally spawns `ic-gateway` next to the replica, and
/// that process terminates the public API on port 80 (the port opened to the
/// network by the cloud-engine firewall rules).
const IC_GATEWAY_PORT: u16 = 80;

/// Number of nodes in the cloud engine subnet under test.
const CLOUD_ENGINE_NODES: usize = 4;

/// Per-request timeout when polling the status endpoint.
const STATUS_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

fn setup(env: TestEnv) {
    InternetComputer::new()
        .with_api_boundary_nodes_playnet(1)
        .add_fast_single_node_subnet(SubnetType::System)
        .add_subnet(Subnet::fast(SubnetType::CloudEngine, CLOUD_ENGINE_NODES))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
}

fn test(env: TestEnv) {
    let logger = env.logger();
    let topology = env.topology_snapshot();

    let cloud_engine_subnet = topology
        .subnets()
        .find(|subnet| subnet.subnet_type() == SubnetType::CloudEngine)
        .expect("the topology must contain a cloud engine subnet");

    let nodes: Vec<IcNodeSnapshot> = cloud_engine_subnet.nodes().collect();
    assert_eq!(
        nodes.len(),
        CLOUD_ENGINE_NODES,
        "unexpected number of cloud engine nodes"
    );

    block_on(async {
        for node in &nodes {
            info!(
                logger,
                "Asserting that cloud engine node {} is healthy on port {} (ic-gateway)",
                node.node_id,
                IC_GATEWAY_PORT,
            );
            // The standard `await_status_is_healthy` targets the replica on port
            // 8080. For cloud engine nodes we instead assert health on port 80,
            // which is served by the `ic-gateway` instance the orchestrator runs
            // next to the replica.
            await_healthy_on_ic_gateway(node, &logger)
                .await
                .unwrap_or_else(|err| {
                    panic!(
                        "cloud engine node {} is not healthy on port {}: {err}",
                        node.node_id, IC_GATEWAY_PORT,
                    )
                });
        }
    });

    info!(
        logger,
        "All {} cloud engine nodes are healthy on port {} (ic-gateway)",
        nodes.len(),
        IC_GATEWAY_PORT,
    );
}

/// Polls `/api/v2/status` of `node` on [`IC_GATEWAY_PORT`] (the port served by
/// the co-located `ic-gateway`) until the replica reports itself `Healthy`.
///
/// This mirrors the driver's standard health check (`status_is_healthy`), but
/// retargets it from port 8080 to port 80.
async fn await_healthy_on_ic_gateway(node: &IcNodeSnapshot, logger: &Logger) -> Result<()> {
    // `get_public_url` yields the replica's URL on port 8080; rewrite the port to
    // reach the co-located `ic-gateway` instead.
    let mut url = node.get_public_url();
    url.set_port(Some(IC_GATEWAY_PORT))
        .map_err(|_| anyhow::anyhow!("failed to set port {IC_GATEWAY_PORT} on {url}"))?;
    let status_url = url
        .join("api/v2/status")
        .expect("failed to join status path");

    retry_with_msg_async!(
        format!(
            "awaiting healthy status of node {} on port {IC_GATEWAY_PORT}",
            node.node_id
        ),
        logger,
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
        || async {
            let response = reqwest::Client::builder()
                .timeout(STATUS_REQUEST_TIMEOUT)
                .build()
                .expect("cannot build a reqwest client")
                .get(status_url.clone())
                .send()
                .await?;

            let status = response.status();
            let body = response
                .bytes()
                .await
                .expect("failed to convert a response to bytes")
                .to_vec();
            if status.is_client_error() || status.is_server_error() {
                bail!(
                    "status check failed with {status}: `{}`",
                    String::from_utf8_lossy(&body)
                );
            }

            let cbor = serde_cbor::from_slice(&body).expect("response is not encoded as cbor");
            let status_response = serde_cbor::value::from_value::<HttpStatusResponse>(cbor)
                .expect("failed to deserialize a response to HttpStatusResponse");

            match status_response.replica_health_status {
                Some(ReplicaHealthStatus::Healthy) => Ok(()),
                other => bail!("replica not healthy yet, status: {other:?}"),
            }
        }
    )
    .await
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}
