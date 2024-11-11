use std::{sync::Arc, time::Duration};

use discower_bowndary::{
    check::{HealthCheck, HealthCheckImpl},
    fetch::{NodesFetcher, NodesFetcherImpl},
    node::Node,
    route_provider::HealthCheckRouteProvider,
    snapshot::Snapshot,
    snapshot_health_based::HealthBasedSnapshot,
    snapshot_latency_based::LatencyBasedSnapshot,
    transport::{TransportProvider, TransportProviderImpl},
};
use ic_agent::{
    agent::http_transport::{
        reqwest_transport::reqwest::Client, route_provider::RouteProvider, ReqwestTransport,
    },
    export::Principal,
    identity::BasicIdentity,
    Agent, AgentError,
};
use tokio::{
    task::JoinHandle,
    time::{sleep_until, Instant},
};

const IC0_DOMAIN: &str = "ic0.app";
const MAINNET_COUNTER_CANISTER_ID: &str = "3muos-6yaaa-aaaaa-qaaua-cai";
const CANISTER_METHOD: &str = "read";
const MAINNET_ROOT_SUBNET_ID: &str =
    "tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe";

// How to run via Bazel/Cargo:
// ic$ bazel run //rs/boundary_node/discower_bowndary:api-bn-dynamic-routing
// ic$ cargo run --bin api_bn_dynamic_routing

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let rps = 100;
    let execution_time = Duration::from_secs(45);
    let effective_canister_id = Principal::from_text(MAINNET_COUNTER_CANISTER_ID).unwrap();

    // Current agent usage: just one static URL (ic0.app).
    let static_agent = agent_with_static_routing(IC0_DOMAIN).await?;

    // Fair dynamic routing (round-robin) over all API Boundary Nodes
    let dynamic_agent_1: Agent =
        agent_with_dynamic_routing(IC0_DOMAIN, HealthBasedSnapshot::new()).await?;

    // Latency based routing (weighted round-robin) over all API Boundary Nodes
    let dynamic_agent_2: Agent =
        agent_with_dynamic_routing(IC0_DOMAIN, LatencyBasedSnapshot::new()).await?;

    dispatch_requests(
        &format!("Static routing via {IC0_DOMAIN}"),
        rps,
        execution_time,
        static_agent,
        effective_canister_id,
        CANISTER_METHOD,
    )
    .await;

    dispatch_requests(
        "Fair dynamic routing via API BNs",
        rps,
        execution_time,
        dynamic_agent_1,
        effective_canister_id,
        CANISTER_METHOD,
    )
    .await;

    dispatch_requests(
        "Latency-based dynamic routing via API BNs",
        rps,
        execution_time,
        dynamic_agent_2,
        effective_canister_id,
        CANISTER_METHOD,
    )
    .await;

    Ok(())
}

async fn dispatch_requests(
    name: &str,
    rps: u64,
    duration: Duration,
    agent: Agent,
    effective_canister_id: Principal,
    canister_method: &str,
) {
    println!("{name}: dispatching requests at {rps} rps during {duration:?}");
    let requests_count = rps * duration.as_secs();
    let mut tasks: Vec<JoinHandle<Duration>> = vec![];
    let offset = Duration::from_secs(1);
    let start = Instant::now() + offset;

    for idx in 0..requests_count {
        let agent = agent.clone();
        let canister_method = canister_method.to_string();
        let request_start = start + Duration::from_secs_f64(idx as f64 / rps as f64);

        tasks.push(tokio::spawn(async move {
            sleep_until(request_start).await;

            let start = Instant::now();
            let _ = agent
                .query(&effective_canister_id, canister_method)
                .call()
                .await;
            start.elapsed()
        }));
    }
    let mut total_duration = Duration::ZERO;
    for handle in tasks {
        total_duration += handle.await.unwrap_or_else(|_| {
            panic!("Awaiting the task handle failed.");
        });
    }
    println!(
        "All {requests_count} were executed within {total_duration:?}, avg request time {:.3} ms",
        total_duration.as_millis() as f64 / requests_count as f64
    );
}

async fn agent_with_static_routing(domain: &str) -> Result<Agent, AgentError> {
    let identity = random_ed25519_identity();
    let agent = Agent::builder()
        .with_url(format!("https://{domain}"))
        .with_identity(identity)
        .build()?;
    agent.fetch_root_key().await?;
    Ok(agent)
}

async fn agent_with_dynamic_routing(
    domain_seed: &str,
    snapshot: impl Snapshot + 'static,
) -> Result<Agent, AgentError> {
    let http_client = Client::builder().build().unwrap();

    let route_provider = {
        let subnet_id = Principal::from_text(MAINNET_ROOT_SUBNET_ID).unwrap();

        let transport_provider = Arc::new(TransportProviderImpl {
            http_client: http_client.clone(),
        }) as Arc<dyn TransportProvider>;

        let fetcher = Arc::new(NodesFetcherImpl::new(transport_provider, subnet_id));

        let fetch_interval = Duration::from_secs(5); // periodicity of checking current topology

        let health_timeout = Duration::from_secs(3);

        let checker = Arc::new(HealthCheckImpl::new(http_client.clone(), health_timeout));

        let check_interval = Duration::from_secs(1); // periodicity of checking node's health

        let route_provider = HealthCheckRouteProvider::new(
            snapshot,
            Arc::clone(&fetcher) as Arc<dyn NodesFetcher>,
            fetch_interval,
            Arc::clone(&checker) as Arc<dyn HealthCheck>,
            check_interval,
            vec![Node::new(domain_seed)],
        );
        Arc::new(route_provider)
    };

    route_provider.run().await;

    // Build a transport layer with route_provider
    let transport = ReqwestTransport::create_with_client_route(
        Arc::clone(&route_provider) as Arc<dyn RouteProvider>,
        http_client,
    )
    .expect("failed to create transport");

    // Initialize an agent with custom transport (Discovery Library)
    let identity = random_ed25519_identity();
    let agent = Agent::builder()
        .with_transport(transport)
        .with_identity(identity)
        .build()?;
    agent.fetch_root_key().await?;
    Ok(agent)
}

// Creates an identity to be used with `Agent`.
pub fn random_ed25519_identity() -> BasicIdentity {
    let rng = ring::rand::SystemRandom::new();
    let key_pair = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)
        .expect("Could not generate a key pair.");

    BasicIdentity::from_key_pair(
        ring::signature::Ed25519KeyPair::from_pkcs8(key_pair.as_ref())
            .expect("Could not read the key pair."),
    )
}
