use std::{sync::Arc, time::Duration};

use discower_bowndary::{
    check::{HealthCheck, HealthCheckImpl},
    fetch::{NodesFetcher, NodesFetcherImpl},
    node::Node,
    route_provider::HealthCheckRouteProvider,
    snapshot::IC0_SEED_DOMAIN,
    snapshot_health_based::HealthBasedSnapshot,
    transport::{TransportProvider, TransportProviderImpl},
};
use ic_agent::{
    agent::http_transport::{
        reqwest_transport::reqwest::Client, route_provider::RouteProvider, ReqwestTransport,
    },
    export::Principal,
    identity::AnonymousIdentity,
    Agent,
};

const MAINNET_ROOT_SUBNET_ID: &str =
    "tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe";
const MAINNET_COUNTER_CANISTER_ID: &str = "3muos-6yaaa-aaaaa-qaaua-cai";
const CANISTER_METHOD: &str = "read";

/// Example usage of the HealthCheckRouteProvider (custom implementation of the RouteProvider trait defined `ic-agent`).
/// devenv-container$ bazel run //rs/boundary_node/discower_bowndary:basic-library-usage
/// ic$ cargo run --bin basic_library_usage

#[tokio::main]
async fn main() {
    let client = Client::builder()
        .build()
        .expect("Could not create HTTP client.");
    let route_provider = {
        let subnet_id = Principal::from_text(MAINNET_ROOT_SUBNET_ID).unwrap();
        let http_client = Client::builder().build().expect("failed to build client");
        let transport_provider =
            Arc::new(TransportProviderImpl { http_client }) as Arc<dyn TransportProvider>;
        let fetcher = Arc::new(NodesFetcherImpl::new(transport_provider, subnet_id));
        let fetch_interval = Duration::from_secs(5); // periodicity of checking current topology
        let health_timeout = Duration::from_secs(3);
        let checker = Arc::new(HealthCheckImpl::new(client.clone(), health_timeout));
        let check_interval = Duration::from_secs(1); // periodicity of checking node's health
        let snapshot = HealthBasedSnapshot::new();
        let route_provider = HealthCheckRouteProvider::new(
            snapshot,
            Arc::clone(&fetcher) as Arc<dyn NodesFetcher>,
            fetch_interval,
            Arc::clone(&checker) as Arc<dyn HealthCheck>,
            check_interval,
            vec![Node::new(IC0_SEED_DOMAIN)],
        );
        Arc::new(route_provider)
    };
    route_provider.run().await;
    // Build a transport layer with route_provider
    let transport = ReqwestTransport::create_with_client_route(
        Arc::clone(&route_provider) as Arc<dyn RouteProvider>,
        client,
    )
    .expect("failed to create transport");
    // Initialize an agent with custom transport
    let agent = Agent::builder()
        .with_transport(transport)
        .with_identity(AnonymousIdentity {})
        .build()
        .expect("failed to create an agent");
    agent
        .fetch_root_key()
        .await
        .expect("failed to fetch root key");
    // Start using the ic-agent for some calls
    let effective_canister_id = Principal::from_text(MAINNET_COUNTER_CANISTER_ID).unwrap();
    let result = agent
        .query(&effective_canister_id, CANISTER_METHOD)
        .call()
        .await
        .unwrap();
    let counter = u32::from_le_bytes(
        result
            .as_slice()
            .try_into()
            .expect("slice with incorrect length"),
    );
    println!("counter canister value on mainnent is {counter}");
    route_provider.stop().await;
}
