use std::{sync::Arc, time::Duration};

use discower_bowndary::{
    check::{HealthCheck, HealthCheckImpl},
    fetch::{NodesFetcher, NodesFetcherImpl},
    route_provider::HealthCheckRouteProvider,
    snapshot::IC0_SEED_DOMAIN,
};
use ic_agent::{
    agent::http_transport::{reqwest_transport::reqwest::Client, ReqwestTransport},
    export::Principal,
    identity::AnonymousIdentity,
    Agent,
};

const EFFECTIVE_CANISTER_ID: &str = "3muos-6yaaa-aaaaa-qaaua-cai"; // counter canister on mainnet
const CANISTER_METHOD: &str = "read";

/// Example usage of the HealthCheckRouteProvider (custom implementation of the RouteProvider trait defined `ic-agent`).
/// devenv-container$ bazel run //rs/boundary_node/discower_bowndary:discower-bowndary-example
/// discower_bowndary$ cargo run --example main

#[tokio::main]
async fn main() {
    let client = Client::builder()
        .build()
        .expect("Could not create HTTP client.");
    let route_provider = {
        // TODO: change to subnet_id when 0.35.0 ic-agent is released
        let effective_canister_id = Principal::from_text(EFFECTIVE_CANISTER_ID).unwrap();
        let fetcher = Arc::new(NodesFetcherImpl::new(client.clone(), effective_canister_id));
        let fetch_interval = Duration::from_secs(5); // periodicity of checking current topology
        let health_timeout = Duration::from_secs(3);
        let checker = Arc::new(HealthCheckImpl::new(client.clone(), health_timeout));
        let check_interval = Duration::from_secs(1); // periodicity of checking node's health
        HealthCheckRouteProvider::new(
            Arc::clone(&fetcher) as Arc<dyn NodesFetcher>,
            fetch_interval,
            Arc::clone(&checker) as Arc<dyn HealthCheck>,
            check_interval,
            vec![IC0_SEED_DOMAIN],
        )
    };
    // Build a transport layer with route_provider
    let transport = ReqwestTransport::create_with_client_route(Box::new(route_provider), client)
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
    let effective_canister_id = Principal::from_text(EFFECTIVE_CANISTER_ID).unwrap();
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
}
