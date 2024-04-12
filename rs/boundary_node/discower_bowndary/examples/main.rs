use discower_bowndary::route_provider::HealthCheckRouteProvider;
use ic_agent::{
    agent::http_transport::{reqwest_transport::reqwest, ReqwestTransport},
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
    let client = reqwest::Client::builder()
        .build()
        .expect("Could not create HTTP client.");
    // Instantiate route_provider
    let route_provider = {
        let route_provider = HealthCheckRouteProvider::default();
        // Spawn internal tasks
        route_provider.run().await;
        route_provider
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
