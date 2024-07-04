use std::env;

use ic_agent::{export::Principal, Agent};

const MAINNET_ROOT_SUBNET_ID: &str =
    "tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe";

// How to run via Bazel/Cargo:
// ic$ bazel run //rs/boundary_node/discower_bowndary:fetch-api-bns -- ic0.app
// ic$ cargo run --bin fetch_api_bns ic0.app

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<_> = env::args().collect();

    let domain = &args[1];

    let agent = Agent::builder()
        .with_url(format!("https://{domain}"))
        .build()?;

    agent.fetch_root_key().await?;

    let subnet_id = Principal::from_text(MAINNET_ROOT_SUBNET_ID).unwrap();

    // retrieve all API Boundary Nodes in a certifiable way from the state tree
    // read_state call: https://ic0.app/api/v2/subnet/subnet_id/read_state
    let api_bns = agent
        .fetch_api_boundary_nodes_by_subnet_id(subnet_id)
        .await?;

    println!("API Boundary Nodes in the State Tree: {api_bns:#?}");

    Ok(())
}
