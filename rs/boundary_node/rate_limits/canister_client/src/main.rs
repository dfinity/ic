use candid::{Decode, Encode, Principal};
use ic_agent::{identity::AnonymousIdentity, Agent};
use rate_limits_api::GetConfigResponse;

const RATE_LIMIT_CANISTER_ID: &str = "zwbmv-jyaaa-aaaab-qacaa-cai";
const IC_DOMAIN: &str = "https://ic0.app";

#[tokio::main]
async fn main() {
    let agent = Agent::builder()
        .with_url(IC_DOMAIN)
        .with_identity(AnonymousIdentity {})
        .build()
        .expect("failed to build the agent");

    agent.fetch_root_key().await.unwrap();

    let canister_id = Principal::from_text(RATE_LIMIT_CANISTER_ID).unwrap();

    // let args = Encode!(&Some(1u64)).unwrap();
    let args = Encode!(&None::<u64>).unwrap();

    let response = agent
        .update(&canister_id, "get_config")
        .with_arg(args)
        .call_and_wait()
        .await
        .expect("update call failed");

    let decoded = Decode!(&response, GetConfigResponse).expect("failed to decode candid response");

    println!("get_config response: {decoded:#?}");
}
