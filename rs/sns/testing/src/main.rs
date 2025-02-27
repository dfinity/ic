use clap::Parser;
use ic_sns_testing::nns_dapp::bootstrap_nns;
use ic_sns_testing::sns::{
    create_sns, install_test_canister, upgrade_sns_controlled_test_canister, TestCanisterInitArgs,
};
use pocket_ic::PocketIcBuilder;
use reqwest::Url;

#[derive(Debug, Parser)]
struct SnsTestingOpts {
    #[arg(long)]
    server_url: Url,
}

#[tokio::main]
async fn main() {
    let opts = SnsTestingOpts::parse();
    let mut pocket_ic = PocketIcBuilder::new()
        .with_server_url(opts.server_url)
        .with_nns_subnet()
        .with_sns_subnet()
        .with_ii_subnet()
        .with_application_subnet()
        .build_async()
        .await;
    let endpoint = pocket_ic.make_live(Some(8080)).await;
    println!("PocketIC endpoint: {}", endpoint);
    bootstrap_nns(&pocket_ic).await;
    let greeting = "Hello there".to_string();
    let test_canister_id = install_test_canister(
        &pocket_ic,
        TestCanisterInitArgs {
            greeting: Some(greeting),
        },
    )
    .await;
    println!("Test canister ID: {}", test_canister_id);
    println!("Creating SNS...");
    let (sns, _nns_proposal_id) = create_sns(&pocket_ic, vec![test_canister_id]).await;
    println!("SNS created");
    println!("Upgrading SNS-controlled test canister...");
    upgrade_sns_controlled_test_canister(
        &pocket_ic,
        sns,
        test_canister_id,
        TestCanisterInitArgs {
            greeting: Some("Hi".to_string()),
        },
    )
    .await;
    println!("Test canister upgraded");
}
