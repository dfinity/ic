use clap::Parser;
use ic_sns_testing::pocket_ic::{
    bootstrap_nns, create_sns, install_test_canister, TestCanisterInitArgs,
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
    let (_, _nns_proposal_id) = create_sns(&pocket_ic, vec![test_canister_id]).await;
}
