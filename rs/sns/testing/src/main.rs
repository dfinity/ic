use std::path::PathBuf;

use clap::Parser;
use ic_base_types::PrincipalId;
use ic_nervous_system_integration_tests::pocket_ic_helpers::load_registry_mutations;
use ic_sns_testing::nns_dapp::bootstrap_nns;
use ic_sns_testing::sns::{
    create_sns_pocket_ic, install_test_canister, upgrade_sns_controlled_test_canister_pocket_ic,
    TestCanisterInitArgs,
};
use pocket_ic::PocketIcBuilder;
use reqwest::Url;

#[derive(Debug, Parser)]
struct SnsTestingOpts {
    #[arg(long)]
    server_url: Url,
    #[arg(long)]
    state_dir: PathBuf,
}

#[tokio::main]
async fn main() {
    let opts = SnsTestingOpts::parse();

    let mut pocket_ic = PocketIcBuilder::new()
        .with_server_url(opts.server_url)
        .with_state_dir(opts.state_dir.clone())
        .with_nns_subnet()
        .with_sns_subnet()
        .with_ii_subnet()
        .with_application_subnet()
        .build_async()
        .await;
    let endpoint = pocket_ic.make_live(Some(8080)).await;
    println!("PocketIC endpoint: {}", endpoint);

    let registry_proto_path = opts.state_dir.join("registry.proto");
    let initial_mutations = load_registry_mutations(registry_proto_path);
    let dev_participant_id = PrincipalId::new_user_test_id(1000);

    bootstrap_nns(
        &pocket_ic,
        vec![initial_mutations],
        vec![],
        vec![dev_participant_id],
    )
    .await;

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
    let sns = create_sns_pocket_ic(&pocket_ic, dev_participant_id, vec![test_canister_id]).await;
    println!("SNS created");
    println!("Upgrading SNS-controlled test canister...");
    upgrade_sns_controlled_test_canister_pocket_ic(
        &pocket_ic,
        dev_participant_id,
        sns,
        test_canister_id,
        TestCanisterInitArgs {
            greeting: Some("Hi".to_string()),
        },
    )
    .await;
    println!("Test canister upgraded");
}
