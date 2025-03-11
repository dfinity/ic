use std::path::PathBuf;

use clap::Parser;
use futures::future::join_all;
use ic_base_types::CanisterId;
use ic_nervous_system_agent::CallCanisters;
use ic_nervous_system_integration_tests::pocket_ic_helpers::load_registry_mutations;
use ic_sns_cli::utils::dfx_interface;
use ic_sns_testing::nns_dapp::bootstrap_nns;
use ic_sns_testing::sns::{create_sns, upgrade_sns_controlled_test_canister, TestCanisterInitArgs};
use ic_sns_testing::utils::{
    build_ephemeral_agent, get_identity_principal, get_nns_neuron_hotkeys, validate_network,
    validate_target_canister, NNS_NEURON_ID, SWAP_PARTICIPANT_SECRET_KEYS, TREASURY_PRINCIPAL_ID,
    TREASURY_SECRET_KEY,
};
use icp_ledger::Tokens;
use pocket_ic::PocketIcBuilder;
use reqwest::Url;

#[derive(Debug, Parser)]
struct SnsTestingOpts {
    #[clap(subcommand)]
    subcommand: SnsTestingSubCommand,
}

#[derive(Debug, Parser)]
enum SnsTestingSubCommand {
    RunBasicScenario(RunBasicScenarioOpts),
    NnsInit(NnsInitOpts),
}

#[derive(Debug, Parser)]
struct RunBasicScenarioOpts {
    #[arg(long)]
    network: String,
    #[arg(long)]
    dev_identity: String,
    #[arg(long)]
    test_canister_id: CanisterId,
}

#[derive(Debug, Parser)]
struct NnsInitOpts {
    #[arg(long)]
    server_url: Url,
    #[arg(long)]
    state_dir: PathBuf,
    #[arg(long)]
    dev_identity: String,
}

async fn nns_init(opts: NnsInitOpts) {
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
    let dev_principal_id = get_identity_principal(&opts.dev_identity).unwrap();

    bootstrap_nns(
        &pocket_ic,
        vec![initial_mutations],
        vec![
            (
                (*TREASURY_PRINCIPAL_ID).into(),
                Tokens::from_tokens(10_000_000).unwrap(),
            ),
            (dev_principal_id.into(), Tokens::from_tokens(100).unwrap()),
        ],
        vec![dev_principal_id],
    )
    .await;
}

async fn run_basic_scenario(opts: RunBasicScenarioOpts) {
    let dfx_interface = dfx_interface(&opts.network, Some(opts.dev_identity))
        .await
        .unwrap();

    let network = dfx_interface.network_descriptor();

    let dev_agent = dfx_interface.agent();
    let treasury_agent = &build_ephemeral_agent(TREASURY_SECRET_KEY.clone(), &network.clone())
        .await
        .unwrap();

    let network_validation_errors = validate_network(dev_agent).await;
    let target_canister_validation_errors =
        validate_target_canister(dev_agent, opts.test_canister_id).await;

    if !network_validation_errors.is_empty() {
        eprintln!("SNS-testing failed to validate the target network:");
        for error in &network_validation_errors {
            eprintln!("{}", error);
        }
    }
    if !target_canister_validation_errors.is_empty() {
        eprintln!("SNS-testing failed to validate the test canister:");
        for error in &target_canister_validation_errors {
            eprintln!("{}", error);
        }
    }
    if !network_validation_errors.is_empty() || !target_canister_validation_errors.is_empty() {
        return;
    }

    match get_nns_neuron_hotkeys(dev_agent, NNS_NEURON_ID).await {
        Ok(nns_neuron_hotkeys) => {
            assert!(
                nns_neuron_hotkeys.contains(&dev_agent.caller().unwrap().into()),
                "Developer identity is not a hotkey for NNS neuron"
            );
        }
        Err(err) => {
            panic!(
                "Failed to get NNS neuron {} hotkeys: {}",
                NNS_NEURON_ID.id, err
            );
        }
    }

    let swap_participants_agents = join_all(
        SWAP_PARTICIPANT_SECRET_KEYS
            .clone()
            .map(|k| async { build_ephemeral_agent(k, &network.clone()).await.unwrap() }),
    )
    .await;

    println!("Creating SNS...");
    let sns = create_sns(
        dev_agent,
        NNS_NEURON_ID,
        dev_agent,
        treasury_agent,
        swap_participants_agents,
        vec![opts.test_canister_id],
    )
    .await;
    println!("SNS created");
    println!("Upgrading SNS-controlled test canister...");
    upgrade_sns_controlled_test_canister(
        dev_agent,
        sns,
        opts.test_canister_id,
        TestCanisterInitArgs {
            greeting: Some("Hi".to_string()),
        },
    )
    .await;
    println!("Test canister upgraded")
}

#[tokio::main]
async fn main() {
    let opts = SnsTestingOpts::parse();

    match opts.subcommand {
        SnsTestingSubCommand::NnsInit(opts) => nns_init(opts).await,
        SnsTestingSubCommand::RunBasicScenario(opts) => run_basic_scenario(opts).await,
    }
}
