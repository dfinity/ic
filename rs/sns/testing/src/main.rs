use std::process::exit;

use clap::Parser;
use futures::future::join_all;
use ic_nervous_system_agent::CallCanisters;
use ic_nervous_system_integration_tests::pocket_ic_helpers::load_registry_mutations;
use ic_sns_cli::utils::{dfx_interface, get_agent};
use ic_sns_testing::nns_dapp::bootstrap_nns;
use ic_sns_testing::sns::{
    create_sns, upgrade_sns_controlled_test_canister, TestCanisterInitArgs,
    DEFAULT_SWAP_PARTICIPANTS_NUMBER,
};
use ic_sns_testing::utils::{
    build_ephemeral_agent, get_identity_principal, get_nns_neuron_hotkeys,
    swap_participant_secret_keys, validate_network as validate_network_impl,
    validate_target_canister, NNS_NEURON_ID, TREASURY_PRINCIPAL_ID, TREASURY_SECRET_KEY,
};
use ic_sns_testing::{
    BasicScenarioArgs, NnsInitArgs, RunSubCommand, SnsTestingArgs, SnsTestingSubCommand,
    ValidateNetworkArgs,
};
use icp_ledger::Tokens;
use pocket_ic::PocketIcBuilder;

async fn nns_init(args: NnsInitArgs) {
    let mut pocket_ic = PocketIcBuilder::new()
        .with_server_url(args.server_url)
        .with_state_dir(args.state_dir.clone())
        .with_nns_subnet()
        .with_sns_subnet()
        .with_ii_subnet()
        .with_application_subnet()
        .build_async()
        .await;
    let endpoint = pocket_ic.make_live(Some(8080)).await;
    println!("PocketIC endpoint: {}", endpoint);

    let registry_proto_path = args.state_dir.join("registry.proto");
    let initial_mutations = load_registry_mutations(registry_proto_path);
    let dev_principal_id = get_identity_principal(&args.dev_identity).unwrap();

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

async fn run_basic_scenario(args: BasicScenarioArgs) {
    let dfx_interface = dfx_interface(&args.network, args.dev_identity)
        .await
        .unwrap();

    let network = dfx_interface.network_descriptor();

    let dev_agent = dfx_interface.agent();
    let treasury_agent = &build_ephemeral_agent(TREASURY_SECRET_KEY.clone(), &network.clone())
        .await
        .unwrap();

    let target_canister_validation_errors =
        validate_target_canister(dev_agent, args.test_canister_id).await;

    if !target_canister_validation_errors.is_empty() {
        eprintln!("SNS-testing failed to validate the test canister:");
        for error in &target_canister_validation_errors {
            eprintln!("{}", error);
        }
        exit(1);
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
        swap_participant_secret_keys(DEFAULT_SWAP_PARTICIPANTS_NUMBER)
            .iter()
            .map(|k| async { build_ephemeral_agent(k.clone(), network).await.unwrap() }),
    )
    .await;

    println!("Creating SNS...");
    let sns = create_sns(
        dev_agent,
        NNS_NEURON_ID,
        dev_agent,
        treasury_agent,
        swap_participants_agents,
        vec![args.test_canister_id],
    )
    .await;
    println!("SNS created");
    println!("Upgrading SNS-controlled test canister...");
    upgrade_sns_controlled_test_canister(
        dev_agent,
        sns,
        args.test_canister_id,
        TestCanisterInitArgs {
            greeting: Some("Hi".to_string()),
        },
    )
    .await;
    println!("Test canister upgraded")
}

async fn validate_network(args: ValidateNetworkArgs) {
    let agent = get_agent(&args.network, None).await.unwrap();

    let network_validation_errors = validate_network_impl(&agent).await;
    if !network_validation_errors.is_empty() {
        eprintln!("SNS-testing failed to validate the target network:");
        for error in &network_validation_errors {
            eprintln!("{}", error);
        }
        exit(1);
    }
}

#[tokio::main]
async fn main() {
    let opts = SnsTestingArgs::parse();

    match opts.subcommand {
        SnsTestingSubCommand::NnsInit(opts) => nns_init(opts).await,
        SnsTestingSubCommand::Run { subcommand } => match subcommand {
            RunSubCommand::ValidateNetwork(args) => validate_network(args).await,
            RunSubCommand::BasicScenario(args) => run_basic_scenario(args).await,
        },
    }
}
