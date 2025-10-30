use std::process::exit;

use clap::Parser;
use ic_nervous_system_agent::CallCanisters;
use ic_nervous_system_agent::helpers::nns::get_nns_neuron_controller;
use ic_nervous_system_agent::helpers::sns::get_principal_neurons;
use ic_nns_common::pb::v1::NeuronId;
use ic_sns_cli::upgrade_sns_controlled_canister::{Wasm, validate_candid_arg_for_wasm};
use ic_sns_cli::utils::get_agent;
use ic_sns_testing::sns::{
    await_sns_controlled_canister_upgrade, complete_sns_swap, create_sns, find_sns_by_name,
    propose_sns_controlled_canister_upgrade, sns_proposal_upvote as sns_proposal_upvote_impl,
};
use ic_sns_testing::utils::{
    DEFAULT_POWERFUL_NNS_NEURON_ID, get_nns_neuron_hotkeys, transfer_icp_from_treasury,
    validate_network as validate_network_impl, validate_target_canister,
};
use ic_sns_testing::{
    RunBasicScenarioArgs, SnsProposalUpvoteArgs, SnsTestingArgs, SnsTestingSubCommand,
    SwapCompleteArgs, TransferICPArgs, TransferRecipientArg,
};
use icp_ledger::{AccountIdentifier, Subaccount};

async fn run_basic_scenario(network: String, args: RunBasicScenarioArgs) {
    let dev_agent = &get_agent(&network, args.dev_identity.clone())
        .await
        .unwrap();

    let target_canister_validation_errors =
        validate_target_canister(dev_agent, args.canister_id).await;

    if !target_canister_validation_errors.is_empty() {
        eprintln!("SNS-testing failed to validate the test canister:");
        for error in &target_canister_validation_errors {
            eprintln!("{error}");
        }
        exit(1);
    }

    let nns_neuron_id = args
        .nns_neuron_id
        .map(|id| NeuronId { id })
        .unwrap_or(DEFAULT_POWERFUL_NNS_NEURON_ID);

    // Get neuron's controller and hotkeys to get the list of principals
    // that can create proposals on behalf of the neuron.
    let mut neuron_controllers = match get_nns_neuron_hotkeys(dev_agent, nns_neuron_id).await {
        Ok(neurons) => neurons,
        Err(err) => panic!(
            "Failed to get NNS neuron {} hotkeys: {}",
            nns_neuron_id.id, err
        ),
    };
    match get_nns_neuron_controller(dev_agent, nns_neuron_id).await {
        Ok(controller) => {
            if let Some(controller) = controller {
                neuron_controllers.push(controller)
            }
        }
        Err(err) => panic!(
            "Failed to get NNS neuron {} controller: {}",
            nns_neuron_id.id, err
        ),
    };

    // Check if provided identity is allowed to create proposals on behalf of the neuron.
    if neuron_controllers
        .iter()
        .all(|&principal| principal != dev_agent.caller().unwrap().into())
    {
        eprintln!(
            "Identity '{}' cannot create NNS proposals on behalf of NNS neuron '{}'",
            args.dev_identity.unwrap_or("default".to_string()),
            nns_neuron_id.id
        );
        exit(1);
    }

    let upgrade_canister_wasm = Wasm::try_from(args.upgrade_wasm_path).unwrap();
    let upgrade_arg =
        validate_candid_arg_for_wasm(&upgrade_canister_wasm, args.upgrade_candid_arg).unwrap();

    println!("Creating SNS...");
    let (sns, dev_sns_neuron_id) = create_sns(
        dev_agent,
        nns_neuron_id,
        dev_agent,
        vec![args.canister_id],
        true,
    )
    .await;
    println!("SNS created");
    println!("Upgrading SNS-controlled test canister...");
    let proposal_id = propose_sns_controlled_canister_upgrade(
        dev_agent,
        dev_sns_neuron_id,
        sns.clone(),
        args.canister_id,
        upgrade_canister_wasm.bytes().to_vec(),
        upgrade_arg,
    )
    .await;
    await_sns_controlled_canister_upgrade(dev_agent, proposal_id, args.canister_id, sns).await;
    println!("Test canister upgraded")
}

async fn validate_network(network: String) {
    let agent = get_agent(&network, None).await.unwrap();

    let network_validation_errors = validate_network_impl(&agent).await;
    if !network_validation_errors.is_empty() {
        eprintln!("SNS-testing failed to validate the target network:");
        for error in &network_validation_errors {
            eprintln!("{error}");
        }
        exit(1);
    }
}

async fn swap_complete(network: String, args: SwapCompleteArgs) {
    let agent = get_agent(&network, args.icp_treasury_identity.clone())
        .await
        .unwrap();

    // Normally, SNSes would have different names, so the vector below would have a single element.
    let target_snses = find_sns_by_name(&agent, args.sns_name.clone()).await;

    if target_snses.is_empty() {
        eprintln!("No SNS found with the name: {}", args.sns_name);
        exit(1);
    }

    for sns in target_snses {
        let mut neurons_to_follow = vec![];
        if let Some(neuron) = &args.follow_neuron {
            neurons_to_follow.push(neuron.0.clone());
        }
        if let Some(principal) = args.follow_principal_neurons {
            let principal_neurons =
                match get_principal_neurons(&agent, sns.governance, principal).await {
                    Ok(neurons) => neurons,
                    Err(e) => {
                        eprintln!("Failed to get principal neurons: {e}");
                        vec![]
                    }
                };
            neurons_to_follow.extend(principal_neurons);
        }
        if let Err(e) = complete_sns_swap(
            &agent,
            args.icp_treasury_identity.is_none(),
            sns.swap,
            sns.governance,
            neurons_to_follow,
        )
        .await
        {
            eprintln!("Failed to complete swap for SNS {}: {}", args.sns_name, e);
            exit(1);
        }
    }
}

async fn sns_proposal_upvote(network: String, args: SnsProposalUpvoteArgs) {
    let agent = get_agent(&network, None).await.unwrap();

    let target_snses = find_sns_by_name(&agent, args.sns_name.clone()).await;
    let target_sns = target_snses.first();

    if let Some(sns) = target_sns {
        println!(
            "Upvoting proposal {} for SNS \"{}\"...",
            args.proposal_id, args.sns_name
        );
        if let Err(e) = sns_proposal_upvote_impl(
            &agent,
            sns.governance,
            sns.swap,
            args.proposal_id,
            args.wait,
        )
        .await
        {
            eprintln!(
                "Failed to upvote proposal {} for SNS {}: {}",
                args.proposal_id, args.sns_name, e
            );
            exit(1);
        }
    } else {
        eprintln!("No SNS found with the name: {}", args.sns_name);
        exit(1);
    }
}

pub async fn transfer_icp(network: String, args: TransferICPArgs) {
    let agent = get_agent(&network, args.icp_treasury_identity.clone())
        .await
        .unwrap();
    let recipient = match args.recipient {
        TransferRecipientArg::Account { account } => account.0,
        TransferRecipientArg::Principal {
            principal_id,
            subaccount,
        } => AccountIdentifier::new(principal_id, subaccount.map(|a| Subaccount(a.0))).to_address(),
    };
    transfer_icp_from_treasury(
        &agent,
        args.icp_treasury_identity.is_none(),
        recipient,
        args.amount.0,
    )
    .await
    .unwrap();
}

#[tokio::main]
async fn main() {
    let SnsTestingArgs {
        network,
        subcommand,
    } = SnsTestingArgs::parse();

    match subcommand {
        SnsTestingSubCommand::ValidateNetwork(_) => validate_network(network).await,
        SnsTestingSubCommand::RunBasicScenario(args) => run_basic_scenario(network, args).await,
        SnsTestingSubCommand::SwapComplete(args) => swap_complete(network, args).await,
        SnsTestingSubCommand::SnsProposalUpvote(args) => sns_proposal_upvote(network, args).await,
        SnsTestingSubCommand::TransferICP(args) => transfer_icp(network, args).await,
    }
}
