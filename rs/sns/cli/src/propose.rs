use crate::{get_identity, MakeProposalResponse, NnsGovernanceCanister};
use clap::Parser;
use ic_nervous_system_common::ledger::compute_neuron_staking_subaccount_bytes;
use ic_nns_common::pb::v1::{NeuronId, ProposalId};
use ic_nns_governance::pb::v1::manage_neuron::NeuronIdOrSubaccount;
use std::{fmt::Debug, path::PathBuf};

#[derive(Debug, Parser)]
pub struct ProposeArgs {
    /// The network to deploy to. This can be "local", "ic", or the URL of an IC
    /// network.
    #[structopt(default_value = "local", long)]
    network: String,

    /// Path to a configuration file specifying the SNS to be created.
    #[clap(parse(from_os_str), default_value = "sns_init.yaml")]
    pub init_config_file: PathBuf,

    /// The neuron with which to make the proposal. The current dfx identity
    /// must be able to operate this neuron. If not specified, it will be
    /// assumed that the current dfx identity has a neuron with memo == 0.
    /// --neuron_memo is an alternative to this.
    #[clap(long)]
    pub neuron_id: Option<u64>,

    /// This is an alternative to --neuron_id for specifying which neuron to
    /// make the proposal with. This is used in conjunction with the current
    /// principal to calculate the subaccount (belonging to the NNS governance
    /// canister) that holds the ICP that backs the proposing neuron.
    #[clap(long)]
    pub neuron_memo: Option<u64>,
}

pub fn exec(args: ProposeArgs) {
    let ProposeArgs {
        network,
        init_config_file,
        neuron_id,
        neuron_memo,
    } = args;

    // Step 0: Validate arguments.
    if neuron_id.is_some() && neuron_memo.is_some() {
        eprintln!("--neuron_id and --neuron_memo are mutually exclusive (yet both were used).");
        std::process::exit(1);
    }

    // Step 1: Load configuration
    let init_config_file = std::fs::read_to_string(&init_config_file).unwrap_or_else(|err| {
        eprintln!(
            "Unable to read the SNS configuration file ({:?}):\n{}",
            init_config_file, err,
        );
        std::process::exit(1);
    });
    let init_config_file = serde_yaml::from_str::<
        crate::init_config_file::friendly::SnsConfigurationFile,
    >(&init_config_file)
    .unwrap_or_else(|err| {
        eprintln!(
            "Unable to parse the SNS configuration file ({:?}):\n{}",
            init_config_file, err,
        );
        std::process::exit(1);
    });
    let create_service_nervous_system = init_config_file
        .try_convert_to_create_service_nervous_system()
        .unwrap_or_else(|err| {
            eprintln!(
                "Unable to parse the SNS configuration file. err = {:?}.\n\
                 init_config_file:\n{:#?}",
                err, init_config_file,
            );
            std::process::exit(1);
        });
    let proposal = create_service_nervous_system.upgrade_to_proposal();

    // Step 2: Send the proposal.
    eprintln!("Loaded configuration.");
    eprintln!(
        "Sending proposal with title {:?} to NNS (--network={})...",
        proposal.title.as_ref().unwrap_or(&"".to_string()),
        network,
    );
    let proposer = if let Some(id) = neuron_id {
        NeuronIdOrSubaccount::NeuronId(NeuronId { id })
    } else {
        let subaccount = compute_neuron_staking_subaccount_bytes(
            get_identity("get-principal", &network),
            neuron_memo.unwrap_or_default(),
        );
        NeuronIdOrSubaccount::Subaccount(subaccount.to_vec())
    };
    let result = NnsGovernanceCanister::new(&network).make_proposal(&proposer, &proposal);

    // Step 3: Report result.
    println!();
    match result {
        Ok(MakeProposalResponse {
            proposal_id: Some(ProposalId { id }),
        }) => {
            println!("🚀 Succes! View the proposal here:");
            println!("https://dashboard.internetcomputer.org/proposal/{}", id);
            println!("Godspeed!")
        }
        err => {
            println!("{:?}", err);
            println!();
            println!("💔 Something went wrong. Look up slightly for diagnostics.");
            println!("Perhaps, share the above error with the community at");
            println!("https://forum.dfinity.org/c/tokenization");
            std::process::exit(1)
        }
    };
}
