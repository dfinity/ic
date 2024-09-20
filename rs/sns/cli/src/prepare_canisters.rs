use crate::call_dfx_or_panic;
use anyhow::Result;
use clap::Parser;
use ic_base_types::PrincipalId;
use ic_nns_constants::ROOT_CANISTER_ID;

#[derive(Debug, Parser)]
pub struct PrepareCanistersArgs {
    /// The network to deploy to. This can be "local", "ic", or the URL of an IC network.
    #[structopt(default_value = "local", long)]
    network: String,

    #[clap(subcommand)]
    sub_command: SubCommand,
}

#[derive(Debug, Parser)]
pub struct SubCommandArgs {
    /// The canisters you want to operate on
    #[clap(name = "CANISTER", required = true, num_args = 1..)]
    canisters: Vec<PrincipalId>,
}

#[derive(Debug, Parser)]
enum SubCommand {
    /// Add NNS Root as a co-controller of one or more canisters
    AddNnsRoot(SubCommandArgs),
    /// Remove NNS Root as a co-controller of one or more canisters
    RemoveNnsRoot(SubCommandArgs),
}

pub fn exec(args: PrepareCanistersArgs) -> Result<()> {
    let (operation, sub_args) = match &args.sub_command {
        SubCommand::AddNnsRoot(sub_args) => ("--add-controller", sub_args),
        SubCommand::RemoveNnsRoot(sub_args) => ("--remove-controller", sub_args),
    };

    for canister in &sub_args.canisters {
        call_dfx_or_panic(&[
            "canister",
            "--network",
            &args.network,
            "update-settings",
            operation,
            &ROOT_CANISTER_ID.to_string(),
            &canister.to_string(),
        ]);
    }

    Ok(())
}
