use crate::subnet_splitting::{SubnetSplitting, SubnetSplittingArgs};

use clap::Parser;
use ic_recovery::{cli, util, NeuronArgs, RecoveryArgs};
use ic_types::ReplicaVersion;
use slog::Logger;
use url::Url;

use std::path::PathBuf;

mod admin_helper;
mod agent_helper;
mod layout;
mod state_tool_helper;
mod steps;
mod subnet_splitting;
mod target_subnet;
mod utils;

#[derive(Parser)]
#[clap(version = "1.0")]
struct Args {
    #[clap(
        short = 'r',
        long,
        alias = "registry-url",
        default_value = "https://ic0.app"
    )]
    /// The URL of an NNS entry point. That is, the URL of any replica on the
    /// NNS subnet.
    nns_url: Url,

    /// replica version of ic-admin binary
    #[clap(long, parse(try_from_str=::std::convert::TryFrom::try_from))]
    replica_version: Option<ReplicaVersion>,

    /// The directory to the subnet splitting in
    #[clap(long, parse(from_os_str))]
    dir: PathBuf,

    /// The path to a private key to be considered for SSH connections
    #[clap(long, parse(from_os_str))]
    key_file: Option<PathBuf>,

    /// Flag to enter test mode
    #[clap(long)]
    test: bool,

    #[clap(flatten)]
    subnet_splitting_args: SubnetSplittingArgs,
}

fn subnet_splitting(
    logger: Logger,
    recovery_args: RecoveryArgs,
    subnet_splitting_args: SubnetSplittingArgs,
    mut neuron_args: Option<NeuronArgs>,
) {
    cli::print_step(&logger, "Subnet Splitting");
    cli::wait_for_confirmation(&logger);

    if neuron_args.is_none() && !recovery_args.test_mode {
        neuron_args = Some(cli::read_neuron_args(&logger));
    }

    let subnet_splitting = SubnetSplitting::new(
        logger.clone(),
        recovery_args,
        neuron_args,
        subnet_splitting_args,
        /*interactive=*/ true,
    );

    cli::execute_steps(&logger, subnet_splitting);
}

fn main() {
    let logger = util::make_logger();
    let args = Args::parse();
    let recovery_args = RecoveryArgs {
        dir: args.dir,
        nns_url: args.nns_url,
        replica_version: args.replica_version,
        key_file: args.key_file,
        test_mode: args.test,
    };

    let subnet_splitting_state =
        cli::read_and_maybe_update_state(&logger, recovery_args, Some(args.subnet_splitting_args));

    subnet_splitting(
        logger,
        subnet_splitting_state.recovery_args,
        subnet_splitting_state.subcommand_args,
        subnet_splitting_state.neuron_args,
    );
}
