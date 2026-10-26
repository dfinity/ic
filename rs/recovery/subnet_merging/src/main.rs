use clap::Parser;
use ic_recovery::{NeuronArgs, RecoveryArgs, cli, util};
use ic_subnet_merging::subnet_merging::{SubnetMerging, SubnetMergingArgs};
use ic_types::ReplicaVersion;
use slog::{Logger, info, warn};
use url::Url;

use std::path::PathBuf;

#[derive(Parser)]
struct MergeArgs {
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
    #[clap(long)]
    replica_version: Option<ReplicaVersion>,

    /// The directory to do the subnet merging in
    #[clap(long)]
    dir: PathBuf,

    /// The path to a private key to be considered for admin SSH connections
    #[clap(long)]
    admin_key_file: Option<PathBuf>,

    /// Flag to enter test mode
    #[clap(long)]
    test: bool,

    /// Flag to make the tool non interactive. No input from the user is requested.
    #[clap(long)]
    skip_prompts: bool,

    #[clap(flatten)]
    subnet_merging_args: SubnetMergingArgs,
}

#[derive(Parser)]
enum Subcommand {
    /// Perform Subnet Merging
    Merge(MergeArgs),
}

#[derive(Parser)]
#[clap(version = "1.0")]
struct SubnetMergingToolArgs {
    #[clap(subcommand)]
    subcommand: Subcommand,
}

fn subnet_merging(
    logger: Logger,
    recovery_args: RecoveryArgs,
    subnet_merging_args: SubnetMergingArgs,
    mut neuron_args: Option<NeuronArgs>,
) {
    cli::print_step(&logger, "Subnet Merging");

    info!(
        logger,
        "Merging subnet with id {} into subnet with id {}",
        subnet_merging_args.source_subnet_id,
        subnet_merging_args.destination_subnet_id,
    );
    warn!(
        logger,
        "Don't forget to announce at the forum the upcoming series of proposals to merge the \
         subnet"
    );
    // TODO: Point to a template for the forum announcement once one exists.

    if !recovery_args.skip_prompts {
        cli::wait_for_confirmation(&logger);
    }

    if neuron_args.is_none() && !recovery_args.test_mode {
        neuron_args = Some(cli::read_neuron_args(&logger));
    }

    let subnet_merging = SubnetMerging::new(
        logger.clone(),
        recovery_args.clone(),
        neuron_args,
        subnet_merging_args,
    );

    cli::execute_steps(&logger, recovery_args.skip_prompts, subnet_merging);
}

fn do_merge(args: MergeArgs, logger: Logger) {
    let recovery_args = RecoveryArgs {
        dir: args.dir,
        nns_url: args.nns_url,
        replica_version: args.replica_version,
        admin_key_file: args.admin_key_file,
        test_mode: args.test,
        skip_prompts: args.skip_prompts,
    };

    let subnet_merging_state =
        cli::read_and_maybe_update_state(&logger, recovery_args, Some(args.subnet_merging_args));

    subnet_merging(
        logger,
        subnet_merging_state.recovery_args,
        subnet_merging_state.subcommand_args,
        subnet_merging_state.neuron_args,
    );
}

fn main() {
    let args = SubnetMergingToolArgs::parse();

    let logger = util::make_logger();

    match args.subcommand {
        Subcommand::Merge(merge_args) => do_merge(merge_args, logger),
    }
}
