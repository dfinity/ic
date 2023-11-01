use clap::Parser;
use ic_base_types::SubnetId;
use ic_recovery::{cli, error::RecoveryResult, util, NeuronArgs, RecoveryArgs};
use ic_subnet_splitting::{
    subnet_splitting::{SubnetSplitting, SubnetSplittingArgs},
    validation::validate_artifacts,
};
use ic_types::ReplicaVersion;
use slog::Logger;
use url::Url;

use std::path::PathBuf;

#[derive(Parser)]
struct SplitArgs {
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

    /// Flag to make the tool non interactive. No input from the user is requested.
    #[clap(long)]
    pub skip_prompts: bool,

    #[clap(flatten)]
    subnet_splitting_args: SubnetSplittingArgs,
}

#[derive(Parser)]
struct ValidateArgs {
    /// Path to the State Tree signed by the NNS
    #[clap(long, parse(from_os_str))]
    state_tree_path: PathBuf,

    /// (Optional) path to the NNS public key. If not set, the built-in public key is used.
    #[clap(long, parse(from_os_str))]
    nns_public_key_path: Option<PathBuf>,

    /// Path to the original, pre-split, CUP retrieved from the Source Subnet.
    #[clap(long, parse(from_os_str))]
    cup_path: PathBuf,

    /// Path to the original, pre-split, state manifest computed from the state on the Source
    /// Subnet.
    #[clap(long, parse(from_os_str))]
    state_manifest_path: PathBuf,

    /// SubnetId of the subnet being split.
    #[clap(long, parse(try_from_str=ic_recovery::util::subnet_id_from_str))]
    source_subnet_id: SubnetId,
}

#[allow(clippy::large_enum_variant)]
#[derive(Parser)]
enum Subcommand {
    /// Perform Subnet Splitting
    Split(SplitArgs),

    /// Validate artifacts produced during subnet splitting
    Validate(ValidateArgs),
}

#[derive(Parser)]
#[clap(version = "1.0")]
struct SubnetSplittingToolArgs {
    #[clap(subcommand)]
    subcommand: Subcommand,
}

fn subnet_splitting(
    logger: Logger,
    recovery_args: RecoveryArgs,
    subnet_splitting_args: SubnetSplittingArgs,
    mut neuron_args: Option<NeuronArgs>,
) {
    cli::print_step(&logger, "Subnet Splitting");
    if !recovery_args.skip_prompts {
        cli::wait_for_confirmation(&logger);
    }
    if neuron_args.is_none() && !recovery_args.test_mode {
        neuron_args = Some(cli::read_neuron_args(&logger));
    }

    let subnet_splitting = SubnetSplitting::new(
        logger.clone(),
        recovery_args.clone(),
        neuron_args,
        subnet_splitting_args,
    );

    cli::execute_steps(&logger, recovery_args.skip_prompts, subnet_splitting);
}

fn do_split(args: SplitArgs, logger: Logger) -> RecoveryResult<()> {
    let recovery_args = RecoveryArgs {
        dir: args.dir,
        nns_url: args.nns_url,
        replica_version: args.replica_version,
        key_file: args.key_file,
        test_mode: args.test,
        skip_prompts: args.skip_prompts,
    };

    let subnet_splitting_state =
        cli::read_and_maybe_update_state(&logger, recovery_args, Some(args.subnet_splitting_args));

    subnet_splitting(
        logger,
        subnet_splitting_state.recovery_args,
        subnet_splitting_state.subcommand_args,
        subnet_splitting_state.neuron_args,
    );

    Ok(())
}

fn do_validate(args: ValidateArgs, logger: Logger) -> RecoveryResult<()> {
    validate_artifacts(
        args.state_tree_path,
        args.nns_public_key_path.as_deref(),
        args.cup_path,
        args.state_manifest_path,
        args.source_subnet_id,
        &logger,
    )
}

fn main() -> RecoveryResult<()> {
    let args = SubnetSplittingToolArgs::parse();

    let logger = util::make_logger();

    match args.subcommand {
        Subcommand::Split(split_args) => do_split(split_args, logger),
        Subcommand::Validate(validate_args) => do_validate(validate_args, logger),
    }
}
