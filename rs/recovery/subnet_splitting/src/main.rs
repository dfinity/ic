use clap::Parser;
use ic_base_types::SubnetId;
use ic_recovery::{NeuronArgs, RecoveryArgs, cli, error::RecoveryResult, util};
use ic_subnet_splitting::{
    subnet_splitting::{SubnetSplitting, SubnetSplittingArgs},
    utils::canister_id_ranges_to_strings,
    validation::validate_artifacts,
};
use ic_types::ReplicaVersion;
use slog::{Logger, info, warn};
use url::Url;

use std::path::PathBuf;

const FORUM_ANNOUNCEMENT_TEMPLATE_URL: &str =
    "https://wiki.internetcomputer.org/wiki/Subnet_splitting_forum_announcement_template";

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
    #[clap(long)]
    replica_version: Option<ReplicaVersion>,

    /// The directory to the subnet splitting in
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
    pub skip_prompts: bool,

    /// Flag to indicate we're running recovery directly on a node, and should use
    /// the locally available binaries. If this option is not set, missing binaries
    /// will be downloaded.
    #[clap(long)]
    pub use_local_binaries: bool,

    #[clap(flatten)]
    subnet_splitting_args: SubnetSplittingArgs,
}

#[derive(Parser)]
struct ValidateArgs {
    /// Path to the State Tree signed by the NNS
    #[clap(long)]
    state_tree_path: PathBuf,

    /// (Optional) path to the NNS public key. If not set, the built-in public key is used.
    #[clap(long)]
    nns_public_key_path: Option<PathBuf>,

    /// Path to the original, pre-split, CUP retrieved from the Source Subnet.
    #[clap(long)]
    cup_path: PathBuf,

    /// Path to the original, pre-split, state manifest computed from the state on the Source
    /// Subnet.
    #[clap(long)]
    state_manifest_path: PathBuf,

    /// SubnetId of the subnet being split.
    #[clap(long, value_parser=ic_recovery::util::subnet_id_from_str)]
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

    info!(
        logger,
        "Splitting canisters within ranges {:?} out of subnet with id {} \
        into subnet with id {}",
        canister_id_ranges_to_strings(&subnet_splitting_args.canister_id_ranges_to_move),
        subnet_splitting_args.source_subnet_id,
        subnet_splitting_args.destination_subnet_id
    );
    warn!(
        logger,
        "Don't forget to announce at the forum the upcoming series of proposals to split the subnet"
    );
    warn!(
        logger,
        "See the template at: {}", FORUM_ANNOUNCEMENT_TEMPLATE_URL
    );

    cli::wait_for_confirmation(&logger);

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
        admin_key_file: args.admin_key_file,
        test_mode: args.test,
        skip_prompts: args.skip_prompts,
        use_local_binaries: args.use_local_binaries,
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
