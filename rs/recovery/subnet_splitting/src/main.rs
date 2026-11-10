use anyhow::Context;
use clap::Parser;
use colored::{Color, Colorize};
use ic_base_types::SubnetId;
use ic_recovery::{NeuronArgs, RecoveryArgs, cli, util};
use ic_registry_routing_table::CanisterIdRange;
use ic_subnet_splitting::{
    post_split_estimations::{self, BrokenConnections, Estimates, PostSplitEstimations},
    subnet_splitting::{SubnetSplitting, SubnetSplittingArgs},
};
use ic_subnet_tools::{utils::canister_id_ranges_to_strings, validation::validate_artifacts};
use ic_types::ReplicaVersion;
use slog::{Logger, info, warn};
use url::Url;

use std::path::{Path, PathBuf};

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

/// Maximum number of broken connections printed per subnet when no
/// [`EstimateArgs::broken_connections_output_path`] is given.
const MAX_BROKEN_CONNECTIONS_TO_PRINT: usize = 50;

#[derive(Parser)]
struct EstimateArgs {
    /// The canister ID ranges to be moved to the destination subnet.
    #[clap(long, num_args(1..), required = true)]
    canister_id_ranges_to_move: Vec<CanisterIdRange>,

    /// Path to a state manifest computed from the state on the source subnet.
    /// Needed to compute the sizes of canisters.
    #[clap(long)]
    state_manifest_path: PathBuf,

    /// Path to a CSV file containing a sample of load metrics on the source subnet.
    #[clap(long)]
    load_samples_path: PathBuf,

    /// Path to a CSV file containing an older sample of load metrics on the source subnet.
    /// We will look at the difference between metrics at
    /// [`EstimateArgs::load_samples_path`] and [`EstimateArgs::load_samples_baseline_path`] to
    /// estimate the load which occurred in the time frame between the two samples were collected.
    #[clap(long)]
    load_samples_baseline_path: PathBuf,

    /// Path to a CSV file containing a sample of subnet-local communication metrics (number of
    /// requests sent from each canister to each other canister) on the source subnet.
    #[clap(long)]
    communication_samples_path: PathBuf,

    /// Path to a CSV file containing an older sample of subnet-local communication metrics on the
    /// source subnet. Used in the same way as [`EstimateArgs::load_samples_baseline_path`].
    #[clap(long)]
    communication_samples_baseline_path: PathBuf,

    /// (Optional) path to a CSV file to write all the subnet-local connections broken by the split
    /// to. If not set, they are printed instead, unless there are too many of them.
    #[clap(long)]
    broken_connections_output_path: Option<PathBuf>,
}

#[allow(clippy::large_enum_variant)]
#[derive(Parser)]
enum Subcommand {
    /// Perform Subnet Splitting
    Split(SplitArgs),

    /// Estimate the states' sizes and loads after splitting the subnet.
    Estimate(EstimateArgs),

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

fn do_split(args: SplitArgs, logger: Logger) -> anyhow::Result<()> {
    let recovery_args = RecoveryArgs {
        dir: args.dir,
        nns_url: args.nns_url,
        replica_version: args.replica_version,
        admin_key_file: args.admin_key_file,
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

fn do_validate(args: ValidateArgs, logger: Logger) -> anyhow::Result<()> {
    validate_artifacts(
        args.state_tree_path,
        args.nns_public_key_path.as_deref(),
        args.cup_path,
        args.state_manifest_path,
        args.source_subnet_id,
        &logger,
    )
    .context("Failed to validate the artifacts")
}

fn do_estimate(args: EstimateArgs, _logger: Logger) -> anyhow::Result<()> {
    let PostSplitEstimations {
        states_sizes_bytes,
        canisters_installed,
        instructions_executed,
        ingress_messages_executed,
        remote_subnet_messages_executed_lower_bound,
        local_subnet_messages_executed_upper_bound,
        http_outcalls_executed,
        heartbeats_and_global_timers_executed,
        canisters_with_broken_local_connections_lower_bound: broken_connections,
    } = post_split_estimations::estimate(
        args.canister_id_ranges_to_move,
        args.state_manifest_path,
        args.load_samples_path,
        args.load_samples_baseline_path,
        args.communication_samples_path,
        args.communication_samples_baseline_path,
    )
    .context("Failed to estimate the load")?;

    println!();
    print_estimates(&[
        ("States sizes in bytes", &states_sizes_bytes),
        (
            "Estimated canisters installed on both subnets",
            &canisters_installed,
        ),
        (
            "Estimated instructions used on both subnets",
            &instructions_executed,
        ),
        (
            "Estimated ingress load on both subnets",
            &ingress_messages_executed,
        ),
        (
            "Remote subnet messages executed on both subnets (lower bound)",
            &remote_subnet_messages_executed_lower_bound,
        ),
        (
            "Local subnet messages executed on both subnets (upper bound)",
            &local_subnet_messages_executed_upper_bound,
        ),
        (
            "Estimated number of http outcalls made on both subnets",
            &http_outcalls_executed,
        ),
        (
            "Estimated number of heartbeats and global timers made on both subnets",
            &heartbeats_and_global_timers_executed,
        ),
        (
            "Canisters whose local subnet messages would become remote (lower bound)",
            &broken_connections.map(|connections| connections.len() as u64),
        ),
    ]);

    println!();
    match args.broken_connections_output_path {
        Some(path) => {
            write_broken_connections(&broken_connections, &path).with_context(|| {
                format!(
                    "Failed to write the broken connections to {}",
                    path.display()
                )
            })?;
            println!("Wrote the broken connections to {}", path.display());
        }
        None => print_broken_connections(&broken_connections),
    }

    Ok(())
}

/// Prints one row per estimate with pretty colors, weight, and alignment
fn print_estimates(rows: &[(&str, &Estimates)]) {
    let label_width = rows
        .iter()
        .map(|(label, _)| label.len() + 1)
        .max()
        .unwrap_or_default();
    let source_width = rows
        .iter()
        .map(|(_, estimates)| estimates.source.to_string().len())
        .max()
        .unwrap_or_default();
    let destination_width = rows
        .iter()
        .map(|(_, estimates)| estimates.destination.to_string().len())
        .max()
        .unwrap_or_default();

    for (label, estimates) in rows {
        let total = estimates.total();
        let percentage = |value: u64| {
            if total == 0 {
                0.0
            } else {
                value as f64 / total as f64 * 100.0
            }
        };

        println!(
            "{}  {} {} {}  {} {} {}",
            format!("{:<label_width$}", format!("{label}:")).bold(),
            "source:".cyan(),
            format!("{:>source_width$}", estimates.source).cyan().bold(),
            format!("({:>6.2}%)", percentage(estimates.source)).cyan(),
            "destination:".magenta(),
            format!("{:>destination_width$}", estimates.destination)
                .magenta()
                .bold(),
            format!("({:>6.2}%)", percentage(estimates.destination)).magenta(),
        );
    }
}

/// Prints, for each subnet, the canisters sending subnet-local requests to canisters which would
/// end up on the other subnet, unless there are too many of them.
fn print_broken_connections(broken_connections: &Estimates<BrokenConnections>) {
    let mut truncated = false;

    for (subnet, other_subnet, color, connections) in [
        (
            "source",
            "destination",
            Color::Cyan,
            &broken_connections.source,
        ),
        (
            "destination",
            "source",
            Color::Magenta,
            &broken_connections.destination,
        ),
    ] {
        println!(
            "{}",
            format!(
                "Broken connections from the {subnet} subnet to the {other_subnet} subnet \
                (sender -> receiver: requests since the baseline):"
            )
            .bold()
        );

        let connections_count: usize = connections.values().map(|receivers| receivers.len()).sum();
        if connections_count == 0 {
            println!("  <none>");
            continue;
        }
        if connections_count > MAX_BROKEN_CONNECTIONS_TO_PRINT {
            truncated = true;
            println!(
                "  <too many to print: {} canisters with {connections_count} total broken connections>",
                connections.len()
            );
            continue;
        }

        for (sender, receivers) in connections {
            let sender = sender.to_string();
            for (i, (receiver, requests_sent)) in receivers.iter().enumerate() {
                /*
                 *  canister_id_1 -> canister_id_2: requests_sent
                 *                -> canister_id_3: requests_sent
                 *  canister_id_4 -> canister_id_5: requests_sent
                 *
                 *  Sender column is printed only for the first receiver, replaced with spaces
                 *  otherwise
                 */
                let sender_column = if i == 0 {
                    sender.clone()
                } else {
                    " ".repeat(sender.len())
                };
                println!(
                    "  {} -> {receiver}: {requests_sent}",
                    sender_column.color(color).bold()
                );
            }
        }
    }

    if truncated {
        println!(
            "{}",
            format!(
                "At most {MAX_BROKEN_CONNECTIONS_TO_PRINT} broken connections are printed per \
                subnet. Pass --broken-connections-output-path <FILE> to write all of them to a file."
            )
            .yellow()
        );
    }
}

/// Writes all the broken connections to a CSV file, with one row per (sender, receiver) pair.
fn write_broken_connections(
    broken_connections: &Estimates<BrokenConnections>,
    path: &Path,
) -> anyhow::Result<()> {
    let mut writer = csv::Writer::from_path(path).context("Failed to create the file")?;
    writer.write_record([
        "sender_subnet",
        "sender_canister_id",
        "receiver_canister_id",
        "requests_sent",
    ])?;

    for (sender_subnet, connections) in [
        ("source", &broken_connections.source),
        ("destination", &broken_connections.destination),
    ] {
        for (sender, receivers) in connections {
            for (receiver, requests_sent) in receivers {
                writer.write_record([
                    sender_subnet,
                    &sender.to_string(),
                    &receiver.to_string(),
                    &requests_sent.to_string(),
                ])?;
            }
        }
    }

    writer.flush()?;
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let args = SubnetSplittingToolArgs::parse();

    let logger = util::make_logger();

    match args.subcommand {
        Subcommand::Split(split_args) => do_split(split_args, logger),
        Subcommand::Validate(validate_args) => do_validate(validate_args, logger),
        Subcommand::Estimate(estimate_args) => do_estimate(estimate_args, logger),
    }
}
