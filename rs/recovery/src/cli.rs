//! Calls the recovery library.
use crate::{
    DataLocation, NeuronArgs, RecoveryArgs,
    app_subnet_recovery::{AppSubnetRecovery, AppSubnetRecoveryArgs},
    args_merger::merge,
    error::GracefulExpect,
    get_node_heights_from_metrics,
    nns_recovery_failover_nodes::{NNSRecoveryFailoverNodes, NNSRecoveryFailoverNodesArgs},
    nns_recovery_same_nodes::{NNSRecoverySameNodes, NNSRecoverySameNodesArgs},
    recovery_iterator::RecoveryIterator,
    recovery_state::{HasRecoveryState, RecoveryState},
    registry_helper::RegistryHelper,
    steps::Step,
    util,
    util::data_location_from_str,
    util::subnet_id_from_str,
};
use core::fmt::Debug;
use ic_types::{NodeId, ReplicaVersion, SubnetId};
use serde::{Serialize, de::DeserializeOwned};
use slog::{Logger, info, warn};
use std::{
    convert::TryFrom,
    fmt::Display,
    io::{Write, stdin, stdout},
    str::FromStr,
};
use strum::EnumMessage;

const SUMMARY: &str = "The recovery process of an application subnet is only necessary,
if a subnet stopped finalizing new blocks and cannot recover from
this failure on its own. If the root cause of the issue was already
identified and a new replica version with a hotfix is ready to be
elected, a recovery process can be started.

On a high level, this process consists of the following steps:

1. Halting the broken subnet and deploying read only access keys.
2. Downloading the most recent state by:
    a) Downloading and merging certification pools from all available nodes
    b) Choosing a node with the highest finalization height and downloading its
       most recent state,
3. Replaying finalized blocks using `ic-replay`.
4. Optionally proposing and upgrading the subnet to a new replica
   version.
5. Proposing the recovery CUP.
6. Uploading the obtained state to one of the nodes.
7. Unhalting the recovered subnet.";

pub fn app_subnet_recovery(
    logger: Logger,
    args: RecoveryArgs,
    subnet_recovery_args: AppSubnetRecoveryArgs,
    mut neuron_args: Option<NeuronArgs>,
) {
    print_step(&logger, "App Subnet Recovery");
    info!(logger, "\n{}\n", SUMMARY);
    print_summary(&logger, &args, subnet_recovery_args.subnet_id);
    if !args.skip_prompts {
        wait_for_confirmation(&logger);
    }
    if neuron_args.is_none() && !args.test_mode {
        neuron_args = Some(read_neuron_args(&logger));
    }

    let subnet_recovery = AppSubnetRecovery::new(
        logger.clone(),
        args.clone(),
        neuron_args,
        subnet_recovery_args,
    );

    execute_steps(&logger, args.skip_prompts, subnet_recovery);
}

/// NNS is recovered on same nodes by:
///     1. Stop the download node
///     2. Downloading the most recent state
///     3. Updating the config to point to downloaded state
///     4. Replaying finalized blocks using `ic-replay` and delete old checkpoints,
///        optionally add Upgrade version
///     5. Update downloaded registry store
///     6. Create state and registry tar files to upload
///     7. Set and extract the recovery CUP locally
///     8. Upload registry store and cup to all nodes
///     9. Upload state to upload node
pub fn nns_recovery_same_nodes(
    logger: Logger,
    args: RecoveryArgs,
    nns_recovery_args: NNSRecoverySameNodesArgs,
) {
    print_step(&logger, "NNS Recovery Same Nodes");
    print_summary(&logger, &args, nns_recovery_args.subnet_id);
    if !args.skip_prompts {
        wait_for_confirmation(&logger);
    }
    let nns_recovery = NNSRecoverySameNodes::new(logger.clone(), args.clone(), nns_recovery_args);

    execute_steps(&logger, args.skip_prompts, nns_recovery);
}

/// NNS is recovered on failover nodes by:
///     1. Stop the download node
///     2. Downloading the most recent state
///     3. Updating the config to point to downloaded state
///     4. Propose to create new NNS as child subnet
///     5. Download parent NNS registry store
///     6. Replaying finalized blocks using `ic-replay` and delete old checkpoints,
///        add downloaded registry store content
///     7. Create, Upload and Host registry tar on auxiliary host
///     8. Propose recovery CUP
///     9. Wait for CUP and upload child state
pub fn nns_recovery_failover_nodes(
    logger: Logger,
    args: RecoveryArgs,
    nns_recovery_args: NNSRecoveryFailoverNodesArgs,
    mut neuron_args: Option<NeuronArgs>,
) {
    print_step(&logger, "NNS Recovery Failover Nodes");
    print_summary(&logger, &args, nns_recovery_args.subnet_id);
    if !args.skip_prompts {
        wait_for_confirmation(&logger);
    }

    if neuron_args.is_none() && !args.test_mode {
        neuron_args = Some(read_neuron_args(&logger));
    }

    let nns_recovery =
        NNSRecoveryFailoverNodes::new(logger.clone(), args.clone(), neuron_args, nns_recovery_args);

    execute_steps(&logger, args.skip_prompts, nns_recovery);
}

pub fn execute_steps<
    StepType: Copy + Debug + PartialEq + EnumMessage,
    SubcommandArgsType: Serialize + DeserializeOwned,
    I: Iterator<Item = StepType>,
    Steps: HasRecoveryState<StepType = StepType, SubcommandArgsType = SubcommandArgsType>
        + RecoveryIterator<StepType, I>
        + Iterator<Item = (StepType, Box<dyn Step>)>,
>(
    logger: &Logger,
    skip_prompts: bool,
    mut steps: Steps,
) {
    if let Some(next_step) = steps.get_next_step() {
        steps.resume(next_step);
    }

    while let Some((_step_type, step)) = steps.next() {
        execute_step_after_consent(logger, skip_prompts, step);

        if let Err(e) = steps.get_state().and_then(|state| state.save()) {
            warn!(logger, "Failed to save the recovery state: {}", e);
        }
    }
}

fn execute_step_after_consent(logger: &Logger, skip_prompts: bool, step: Box<dyn Step>) {
    info!(logger, "{}", step.descr());
    if !skip_prompts && !consent_given(logger, "Execute now?") {
        return;
    }

    loop {
        match step.exec() {
            Ok(()) => break,
            Err(e) => {
                warn!(logger, "Error: {}", e);
                if !skip_prompts && !consent_given(logger, "Retry now?") {
                    break;
                }
            }
        }
    }
}

fn print_summary(logger: &Logger, args: &RecoveryArgs, subnet_id: SubnetId) {
    info!(logger, "NNS Url: {}", args.nns_url);
    info!(logger, "Starting recovery of subnet with ID:");
    info!(logger, "-> {:?}", subnet_id);
    info!(logger, "Binary version:");
    info!(logger, "-> {:?}", args.replica_version);
    info!(logger, "Creating recovery directory in {:?}", args.dir);
}

pub fn print_height_info(logger: &Logger, registry_helper: &RegistryHelper, subnet_id: SubnetId) {
    info!(logger, "Collecting node heights from metrics...");
    info!(logger, "Select a node with highest finalization height:");
    match get_node_heights_from_metrics(logger, registry_helper, subnet_id) {
        Ok(heights) => info!(logger, "{:#?}", heights),
        Err(err) => warn!(logger, "Failed to query height info: {:?}", err),
    }
}

/// Print the title of a step
pub fn print_step(logger: &Logger, title: &str) {
    let len = title.len();
    info!(logger, "\n");
    info!(logger, "{}", "#".repeat(len + 12));
    info!(logger, "V     {}     V", title);
    info!(logger, "{}", "#".repeat(len + 12));
}

/// Prints a question to the user and returns `true`
/// if the user replied with a yes. Returns `false` if the user replied with a no.
/// Skips all other inputs.
pub fn consent_given(logger: &Logger, question: &str) -> bool {
    info!(logger, "{} [y/n] ", question);
    loop {
        let _ = stdout().flush();
        let mut s = String::new();
        stdin().read_line(&mut s).expect("Couldn't read user input");
        match s.as_str() {
            "y\n" | "Y\n" => return true,
            "n\n" | "N\n" => return false,
            _ => continue,
        }
    }
}

/// Prints a question to the user and returns `true`
/// if the user replied with a yes.
pub fn wait_for_confirmation(logger: &Logger) {
    let _ = read_input(logger, "Press [ENTER] to continue...");
}

/// Request and read input from the user with the given prompt.
pub fn read_input(logger: &Logger, prompt: &str) -> String {
    info!(logger, "{}", prompt);
    let _ = stdout().flush();
    let mut input = String::new();
    stdin().read_line(&mut input).expect("failed to read line");
    input.trim().to_string()
}

/// Request and read input from the user with the given prompt. Convert empty
/// input to `None`.
fn read_optional_input(logger: &Logger, prompt: &str) -> Option<String> {
    let input = read_input(logger, &format!("(Optional) {prompt}"));
    if input.is_empty() { None } else { Some(input) }
}

pub fn read_optional_node_ids(logger: &Logger, prompt: &str) -> Option<Vec<NodeId>> {
    read_optional_type(logger, prompt, |input| {
        input
            .split(' ')
            .map(util::node_id_from_str)
            .collect::<Result<Vec<NodeId>, _>>()
    })
}

pub fn read_optional<T: FromStr>(logger: &Logger, prompt: &str) -> Option<T>
where
    <T as FromStr>::Err: std::fmt::Display,
{
    read_optional_type(logger, prompt, FromStr::from_str)
}

pub fn read_optional_version(logger: &Logger, prompt: &str) -> Option<ReplicaVersion> {
    read_optional_type(logger, prompt, |s| ReplicaVersion::try_from(s))
}

pub fn read_optional_subnet_id(logger: &Logger, prompt: &str) -> Option<SubnetId> {
    read_optional_type(logger, prompt, subnet_id_from_str)
}

pub fn read_optional_data_location(logger: &Logger, prompt: &str) -> Option<DataLocation> {
    read_optional_type(logger, prompt, data_location_from_str)
}

/// Optionally read an input of the generic type by applying the given deserialization function.
pub fn read_optional_type<T, E: Display>(
    logger: &Logger,
    prompt: &str,
    mapper: impl Fn(&str) -> Result<T, E>,
) -> Option<T> {
    loop {
        match mapper(&read_optional_input(logger, prompt)?) {
            Err(e) => {
                warn!(logger, "Could not parse input: {}", e);
            }
            Ok(v) => return Some(v),
        }
    }
}

pub fn read_neuron_args(logger: &Logger) -> NeuronArgs {
    NeuronArgs {
        dfx_hsm_pin: read_input(logger, "Enter DFX HSM PIN: "),
        slot: read_input(logger, "Enter slot number: "),
        neuron_id: read_input(logger, "Enter neuron ID: "),
        key_id: read_input(logger, "Enter key ID: "),
    }
}

pub fn read_and_maybe_update_state<T: Serialize + DeserializeOwned + Clone + PartialEq>(
    logger: &Logger,
    recovery_args: RecoveryArgs,
    subcommand_args: Option<T>,
) -> RecoveryState<T> {
    let state = RecoveryState::<T>::read(&recovery_args.dir)
        .expect_graceful("Failed to read the recovery state file");

    if let Some(state) = state {
        info!(
            &logger,
            "Recovery state file found with parameters {}",
            serde_json::to_string_pretty(&state).expect("Failed to stringify the recovery state"),
        );

        // In system tests where `recovery_args.skip_prompts` is set, we want to execute the CLI
        // arguments without making any assumptions on the saved state.
        if !recovery_args.skip_prompts
            && consent_given(logger, "Resume previously started recovery?")
        {
            let state = maybe_update_state(logger, state, &recovery_args, &subcommand_args);
            // Immediately save the state with potentially new arguments
            if let Err(e) = state.save() {
                warn!(logger, "Failed to save the recovery state: {}", e);
            }
            return state;
        }
    }

    // We are not resuming previously started recovery. Use the command-line arguments as is.
    RecoveryState {
        recovery_args,
        subcommand_args: subcommand_args.expect("subcommand not provided"),
        neuron_args: None,
    }
}

/// Checks if there are any differences between the arguments passed to the tool in this run
/// compared to the last run. If there are, asks user whether to use the new arguments.
fn maybe_update_state<T: Serialize + DeserializeOwned + Clone + PartialEq>(
    logger: &Logger,
    recovery_state: RecoveryState<T>,
    recovery_args: &RecoveryArgs,
    subcommand_args: &Option<T>,
) -> RecoveryState<T> {
    let mut updated_recovery_state = recovery_state.clone();

    updated_recovery_state.recovery_args = merge(
        logger,
        "Recovery Arguments",
        &recovery_state.recovery_args,
        recovery_args,
    )
    .unwrap();

    if let Some(subcommand_args) = subcommand_args.as_ref() {
        updated_recovery_state.subcommand_args = merge(
            logger,
            "Subcommand Arguments",
            &recovery_state.subcommand_args,
            subcommand_args,
        )
        .expect(
            "Failed to merge subcommand arguments. \
             Did you use a different subcommand than in the previous run?",
        );
    }

    if updated_recovery_state != recovery_state
        && consent_given(
            logger,
            "The arguments are different now than in the previous run. Use the new arguments?",
        )
    {
        updated_recovery_state
    } else {
        recovery_state
    }
}
