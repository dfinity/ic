//! Command line interfaces to various subnet recovery processes.
//! Calls the recovery library.
use crate::app_subnet_recovery::{AppSubnetRecovery, AppSubnetRecoveryArgs};
use crate::get_node_heights_from_metrics;
use crate::nns_recovery_failover_nodes::{NNSRecoveryFailoverNodes, NNSRecoveryFailoverNodesArgs};
use crate::nns_recovery_same_nodes::{NNSRecoverySameNodes, NNSRecoverySameNodesArgs};
use crate::steps::Step;
use crate::util;
use crate::util::subnet_id_from_str;
use crate::{NeuronArgs, RecoveryArgs};
use ic_registry_client::client::RegistryClientImpl;
use ic_types::{NodeId, ReplicaVersion, SubnetId};
use slog::{info, warn, Logger};
use std::convert::TryFrom;
use std::io::{stdin, stdout, Write};
use std::net::IpAddr;
use std::sync::Arc;
use url::Url;

/// Application subnets are recovered by:
///     1. Halting the broken subnet
///     2. Downloading the most recent state by
///         a) Choosing a node with max finalization height
///         b) Optionally deploying read only access keys
///     3. Updating the config to point to downloaded state
///     4. Deleting old checkpoints
///     5. Replaying finalized blocks using `ic-replay`
///     6. Optionally proposing and upgrading the subnet to a new replica
///        version     
///     7. Proposing the recovery CUP
///     8. Uploading the replayed state to one of the nodes
///     9. Unhalting the recovered subnet
pub fn app_subnet_recovery(
    logger: Logger,
    args: RecoveryArgs,
    subnet_recovery_args: AppSubnetRecoveryArgs,
    test: bool,
) {
    print_step(&logger, "App Subnet Recovery");
    print_summary(&logger, &args, subnet_recovery_args.subnet_id);
    wait_for_confirmation(&logger);

    let mut neuron_args = None;
    if !test {
        neuron_args = Some(read_neuron_args(&logger));
    }

    let subnet_recovery = AppSubnetRecovery::new(
        logger.clone(),
        args,
        neuron_args,
        subnet_recovery_args,
        true,
    );

    for (step_type, step) in subnet_recovery {
        print_step(&logger, &format!("{:?}", step_type));
        execute_step_after_consent(&logger, step);
    }
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
    test: bool,
) {
    print_step(&logger, "NNS Recovery Same Nodes");
    print_summary(&logger, &args, nns_recovery_args.subnet_id);
    wait_for_confirmation(&logger);

    let nns_recovery =
        NNSRecoverySameNodes::new(logger.clone(), args, nns_recovery_args, test, true);

    for (step_type, step) in nns_recovery {
        print_step(&logger, &format!("{:?}", step_type));
        execute_step_after_consent(&logger, step);
    }
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
    test: bool,
) {
    print_step(&logger, "NNS Recovery Failover Nodes");
    print_summary(&logger, &args, nns_recovery_args.subnet_id);
    wait_for_confirmation(&logger);

    let mut neuron_args = None;
    if !test {
        neuron_args = Some(read_neuron_args(&logger));
    }

    let nns_recovery =
        NNSRecoveryFailoverNodes::new(logger.clone(), args, neuron_args, nns_recovery_args, true);

    for (step_type, step) in nns_recovery {
        print_step(&logger, &format!("{:?}", step_type));
        execute_step_after_consent(&logger, step);
    }
}

pub fn execute_step_after_consent(logger: &Logger, step: Box<dyn Step>) {
    info!(logger, "{}", step.descr());
    if consent_given(logger, "Execute now?") {
        loop {
            match step.exec() {
                Ok(()) => break,
                Err(e) => {
                    warn!(logger, "Error: {}", e);
                    if !consent_given(logger, "Retry now?") {
                        break;
                    }
                }
            }
        }
    }
}

pub fn print_summary(logger: &Logger, args: &RecoveryArgs, subnet_id: SubnetId) {
    info!(logger, "NNS Url: {}", args.nns_url);
    info!(logger, "Starting recovery of subnet with ID:");
    info!(logger, "-> {:?}", subnet_id);
    info!(logger, "Binary version:");
    info!(logger, "-> {:?}", args.replica_version);
    info!(logger, "Creating recovery directory in {:?}", args.dir);
}

pub fn print_height_info(
    logger: &Logger,
    registry_client: Arc<RegistryClientImpl>,
    subnet_id: SubnetId,
) {
    info!(logger, "Collecting node heights from metrics...");
    info!(logger, "Select a node with highest finalization height:");
    match get_node_heights_from_metrics(logger, registry_client, subnet_id) {
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
pub fn read_optional(logger: &Logger, prompt: &str) -> Option<String> {
    let input = read_input(logger, &format!("(Optional) {}", prompt));
    if input.is_empty() {
        None
    } else {
        Some(input)
    }
}

pub fn read_optional_node_ids(logger: &Logger, prompt: &str) -> Option<Vec<NodeId>> {
    read_optional_type(logger, prompt, |input| {
        input
            .split(' ')
            .map(util::node_id_from_str)
            .collect::<Result<Vec<NodeId>, _>>()
    })
}

pub fn read_optional_ip(logger: &Logger, prompt: &str) -> Option<IpAddr> {
    read_optional_type(logger, prompt, |input| {
        input.parse::<IpAddr>().map_err(|err| err.to_string())
    })
}

pub fn read_optional_version(logger: &Logger, prompt: &str) -> Option<ReplicaVersion> {
    read_optional_type(logger, prompt, |input| {
        ReplicaVersion::try_from(input).map_err(|err| err.to_string())
    })
}

pub fn read_optional_url(logger: &Logger, prompt: &str) -> Option<Url> {
    read_optional_type(logger, prompt, |input| {
        Url::parse(&input).map_err(|e| e.to_string())
    })
}

pub fn read_optional_subnet_id(logger: &Logger, prompt: &str) -> Option<SubnetId> {
    read_optional_type(logger, prompt, |input| subnet_id_from_str(&input))
}

/// Optionally read an input of the generic type by applying the given deserialization function.
pub fn read_optional_type<T>(
    logger: &Logger,
    prompt: &str,
    mapper: impl Fn(String) -> Result<T, String> + Copy,
) -> Option<T> {
    loop {
        match read_optional(logger, prompt).map(mapper) {
            Some(Err(e)) => {
                warn!(logger, "Could not parse input: {}", e);
            }
            Some(Ok(v)) => return Some(v),
            None => return None,
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
