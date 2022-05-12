//! Command line interfaces to various subnet recovery processes.
//! Calls the recovery library.
use crate::app_subnet_recovery::{AppSubnetRecovery, AppSubnetRecoveryArgs, StepType};
use crate::error::RecoveryError;
use crate::{NeuronArgs, Recovery, RecoveryArgs};
use ic_types::ReplicaVersion;
use slog::{info, warn, Logger};
use std::convert::TryFrom;
use std::io::{stdin, stdout, Write};
use std::net::IpAddr;

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
///
/// Operations on the subnet state are largely idempotent, but certain
/// execution/restart orders will naturally lead to errors.
pub fn app_subnet_recovery(
    logger: Logger,
    args: RecoveryArgs,
    subnet_recovery_args: AppSubnetRecoveryArgs,
    test: bool,
) {
    print_step(&logger, "App Subnet Recovery");

    info!(logger, "NNS Url: {}", args.nns_url);
    info!(logger, "Starting recovery of subnet with ID:");
    info!(logger, "-> {:?}", subnet_recovery_args.subnet_id);
    info!(logger, "Binary version:");
    info!(logger, "-> {:?}", args.replica_version);
    info!(logger, "Creating recovery directory in {:?}", args.dir);
    wait_for_confirmation(&logger);

    let mut neuron_args = None;
    if !test {
        neuron_args = Some(NeuronArgs {
            dfx_hsm_pin: read_input(&logger, "Enter DFX HSM PIN: "),
            slot: read_input(&logger, "Enter slot number: "),
            neuron_id: read_input(&logger, "Enter neuron ID: "),
            key_id: read_input(&logger, "Enter key ID: "),
        });
    }

    let mut subnet_recovery =
        AppSubnetRecovery::new(logger.clone(), args, neuron_args, subnet_recovery_args);

    if subnet_recovery.params.pub_key.is_none() {
        if let Some(pub_key) = read_optional(
            &logger,
            "Enter public key to add readonly SSH access to subnet: ",
        ) {
            subnet_recovery.params.pub_key = Some(pub_key);
        }
    }

    while let Some((step_type, step)) = subnet_recovery.next() {
        print_step_type(&logger, step_type);
        info!(logger, "{}", step.descr());
        if consent_given(&logger, "Execute now?") {
            match step.exec() {
                Err(RecoveryError::OutputError(e))
                    if matches!(step_type, StepType::ValidateReplayOutput) =>
                {
                    warn!(logger, "Error: {}", e);
                    wait_for_confirmation(&logger);
                }
                res => res.expect("Execution of step failed"),
            }
        }
        // Depending on which step we just executed we might require some user interaction before we can start the next step.
        match step_type {
            StepType::Halt => {
                info!(logger, "Ensure subnet is halted.");
                // This can hardly be automated as currently the notion of "subnet is halted" is unclear,
                // especially in the presence of failures.
                wait_for_confirmation(&logger);

                // We could pick a node with highest finalization height automatically,
                // but we might have a preference between nodes of the same finalization height.
                info!(logger, "Select a node with highest finalization height:");
                let cert_height =
                    Recovery::get_certification_height(subnet_recovery.params.subnet_id)
                        .expect("Failed to get certification height");
                let finalization_heights =
                    Recovery::get_finalization_heights(subnet_recovery.params.subnet_id)
                        .expect("Failed to get finalization heights");
                info!(logger, "Certification height: {}", cert_height);
                info!(logger, "Finalization heights: {:#?}", finalization_heights);

                if let Some(input) = read_optional(&logger, "Enter download IP:") {
                    let node_ip = input
                        .parse::<IpAddr>()
                        .expect("Couldn't parse given address.");
                    subnet_recovery.params.download_node = Some(node_ip);
                }
            }

            StepType::ValidateReplayOutput => {
                if subnet_recovery.params.upgrade_version.is_none() {
                    if let Some(version) = read_optional(&logger, "Upgrade version: ") {
                        let upgrade_version = ReplicaVersion::try_from(version)
                            .expect("Could not parse replica version");
                        subnet_recovery.params.upgrade_version = Some(upgrade_version);
                    }
                }
                if subnet_recovery.params.replacement_nodes.is_none() {
                    let input =
                        read_optional(&logger, "Enter space separated list of replacement nodes: ");
                    if let Some(nodes_string) = input {
                        let nodes = nodes_string.split(' ').map(|s| s.to_string()).collect();
                        subnet_recovery.params.replacement_nodes = Some(nodes);
                    }
                }
            }

            StepType::ProposeCup => {
                if subnet_recovery.params.upload_node.is_none() {
                    if let Some(input) =
                        read_optional(&logger, "Enter IP of node with admin access: ")
                    {
                        let admin_node_ip = input
                            .parse::<IpAddr>()
                            .expect("Couldn't parse given address.");
                        subnet_recovery.params.upload_node = Some(admin_node_ip);
                    }
                }
            }
            _ => {}
        }
    }
    // Print final step we ended in
    if subnet_recovery.success() {
        info!(logger, "Recovery successful!");
    } else {
        warn!(logger, "Recovery unsucessful");
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

/// Print the type of a step as the title
pub fn print_step_type(logger: &Logger, step: StepType) {
    print_step(logger, &format!("{:?}", step))
}

/// Prints a question to the user and returns `true`
/// if the user replied with a yes.
pub fn consent_given(logger: &Logger, question: &str) -> bool {
    info!(logger, "{} [y/N] ", question);
    let _ = stdout().flush();
    let mut s = String::new();
    stdin().read_line(&mut s).expect("Couldn't read user input");
    matches!(s.as_str(), "y\n" | "Y\n")
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
