//! Command line interfaces to various subnet recovery processes.
//! Calls the recovery library.
use crate::app_subnet_recovery::{AppSubnetRecovery, AppSubnetRecoveryArgs};
use crate::nns_recovery_failover_nodes;
use crate::nns_recovery_failover_nodes::{NNSRecoveryFailoverNodes, NNSRecoveryFailoverNodesArgs};
use crate::nns_recovery_same_nodes;
use crate::nns_recovery_same_nodes::{NNSRecoverySameNodes, NNSRecoverySameNodesArgs};
use crate::steps::Step;
use crate::{app_subnet_recovery, util};
use crate::{NeuronArgs, Recovery, RecoveryArgs};
use ic_types::{NodeId, ReplicaVersion, SubnetId};
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

    let mut subnet_recovery =
        AppSubnetRecovery::new(logger.clone(), args, neuron_args, subnet_recovery_args);

    if subnet_recovery.params.pub_key.is_none() {
        subnet_recovery.params.pub_key = read_optional(
            &logger,
            "Enter public key to add readonly SSH access to subnet: ",
        );
    }

    while let Some((step_type, step)) = subnet_recovery.next() {
        print_step(&logger, &format!("{:?}", step_type));
        execute_step_after_consent(&logger, step);

        // Depending on which step we just executed we might require some user interaction before we can start the next step.
        match step_type {
            app_subnet_recovery::StepType::Halt => {
                info!(logger, "Ensure subnet is halted.");
                // This can hardly be automated as currently the notion of "subnet is halted" is unclear,
                // especially in the presence of failures.
                wait_for_confirmation(&logger);

                // We could pick a node with highest finalization height automatically,
                // but we might have a preference between nodes of the same finalization height.
                print_height_info(&logger, subnet_recovery.params.subnet_id);

                if subnet_recovery.params.download_node.is_none() {
                    subnet_recovery.params.download_node =
                        read_optional_ip(&logger, "Enter download IP:");
                }
            }

            app_subnet_recovery::StepType::ValidateReplayOutput => {
                if subnet_recovery.params.upgrade_version.is_none() {
                    subnet_recovery.params.upgrade_version =
                        read_optional_version(&logger, "Upgrade version: ");
                }
                if subnet_recovery.params.replacement_nodes.is_none() {
                    subnet_recovery.params.replacement_nodes = read_optional_node_ids(
                        &logger,
                        "Enter space separated list of replacement nodes: ",
                    );
                }
            }

            app_subnet_recovery::StepType::ProposeCup => {
                if subnet_recovery.params.upload_node.is_none() {
                    subnet_recovery.params.upload_node =
                        read_optional_ip(&logger, "Enter IP of node with admin access: ");
                }
            }
            _ => {}
        }
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

    let mut nns_recovery = NNSRecoverySameNodes::new(logger.clone(), args, nns_recovery_args, test);

    print_height_info(&logger, nns_recovery.params.subnet_id);

    if nns_recovery.params.download_node.is_none() {
        nns_recovery.params.download_node = read_optional_ip(&logger, "Enter download IP:");
    }
    while let Some((step_type, step)) = nns_recovery.next() {
        print_step(&logger, &format!("{:?}", step_type));
        execute_step_after_consent(&logger, step);

        match step_type {
            nns_recovery_same_nodes::StepType::UpdateConfig => {
                if nns_recovery.params.upgrade_version.is_none() {
                    nns_recovery.params.upgrade_version =
                        read_optional_version(&logger, "Upgrade version: ");
                }
            }
            nns_recovery_same_nodes::StepType::UploadCUPandRegistry => {
                if nns_recovery.params.upload_node.is_none() {
                    nns_recovery.params.upload_node = read_optional_ip(&logger, "Enter upload IP:");
                }
            }
            _ => {}
        }
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

    let mut nns_recovery =
        NNSRecoveryFailoverNodes::new(logger.clone(), args, neuron_args, nns_recovery_args);

    print_height_info(&logger, nns_recovery.params.subnet_id);

    if nns_recovery.params.download_node.is_none() {
        nns_recovery.params.download_node = read_optional_ip(&logger, "Enter download IP:");
    }

    while let Some((step_type, step)) = nns_recovery.next() {
        print_step(&logger, &format!("{:?}", step_type));
        execute_step_after_consent(&logger, step);

        match step_type {
            nns_recovery_failover_nodes::StepType::UpdateConfig => {
                if nns_recovery.params.replica_version.is_none() {
                    nns_recovery.params.replica_version = read_optional_version(
                        &logger,
                        "New NNS version (current unassigned version or other version blessed by parent NNS): ",
                    );
                }
                if nns_recovery.params.replacement_nodes.is_none() {
                    nns_recovery.params.replacement_nodes = read_optional_node_ids(
                        &logger,
                        "Enter space separated list of replacement nodes: ",
                    );
                }
            }
            nns_recovery_failover_nodes::StepType::ProposeToCreateSubnet => {
                if nns_recovery.params.parent_nns_host_ip.is_none() {
                    nns_recovery.params.parent_nns_host_ip =
                        read_optional_ip(&logger, "Enter parent NNS IP:");
                }
            }
            nns_recovery_failover_nodes::StepType::CreateRegistryTar => {
                if nns_recovery.params.aux_user.is_none() {
                    nns_recovery.params.aux_user = read_optional(&logger, "Enter aux user:");
                }
                if nns_recovery.params.aux_ip.is_none() {
                    nns_recovery.params.aux_ip = read_optional_ip(&logger, "Enter aux IP:");
                }
            }
            nns_recovery_failover_nodes::StepType::ProposeCUP => {
                if nns_recovery.params.upload_node.is_none() {
                    nns_recovery.params.upload_node =
                        read_optional_ip(&logger, "Enter IP of node with admin access: ");
                }
            }
            _ => {}
        }
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

pub fn print_height_info(logger: &Logger, subnet_id: SubnetId) {
    info!(logger, "Select a node with highest finalization height:");
    if consent_given(logger, "Query height info?") {
        let cert_height = Recovery::get_certification_height(subnet_id);
        let finalization_heights = Recovery::get_finalization_heights(subnet_id);
        if let (Ok(ch), Ok(fh)) = (cert_height, finalization_heights) {
            info!(logger, "Certification height: {}", ch);
            info!(logger, "Finalization heights: {:#?}", fh);
        } else {
            warn!(logger, "Failed to query height info.");
        }
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

pub fn read_optional_node_ids(logger: &Logger, prompt: &str) -> Option<Vec<NodeId>> {
    loop {
        match read_optional(logger, prompt).map(|nodes_string| {
            nodes_string
                .split(' ')
                .map(|s| util::node_id_from_str(s))
                .collect::<Result<Vec<NodeId>, _>>()
        }) {
            Some(Err(e)) => {
                warn!(logger, "Failed to parse node ID: {}", e);
            }
            Some(Ok(v)) => return Some(v),
            None => return None,
        }
    }
}

pub fn read_optional_ip(logger: &Logger, prompt: &str) -> Option<IpAddr> {
    loop {
        match read_optional(logger, prompt).map(|input| input.parse::<IpAddr>()) {
            Some(Err(e)) => {
                warn!(logger, "Couldn't parse given address: {}", e);
            }
            Some(Ok(v)) => return Some(v),
            None => return None,
        }
    }
}

pub fn read_optional_version(logger: &Logger, prompt: &str) -> Option<ReplicaVersion> {
    loop {
        match read_optional(logger, prompt).map(|input| ReplicaVersion::try_from(input)) {
            Some(Err(e)) => {
                warn!(logger, "Could not parse replica version: {}", e);
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
