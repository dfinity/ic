use crate::{
    admin_helper::get_propose_recovery_cup_command,
    layout::Layout,
    readiness,
    subnet_merging::TargetSubnet,
    utils::{
        ensure_default_initial_dkg_subnet_is_not_merged, get_subnet_record_at_version, wait_for,
    },
};

use ic_base_types::SubnetId;
use ic_cup_explorer::get_cup;
use ic_protobuf::types::v1 as pb;
use ic_recovery::{
    IC_CHECKPOINTS_PATH, IC_DATA_PATH, Recovery,
    admin_helper::AdminHelper,
    command_helper::confirm_exec_cmd,
    error::{RecoveryError, RecoveryResult},
    file_sync_helper::{create_dir, remove_dir},
    registry_helper::RegistryHelper,
    steps::{
        AdminStep, CMD_STOP_REPLICA, CopyLocalIcStateStep, DownloadIcDataStep, Step,
        UploadStateAndRestartStep, stop_and_restart_replica_command,
    },
    util::{CheckpointHeight, DataLocation, ExecutionMode, SshUser, block_on},
};
use ic_state_layout::{CheckpointStatus, StateLayout};
use ic_subnet_tools::{
    agent_helper::AgentHelper,
    state_tool_helper,
    utils::{get_batch_time_from_cup, get_cup as read_cup_file},
    validation::validate_artifacts,
};
use ic_types::{
    Height, Time,
    consensus::{CatchUpPackage, HasHeight},
};
use slog::{Logger, info};
use url::Url;

use std::{
    net::{IpAddr, Ipv6Addr},
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[cfg(test)]
mod tests;

/// Waits until the record of the subnet that is being merged away is labeled
/// "cooling down" and persists the registry version `V` it was read at (not
/// necessarily the version that set the label), which is what the merge
/// readiness condition is evaluated against.
pub(crate) struct CheckCoolingDownStep {
    pub(crate) source_subnet_id: SubnetId,
    pub(crate) registry_helper: RegistryHelper,
    pub(crate) layout: Layout,
    pub(crate) timeout: Duration,
    pub(crate) poll_interval: Duration,
    pub(crate) logger: Logger,
}

impl Step for CheckCoolingDownStep {
    fn descr(&self) -> String {
        format!(
            "Wait until the registry labels subnet {} as \"cooling down\", and record the \
             registry version at which the label was read.",
            self.source_subnet_id,
        )
    }

    fn exec(&self) -> RecoveryResult<()> {
        let source_subnet_id = self.source_subnet_id;
        let cooling_down_version = wait_for(
            &format!("subnet {source_subnet_id} is labeled \"cooling down\""),
            self.timeout,
            self.poll_interval,
            &self.logger,
            || {
                let (registry_version, subnet_record) =
                    self.registry_helper.get_subnet_record(source_subnet_id)?;
                let Some(subnet_record) = subnet_record else {
                    return Err(RecoveryError::RegistryError(format!(
                        "No record of subnet {source_subnet_id} at registry version \
                         {registry_version}"
                    )));
                };
                if !subnet_record.cooling_down {
                    return Err(RecoveryError::RegistryError(format!(
                        "Subnet {source_subnet_id} is not labeled \"cooling down\" at registry \
                         version {registry_version} yet"
                    )));
                }
                Ok(registry_version)
            },
        )?;

        info!(
            self.logger,
            "Subnet {source_subnet_id} is labeled \"cooling down\" at registry version \
             {cooling_down_version}",
        );

        self.layout
            .write_cooling_down_registry_version(source_subnet_id, cooling_down_version.get())
    }
}

/// Waits until the merge readiness condition holds for the subnet that is
/// cooling down.
pub(crate) struct CheckMergeReadinessStep {
    pub(crate) source_subnet_id: SubnetId,
    pub(crate) registry_helper: RegistryHelper,
    pub(crate) layout: Layout,
    pub(crate) timeout: Duration,
    pub(crate) poll_interval: Duration,
    pub(crate) logger: Logger,
}

impl Step for CheckMergeReadinessStep {
    fn descr(&self) -> String {
        format!(
            "Wait until subnet {} is ready to be merged.",
            self.source_subnet_id,
        )
    }

    fn exec(&self) -> RecoveryResult<()> {
        let registry_version = self
            .layout
            .read_cooling_down_registry_version(self.source_subnet_id)?;

        readiness::await_merge_readiness(
            &self.registry_helper,
            self.source_subnet_id,
            registry_version,
            self.timeout,
            self.poll_interval,
            &self.logger,
        )
    }
}

/// Waits until the CUP where the subnet halts appears on the node the state is
/// downloaded from. At that point, we have the guarantee that the subnet is
/// halted. The CUP, as served by the node, is persisted, so that the state
/// downloaded later can be validated against it (its threshold signature and
/// its state hash) without downloading the CUP again.
pub(crate) struct WaitForHaltingCupStep {
    pub(crate) subnet_id: SubnetId,
    pub(crate) node: DataLocation,
    pub(crate) registry_helper: RegistryHelper,
    pub(crate) layout: Layout,
    pub(crate) timeout: Duration,
    pub(crate) poll_interval: Duration,
    pub(crate) logger: Logger,
}

impl Step for WaitForHaltingCupStep {
    fn descr(&self) -> String {
        format!(
            "Wait until node {} serves the CUP subnet {} halts at.",
            self.node_ip(),
            self.subnet_id,
        )
    }

    fn exec(&self) -> RecoveryResult<()> {
        let (cup, proto) = wait_for(
            &format!("subnet {} reaches the CUP it halts at", self.subnet_id),
            self.timeout,
            self.poll_interval,
            &self.logger,
            || {
                self.check()?.ok_or_else(|| {
                    RecoveryError::UnexpectedError(format!(
                        "node {} does not serve the CUP subnet {} halts at yet",
                        self.node_ip(),
                        self.subnet_id,
                    ))
                })
            },
        )?;

        // Logged so that the operator can double check that this is the CUP of
        // the current halt, and not of an earlier one the node is lagging at.
        info!(
            self.logger,
            "Subnet {} halted at the CUP at height {} with registry version {} and state hash \
             {}",
            self.subnet_id,
            cup.height(),
            cup.content.registry_version(),
            hex::encode(&cup.content.state_hash.get_ref().0),
        );

        self.layout.write_halting_cup(self.subnet_id, &proto)
    }
}

impl WaitForHaltingCupStep {
    fn node_ip(&self) -> IpAddr {
        match self.node {
            DataLocation::Remote(ip) => ip,
            DataLocation::Local => IpAddr::V6(Ipv6Addr::LOCALHOST),
        }
    }

    fn node_url(&self) -> RecoveryResult<Url> {
        let node_ip = self.node_ip();
        Url::parse(&format!("http://[{node_ip}]:8080/")).map_err(|err| {
            RecoveryError::UnexpectedError(format!("Invalid URL of node {node_ip}: {err}"))
        })
    }

    /// Returns the halting CUP, both decoded and as the protobuf served by the
    /// node, if the node serves it, `None` if it does not yet, and an error if
    /// the node could not be asked.
    fn check(&self) -> RecoveryResult<Option<(CatchUpPackage, pb::CatchUpPackage)>> {
        let node_ip = self.node_ip();
        let node_url = self.node_url()?;
        let Some(proto) = block_on(get_cup(&node_url)).map_err(|err| {
            RecoveryError::UnexpectedError(format!(
                "Failed to get the CUP of node {node_ip}: {err}"
            ))
        })?
        else {
            return Ok(None);
        };
        // Also checks the integrity of the CUP.
        let cup = CatchUpPackage::try_from(&proto).map_err(|err| {
            RecoveryError::UnexpectedError(format!(
                "Failed to decode the CUP of node {node_ip}: {err}"
            ))
        })?;
        let cup_height = cup.height();
        let cup_registry_version = cup.content.registry_version();

        // The `halt_at_cup_height` flag is read at the registry version of the
        // summary block active at a height, and that version only changes at a
        // summary, so batch delivery stops exactly when the summary carrying the
        // flag becomes active. No CUP follows the one carrying the flag, so the
        // first such CUP is the one the subnet halts at.
        let halting = get_subnet_record_at_version(
            &self.registry_helper,
            self.subnet_id,
            cup_registry_version,
        )?
        .is_some_and(|record| record.halt_at_cup_height);
        if !halting {
            info!(
                self.logger,
                "Node {node_ip} serves the CUP at height {cup_height}, whose registry version \
                 {cup_registry_version} does not carry the `halt_at_cup_height` flag of subnet {} \
                 yet",
                self.subnet_id,
            );
            return Ok(None);
        }

        Ok(Some((cup, proto)))
    }
}

/// Stops the replica and crypto vault of the node the state of a subnet is
/// downloaded from, but only once the node holds a finished checkpoint at the
/// height of the CUP the subnet halts at.
///
/// Holding the halting CUP does not imply holding the checkpoint at its
/// height: the node may hold the CUP before it has written the checkpoint (e.g.
/// if it got the CUP from its peers), and a checkpoint stays unverified while
/// its files are still being written (or state-synced).
pub(crate) struct StopReplicaAtHaltingCheckpointStep {
    pub(crate) subnet_id: SubnetId,
    pub(crate) node: ExecutionMode,
    pub(crate) require_confirmation: bool,
    pub(crate) layout: Layout,
    pub(crate) timeout: Duration,
    pub(crate) poll_interval: Duration,
    pub(crate) logger: Logger,
}

impl Step for StopReplicaAtHaltingCheckpointStep {
    fn descr(&self) -> String {
        format!(
            "Wait until {} holds a finished checkpoint at the height of the CUP subnet {} halts \
             at, then stop its replica and crypto vault.",
            self.node, self.subnet_id,
        )
    }

    fn exec(&self) -> RecoveryResult<()> {
        let height = read_cup_file(&self.layout.halting_cup_file(self.subnet_id))?.height();

        wait_for(
            &format!(
                "{} holds a finished checkpoint at height {height} of subnet {}",
                self.node, self.subnet_id,
            ),
            self.timeout,
            self.poll_interval,
            &self.logger,
            || self.check_checkpoint_finished(height),
        )?;
        info!(
            self.logger,
            "{} holds a finished checkpoint at height {height} of subnet {}",
            self.node,
            self.subnet_id,
        );

        info!(
            self.logger,
            "Stopping the replica and crypto vault on {}", self.node
        );
        // Unlike the checks on the node, stopping its replica asks for
        // confirmation on a local node too.
        self.node.execute(
            CMD_STOP_REPLICA.to_string(),
            self.require_confirmation.then_some(&self.logger),
        )?;
        Ok(())
    }
}

impl StopReplicaAtHaltingCheckpointStep {
    /// Succeeds if the node holds the checkpoint at `height` and it is
    /// verified, i.e. finished.
    fn check_checkpoint_finished(&self, height: Height) -> RecoveryResult<()> {
        let checkpoint = PathBuf::from(IC_DATA_PATH)
            .join(IC_CHECKPOINTS_PATH)
            .join(StateLayout::checkpoint_name(height));

        match self.node.checkpoint_status(&checkpoint)? {
            Some(CheckpointStatus::Verified) => Ok(()),
            None => Err(RecoveryError::UnexpectedError(format!(
                "{} does not hold the checkpoint {} yet",
                self.node,
                checkpoint.display()
            ))),
            Some(CheckpointStatus::UnverifiedRegular | CheckpointStatus::UnverifiedStateSync) => {
                Err(RecoveryError::UnexpectedError(format!(
                    "the checkpoint {} on {} is not finished yet",
                    checkpoint.display(),
                    self.node
                )))
            }
        }
    }
}

/// Downloads the checkpoint at the height of the CUP a subnet halted at, as
/// recorded by [WaitForHaltingCupStep], into that subnet's working directory:
/// over SSH from a remote node, and by copying it if the tool runs on the node.
/// The CUP itself is not downloaded again. If the node does not hold that
/// checkpoint, the step fails.
pub(crate) struct DownloadStateStep {
    pub(crate) subnet_id: SubnetId,
    pub(crate) target_subnet: TargetSubnet,
    pub(crate) node: ExecutionMode,
    pub(crate) require_confirmation: bool,
    pub(crate) layout: Layout,
    pub(crate) logger: Logger,
}

impl Step for DownloadStateStep {
    fn descr(&self) -> String {
        format!(
            "Download the checkpoint at the height of the CUP the {} subnet {} halted at from {} \
             to {}.",
            self.target_subnet,
            self.subnet_id,
            self.node,
            self.layout.work_dir(self.target_subnet).display(),
        )
    }

    fn exec(&self) -> RecoveryResult<()> {
        let height = read_cup_file(&self.layout.halting_cup_file(self.subnet_id))?.height();
        let working_dir = self.layout.work_dir(self.target_subnet);

        // A working directory is reused when the download is retried, e.g.
        // after an interrupted transfer, or when the tool is run again with the
        // same directory. Only the checkpoint at the halting height is kept, so
        // that checkpoints at other heights cannot be mistaken for the
        // downloaded one by later steps.
        self.layout
            .remove_checkpoints_except(self.target_subnet, height)?;

        match &self.node {
            ExecutionMode::Local => {
                // Unlike the `rsync --delete` of a download, `cp` keeps files
                // that are only in a stale copy, which would then enter the
                // recomputed manifest, so the checkpoint is copied afresh.
                remove_dir(&self.layout.checkpoint_dir(self.target_subnet, height))?;
                let data_includes = Recovery::get_ic_state_includes(
                    &self.logger,
                    ExecutionMode::Local,
                    CheckpointHeight::Specified(height.get()),
                )?;
                CopyLocalIcStateStep {
                    logger: self.logger.clone(),
                    working_dir,
                    require_confirmation: self.require_confirmation,
                    data_includes,
                    include_config: false,
                }
                .exec()
            }
            // The checkpoint at the halting height is kept: `rsync --delete`
            // removes stale files from it, and `--partial` lets a retry resume
            // the transfer instead of starting over.
            ExecutionMode::Remote(ssh_helper) => {
                ssh_helper.wait_for_access().map_err(|err| {
                    RecoveryError::UnexpectedError(format!(
                        "SSH access to {} with the admin key denied: {err}",
                        self.node
                    ))
                })?;
                let data_includes = Recovery::get_ic_state_includes(
                    &self.logger,
                    ExecutionMode::Remote(ssh_helper.clone()),
                    CheckpointHeight::Specified(height.get()),
                )?;
                DownloadIcDataStep {
                    logger: self.logger.clone(),
                    ssh_helper: ssh_helper.clone(),
                    // No pristine copy of the downloaded state has to be kept
                    // apart, as the merge never modifies it in place.
                    backup_dir: None,
                    working_dir,
                    data_includes,
                    include_config: false,
                }
                .exec()
            }
        }
    }
}

/// Validates the CUP a subnet halted at, as recorded by [WaitForHaltingCupStep]
/// from the node's public endpoint, and the state downloaded at its height: the
/// subnet's public key is taken from the NNS signed state tree, the CUP
/// signature is verified against it, and the manifest recomputed from the
/// downloaded state has to match the state hash the CUP names.
pub(crate) struct ValidateCupStep {
    pub(crate) subnet_id: SubnetId,
    pub(crate) target_subnet: TargetSubnet,
    pub(crate) nns_url: Url,
    pub(crate) layout: Layout,
    pub(crate) logger: Logger,
}

impl Step for ValidateCupStep {
    fn descr(&self) -> String {
        format!(
            "Validate the CUP and the state downloaded from the {} subnet {}, and preserve the \
             subnet's public key and the state tree (with only the relevant paths).",
            self.target_subnet, self.subnet_id,
        )
    }

    fn exec(&self) -> RecoveryResult<()> {
        // 1. Compute the manifest of the downloaded state. This comes before
        // getting the state tree: hashing a large state can take longer than
        // the certificate of the state tree stays fresh, and the validation
        // below rejects a stale certificate.
        info!(self.logger, "Computing the state manifest");
        // The checkpoint at the height of the halting CUP, whose state hash the
        // manifest is checked against.
        let height = read_cup_file(&self.layout.halting_cup_file(self.subnet_id))?.height();
        let checkpoint_dir = self.layout.checkpoint_dir(self.target_subnet, height);
        if !checkpoint_dir.is_dir() {
            return Err(RecoveryError::UnexpectedError(format!(
                "the checkpoint {} at the height of the halting CUP was not downloaded",
                checkpoint_dir.display()
            )));
        }
        let manifest_path = self.layout.actual_manifest_file(self.subnet_id);

        state_tool_helper::compute_manifest(&checkpoint_dir, &manifest_path)?;

        // 2. Get the NNS signed State Tree and the subnet's public key.
        info!(self.logger, "Getting the NNS signed State Tree");
        let agent_helper = AgentHelper::new(
            &self.nns_url,
            Some(self.layout.nns_public_key_file().as_path()),
            self.logger.clone(),
        )?;

        let pruned_state_tree = agent_helper.read_subnet_data(self.subnet_id)?;
        pruned_state_tree.save_to_file(&self.layout.pruned_state_tree_file(self.subnet_id))?;
        pruned_state_tree
            .save_public_key_to_file(&self.layout.subnet_public_key_file(self.subnet_id))?;

        // 3. Validate all the artifacts (state tree, CUP, state manifest).
        validate_artifacts(
            self.layout.pruned_state_tree_file(self.subnet_id),
            Some(self.layout.nns_public_key_file().as_path()),
            self.layout.halting_cup_file(self.subnet_id),
            manifest_path,
            self.subnet_id,
            &self.logger,
        )
    }
}

/// Computes the manifest the merged state is expected to have from the
/// manifests of the states the two subnets halted at, which the validation
/// steps checked against the halting CUPs. This ties the state hash of the
/// merged state to the state hashes in the two halting CUPs.
pub(crate) struct ComputeExpectedMergedManifestStep {
    pub(crate) source_subnet_id: SubnetId,
    pub(crate) destination_subnet_id: SubnetId,
    pub(crate) layout: Layout,
}

impl Step for ComputeExpectedMergedManifestStep {
    fn descr(&self) -> String {
        format!(
            "Compute the manifest the merged state is expected to have from the manifests {} and \
             {} of the validated states of the destination and source subnets, and write it to \
             {}.",
            self.layout
                .actual_manifest_file(self.destination_subnet_id)
                .display(),
            self.layout
                .actual_manifest_file(self.source_subnet_id)
                .display(),
            self.layout.expected_merged_state_manifest_file().display(),
        )
    }

    fn exec(&self) -> RecoveryResult<()> {
        state_tool_helper::merge_manifests(
            &self.layout.actual_manifest_file(self.destination_subnet_id),
            &self.layout.actual_manifest_file(self.source_subnet_id),
            &self.layout.expected_merged_state_manifest_file(),
        )
    }
}

/// Assembles the merged state from the states the two subnets halted at: the
/// state of the destination subnet, with the canisters and canister snapshots
/// of the source subnet added to it, as a new checkpoint that the destination
/// subnet is then recovered at.
pub(crate) struct MergeStatesStep {
    pub(crate) source_subnet_id: SubnetId,
    pub(crate) destination_subnet_id: SubnetId,
    pub(crate) layout: Layout,
    pub(crate) logger: Logger,
}

impl Step for MergeStatesStep {
    fn descr(&self) -> String {
        format!(
            "Assemble the merged state from the checkpoints downloaded to {} and {} at the \
             heights of the CUPs the two subnets halted at, as a new checkpoint in {}, compute \
             its manifest, and check it against the expected manifest {}.",
            self.layout.work_dir(TargetSubnet::Source).display(),
            self.layout.work_dir(TargetSubnet::Destination).display(),
            self.layout.merged_work_dir().display(),
            self.layout.expected_merged_state_manifest_file().display(),
        )
    }

    fn exec(&self) -> RecoveryResult<()> {
        // The checkpoints the two subnets halted at, which the validation steps
        // checked against the halting CUPs, selected by height like in the
        // steps that downloaded and validated them.
        let source_height =
            read_cup_file(&self.layout.halting_cup_file(self.source_subnet_id))?.height();
        let destination_height =
            read_cup_file(&self.layout.halting_cup_file(self.destination_subnet_id))?.height();
        let source_checkpoint = self
            .layout
            .checkpoint_dir(TargetSubnet::Source, source_height);
        let destination_checkpoint = self
            .layout
            .checkpoint_dir(TargetSubnet::Destination, destination_height);

        let merged_height = merged_recovery_height(source_height, destination_height);
        let merged_checkpoint = self.layout.merged_checkpoint_dir(merged_height);

        info!(
            self.logger,
            "The source subnet halted at height {source_height} and the destination subnet at \
             height {destination_height}; the merged state is the checkpoint {merged_height}",
        );

        // Clean up after a previous run of this step.
        let manifest_path = self.layout.merged_state_manifest_file();
        remove_file_if_exists(&manifest_path)?;
        remove_dir(&self.layout.merged_checkpoints_dir())?;

        info!(self.logger, "Merging the states");
        state_tool_helper::merge_checkpoints(
            &destination_checkpoint,
            &source_checkpoint,
            &merged_checkpoint,
        )?;

        info!(self.logger, "Computing the manifest of the merged state");
        state_tool_helper::compute_manifest(&merged_checkpoint, &manifest_path)?;

        info!(self.logger, "Validating the manifest of the merged state");
        let state_hash = merged_state_hash(&self.layout)?;
        info!(
            self.logger,
            "The merged state at height {merged_height} has the expected state hash {state_hash}"
        );

        Ok(())
    }
}

/// Overlay files retain the heights at which either subnet wrote them. The
/// recovery height must exceed both halting heights so that subsequent writes
/// take precedence over all imported overlays when the page maps are reloaded.
fn merged_recovery_height(source_height: Height, destination_height: Height) -> Height {
    Recovery::get_recovery_height(source_height.max(destination_height))
}

/// Removes the file at `path`, which need not exist.
fn remove_file_if_exists(path: &Path) -> RecoveryResult<()> {
    match std::fs::remove_file(path) {
        Err(err) if err.kind() != std::io::ErrorKind::NotFound => {
            Err(RecoveryError::file_error(path, err))
        }
        _ => Ok(()),
    }
}

/// Waits until the routing table no longer assigns any canister ID range to the
/// subnet that was merged away, and persists the registry version it was read
/// at (not necessarily the version that rerouted the ranges), which is what
/// every other subnet has to reach before that subnet may be deleted.
pub(crate) struct CheckRoutingTableStep {
    pub(crate) source_subnet_id: SubnetId,
    pub(crate) destination_subnet_id: SubnetId,
    pub(crate) registry_helper: RegistryHelper,
    pub(crate) layout: Layout,
    pub(crate) timeout: Duration,
    pub(crate) poll_interval: Duration,
    pub(crate) logger: Logger,
}

impl Step for CheckRoutingTableStep {
    fn descr(&self) -> String {
        format!(
            "Wait until the routing table assigns no canister id range to subnet {} anymore, and \
             record the registry version at which this was read.",
            self.source_subnet_id,
        )
    }

    fn exec(&self) -> RecoveryResult<()> {
        let source_subnet_id = self.source_subnet_id;
        let (merge_registry_version, routing_table) = wait_for(
            &format!("subnet {source_subnet_id} hosts no canister id range anymore"),
            self.timeout,
            self.poll_interval,
            &self.logger,
            || {
                let (registry_version, routing_table) = self.registry_helper.get_routing_table()?;
                let Some(routing_table) = routing_table else {
                    return Err(RecoveryError::RegistryError(format!(
                        "No routing table at registry version {registry_version}"
                    )));
                };
                if !routing_table.ranges(source_subnet_id).is_empty() {
                    return Err(RecoveryError::RegistryError(format!(
                        "Subnet {source_subnet_id} still hosts canister id ranges at registry \
                         version {registry_version}"
                    )));
                }
                Ok((registry_version, routing_table))
            },
        )?;

        info!(
            self.logger,
            "Subnet {source_subnet_id} hosts no canister id range anymore at registry version \
             {merge_registry_version}; subnet {} hosts: {:#?}",
            self.destination_subnet_id,
            routing_table.ranges(self.destination_subnet_id),
        );

        self.layout
            .write_merge_registry_version(source_subnet_id, merge_registry_version.get())
    }
}

/// The state hash of the merged state assembled by [MergeStatesStep]: the root
/// hash of its manifest, which has to match the expected one.
fn merged_state_hash(layout: &Layout) -> RecoveryResult<String> {
    let manifest_path = layout.merged_state_manifest_file();
    let state_hash = state_tool_helper::verify_manifest(&manifest_path)
        .map_err(|err| RecoveryError::validation_failed("Manifest verification failed", err))?;
    let expected_manifest_path = layout.expected_merged_state_manifest_file();
    let expected_state_hash =
        state_tool_helper::verify_manifest(&expected_manifest_path).map_err(|err| {
            RecoveryError::validation_failed("Expected manifest verification failed", err)
        })?;
    if state_hash != expected_state_hash {
        return Err(RecoveryError::ValidationFailed(format!(
            "The merged state has the state hash {state_hash}, but the state hash \
             {expected_state_hash} is expected; compare {} with {}",
            manifest_path.display(),
            expected_manifest_path.display(),
        )));
    }
    Ok(state_hash)
}

/// Checks that `time`, which the recovery CUP is stamped with, is past each of
/// `halting_times`, the times of the CUPs the given subnets halted at.
fn check_time_is_past_halting_times(
    time: SystemTime,
    halting_times: &[(SubnetId, Time)],
) -> RecoveryResult<()> {
    let time_nanos = time
        .duration_since(UNIX_EPOCH)
        .map_err(|err| {
            RecoveryError::UnexpectedError(format!(
                "The clock of this machine is before the Unix epoch: {err}"
            ))
        })?
        .as_nanos();
    for (subnet_id, halting_time) in halting_times {
        if time_nanos <= u128::from(halting_time.as_nanos_since_unix_epoch()) {
            return Err(RecoveryError::ValidationFailed(format!(
                "The time the recovery CUP would be stamped with ({time_nanos} ns since the \
                 Unix epoch) is not past the time {halting_time} of the CUP subnet {subnet_id} \
                 halted at. Check the clock of this machine and retry.",
            )));
        }
    }
    Ok(())
}

/// Proposes the recovery CUP of the destination subnet at the merged state
/// assembled by [MergeStatesStep].
///
/// Its height and state hash are read when the step is described or executed
/// rather than when it is created: a step that fails to be created is skipped,
/// and the tool would then carry on without a recovery CUP.
pub(crate) struct ProposeRecoveryCupStep {
    pub(crate) source_subnet_id: SubnetId,
    pub(crate) destination_subnet_id: SubnetId,
    pub(crate) admin_helper: AdminHelper,
    pub(crate) registry_helper: RegistryHelper,
    pub(crate) layout: Layout,
    pub(crate) logger: Logger,
}

impl ProposeRecoveryCupStep {
    /// The proposal for the recovery CUP at the merged state, stamped with
    /// `time`. The height of the merged state follows from the heights of the
    /// CUPs the two subnets halted at, as in [MergeStatesStep].
    fn admin_step(&self, time: SystemTime) -> RecoveryResult<AdminStep> {
        let source_height =
            read_cup_file(&self.layout.halting_cup_file(self.source_subnet_id))?.height();
        let destination_height =
            read_cup_file(&self.layout.halting_cup_file(self.destination_subnet_id))?.height();

        Ok(AdminStep {
            logger: self.logger.clone(),
            ic_admin_cmd: get_propose_recovery_cup_command(
                &self.admin_helper,
                self.source_subnet_id,
                self.destination_subnet_id,
                merged_recovery_height(source_height, destination_height),
                merged_state_hash(&self.layout)?,
                time,
            ),
        })
    }

    /// Checks that `time`, which the recovery CUP is stamped with, is past the
    /// batch times of both checkpoints the merged state is assembled from, i.e.
    /// the times of the CUPs the two subnets halted at, so that time is
    /// strictly monotone from the point of view of every canister.
    ///
    /// Both subnets halted well before this step runs, so this only fails if
    /// the clock of this machine is behind the clocks of the subnets.
    fn check_time_is_past_halting_cups(&self, time: SystemTime) -> RecoveryResult<()> {
        let halting_times = [self.source_subnet_id, self.destination_subnet_id]
            .into_iter()
            .map(|subnet_id| {
                get_batch_time_from_cup(&self.layout.halting_cup_file(subnet_id))
                    .map(|halting_time| (subnet_id, halting_time))
            })
            .collect::<RecoveryResult<Vec<_>>>()?;
        check_time_is_past_halting_times(time, &halting_times)
    }
}

impl Step for ProposeRecoveryCupStep {
    fn descr(&self) -> String {
        let summary = format!(
            "Propose a recovery CUP for subnet {} at the height and state hash of the merged \
             state, whose manifest is {}, with its DKG run by the default initial DKG subnet (or the \
             NNS subnet if none is set), which must be neither subnet of the merge.",
            self.destination_subnet_id,
            self.layout.merged_state_manifest_file().display(),
        );
        // Like the description of any other proposal, this shows the command
        // that is about to run, except for its timestamp, which is taken anew
        // when the step is executed. The command can only be missing if the
        // operator went on without the merged state, e.g. after skipping or
        // declining `MergeStates`.
        match self.admin_step(SystemTime::now()) {
            Ok(step) => format!(
                "{summary} The command, up to the timestamp, which is taken when it is run: {}",
                step.descr(),
            ),
            Err(err) => format!("{summary} The command cannot be shown yet: {err}"),
        }
    }

    fn exec(&self) -> RecoveryResult<()> {
        // Checked when the tool starts, but the default may have changed since.
        ensure_default_initial_dkg_subnet_is_not_merged(
            &self.registry_helper,
            self.source_subnet_id,
            self.destination_subnet_id,
        )?;
        let time = SystemTime::now();
        self.check_time_is_past_halting_cups(time)?;
        let step = self.admin_step(time)?;
        info!(self.logger, "{}", step.descr());
        step.exec()
    }
}

/// Replaces the state of the node of the destination subnet, whose replica was
/// stopped before its state was downloaded, with the merged state.
///
/// If the tool runs on that node, a copy of the merged state is moved into
/// place, because the merged checkpoint's files are hard links into the tool's
/// directory, and the replica can't start from files shared with it.
pub(crate) struct UploadMergedStateStep {
    pub(crate) node: DataLocation,
    pub(crate) layout: Layout,
    pub(crate) require_confirmation: bool,
    pub(crate) key_file: Option<PathBuf>,
    pub(crate) logger: Logger,
}

impl UploadMergedStateStep {
    fn upload_step(&self) -> UploadStateAndRestartStep {
        let data_src = match self.node {
            DataLocation::Local => self.layout.merged_ic_state_copy_dir(),
            DataLocation::Remote(_) => self.layout.merged_ic_state_dir(),
        };
        UploadStateAndRestartStep {
            logger: self.logger.clone(),
            ssh_user: SshUser::Admin,
            upload_method: self.node,
            work_dir: self.layout.merged_work_dir(),
            data_src,
            require_confirmation: self.require_confirmation,
            key_file: self.key_file.clone(),
            check_ic_replay_height: false,
        }
    }

    /// Copies the merged state to `Layout::merged_ic_state_copy_dir`, replacing
    /// any copy left by an earlier run of this step. `cp` without `-a` gives
    /// each link its own file, so the copy shares no files with anything else.
    fn copy_merged_state(&self) -> RecoveryResult<()> {
        let copy = self.layout.merged_ic_state_copy_dir();
        remove_dir(&copy)?;
        create_dir(copy.parent().expect("the copy is in a directory"))?;
        let mut cp = Command::new("cp");
        cp.arg("-r")
            .arg(self.layout.merged_ic_state_dir())
            .arg(&copy);
        confirm_exec_cmd(&mut cp, self.require_confirmation.then_some(&self.logger))?;
        Ok(())
    }
}

impl Step for UploadMergedStateStep {
    fn descr(&self) -> String {
        let upload = self.upload_step().upload_description();
        match self.node {
            DataLocation::Local => format!(
                "Copy the merged state {} to {}, so that it shares no files with the downloaded \
                 states. {upload}",
                self.layout.merged_ic_state_dir().display(),
                self.layout.merged_ic_state_copy_dir().display(),
            ),
            DataLocation::Remote(_) => upload,
        }
    }

    fn exec(&self) -> RecoveryResult<()> {
        if let DataLocation::Local = self.node {
            info!(self.logger, "Copying the merged state...");
            self.copy_merged_state()?;
        }
        self.upload_step().upload_state()
    }
}

/// Restart the destination replica on the installed merged state.
pub(crate) struct RestartDestinationReplicaStep {
    pub(crate) node: ExecutionMode,
    pub(crate) require_confirmation: bool,
    pub(crate) logger: Logger,
}

impl Step for RestartDestinationReplicaStep {
    fn descr(&self) -> String {
        format!(
            "Stop the replica and crypto vault on {}, run setup-permissions, then start the \
             vault and replica and check the replica's status.",
            self.node
        )
    }

    fn exec(&self) -> RecoveryResult<()> {
        self.node.execute(
            stop_and_restart_replica_command(),
            self.require_confirmation.then_some(&self.logger),
        )?;
        Ok(())
    }
}
