use crate::{
    download_node::DownloadNode,
    layout::Layout,
    readiness,
    subnet_merging::TargetSubnet,
    utils::{MergedStateParams, get_subnet_record_at_version, wait_for},
};

use ic_base_types::SubnetId;
use ic_cup_explorer::get_cup;
use ic_protobuf::types::v1 as pb;
use ic_recovery::{
    IC_CHECKPOINTS_PATH, IC_DATA_PATH, Recovery, STATES_METADATA,
    admin_helper::AdminHelper,
    error::{RecoveryError, RecoveryResult},
    file_sync_helper::remove_dir,
    registry_helper::RegistryHelper,
    steps::{AdminStep, CopyLocalIcStateStep, DownloadIcDataStep, Step},
    util::{CheckpointHeight, DataLocation, ExecutionMode, block_on},
};
use ic_state_layout::{CheckpointStatus, StateLayout};
use ic_subnet_tools::{
    agent_helper::AgentHelper,
    state_tool_helper,
    utils::{get_cup as read_cup_file, get_state_hash},
    validation::validate_artifacts,
};
use ic_types::{
    Height,
    consensus::{CatchUpPackage, HasHeight},
};
use slog::{Logger, info};
use url::Url;

use std::{
    net::{IpAddr, Ipv6Addr},
    path::PathBuf,
    thread::sleep,
    time::{Duration, SystemTime},
};

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

/// Stops the replica of the node the state of a subnet is downloaded from, but
/// only once the node holds a finished checkpoint at the height of the CUP the
/// subnet halts at.
///
/// Holding the halting CUP does not imply holding the checkpoint at its
/// height: the node may hold the CUP before it has written the checkpoint (e.g.
/// if it got the CUP from its peers), and a checkpoint stays unverified while
/// its files are still being written (or state-synced).
pub(crate) struct StopReplicaAtHaltingCheckpointStep {
    pub(crate) subnet_id: SubnetId,
    pub(crate) node: DownloadNode,
    pub(crate) layout: Layout,
    pub(crate) timeout: Duration,
    pub(crate) poll_interval: Duration,
    pub(crate) logger: Logger,
}

impl Step for StopReplicaAtHaltingCheckpointStep {
    fn descr(&self) -> String {
        format!(
            "Wait until {} holds a finished checkpoint at the height of the CUP subnet {} halts \
             at, then stop its replica.",
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

        info!(self.logger, "Stopping the replica on {}", self.node);
        self.node
            .execute("sudo systemctl stop ic-replica".to_string())?;
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

        match self.node.mode().checkpoint_status(&checkpoint)? {
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
    pub(crate) node: DownloadNode,
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

        match self.node.ssh_helper() {
            None => {
                // Unlike the `rsync --delete` of a download, `cp` keeps files
                // that are only in the copy, e.g. of a different checkpoint at
                // the same height left over in a reused working directory,
                // which would then enter the recomputed manifest. Checkpoints
                // at other heights are left alone.
                remove_dir(&self.layout.checkpoint_dir(self.target_subnet, height))?;
                let data_includes = Recovery::get_ic_state_includes(
                    &self.logger,
                    ExecutionMode::Local,
                    CheckpointHeight::Specified(height.get()),
                )?;
                CopyLocalIcStateStep {
                    logger: self.logger.clone(),
                    working_dir,
                    require_confirmation: self.node.require_confirmation(),
                    data_includes,
                    include_config: false,
                }
                .exec()
            }
            Some(ssh_helper) => {
                ssh_helper.wait_for_access().map_err(|err| {
                    RecoveryError::UnexpectedError(format!(
                        "SSH access to {} with the admin key denied: {err}",
                        self.node
                    ))
                })?;
                let data_includes = Recovery::get_ic_state_includes(
                    &self.logger,
                    ExecutionMode::Remote(ssh_helper),
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

/// How long [MergeStatesStep] waits before it reports success, so that the
/// recovery CUP proposed afterwards is stamped past the batch times of the two
/// checkpoints the merged state was assembled from.
const SETTLE_TIME: Duration = Duration::from_secs(30);

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
             heights of the CUPs the two subnets halted at, as a new checkpoint in {}, and \
             compute the height and the state hash the recovery of the destination subnet needs.",
            self.layout.work_dir(TargetSubnet::Source).display(),
            self.layout.work_dir(TargetSubnet::Destination).display(),
            self.layout.work_dir(TargetSubnet::Merged).display(),
        )
    }

    fn exec(&self) -> RecoveryResult<()> {
        // The checkpoints the two subnets halted at, which the validation steps
        // checked against the halting CUPs. A reused working directory may hold
        // other checkpoints too, so they are selected by height rather than as
        // the latest ones.
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

        // The recovery CUP is created at the next recovery height above the one
        // the destination subnet halted at, exactly as in any other recovery.
        let merged_height = Recovery::get_recovery_height(destination_height);
        let merged_checkpoint = self
            .layout
            .checkpoint_dir(TargetSubnet::Merged, merged_height);

        info!(
            self.logger,
            "The source subnet halted at height {source_height} and the destination subnet at \
             height {destination_height}; the merged state is the checkpoint {merged_height}",
        );

        // The merge claims its output directory by creating it, and the upload
        // step refuses a state directory holding more than one checkpoint, so
        // every merged checkpoint left over from an earlier run of this step
        // is removed first, whatever its height. The downloaded checkpoints of
        // the two subnets are in other directories and stay untouched.
        remove_dir(&self.layout.checkpoints_dir(TargetSubnet::Merged))?;

        info!(self.logger, "Merging the states");
        state_tool_helper::merge_checkpoints(
            &destination_checkpoint,
            &source_checkpoint,
            &merged_checkpoint,
        )?;

        info!(self.logger, "Computing the manifest of the merged state");
        let manifest_path = self.layout.merged_state_manifest_file();
        state_tool_helper::compute_manifest(&merged_checkpoint, &manifest_path)?;

        info!(self.logger, "Validating the manifest of the merged state");
        let manifest_hash = state_tool_helper::verify_manifest(&manifest_path)
            .map_err(|err| RecoveryError::validation_failed("Manifest verification failed", err))?;
        let state_hash = get_state_hash(&merged_checkpoint)?;
        if manifest_hash != state_hash {
            return Err(RecoveryError::ValidationFailed(format!(
                "The root hash {manifest_hash} of the manifest of the merged state differs from \
                 the hash {state_hash} recomputed from the merged checkpoint",
            )));
        }

        // The upload step transfers the states metadata alongside the
        // checkpoint, and rsync is given every path it transfers as an explicit
        // source, so a missing one fails the whole transfer: take the
        // destination subnet's along.
        //
        // It is a manifest cache, which the state manager recomputes for the
        // checkpoints it finds whenever it is missing or does not describe them,
        // and the heights it names here are the ones the destination subnet held
        // before the merge, none of which the merged state directory has. That is
        // the same mismatch a plain subnet recovery uploads, where the metadata
        // comes from the state that was downloaded and the checkpoint from the
        // replay that followed.
        std::fs::copy(
            self.layout
                .ic_state_dir(TargetSubnet::Destination)
                .join(STATES_METADATA),
            self.layout
                .ic_state_dir(TargetSubnet::Merged)
                .join(STATES_METADATA),
        )
        .map_err(|err| {
            RecoveryError::UnexpectedError(format!("Failed to copy the states metadata: {err}"))
        })?;

        let params = MergedStateParams {
            height: merged_height.get(),
            state_hash,
        };
        info!(self.logger, "The merged state: {params:?}");

        params.write(&self.layout.merged_state_params_file())?;

        // The recovery CUP is stamped with the time it is proposed at, and the
        // merged subnet has to resume past the batch times of both checkpoints
        // it is assembled from: either subnet's canisters may have run ahead of
        // the merged state's own batch time, which is the destination subnet's.
        // Both subnets halted before this step ran, so both batch times are in
        // the past already; this wait puts the clock clear of them.
        info!(
            self.logger,
            "Waiting {SETTLE_TIME:?}, so that the recovery CUP is stamped past the batch times of \
             both checkpoints",
        );
        sleep(SETTLE_TIME);

        Ok(())
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

/// Proposes the recovery CUP of the destination subnet at the merged state,
/// with the height and state hash recorded by [MergeStatesStep].
///
/// They are read when the step is executed rather than when it is created: a
/// step that fails to be created is skipped, and the tool would then upload the
/// merged state and unhalt the destination subnet without a recovery CUP.
pub(crate) struct ProposeRecoveryCupStep {
    pub(crate) destination_subnet_id: SubnetId,
    pub(crate) admin_helper: AdminHelper,
    pub(crate) layout: Layout,
    pub(crate) logger: Logger,
}

impl Step for ProposeRecoveryCupStep {
    fn descr(&self) -> String {
        format!(
            "Propose a recovery CUP for subnet {} at the height and state hash of the merged \
             state recorded in {}, with its DKG run by the default initial DKG subnet (or the \
             NNS subnet if none is set).",
            self.destination_subnet_id,
            self.layout.merged_state_params_file().display(),
        )
    }

    fn exec(&self) -> RecoveryResult<()> {
        let params = MergedStateParams::read(&self.layout.merged_state_params_file())?;

        AdminStep {
            logger: self.logger.clone(),
            ic_admin_cmd: self
                .admin_helper
                .get_propose_to_update_recovery_cup_command(
                    self.destination_subnet_id,
                    Height::from(params.height),
                    params.state_hash,
                    /*initial_dkg_subnet_id=*/ None,
                    /*chain_key_config=*/ None,
                    /*replacement_nodes=*/ &[],
                    /*registry_params=*/ None,
                    SystemTime::now(),
                ),
        }
        .exec()
    }
}

/// Waits until the destination subnet came up on the merged state, i.e. until
/// the node the merged state was uploaded to reports the recovery CUP.
pub(crate) struct WaitForRecoveryCupStep {
    pub(crate) node_ip: IpAddr,
    pub(crate) layout: Layout,
    pub(crate) logger: Logger,
}

impl Step for WaitForRecoveryCupStep {
    fn descr(&self) -> String {
        format!(
            "Wait until node {} reports the recovery CUP holding the merged state.",
            self.node_ip,
        )
    }

    fn exec(&self) -> RecoveryResult<()> {
        let params = MergedStateParams::read(&self.layout.merged_state_params_file())?;

        Recovery::wait_for_recovery_cup(
            &self.logger,
            self.node_ip,
            Height::from(params.height),
            params.state_hash,
        )
    }
}
