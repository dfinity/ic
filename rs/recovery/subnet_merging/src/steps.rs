use crate::{
    agent_helper::AgentHelper,
    layout::{CUP_FILE_NAME, Layout},
    readiness, state_tool_helper,
    target_subnet::TargetSubnet,
    utils::{MergedStateParams, first_registry_version_where, get_cup, get_state_hash},
    validation::validate_artifacts,
};

use ic_base_types::SubnetId;
use ic_recovery::{
    IC_DATA_PATH, Recovery, STATES_METADATA,
    error::{RecoveryError, RecoveryResult},
    get_node_metrics,
    registry_helper::RegistryHelper,
    ssh_helper::SshHelper,
    steps::Step,
    util::block_on,
};
use ic_registry_client_helpers::routing_table::RoutingTableRegistry;
use ic_registry_routing_table::RoutingTable;
use ic_types::{Height, consensus::CatchUpPackage, consensus::HasHeight};
use slog::{Logger, info, warn};
use url::Url;

use std::{
    net::IpAddr,
    path::PathBuf,
    thread::sleep,
    time::{Duration, Instant},
};

/// Retries `check` until it reports success, `timeout` elapses, or it fails
/// with an error that is not worth retrying.
///
/// What the steps below use it for is the registry catching up with a proposal
/// that `ic-admin` just reported as executed: the local store is polled on
/// every read, but the mutation may not have made it into the registry canister
/// the poll reads from yet.
fn wait_for(
    what: &str,
    timeout: Duration,
    poll_interval: Duration,
    logger: &Logger,
    check: impl Fn() -> RecoveryResult<bool>,
) -> RecoveryResult<()> {
    let deadline = Instant::now() + timeout;
    loop {
        match check() {
            Ok(true) => return Ok(()),
            Ok(false) => info!(logger, "Waiting until {what}"),
            Err(err) => warn!(logger, "Waiting until {what}, last attempt failed: {err}"),
        }

        if Instant::now() >= deadline {
            return Err(RecoveryError::UnexpectedError(format!(
                "Gave up waiting until {what} after {timeout:?}"
            )));
        }
        sleep(poll_interval);
    }
}

/// Reads the record of the subnet that is being merged away, checks that it is
/// labeled "cooling down" and determines (and persists) the registry version
/// `V` at which it was labeled so, which is what the merge readiness condition
/// is evaluated against.
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
            "Read the registry to check that subnet {} is labeled \"cooling down\", and determine \
             the registry version it was labeled so at.",
            self.source_subnet_id,
        )
    }

    fn exec(&self) -> RecoveryResult<()> {
        let source_subnet_id = self.source_subnet_id;
        wait_for(
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
                Ok(subnet_record.cooling_down)
            },
        )?;

        let registry_helper = self.registry_helper.clone();
        let cooling_down_version =
            first_registry_version_where(&self.registry_helper, |version| {
                Ok(registry_helper
                    .get_subnet_record_at_version(source_subnet_id, version)?
                    .is_some_and(|record| record.cooling_down))
            })?;

        info!(
            self.logger,
            "Subnet {source_subnet_id} has been labeled \"cooling down\" since registry version \
             {cooling_down_version}",
        );

        self.layout
            .write_cooling_down_registry_version(cooling_down_version.get())
    }
}

/// Waits until the merge readiness condition of the `Subnet merging` dashboard
/// holds for the subnet that is cooling down.
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
            "Wait until subnet {} is ready to be merged, i.e. until it has come to a complete \
             rest: every subnet has observed that it is cooling down, no message is in flight to \
             or from it, its ingress history holds nothing but `processing` entries, its subnet \
             queues and call context manager are empty and its refund pool holds no pending \
             anonymous refund.",
            self.source_subnet_id,
        )
    }

    fn exec(&self) -> RecoveryResult<()> {
        let registry_version = self.layout.read_cooling_down_registry_version()?;

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

/// Waits until the node the state is downloaded from holds the CUP its subnet
/// halts at, i.e. the first one whose summary is created at a registry version
/// carrying the `halt_at_cup_height` flag.
///
/// Waiting for the CUP rather than for the subnet to report that it is halted:
/// the CUP is what names the state the subnet came to rest in, and it exists
/// only once that state has been certified and its hash agreed upon. A subnet
/// that has just stopped delivering batches, on the other hand, may not have
/// finished writing and hashing the checkpoint it stopped at, and downloading
/// its latest checkpoint then yields the previous one, a whole DKG interval
/// before the state the merge is supposed to be assembled from.
///
/// The CUP the node serves over HTTP is not enough: the orchestrator writes the
/// CUP to disk asynchronously, and it is the on-disk copy that is downloaded
/// with the state and validated afterwards. So this waits for both, and for
/// them to agree.
pub(crate) struct WaitForHaltingCupStep {
    pub(crate) subnet_id: SubnetId,
    pub(crate) node_ip: IpAddr,
    pub(crate) registry_helper: RegistryHelper,
    pub(crate) layout: Layout,
    pub(crate) ssh_helper: SshHelper,
    pub(crate) timeout: Duration,
    pub(crate) poll_interval: Duration,
    pub(crate) logger: Logger,
}

impl Step for WaitForHaltingCupStep {
    fn descr(&self) -> String {
        format!(
            "Wait until node {} holds the CUP subnet {} halts at, both at its public endpoint and \
             on disk, and until it has certified the state that CUP names.",
            self.node_ip, self.subnet_id,
        )
    }

    fn exec(&self) -> RecoveryResult<()> {
        let deadline = Instant::now() + self.timeout;
        loop {
            match self.check() {
                Ok(Some(height)) => {
                    info!(
                        self.logger,
                        "Subnet {} halted at height {height}", self.subnet_id
                    );
                    return Ok(());
                }
                Ok(None) => {}
                // A node that is not answering yet, or a CUP that cannot be
                // pulled off it yet, is the normal state of affairs while the
                // subnet is still running towards its halting CUP.
                Err(err) => warn!(
                    self.logger,
                    "Subnet {} has not halted yet: {err}", self.subnet_id
                ),
            }

            if Instant::now() >= deadline {
                return Err(RecoveryError::UnexpectedError(format!(
                    "Subnet {} did not reach the CUP it halts at within {:?}",
                    self.subnet_id, self.timeout,
                )));
            }
            sleep(self.poll_interval);
        }
    }
}

impl WaitForHaltingCupStep {
    /// Returns the height of the halting CUP if the node has reached it, `None`
    /// if it has not yet, and an error if the node could not be asked.
    fn check(&self) -> RecoveryResult<Option<Height>> {
        let cup = self.served_cup()?;
        let cup_height = cup.height();
        let cup_registry_version = cup
            .content
            .block
            .get_value()
            .payload
            .as_ref()
            .as_summary()
            .dkg
            .registry_version;

        // The `halt_at_cup_height` flag is read at the registry version of the
        // summary block active at a height, and that version only changes at a
        // summary, so batch delivery stops exactly when the summary carrying the
        // flag becomes active.
        let halting = self
            .registry_helper
            .get_subnet_record_at_version(self.subnet_id, cup_registry_version)?
            .is_some_and(|record| record.halt_at_cup_height);
        if !halting {
            info!(
                self.logger,
                "Subnet {} is at the CUP at height {cup_height}, whose registry version \
                 {cup_registry_version} does not carry the `halt_at_cup_height` flag yet",
                self.subnet_id,
            );
            return Ok(None);
        }

        // The node has to have caught up with the CUP itself: it is its state
        // that is downloaded, and a node can hold a CUP that the rest of the
        // subnet assembled before it got there.
        let metrics = block_on(get_node_metrics(&self.logger, &self.node_ip)).ok_or_else(|| {
            RecoveryError::UnexpectedError(format!(
                "Failed to get the metrics of node {}",
                self.node_ip
            ))
        })?;
        if metrics.certification_height > cup_height {
            return Err(RecoveryError::ValidationFailed(format!(
                "Subnet {} certified height {}, past the CUP at height {cup_height} it should \
                 have halted at",
                self.subnet_id, metrics.certification_height,
            )));
        }
        if metrics.certification_height < cup_height {
            info!(
                self.logger,
                "Subnet {} holds the CUP at height {cup_height} but node {} has only certified up \
                 to height {}",
                self.subnet_id,
                self.node_ip,
                metrics.certification_height,
            );
            return Ok(None);
        }

        // The CUP the orchestrator has written to disk is the one that is
        // downloaded with the state and validated afterwards, so it has to be
        // the halting CUP, too.
        let on_disk_cup = self.on_disk_cup()?;
        if on_disk_cup.height() != cup_height
            || on_disk_cup.content.state_hash != cup.content.state_hash
        {
            info!(
                self.logger,
                "Node {} still holds the CUP at height {} on disk, not the one at height \
                 {cup_height} it serves",
                self.node_ip,
                on_disk_cup.height(),
            );
            return Ok(None);
        }

        Ok(Some(cup_height))
    }

    /// The CUP the node serves at its public endpoint.
    fn served_cup(&self) -> RecoveryResult<CatchUpPackage> {
        let url = Url::parse(&format!("http://[{}]:8080/", self.node_ip)).map_err(|err| {
            RecoveryError::UnexpectedError(format!(
                "Could not parse the URL of node {}: {err}",
                self.node_ip
            ))
        })?;

        let cup_proto = block_on(ic_cup_explorer::get_cup(&url))
            .map_err(|err| {
                RecoveryError::UnexpectedError(format!(
                    "Failed to get the CUP of node {}: {err}",
                    self.node_ip
                ))
            })?
            .ok_or_else(|| {
                RecoveryError::UnexpectedError(format!("Node {} serves no CUP", self.node_ip))
            })?;

        CatchUpPackage::try_from(&cup_proto).map_err(|err| {
            RecoveryError::UnexpectedError(format!(
                "Failed to deserialize the CUP of node {}: {err}",
                self.node_ip
            ))
        })
    }

    /// The CUP the orchestrator of the node has written to disk, pulled off the
    /// node and kept next to the other artifacts of the merge.
    fn on_disk_cup(&self) -> RecoveryResult<CatchUpPackage> {
        let remote_cup = self.ssh_helper.remote_path(
            PathBuf::from(IC_DATA_PATH)
                .join(ic_recovery::CUPS_DIR)
                .join(CUP_FILE_NAME),
        );
        let local_cup = self.layout.halting_cup_file(self.subnet_id);

        self.ssh_helper.rsync(remote_cup, &local_cup)?;

        get_cup(&local_cup)
    }
}

/// Validates the CUP a subnet halted at and the state that was downloaded with
/// it: the subnet's public key is taken from the NNS signed state tree, the CUP
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
             subnet's public key and the state tree (with only the relevant paths) so that they \
             can be verified independently.",
            self.target_subnet, self.subnet_id,
        )
    }

    fn exec(&self) -> RecoveryResult<()> {
        // 1. Get the subnet's public key using `ic-agent` and persist it on disk.
        info!(self.logger, "Getting the NNS signed State Tree");
        let agent_helper = AgentHelper::new(
            &self.nns_url,
            Some(self.layout.nns_public_key_file()),
            self.logger.clone(),
        )?;

        let pruned_state_tree = agent_helper.read_subnet_data(self.subnet_id)?;
        pruned_state_tree.save_to_file(&self.layout.pruned_state_tree_file(self.subnet_id))?;
        pruned_state_tree
            .save_public_key_to_file(&self.layout.subnet_public_key_file(self.subnet_id))?;

        // 2. Compute the manifest of the downloaded state.
        info!(self.logger, "Computing the state manifest");
        let checkpoint_dir = self.layout.latest_checkpoint_dir(self.target_subnet)?;
        let manifest_path = self.layout.actual_manifest_file(self.subnet_id);

        state_tool_helper::compute_manifest(&checkpoint_dir, &manifest_path)?;

        // 3. Validate all the artifacts (state tree, CUP, state manifest).
        validate_artifacts(
            self.layout.pruned_state_tree_file(self.subnet_id),
            Some(self.layout.nns_public_key_file()),
            self.layout.downloaded_cup_file(self.target_subnet),
            manifest_path,
            self.subnet_id,
            &self.logger,
        )
    }
}

/// Assembles the merged state from the states the two subnets halted at: the
/// state of the destination subnet, with the canisters and canister snapshots
/// of the source subnet added to it, as a new checkpoint that the destination
/// subnet is then recovered at.
pub(crate) struct MergeStatesStep {
    pub(crate) layout: Layout,
    pub(crate) time_margin: Duration,
    pub(crate) logger: Logger,
}

impl Step for MergeStatesStep {
    fn descr(&self) -> String {
        format!(
            "Assemble the merged state from the states downloaded to {} and {}, as a new \
             checkpoint in {}, and compute the height, the batch time and the state hash the \
             recovery of the destination subnet needs.",
            self.layout.work_dir(TargetSubnet::Source).display(),
            self.layout.work_dir(TargetSubnet::Destination).display(),
            self.layout.work_dir(TargetSubnet::Merged).display(),
        )
    }

    fn exec(&self) -> RecoveryResult<()> {
        let source_height = self.layout.latest_checkpoint_height(TargetSubnet::Source)?;
        let destination_height = self
            .layout
            .latest_checkpoint_height(TargetSubnet::Destination)?;
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

        // The block time the recovered subnet starts from has to be larger than
        // the times of both checkpoints the merged state is assembled from.
        let source_time = state_tool_helper::checkpoint_time_nanos(&source_checkpoint)?;
        let destination_time = state_tool_helper::checkpoint_time_nanos(&destination_checkpoint)?;
        let merged_time = source_time.max(destination_time) + self.time_margin.as_nanos() as u64;
        info!(
            self.logger,
            "The source subnet halted at height {source_height} and time {source_time}, the \
             destination subnet at height {destination_height} and time {destination_time}; the \
             merged state is the checkpoint {merged_height} and starts at time {merged_time}",
        );

        info!(self.logger, "Merging the states");
        state_tool_helper::merge_checkpoints(
            &destination_checkpoint,
            &source_checkpoint,
            &merged_checkpoint,
        )?;

        info!(self.logger, "Computing the manifest of the merged state");
        let manifest_path = self.layout.merged_state_manifest_file();
        state_tool_helper::compute_manifest(&merged_checkpoint, manifest_path)?;

        info!(self.logger, "Validating the manifest of the merged state");
        let manifest_hash = state_tool_helper::verify_manifest(manifest_path)
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
            time_nanos: merged_time,
            state_hash,
        };
        info!(self.logger, "The merged state: {params:?}");

        params.write(self.layout.merged_state_params_file())
    }
}

/// Reads the routing table, checks that the canister ID ranges of the subnet
/// that was merged away are hosted by the destination subnet now, and
/// determines (and persists) the registry version the merge was applied at.
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
            "Read the routing table to check that subnet {} hosts no canister id range anymore \
             and that subnet {} hosts them now.",
            self.source_subnet_id, self.destination_subnet_id,
        )
    }

    fn exec(&self) -> RecoveryResult<()> {
        let source_subnet_id = self.source_subnet_id;
        wait_for(
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
                Ok(source_subnet_is_empty(&routing_table, source_subnet_id))
            },
        )?;

        let (registry_version, routing_table) = self.registry_helper.get_routing_table()?;
        let Some(routing_table) = routing_table else {
            return Err(RecoveryError::RegistryError(format!(
                "No routing table at registry version {registry_version}"
            )));
        };
        info!(
            self.logger,
            "Canister id ranges of subnet {} at registry version {registry_version}: {:#?}",
            self.destination_subnet_id,
            routing_table.ranges(self.destination_subnet_id),
        );

        let registry_client = self.registry_helper.registry_client();
        let merge_registry_version =
            first_registry_version_where(&self.registry_helper, |version| {
                let routing_table = registry_client
                    .get_routing_table(version)
                    .map_err(|err| {
                        RecoveryError::RegistryError(format!(
                            "Failed to get the routing table at registry version {version}: {err}"
                        ))
                    })?
                    .ok_or_else(|| {
                        RecoveryError::RegistryError(format!(
                            "No routing table at registry version {version}"
                        ))
                    })?;
                Ok(source_subnet_is_empty(&routing_table, source_subnet_id))
            })?;

        info!(
            self.logger,
            "Subnet {source_subnet_id} has been merged away as of registry version \
             {merge_registry_version}",
        );

        self.layout
            .write_merge_registry_version(merge_registry_version.get())
    }
}

fn source_subnet_is_empty(routing_table: &RoutingTable, source_subnet_id: SubnetId) -> bool {
    routing_table.ranges(source_subnet_id).is_empty()
}

/// Waits until every subnet other than the one that was merged away routes the
/// canisters of the merged subnet to the destination subnet, i.e. until it is
/// safe to delete the merged subnet.
pub(crate) struct CheckRegistryVersionOnAllSubnetsStep {
    pub(crate) source_subnet_id: SubnetId,
    pub(crate) registry_helper: RegistryHelper,
    pub(crate) layout: Layout,
    pub(crate) timeout: Duration,
    pub(crate) poll_interval: Duration,
    pub(crate) logger: Logger,
}

impl Step for CheckRegistryVersionOnAllSubnetsStep {
    fn descr(&self) -> String {
        format!(
            "Wait until every subnet other than {} has reached the registry version the merge \
             created, i.e. routes the canisters that used to be hosted by it to the destination \
             subnet.",
            self.source_subnet_id,
        )
    }

    fn exec(&self) -> RecoveryResult<()> {
        let registry_version = self.layout.read_merge_registry_version()?;

        readiness::await_registry_version_on_all_subnets(
            &self.registry_helper,
            self.source_subnet_id,
            registry_version,
            self.timeout,
            self.poll_interval,
            &self.logger,
        )
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
        let params = MergedStateParams::read(self.layout.merged_state_params_file())?;

        Recovery::wait_for_recovery_cup(
            &self.logger,
            self.node_ip,
            Height::from(params.height),
            params.state_hash,
        )
    }
}
