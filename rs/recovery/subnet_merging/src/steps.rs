use crate::{
    layout::{CUP_FILE_NAME, Layout},
    readiness,
    target_subnet::TargetSubnet,
    utils::{get_subnet_record_at_version, wait_for},
};

use ic_base_types::SubnetId;
use ic_cup_explorer::get_cup;
use ic_protobuf::types::v1 as pb;
use ic_recovery::{
    IC_DATA_PATH,
    error::{RecoveryError, RecoveryResult},
    get_node_metrics,
    registry_helper::RegistryHelper,
    ssh_helper::SshHelper,
    steps::Step,
    util::{DataLocation, block_on},
};
use ic_subnet_tools::{
    agent_helper::AgentHelper, state_tool_helper, utils::get_cup as read_cup_file,
    validation::validate_artifacts,
};
use ic_types::consensus::{CatchUpPackage, HasHeight};
use slog::{Logger, info};
use url::Url;

use std::{
    net::{IpAddr, Ipv6Addr},
    path::PathBuf,
    time::Duration,
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

/// Waits until the node the state is downloaded from has certified the state
/// its subnet halts at, and has written the CUP the subnet halts at to disk.
///
/// That the node serves the halting CUP, which [WaitForHaltingCupStep] waits
/// for, is not enough to download the state: a node can hold a CUP that the
/// rest of the subnet assembled before it got there, i.e. before it finished
/// writing and hashing the checkpoint the CUP names, and downloading its
/// latest checkpoint then yields the previous one, a whole DKG interval before
/// the state the merge is supposed to be assembled from. Moreover, the
/// orchestrator writes the CUP to disk asynchronously, and it is the on-disk
/// copy that is downloaded with the state and validated afterwards.
pub(crate) struct WaitForHaltingCheckpointStep {
    pub(crate) subnet_id: SubnetId,
    pub(crate) node_ip: IpAddr,
    pub(crate) layout: Layout,
    pub(crate) ssh_helper: SshHelper,
    pub(crate) timeout: Duration,
    pub(crate) poll_interval: Duration,
    pub(crate) logger: Logger,
}

impl Step for WaitForHaltingCheckpointStep {
    fn descr(&self) -> String {
        format!(
            "Wait until node {} has certified the state subnet {} halts at and has written the \
             CUP it halts at to disk.",
            self.node_ip, self.subnet_id,
        )
    }

    fn exec(&self) -> RecoveryResult<()> {
        let halting_cup = read_cup_file(&self.layout.halting_cup_file(self.subnet_id))?;

        // A node that is not answering yet, or a CUP that cannot be pulled off
        // it yet, is the normal state of affairs while the node is still
        // catching up with the halting CUP, so every error is retried.
        wait_for(
            &format!(
                "node {} has certified the state subnet {} halts at and has written the CUP it \
                 halts at to disk",
                self.node_ip, self.subnet_id,
            ),
            self.timeout,
            self.poll_interval,
            &self.logger,
            || {
                if self.check(&halting_cup)? {
                    Ok(())
                } else {
                    Err(RecoveryError::UnexpectedError(format!(
                        "node {} has not reached the CUP subnet {} halts at yet",
                        self.node_ip, self.subnet_id,
                    )))
                }
            },
        )?;
        info!(
            self.logger,
            "Node {} has certified height {} and holds the CUP subnet {} halts at on disk",
            self.node_ip,
            halting_cup.height(),
            self.subnet_id,
        );
        Ok(())
    }
}

impl WaitForHaltingCheckpointStep {
    /// Returns whether the node has certified the height of `halting_cup` and
    /// holds it on disk, and an error if the node could not be asked.
    fn check(&self, halting_cup: &CatchUpPackage) -> RecoveryResult<bool> {
        let cup_height = halting_cup.height();

        // The node has to have caught up with the CUP itself: it is its state
        // that is downloaded.
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
                "Subnet {} halts at the CUP at height {cup_height} but node {} has only certified \
                 up to height {}",
                self.subnet_id,
                self.node_ip,
                metrics.certification_height,
            );
            return Ok(false);
        }

        // The CUP the orchestrator has written to disk is the one that is
        // downloaded with the state and validated afterwards, so it has to be
        // the halting CUP, too.
        let on_disk_cup = self.on_disk_cup()?;
        if on_disk_cup.height() != cup_height
            || on_disk_cup.content.state_hash != halting_cup.content.state_hash
        {
            info!(
                self.logger,
                "Node {} still holds the CUP at height {} on disk, not the one at height \
                 {cup_height} subnet {} halts at",
                self.node_ip,
                on_disk_cup.height(),
                self.subnet_id,
            );
            return Ok(false);
        }

        Ok(true)
    }

    /// The CUP the orchestrator of the node has written to disk, pulled off the
    /// node and kept next to the other artifacts of the merge.
    fn on_disk_cup(&self) -> RecoveryResult<CatchUpPackage> {
        let remote_cup = self.ssh_helper.remote_path(
            PathBuf::from(IC_DATA_PATH)
                .join(ic_recovery::CUPS_DIR)
                .join(CUP_FILE_NAME),
        );
        let local_cup = self.layout.on_disk_cup_file(self.subnet_id);

        self.ssh_helper.rsync(remote_cup, &local_cup)?;

        read_cup_file(&local_cup)
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

        // 3. Check that the downloaded CUP is the one the subnet halts at, as
        // observed by `WaitForHaltingCupStep`, rather than one of an earlier
        // height that the node still held on disk.
        let halting_cup = read_cup_file(&self.layout.halting_cup_file(self.subnet_id))?;
        let downloaded_cup = read_cup_file(&self.layout.downloaded_cup_file(self.target_subnet))?;
        if downloaded_cup.height() != halting_cup.height()
            || downloaded_cup.content.state_hash != halting_cup.content.state_hash
        {
            return Err(RecoveryError::ValidationFailed(format!(
                "The CUP downloaded from subnet {} is at height {}, not the CUP at height {} the \
                 subnet halts at",
                self.subnet_id,
                downloaded_cup.height(),
                halting_cup.height(),
            )));
        }

        // 4. Validate all the artifacts (state tree, CUP, state manifest).
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
