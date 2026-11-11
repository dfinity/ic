use crate::{
    layout::Layout,
    readiness,
    target_subnet::TargetSubnet,
    utils::{get_subnet_record_at_version, wait_for},
};

use ic_base_types::SubnetId;
use ic_cup_explorer::get_cup;
use ic_protobuf::types::v1 as pb;
use ic_recovery::{
    IC_CHECKPOINTS_PATH, IC_DATA_PATH,
    error::{RecoveryError, RecoveryResult},
    registry_helper::RegistryHelper,
    ssh_helper::SshHelper,
    steps::Step,
    util::{DataLocation, block_on},
};
use ic_state_layout::{STATE_SYNC_CHECKPOINT_MARKER, StateLayout, UNVERIFIED_CHECKPOINT_MARKER};
use ic_subnet_tools::{
    agent_helper::AgentHelper, state_tool_helper, utils::get_cup as read_cup_file,
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
            self.layout.halting_cup_file(self.subnet_id),
            manifest_path,
            self.subnet_id,
            &self.logger,
        )
    }
}

/// Stops the replica of the node the state of a subnet is downloaded from, but
/// only once the node holds a finished checkpoint at the height of the CUP the
/// subnet halts at.
///
/// The state manager renames a checkpoint into the `checkpoints` directory
/// together with an unverified marker, keeps writing its files asynchronously,
/// and only removes the marker once they are all written and synced (a
/// checkpoint obtained by state sync carries a second marker, which is removed
/// last). A node may also hold the halting CUP before it has written the
/// checkpoint at all, e.g. if it got the CUP from its peers. Stopping the
/// replica before the checkpoint is finished would leave it unfinished for
/// good, so the step waits for that first. Once the replica is stopped, nothing
/// changes the checkpoint anymore, so the state that is downloaded is the one
/// that was checked here.
pub(crate) struct StopReplicaAtHaltingCheckpointStep {
    pub(crate) subnet_id: SubnetId,
    pub(crate) node_ip: IpAddr,
    pub(crate) layout: Layout,
    pub(crate) ssh_helper: SshHelper,
    pub(crate) stop_replica: Box<dyn Step>,
    pub(crate) timeout: Duration,
    pub(crate) poll_interval: Duration,
    pub(crate) logger: Logger,
}

impl Step for StopReplicaAtHaltingCheckpointStep {
    fn descr(&self) -> String {
        format!(
            "Wait until node {} holds a finished checkpoint at the height of the CUP subnet {} \
             halts at, then: {}",
            self.node_ip,
            self.subnet_id,
            self.stop_replica.descr(),
        )
    }

    fn exec(&self) -> RecoveryResult<()> {
        let height = read_cup_file(&self.layout.halting_cup_file(self.subnet_id))?.height();

        // A checkpoint that does not exist yet, or is not finished yet, is the
        // normal state of affairs while the node is still catching up with the
        // halting CUP, so every error is retried.
        wait_for(
            &format!(
                "node {} holds a finished checkpoint at height {height} of subnet {}",
                self.node_ip, self.subnet_id,
            ),
            self.timeout,
            self.poll_interval,
            &self.logger,
            || self.check_checkpoint_finished(height),
        )?;
        info!(
            self.logger,
            "Node {} holds a finished checkpoint at height {height} of subnet {}",
            self.node_ip,
            self.subnet_id,
        );

        self.stop_replica.exec()
    }
}

impl StopReplicaAtHaltingCheckpointStep {
    /// Succeeds if the node holds the checkpoint at `height` and it carries
    /// neither of the markers of an unfinished checkpoint.
    fn check_checkpoint_finished(&self, height: Height) -> RecoveryResult<()> {
        let checkpoint = PathBuf::from(IC_DATA_PATH)
            .join(IC_CHECKPOINTS_PATH)
            .join(StateLayout::checkpoint_name(height));
        let checkpoint = checkpoint.display();
        let output = self.ssh_helper.ssh(format!(
            "if [ ! -d {checkpoint} ]; then echo missing; \
             elif [ -e {checkpoint}/{UNVERIFIED_CHECKPOINT_MARKER} ] \
             || [ -e {checkpoint}/{STATE_SYNC_CHECKPOINT_MARKER} ]; then echo unfinished; \
             else echo finished; fi"
        ))?;

        match output.as_deref().map(str::trim) {
            Some("finished") => Ok(()),
            Some("missing") => Err(RecoveryError::UnexpectedError(format!(
                "node {} does not hold the checkpoint {checkpoint} yet",
                self.node_ip
            ))),
            Some("unfinished") => Err(RecoveryError::UnexpectedError(format!(
                "the checkpoint {checkpoint} on node {} is not finished yet",
                self.node_ip
            ))),
            other => Err(RecoveryError::UnexpectedError(format!(
                "unexpected output while checking the checkpoint {checkpoint} on node {}: \
                 {other:?}",
                self.node_ip
            ))),
        }
    }
}
