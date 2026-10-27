use crate::{
    layout::{CUP_FILE_NAME, Layout},
    readiness,
    utils::{get_subnet_record_at_version, wait_for},
};

use ic_base_types::SubnetId;
use ic_recovery::{
    CUPS_DIR, IC_DATA_PATH,
    error::{RecoveryError, RecoveryResult},
    get_node_metrics,
    registry_helper::RegistryHelper,
    ssh_helper::SshHelper,
    steps::Step,
    util::block_on,
};
use ic_subnet_tools::utils::get_cup;
use ic_types::{
    Height,
    consensus::{CatchUpContent, CatchUpPackage, HasHeight},
};
use slog::{Logger, info};
use url::Url;

use std::{net::IpAddr, path::PathBuf, time::Duration};

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
/// with the state (by a later step) and validated against it. So this waits for both, and for
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
        // A node that is not answering yet, or a CUP that cannot be pulled off
        // it yet, is the normal state of affairs while the subnet is still
        // running towards its halting CUP, so every error is retried.
        let height = wait_for(
            &format!("subnet {} reaches the CUP it halts at", self.subnet_id),
            self.timeout,
            self.poll_interval,
            &self.logger,
            || {
                self.check()?.ok_or_else(|| {
                    RecoveryError::UnexpectedError(format!(
                        "node {} does not hold the CUP subnet {} halts at yet",
                        self.node_ip, self.subnet_id,
                    ))
                })
            },
        )?;
        info!(
            self.logger,
            "Subnet {} halted at height {height}", self.subnet_id
        );
        Ok(())
    }
}

impl WaitForHaltingCupStep {
    /// Returns the height of the halting CUP if the node has reached it, `None`
    /// if it has not yet, and an error if the node could not be asked.
    fn check(&self) -> RecoveryResult<Option<Height>> {
        let cup_content = self.served_cup_content()?;
        let cup_height = cup_content.height();
        let cup_registry_version = cup_content.registry_version();

        // The `halt_at_cup_height` flag is read at the registry version of the
        // summary block active at a height, and that version only changes at a
        // summary, so batch delivery stops exactly when the summary carrying the
        // flag becomes active.
        let halting = get_subnet_record_at_version(
            &self.registry_helper,
            self.subnet_id,
            cup_registry_version,
        )?
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
        // downloaded with the state and validated against it by later steps, so
        // it has to be the halting CUP, too.
        let on_disk_cup = self.on_disk_cup()?;
        if on_disk_cup.height() != cup_height
            || on_disk_cup.content.state_hash != cup_content.state_hash
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

    /// The content of the CUP the node serves at its public endpoint.
    ///
    /// Only the content, which is all that is checked here; the signature of
    /// the CUP the state is downloaded with is verified once it is downloaded.
    fn served_cup_content(&self) -> RecoveryResult<CatchUpContent> {
        let url = Url::parse(&format!("http://[{}]:8080/", self.node_ip)).map_err(|err| {
            RecoveryError::UnexpectedError(format!(
                "Could not parse the URL of node {}: {err}",
                self.node_ip
            ))
        })?;

        let content_proto = block_on(ic_cup_explorer::get_catchup_content(&url))
            .map_err(|err| {
                RecoveryError::UnexpectedError(format!(
                    "Failed to get the CUP of node {}: {err}",
                    self.node_ip
                ))
            })?
            .ok_or_else(|| {
                RecoveryError::UnexpectedError(format!("Node {} serves no CUP", self.node_ip))
            })?;

        CatchUpContent::try_from(content_proto).map_err(|err| {
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
                .join(CUPS_DIR)
                .join(CUP_FILE_NAME),
        );
        let local_cup = self.layout.halting_cup_file(self.subnet_id);

        self.ssh_helper.rsync(remote_cup, &local_cup)?;

        get_cup(&local_cup)
    }
}
