use crate::{
    layout::Layout,
    readiness,
    utils::{get_subnet_record_at_version, wait_for},
};

use ic_base_types::SubnetId;
use ic_cup_explorer::get_catchup_content;
use ic_recovery::{
    error::{RecoveryError, RecoveryResult},
    registry_helper::RegistryHelper,
    steps::Step,
    util::{DataLocation, block_on},
};
use ic_types::consensus::{CatchUpContent, HasHeight};
use slog::{Logger, info};
use url::Url;

use std::{
    net::{IpAddr, Ipv6Addr},
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

/// Waits until the registry sets the `halt_at_cup_height` flag of a subnet,
/// i.e. until the proposal halting the subnet at its next CUP has been adopted
/// and executed.
///
/// Submitting that proposal does not wait for its adoption, which may take a
/// while, so this wait is separate from the one for the halting CUP.
pub(crate) struct CheckHaltAtCupHeightStep {
    pub(crate) subnet_id: SubnetId,
    pub(crate) registry_helper: RegistryHelper,
    pub(crate) timeout: Duration,
    pub(crate) poll_interval: Duration,
    pub(crate) logger: Logger,
}

impl Step for CheckHaltAtCupHeightStep {
    fn descr(&self) -> String {
        format!(
            "Wait until the registry sets the `halt_at_cup_height` flag of subnet {}.",
            self.subnet_id,
        )
    }

    fn exec(&self) -> RecoveryResult<()> {
        let subnet_id = self.subnet_id;
        let registry_version = wait_for(
            &format!("subnet {subnet_id} has the `halt_at_cup_height` flag set"),
            self.timeout,
            self.poll_interval,
            &self.logger,
            || {
                let (registry_version, subnet_record) =
                    self.registry_helper.get_subnet_record(subnet_id)?;
                let Some(subnet_record) = subnet_record else {
                    return Err(RecoveryError::RegistryError(format!(
                        "No record of subnet {subnet_id} at registry version {registry_version}"
                    )));
                };
                if !subnet_record.halt_at_cup_height {
                    return Err(RecoveryError::RegistryError(format!(
                        "Subnet {subnet_id} does not have the `halt_at_cup_height` flag set at \
                         registry version {registry_version} yet"
                    )));
                }
                Ok(registry_version)
            },
        )?;

        info!(
            self.logger,
            "Subnet {subnet_id} has the `halt_at_cup_height` flag set at registry version \
             {registry_version}",
        );
        Ok(())
    }
}

/// Waits until the node the state is downloaded from serves the CUP its subnet
/// halts at.
///
/// The CUP is read from the node's public CUP endpoint. Neither the CUP nor the
/// presence of a checkpoint of the state it names on the node is validated
/// here: both are validated when the state is downloaded.
pub(crate) struct WaitForHaltingCupStep {
    pub(crate) subnet_id: SubnetId,
    pub(crate) node: DataLocation,
    pub(crate) registry_helper: RegistryHelper,
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
        let node_url = self.node_url()?;

        // A node that is not answering yet is the normal state of affairs while
        // the subnet is still running towards its halting CUP, so errors are
        // retried.
        let cup = wait_for(
            &format!("subnet {} reaches the CUP it halts at", self.subnet_id),
            self.timeout,
            self.poll_interval,
            &self.logger,
            || {
                self.check(&node_url)?.ok_or_else(|| {
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
            cup.registry_version(),
            hex::encode(&cup.state_hash.get_ref().0),
        );
        Ok(())
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

    /// Returns the halting CUP if the node serves it, `None` if it does not
    /// yet, and an error if the node could not be asked.
    fn check(&self, node_url: &Url) -> RecoveryResult<Option<CatchUpContent>> {
        let node_ip = self.node_ip();
        let Some(cup) = block_on(get_catchup_content(node_url)).map_err(|err| {
            RecoveryError::UnexpectedError(format!(
                "Failed to get the CUP of node {node_ip}: {err}"
            ))
        })?
        else {
            return Ok(None);
        };
        let cup = CatchUpContent::try_from(cup).map_err(|err| {
            RecoveryError::UnexpectedError(format!(
                "Failed to decode the CUP of node {node_ip}: {err}"
            ))
        })?;
        // Checked before reading the registry version, which panics if the
        // CUP's block does not carry a summary payload.
        if !cup.check_integrity() {
            return Err(RecoveryError::ValidationFailed(format!(
                "The CUP of node {node_ip} does not pass the integrity check"
            )));
        }
        let cup_height = cup.height();
        let cup_registry_version = cup.registry_version();

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

        Ok(Some(cup))
    }
}
