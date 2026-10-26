use crate::{layout::Layout, readiness, utils::wait_for};

use ic_base_types::SubnetId;
use ic_recovery::{
    error::{RecoveryError, RecoveryResult},
    registry_helper::RegistryHelper,
    steps::Step,
};
use slog::{Logger, info};

use std::time::Duration;

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
