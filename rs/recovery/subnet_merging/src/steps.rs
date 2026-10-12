use crate::{layout::Layout, readiness};

use ic_base_types::SubnetId;
use ic_recovery::{
    error::{RecoveryError, RecoveryResult},
    registry_helper::RegistryHelper,
    steps::Step,
};
use slog::{Logger, info, warn};

use std::{
    thread::sleep,
    time::{Duration, Instant},
};

/// Retries `check` until it reports success (by returning a value, which is
/// then returned) or `timeout` elapses.
///
/// What the steps below use it for is the registry catching up with a proposal
/// that `ic-admin` just reported as executed: the local store is polled on
/// every read, but the mutation may not have made it into the registry canister
/// the poll reads from yet.
fn wait_for<T>(
    what: &str,
    timeout: Duration,
    poll_interval: Duration,
    logger: &Logger,
    check: impl Fn() -> RecoveryResult<Option<T>>,
) -> RecoveryResult<T> {
    let deadline = Instant::now() + timeout;
    loop {
        match check() {
            Ok(Some(value)) => return Ok(value),
            Ok(None) => info!(logger, "Waiting until {what}"),
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

/// Waits until the record of the subnet that is being merged away is labeled
/// "cooling down" and persists the registry version `V` it was read at, which
/// is what the merge readiness condition is evaluated against.
///
/// `V` need not be the version that labeled the subnet so, just one at which it
/// is labeled so: all the readiness condition needs of `V` is that a subnet that
/// has reached it treats the subnet as cooling down, which holds for every
/// version from the labeling one onwards.
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
            "Read the registry to check that subnet {} is labeled \"cooling down\", and record \
             the registry version it is labeled so at.",
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
                Ok(subnet_record.cooling_down.then_some(registry_version))
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
