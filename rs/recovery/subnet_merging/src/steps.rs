use crate::{
    layout::Layout,
    readiness,
    utils::{first_registry_version_where, get_subnet_record_at_version},
};

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
                Ok(
                    get_subnet_record_at_version(&registry_helper, source_subnet_id, version)?
                        .is_some_and(|record| record.cooling_down),
                )
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
