//! Steps shared by the subnet splitting and subnet merging tools.

use crate::{admin_helper::get_halt_subnet_at_cup_height_command, utils::readonly_keys_adding};

use ic_base_types::SubnetId;
use ic_recovery::{
    admin_helper::{AdminHelper, IcAdmin},
    cli::consent_given,
    error::RecoveryResult,
    registry_helper::{RegistryHelper, VersionedRecoveryResult},
    steps::{AdminStep, Step},
};
use slog::{Logger, error, info};

use std::cell::OnceCell;

/// Reads a part of the registry and logs it, so that an operator can check
/// what a proposal of these tools did before the next one is submitted. When
/// interactive, it offers to read the registry again, for a mutation that has
/// not been applied yet.
pub struct ReadRegistryStep<T: std::fmt::Debug, F: Fn() -> VersionedRecoveryResult<T>> {
    pub logger: Logger,
    pub label: String,
    pub interactive: bool,
    pub querier: F,
}

impl<T: std::fmt::Debug, F: Fn() -> VersionedRecoveryResult<T>> Step for ReadRegistryStep<T, F> {
    fn descr(&self) -> String {
        format!("Read Registry to get the most recent {}", self.label)
    }

    fn exec(&self) -> RecoveryResult<()> {
        loop {
            match (self.querier)() {
                Ok((registry_version, value)) => info!(
                    self.logger,
                    "{} at registry version {}: {:#?}", self.label, registry_version, value,
                ),
                Err(err) => error!(self.logger, "Failed getting {}, error: {}", self.label, err),
            }

            if !self.interactive || !consent_given(&self.logger, "Read registry again?") {
                break;
            }
        }

        Ok(())
    }
}

/// Proposes to halt a subnet at its next CUP and, if a readonly key is
/// supplied, to add it to the readonly keys of the subnet.
///
/// The proposal replaces the subnet's entire list of readonly keys, so the keys
/// the subnet has in the latest registry version are read and proposed along
/// with the supplied one. They are read when the step is described or
/// executed, not when it is created: a step that fails to be created is
/// skipped, which would leave the subnet running, whereas a step that fails to
/// execute is retried.
///
/// The command is built only once, so that the command executed is the one
/// that was described, even if the registry changes in between.
pub struct HaltSubnetAtCupHeightStep {
    logger: Logger,
    admin_helper: AdminHelper,
    registry_helper: RegistryHelper,
    subnet_id: SubnetId,
    readonly_key: Option<String>,
    ic_admin_cmd: OnceCell<IcAdmin>,
}

impl HaltSubnetAtCupHeightStep {
    pub fn new(
        logger: Logger,
        admin_helper: AdminHelper,
        registry_helper: RegistryHelper,
        subnet_id: SubnetId,
        readonly_key: Option<String>,
    ) -> Self {
        Self {
            logger,
            admin_helper,
            registry_helper,
            subnet_id,
            readonly_key,
            ic_admin_cmd: OnceCell::new(),
        }
    }

    /// The `ic-admin` command proposing the halt, built the first time it is
    /// asked for successfully.
    fn ic_admin_cmd(&self) -> RecoveryResult<&IcAdmin> {
        if let Some(ic_admin_cmd) = self.ic_admin_cmd.get() {
            return Ok(ic_admin_cmd);
        }

        let readonly_keys =
            readonly_keys_adding(&self.registry_helper, self.subnet_id, &self.readonly_key)?;
        let ic_admin_cmd = get_halt_subnet_at_cup_height_command(
            &self.admin_helper,
            self.subnet_id,
            &readonly_keys,
        );

        Ok(self.ic_admin_cmd.get_or_init(|| ic_admin_cmd))
    }
}

impl Step for HaltSubnetAtCupHeightStep {
    fn descr(&self) -> String {
        match self.ic_admin_cmd() {
            Ok(ic_admin_cmd) => ic_admin_cmd.join(" "),
            Err(err) => format!(
                "Propose to halt subnet {} at its next CUP height, adding the readonly key {:?} \
                 to the readonly keys it has in the latest registry version. Reading those keys \
                 failed ({err}); they are read again when the step is executed.",
                self.subnet_id,
                self.readonly_key.as_deref().unwrap_or_default(),
            ),
        }
    }

    fn exec(&self) -> RecoveryResult<()> {
        let ic_admin_cmd = self.ic_admin_cmd()?;
        info!(self.logger, "Executing: {}", ic_admin_cmd.join(" "));

        AdminStep {
            logger: self.logger.clone(),
            ic_admin_cmd: ic_admin_cmd.clone(),
        }
        .exec()
    }
}
