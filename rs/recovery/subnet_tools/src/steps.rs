//! Steps shared by the subnet splitting and subnet merging tools.

use ic_recovery::{
    cli::consent_given, error::RecoveryResult, registry_helper::VersionedRecoveryResult,
    steps::Step,
};
use slog::{Logger, error, info};

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
