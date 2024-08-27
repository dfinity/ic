use slog::info;

use super::Step;

#[derive(Clone)]
pub struct RetireBlessedVersion {
    pub version: String,
}

impl Step for RetireBlessedVersion {
    fn execute(
        &self,
        env: ic_system_test_driver::driver::test_env::TestEnv,
        rt: tokio::runtime::Handle,
        registry: super::RegistryWrapper,
    ) -> anyhow::Result<()> {
        let blessed_versions = registry.get_blessed_versins()?;

        if !blessed_versions.contains(&self.version) {
            info!(env.logger(), "Version `{}` is not blessed", self.version);
            return Ok(());
        }

        Ok(())
    }

    fn max_retries(&self) -> usize {
        1
    }
}
