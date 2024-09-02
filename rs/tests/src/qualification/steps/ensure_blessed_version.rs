use std::time::Duration;

use ic_consensus_system_test_utils::upgrade::bless_public_replica_version;
use ic_system_test_driver::driver::test_env_api::{
    GetFirstHealthyNodeSnapshot, HasTopologySnapshot,
};
use slog::info;
use tokio::runtime::Handle;

use super::Step;

#[derive(Clone)]
pub struct EnsureBlessedVersion {
    pub version: String,
}

impl Step for EnsureBlessedVersion {
    fn execute(
        &self,
        env: ic_system_test_driver::driver::test_env::TestEnv,
        rt: Handle,
    ) -> anyhow::Result<()> {
        let blessed_versions = env.topology_snapshot().blessed_replica_versions()?;
        if blessed_versions.contains(&self.version) {
            info!(env.logger(), "Version `{}` already blessed", self.version);
            return Ok(());
        }

        let nns_node = env.get_first_healthy_system_node_snapshot();

        rt.block_on(bless_public_replica_version(
            &nns_node,
            &self.version,
            ic_consensus_system_test_utils::upgrade::UpdateImageType::Image,
            ic_consensus_system_test_utils::upgrade::UpdateImageType::Image,
            &env.logger(),
        ));

        // This call updates the local registry
        let new_snapshot = rt.block_on(
            env.topology_snapshot()
                .block_for_newer_registry_version_within_duration(
                    Duration::from_secs(10 * 60),
                    Duration::from_secs(10),
                ),
        )?;

        let blessed_versions = new_snapshot.blessed_replica_versions()?;

        match blessed_versions.contains(&self.version) {
            true => Ok(()),
            false => Err(anyhow::anyhow!("Blessed version not found in the registry")),
        }
    }
}
