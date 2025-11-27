use std::time::Duration;

use ic_consensus_system_test_utils::upgrade::bless_replica_version_with_urls;
use ic_protobuf::registry::replica_version::v1::GuestLaunchMeasurements;
use ic_system_test_driver::driver::test_env_api::{
    GetFirstHealthyNodeSnapshot, HasTopologySnapshot,
};
use ic_types::ReplicaVersion;
use slog::info;
use tokio::runtime::Handle;
use url::Url;

use super::Step;

#[derive(Clone)]
pub struct EnsureElectedVersion {
    pub version: ReplicaVersion,
    pub url: Url,
    pub sha256: String,
    pub guest_launch_measurements: Option<GuestLaunchMeasurements>,
}

impl Step for EnsureElectedVersion {
    fn execute(
        &self,
        env: ic_system_test_driver::driver::test_env::TestEnv,
        rt: Handle,
    ) -> anyhow::Result<()> {
        let elected_versions = env.topology_snapshot().elected_replica_versions()?;
        if elected_versions.iter().any(|v| v == self.version.as_ref()) {
            info!(env.logger(), "Version `{}` already blessed", self.version);
            return Ok(());
        }

        let nns_node = env.get_first_healthy_system_node_snapshot();

        info!(env.logger(), "Upgrade URL: {}", self.url);

        rt.block_on(bless_replica_version_with_urls(
            &nns_node,
            &self.version,
            vec![self.url.to_string()],
            self.sha256.clone(),
            self.guest_launch_measurements.clone(),
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

        let elected_versions = new_snapshot.elected_replica_versions()?;

        match elected_versions.iter().any(|v| v == self.version.as_ref()) {
            true => Ok(()),
            false => Err(anyhow::anyhow!("Blessed version not found in the registry")),
        }
    }
}
