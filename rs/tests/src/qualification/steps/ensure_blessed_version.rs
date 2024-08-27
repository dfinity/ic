use std::time::Duration;

use ic_consensus_system_test_utils::upgrade::bless_public_replica_version;
use ic_protobuf::registry::replica_version::v1::BlessedReplicaVersions;
use ic_system_test_driver::driver::test_env_api::{
    GetFirstHealthyNodeSnapshot, HasIcDependencies, HasPublicApiUrl, HasTopologySnapshot,
};
use slog::info;

use super::{RegistryWrapper, Step};

#[derive(Clone)]
pub struct EnsureBlessedVersion {
    pub version: String,
}

impl Step for EnsureBlessedVersion {
    async fn execute(
        &self,
        env: ic_system_test_driver::driver::test_env::TestEnv,
        registry: RegistryWrapper,
    ) -> anyhow::Result<()> {
        let blessed_versions = registry
            .get_family_entries::<BlessedReplicaVersions>()?
            .first_entry()
            .ok_or(anyhow::anyhow!("No blessed replica versions found"))?
            .get()
            .to_owned();
        if blessed_versions.blessed_version_ids.contains(&self.version) {
            info!(env.logger(), "Version `{}` already blessed", self.version);
            return Ok(());
        }

        let nns_node = env.get_first_healthy_system_node_snapshot();

        bless_public_replica_version(
            &nns_node,
            &self.version,
            ic_consensus_system_test_utils::upgrade::UpdateImageType::Image,
            ic_consensus_system_test_utils::upgrade::UpdateImageType::Sha256,
            &env.logger(),
        )
        .await;

        // This call updates the local registry
        env.topology_snapshot()
            .block_for_newer_registry_version_within_duration(
                Duration::from_secs(10 * 60),
                Duration::from_secs(10),
            )
            .await?;

        registry.sync_with_local_store().await?;
        let blessed_versions = registry
            .get_family_entries::<BlessedReplicaVersions>()?
            .first_entry()
            .ok_or(anyhow::anyhow!("No blessed replica versions found"))?
            .get()
            .to_owned();

        match blessed_versions.blessed_version_ids.contains(&self.version) {
            true => Ok(()),
            false => Err(anyhow::anyhow!("Blessed version not found in the registry")),
        }
    }

    // Should be able to bless version in one try
    fn max_retries(&self) -> usize {
        1
    }
}
