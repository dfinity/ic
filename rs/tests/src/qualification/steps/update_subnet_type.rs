use std::str::FromStr;

use ic_consensus_system_test_utils::upgrade::deploy_guestos_to_all_subnet_nodes;
use ic_protobuf::registry::subnet::v1::{SubnetRecord, SubnetType};
use ic_system_test_driver::driver::test_env_api::GetFirstHealthyNodeSnapshot;
use ic_types::PrincipalId;
use slog::info;
use tokio::runtime::Handle;

use super::Step;

#[derive(Clone)]
pub struct UpdateSubnetType {
    pub subnet_type: SubnetType,
    pub version: String,
}

impl Step for UpdateSubnetType {
    fn execute(
        &self,
        env: ic_system_test_driver::driver::test_env::TestEnv,
        rt: Handle,
        registry: super::RegistryWrapper,
    ) -> anyhow::Result<()> {
        let logger = env.logger();
        let nns_node = env.get_first_healthy_system_node_snapshot();

        for (key, subnet) in registry
            .get_family_entries::<SubnetRecord>()?
            .iter()
            .filter(|(_, subnet)| subnet.subnet_type().eq(&self.subnet_type))
        {
            if subnet.replica_version_id.eq(&self.version) {
                info!(
                    logger,
                    "Subnet `{}` is already on version `{}`", key, self.version
                );
                continue;
            }
            info!(
                logger,
                "Upgrading subnet `{}` to version `{}`", key, self.version
            );

            rt.block_on(deploy_guestos_to_all_subnet_nodes(
                &nns_node,
                &ic_types::ReplicaVersion::try_from(self.version.clone())?,
                PrincipalId::from_str(&key)?.into(),
            ));
            rt.block_on(registry.sync_with_nns())?;

            let current_subnet = registry
                .get_family_entries::<SubnetRecord>()?
                .iter()
                .find_map(|(k, s)| if k.eq(key) { Some(s) } else { None })
                .cloned()
                .ok_or(anyhow::anyhow!(
                    "Didn't find subnet with key `{}` after upgrade",
                    key
                ))?;

            if !current_subnet.replica_version_id.eq(&self.version) {
                return Err(anyhow::anyhow!(
                    "Subnet `{}` is not at the correct version after upgrade",
                    key
                ));
            }
        }

        Ok(())
    }

    fn max_retries(&self) -> usize {
        1
    }
}
