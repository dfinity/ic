use ic_protobuf::registry::subnet::v1::{SubnetRecord, SubnetType};
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
                "Placing proposal to upgrade subnet `{}` to version `{}`", key, self.version
            );

            // Place proposal and monitor
        }

        Ok(())
    }

    fn max_retries(&self) -> usize {
        1
    }
}
