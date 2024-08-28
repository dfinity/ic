use std::str::FromStr;

use futures::future::join_all;
use ic_consensus_system_test_utils::upgrade::{
    assert_assigned_replica_version, deploy_guestos_to_all_subnet_nodes,
};
use ic_protobuf::registry::subnet::v1::{SubnetRecord, SubnetType};
use ic_system_test_driver::driver::test_env_api::{
    GetFirstHealthyNodeSnapshot, HasTopologySnapshot, IcNodeContainer, TopologySnapshot,
};
use ic_types::PrincipalId;
use itertools::Itertools;
use slog::{info, Logger};
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
            let new_topology =
                rt.block_on(env.topology_snapshot().block_for_newer_registry_version())?;
            rt.block_on(registry.sync_with_nns())?;

            let (curr_subnet_id, current_subnet) = registry
                .get_family_entries::<SubnetRecord>()?
                .into_iter()
                .find_map(|(k, s)| {
                    if k.eq(key) {
                        Some((
                            PrincipalId::from_str(&k)
                                .expect("Should be able to map string to Principals"),
                            s,
                        ))
                    } else {
                        None
                    }
                })
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

            // Will panic if not upgraded
            let handle = rt.clone();
            rt.block_on(assert_version_on_all_nodes(
                new_topology,
                curr_subnet_id,
                env.logger(),
                self.version.clone(),
                handle,
            ));
        }

        Ok(())
    }

    fn max_retries(&self) -> usize {
        1
    }
}

async fn assert_version_on_all_nodes(
    snapshot: TopologySnapshot,
    subnet_id: PrincipalId,
    logger: Logger,
    version: String,
    rt: Handle,
) {
    let threads = snapshot
        .subnets()
        .into_iter()
        .filter(|subnet| subnet.subnet_id.get().eq(&subnet_id))
        .flat_map(|subnet| {
            subnet.nodes().into_iter().map(|node| {
                let logger_clone = logger.clone();
                let version_clone = version.clone();
                rt.spawn_blocking(move || {
                    assert_assigned_replica_version(&node, &version_clone, logger_clone)
                })
            })
        })
        .collect_vec();

    join_all(threads.into_iter().map(|t| async { t.await })).await;
}
