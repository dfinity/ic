use std::{str::FromStr, time::Duration};

use ic_consensus_system_test_utils::upgrade::deploy_guestos_to_all_subnet_nodes;
use ic_protobuf::registry::subnet::v1::{SubnetRecord, SubnetType};
use ic_registry_client_helpers::node::NodeRecord;
use ic_system_test_driver::driver::test_env_api::GetFirstHealthyNodeSnapshot;
use ic_types::PrincipalId;
use reqwest::Client;
use slog::{info, Logger};
use tokio::{runtime::Handle, try_join};

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

            let nodes = registry
                .get_family_entries::<NodeRecord>()?
                .into_iter()
                .filter_map(|(principal, node)| {
                    let subnet_id = registry
                        .get_subnet_id_from_node_id(&principal)
                        .unwrap_or_else(|_| {
                            panic!("Failed to find subnet id from node id {}", principal)
                        });

                    match subnet_id {
                        Some(subnet_id) if subnet_id.eq(&curr_subnet_id) => Some(node),
                        _ => None,
                    }
                })
                .collect();

            rt.block_on(self.wait_for_upgrade(&nodes, env.logger(), curr_subnet_id))?
        }

        Ok(())
    }

    fn max_retries(&self) -> usize {
        1
    }
}

impl UpdateSubnetType {
    fn max_retries_upgrade(&self) -> usize {
        100
    }
    fn backoff(&self) -> Duration {
        Duration::from_secs(15)
    }
    fn timeout(&self) -> Duration {
        Duration::from_secs(30)
    }

    async fn wait_for_upgrade(
        &self,
        nodes: &Vec<NodeRecord>,
        logger: Logger,
        subnet: PrincipalId,
    ) -> anyhow::Result<()> {
        let client = Client::builder().timeout(self.timeout()).build()?;

        for i in 0..self.max_retries_upgrade() {
            tokio::time::sleep(self.backoff()).await;
            info!(
                logger,
                "Iter {}: checking if version {} is on subnet {}", i, self.version, subnet
            );

            match try_join!(nodes.iter().map(|node| async { poll_node_metrics_for_new_version(
                &self.version,
                &node
                    .http
                    .ok_or(anyhow::anyhow!(
                        "Failed to get connection details about the nodes in subnet {}",
                        subnet
                    ))?
                    .ip_addr
            ).await } )) {
                Ok(_) => {
                    info!(
                        logger,
                        "Iter {}: found version {} on all nodes in subnet {}", i, self.version, subnet
                    );
                    break;
                },
                Err(e) => info!(
                    logger,
                    "Iter {}: didn't find version {} on all nodes in subnet {}, received error: {:?}",
                    i,
                    self.version,
                    subnet,
                    e
                ),
            }
        }

        Ok(())
    }
}

async fn poll_node_metrics_for_new_version(version: &str, ip: &str) -> anyhow::Result<()> {
    Ok(())
}
