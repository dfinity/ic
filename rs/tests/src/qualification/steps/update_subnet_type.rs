use futures::future::join_all;
use ic_canister_client::Sender;
use ic_consensus_system_test_utils::upgrade::{
    assert_assigned_replica_version_with_time, deploy_guestos_to_all_subnet_nodes,
};
use ic_nervous_system_common_test_keys::{TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_KEYPAIR};
use ic_nns_common::types::NeuronId;
use ic_protobuf::registry::subnet::v1::SubnetType;
use ic_system_test_driver::{
    driver::test_env_api::{
        GetFirstHealthyNodeSnapshot, HasIcDependencies, HasPublicApiUrl, HasTopologySnapshot,
        IcNodeContainer, IcNodeSnapshot, TopologySnapshot,
    },
    nns::{
        get_governance_canister, submit_update_unassigned_node_version_proposal,
        vote_execute_proposal_assert_executed,
    },
    util::runtime_from_url,
};
use itertools::Itertools;
use slog::{info, Logger};
use tokio::runtime::Handle;

use super::Step;

#[derive(Clone)]
pub struct UpdateSubnetType {
    pub subnet_type: Option<SubnetType>,
    pub version: String,
}

impl Step for UpdateSubnetType {
    fn execute(
        &self,
        env: ic_system_test_driver::driver::test_env::TestEnv,
        rt: Handle,
    ) -> anyhow::Result<()> {
        let logger = env.logger();
        let nns_node = env.get_first_healthy_system_node_snapshot();

        if let Some(subnet_type) = self.subnet_type {
            for subnet_snaphost in env
                .topology_snapshot()
                .subnets()
                .filter(|subnet| subnet.raw_subnet_record().subnet_type().eq(&subnet_type))
            {
                let raw_record = subnet_snaphost.raw_subnet_record();
                if raw_record.replica_version_id.eq(&self.version) {
                    info!(
                        logger,
                        "Subnet `{}` is already on version `{}`",
                        subnet_snaphost.subnet_id,
                        self.version
                    );
                    continue;
                }
                info!(
                    logger,
                    "Upgrading subnet `{}` to version `{}`",
                    subnet_snaphost.subnet_id,
                    self.version
                );

                rt.block_on(deploy_guestos_to_all_subnet_nodes(
                    &nns_node,
                    &ic_types::ReplicaVersion::try_from(self.version.clone())?,
                    subnet_snaphost.subnet_id,
                ));
                let new_topology =
                    rt.block_on(env.topology_snapshot().block_for_newer_registry_version())?;

                let current_subnet = new_topology
                    .subnets()
                    .find_map(|s| {
                        if s.subnet_id.eq(&subnet_snaphost.subnet_id) {
                            Some(s.raw_subnet_record())
                        } else {
                            None
                        }
                    })
                    .ok_or(anyhow::anyhow!(
                        "Didn't find subnet with key `{}` after upgrade",
                        subnet_snaphost.subnet_id
                    ))?;

                if !current_subnet.replica_version_id.eq(&self.version) {
                    return Err(anyhow::anyhow!(
                        "Subnet `{}` is not at the correct version after upgrade",
                        subnet_snaphost.subnet_id
                    ));
                }

                // Will panic if not upgraded
                let handle = rt.clone();
                rt.block_on(assert_version_on_all_nodes(
                    subnet_snaphost.nodes().collect_vec(),
                    env.logger(),
                    self.version.clone(),
                    handle,
                ));
            }
        } else {
            let versions = get_unassigned_nodes_version(env.topology_snapshot());
            if versions.len() > 1 {
                return Err(anyhow::anyhow!(
                    "Found multiple versions on unassigned nodes: {}",
                    versions.iter().join(", ")
                ));
            }

            if versions.is_empty() {
                info!(logger, "Network contains no unassigned nodes");
                return Ok(());
            }

            let version = versions.first().unwrap();
            if version.eq(&self.version) {
                info!(
                    logger,
                    "Unassigned nodes already on version {}", self.version
                );
                return Ok(());
            }

            let nns_node = env.get_first_healthy_nns_node_snapshot();
            let nns = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
            let governance_canister = get_governance_canister(&nns);
            let test_neuron_id = NeuronId(TEST_NEURON_1_ID);
            let proposal_sender = Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR);

            let proposal_id = rt.block_on(submit_update_unassigned_node_version_proposal(
                &governance_canister,
                proposal_sender,
                test_neuron_id,
                self.version.clone(),
            ));
            rt.block_on(vote_execute_proposal_assert_executed(
                &governance_canister,
                proposal_id,
            ));

            rt.block_on(env.topology_snapshot().block_for_newer_registry_version())?;
        }

        Ok(())
    }

    fn max_retries(&self) -> usize {
        1
    }
}

async fn assert_version_on_all_nodes(
    nodes: Vec<IcNodeSnapshot>,
    logger: Logger,
    version: String,
    rt: Handle,
) -> anyhow::Result<()> {
    let threads = nodes.into_iter().map(|node| {
        let logger_clone = logger.clone();
        let version_clone = version.clone();
        rt.spawn_blocking(move || {
            assert_assigned_replica_version_with_time(&node, &version_clone, logger_clone, 1500, 15)
        })
    });

    if join_all(threads.into_iter())
        .await
        .iter()
        .any(|r| r.is_err())
    {
        anyhow::bail!(
            "Failed to ensure replica version {} on the current subnet",
            version
        )
    }

    Ok(())
}

fn get_unassigned_nodes_version(topology_snapshot: TopologySnapshot) -> Vec<String> {
    let unassigned_nodes = topology_snapshot.unassigned_nodes().collect_vec();
    unassigned_nodes
        .iter()
        .map(|n| {
            n.get_initial_replica_version()
                .expect("Should be able to read unassigned nodes version")
                .to_string()
        })
        .dedup()
        .collect_vec()
}
