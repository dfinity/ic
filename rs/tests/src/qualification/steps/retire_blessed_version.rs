#![allow(dead_code)]

use ic_canister_client::Sender;
use ic_nervous_system_common_test_keys::{TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_KEYPAIR};
use ic_nns_common::types::NeuronId;
use ic_system_test_driver::{
    driver::test_env_api::{GetFirstHealthyNodeSnapshot, HasPublicApiUrl, HasTopologySnapshot},
    nns::{
        get_governance_canister, submit_update_elected_replica_versions_proposal,
        vote_execute_proposal_assert_executed,
    },
    util::runtime_from_url,
};
use itertools::Itertools;
use slog::info;

use super::Step;

#[derive(Clone)]
pub struct RetireBlessedVersions {
    pub versions: Vec<String>,
}

impl Step for RetireBlessedVersions {
    fn execute(
        &self,
        env: ic_system_test_driver::driver::test_env::TestEnv,
        rt: tokio::runtime::Handle,
    ) -> anyhow::Result<()> {
        let blessed_versions = env.topology_snapshot().blessed_replica_versions()?;

        let versions_to_unelect = self
            .versions
            .iter()
            .filter(|version| blessed_versions.contains(version))
            .cloned()
            .collect_vec();

        if versions_to_unelect.is_empty() {
            info!(
                env.logger(),
                "Versions {} are not blessed",
                self.versions.iter().join(", ")
            );
            return Ok(());
        }

        let nns_node = env.get_first_healthy_nns_node_snapshot();
        let nns = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
        let governance_canister = get_governance_canister(&nns);

        let proposal_sender = Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR);
        let test_neuron_id = NeuronId(TEST_NEURON_1_ID);

        let proposal_id = rt.block_on(submit_update_elected_replica_versions_proposal(
            &governance_canister,
            proposal_sender.clone(),
            test_neuron_id,
            None,
            None,
            vec![],
            versions_to_unelect,
        ));

        rt.block_on(vote_execute_proposal_assert_executed(
            &governance_canister,
            proposal_id,
        ));
        Ok(())
    }

    fn max_retries(&self) -> usize {
        1
    }
}
