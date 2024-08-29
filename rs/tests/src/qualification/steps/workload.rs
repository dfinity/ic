use futures::future::join_all;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    canister_agent::HasCanisterAgentCapability,
    driver::test_env_api::{HasTopologySnapshot, IcNodeContainer},
};
use itertools::Itertools;
use slog::info;

use super::Step;

#[derive(Clone)]
pub struct Workload {
    pub canister_count: usize,
}

impl Step for Workload {
    fn execute(
        &self,
        env: ic_system_test_driver::driver::test_env::TestEnv,
        rt: tokio::runtime::Handle,
    ) -> anyhow::Result<()> {
        let logger = env.logger();

        let subnet = env
            .topology_snapshot()
            .subnets()
            .find(|s| s.subnet_type() == SubnetType::Application)
            .ok_or(anyhow::anyhow!("Failed to find app subnet"))?;
        let app_node = subnet
            .nodes()
            .next()
            .ok_or(anyhow::anyhow!("App subnet has no nodes"))?;

        info!(
            logger,
            "Installing {} canisters on the subnet...", self.canister_count
        );

        let mut canisters = Vec::with_capacity(self.canister_count);
        let agent = rt.block_on(app_node.build_canister_agent());
        let nodes = subnet.nodes().collect_vec();
        let agents = rt.block_on(join_all(
            nodes
                .into_iter()
                .map(|n| async move { n.build_canister_agent().await }),
        ));

        for i in 0..self.canister_count {
            canisters.insert(
                i,
                app_node.create_and_install_canister_with_arg("rs/tests/src/counter.wat", None),
            )
        }
        info!(
            logger,
            "{} Canisters installed successfully.",
            canisters.len()
        );

        Ok(())
    }

    fn max_retries(&self) -> usize {
        3
    }
}
