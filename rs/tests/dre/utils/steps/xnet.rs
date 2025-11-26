use super::Step;
use ic_system_test_driver::{
    driver::test_env_api::{HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer},
    util::runtime_from_url,
};
use itertools::Itertools;
use xnet_slo_test_lib::{Config, test_async_impl};

#[derive(Clone)]
pub struct XNet {
    pub subnets: usize,
    pub nodes_per_subnet: usize,
    pub runtime: std::time::Duration,
    pub request_rate: usize,
}

// Defaults come from `rs/tests/message_routing/xnet/xnet_slo_3_subnets_test.rs`
// tweaked for our use case
impl Default for XNet {
    fn default() -> Self {
        Self {
            subnets: 2,
            nodes_per_subnet: 4,
            runtime: std::time::Duration::from_secs(600),
            request_rate: 10,
        }
    }
}

impl Step for XNet {
    fn execute(
        &self,
        env: ic_system_test_driver::driver::test_env::TestEnv,
        rt: tokio::runtime::Handle,
    ) -> anyhow::Result<()> {
        // Both guaranteed response and best-effort calls.
        let config = Config::new(
            self.subnets,
            self.nodes_per_subnet,
            self.runtime,
            self.request_rate,
        );

        let mut subnets = env
            .topology_snapshot()
            .subnets()
            .filter(|s| {
                s.subnet_type()
                    .eq(&ic_registry_subnet_type::SubnetType::Application)
            })
            .map(|s| s.nodes().next().unwrap())
            .map(|node| runtime_from_url(node.get_public_url(), node.effective_canister_id()))
            .collect_vec();
        if subnets.len() < self.subnets {
            panic!(
                "Topology has only {} application subnets, but {} is required for XNet test",
                subnets.len(),
                self.subnets
            )
        }
        subnets.truncate(self.subnets);

        let threaded = rt.spawn(async move {
            test_async_impl(env.clone(), subnets.into_iter(), config, &env.logger()).await
        });
        rt.block_on(threaded).map_err(anyhow::Error::from)
    }
}
