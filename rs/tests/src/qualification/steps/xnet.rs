use ic_system_test_driver::driver::test_env_api::HasTopologySnapshot;
use itertools::Itertools;

use crate::message_routing;

use super::Step;

#[derive(Clone)]
pub struct XNet {}

impl Step for XNet {
    fn execute(
        &self,
        env: ic_system_test_driver::driver::test_env::TestEnv,
        rt: tokio::runtime::Handle,
    ) -> anyhow::Result<()> {
        let subnets = env
            .topology_snapshot()
            .subnets()
            .filter(|s| {
                s.subnet_type()
                    .eq(&ic_registry_subnet_type::SubnetType::Application)
            })
            .collect_vec();

        if subnets.len() < 2 {
            panic!("Need at least two application subnets");
        }
        let subnets = subnets[0..2].to_vec();
        let handle = rt.spawn_blocking(|| message_routing::global_reboot_test::test_on_subnets(env, subnets));
        rt.block_on(handle).map_err(|e| anyhow::anyhow!("Received panic while running xnet test: {:?}", e))
    }

    fn total_runs(&self) -> usize {
        3
    }
}
