/* tag::catalog[]
end::catalog[] */

use anyhow::Result;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        ic::{InternetComputer, Subnet},
        prometheus_vm::{HasPrometheus, PrometheusVm},
        test_env::TestEnv,
        test_env_api::{HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer},
    },
    systest,
};
use ic_types::Height;
use std::time::Duration;

fn setup(env: TestEnv) {
    PrometheusVm::default()
        .start(&env)
        .expect("failed to start prometheus VM");

    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_dkg_interval_length(Height::from(99))
                .with_unit_delay(Duration::from_millis(100))
                .with_initial_notary_delay(Duration::from_millis(100))
                .add_nodes(1),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });

    env.sync_with_prometheus();
}

fn test(env: TestEnv) {
    todo!()
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;

    Ok(())
}
