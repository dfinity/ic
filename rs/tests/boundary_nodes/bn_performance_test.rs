use anyhow::Result;
use ic_system_test_driver::{driver::group::SystemTestGroup, systest};
use ic_tests::boundary_nodes::{
    helpers::BoundaryNodeHttpsConfig,
    performance_test::{query_calls_test, setup, update_calls_test},
};
use std::time::Duration;

fn main() -> Result<()> {
    let setup_with_config = |env| {
        setup(
            BoundaryNodeHttpsConfig::AcceptInvalidCertsAndResolveClientSide,
            env,
        )
    };
    SystemTestGroup::new()
        .with_setup(setup_with_config)
        .add_test(systest!(update_calls_test))
        .add_test(systest!(query_calls_test))
        .with_timeout_per_test(Duration::from_secs(140 * 60))
        .execute_from_args()?;
    Ok(())
}
