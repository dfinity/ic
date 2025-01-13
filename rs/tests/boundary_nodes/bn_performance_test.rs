use anyhow::Result;
use ic_boundary_nodes_performance_test_common::{query_calls_test, setup, update_calls_test};
use ic_boundary_nodes_system_test_utils::helpers::BoundaryNodeHttpsConfig;
use ic_system_test_driver::{driver::group::SystemTestGroup, systest};
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
