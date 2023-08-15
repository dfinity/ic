use anyhow::Result;
use ic_tests::{
    boundary_nodes_integration::{
        boundary_nodes::BoundaryNodeHttpsConfig,
        performance_test::{self, setup},
    },
    driver::group::SystemTestGroup,
    systest,
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
        .add_test(systest!(performance_test::update_calls_test))
        .with_timeout_per_test(Duration::from_secs(30 * 60))
        .execute_from_args()?;
    Ok(())
}
