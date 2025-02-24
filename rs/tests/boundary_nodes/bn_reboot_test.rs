#[rustfmt::skip]

use anyhow::Result;

use ic_boundary_nodes_integration_test_common::reboot_test;
use ic_boundary_nodes_system_test_utils::{
    constants::BOUNDARY_NODE_NAME, helpers::BoundaryNodeHttpsConfig, setup::setup_ic_with_bn,
};
use ic_system_test_driver::{driver::group::SystemTestGroup, systest};

fn main() -> Result<()> {
    let setup = |env| {
        setup_ic_with_bn(
            BOUNDARY_NODE_NAME,
            BoundaryNodeHttpsConfig::AcceptInvalidCertsAndResolveClientSide,
            env,
        )
    };
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(reboot_test))
        .execute_from_args()?;

    Ok(())
}
