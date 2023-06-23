#[rustfmt::skip]

use anyhow::Result;

use ic_tests::{
    api_boundary_nodes_integration::api_bn::{mk_setup, noop_test, ApiBoundaryNodeHttpsConfig},
    driver::group::SystemTestGroup,
    systest,
};

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(mk_setup(
            ApiBoundaryNodeHttpsConfig::AcceptInvalidCertsAndResolveClientSide,
        ))
        .add_test(systest!(noop_test))
        .execute_from_args()?;

    Ok(())
}
