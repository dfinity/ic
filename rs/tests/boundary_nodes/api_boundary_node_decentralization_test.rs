use anyhow::Result;

use ic_tests::{
    boundary_nodes::{api_boundary_nodes_integration::decentralization_test, setup::setup_ic},
    driver::group::SystemTestGroup,
    systest,
};

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup_ic)
        .add_test(systest!(decentralization_test))
        .execute_from_args()?;
    Ok(())
}
