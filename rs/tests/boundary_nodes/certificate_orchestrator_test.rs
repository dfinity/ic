#[rustfmt::skip]

use anyhow::Result;
use ic_tests::{
    certificate_orchestrator::{certificate_orchestrator_test, config},
    driver::group::SystemTestGroup,
    systest,
};

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(config)
        .add_test(systest!(certificate_orchestrator_test))
        .execute_from_args()?;
    Ok(())
}
