use anyhow::Result;
use ic_tests::{
    driver::group::SystemTestGroup,
    orchestrator::subnet_splitting::{setup, subnet_splitting_test as test},
    systest,
};

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()
}
