#[rustfmt::skip]

use anyhow::Result;
use ic_tests::{
    custom_domains_integration::{
        certificate_orchestrator::test_end_to_end_registration, setup::setup,
    },
    driver::group::SystemTestGroup,
    systest,
};

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test_end_to_end_registration))
        .execute_from_args()
}
