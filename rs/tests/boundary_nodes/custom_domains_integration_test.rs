#[rustfmt::skip]

use anyhow::Result;
use ic_system_test_driver::{driver::group::SystemTestGroup, systest};
use ic_tests::custom_domains_integration::{
    certificate_orchestrator::test_end_to_end_registration, setup::setup,
};

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test_end_to_end_registration))
        .execute_from_args()
}
