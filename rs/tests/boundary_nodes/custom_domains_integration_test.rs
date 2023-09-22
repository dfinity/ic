#[rustfmt::skip]

use anyhow::Result;
use ic_tests::{
    custom_domains_integration::{
        certificate_orchestrator::{test_end_to_end_registration, test_nop_2, test_nop_3},
        setup::setup,
    },
    driver::group::SystemTestGroup,
    systest,
};

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test_end_to_end_registration))
        .add_test(systest!(test_nop_2))
        .add_test(systest!(test_nop_3))
        .execute_from_args()
}
