#[rustfmt::skip]

use anyhow::Result;
use ic_system_test_driver::{
    driver::group::{SystemTestGroup, SystemTestSubGroup},
    systest,
};
use ic_tests::certificate_orchestrator::{
    access_control_test, certificate_export_test, config, expiration_test, registration_test,
    renewal_expiration_test, retry_test, task_queue_test,
};

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(config)
        .add_parallel(
            SystemTestSubGroup::new()
                .add_test(systest!(access_control_test))
                .add_test(systest!(registration_test))
                .add_test(systest!(expiration_test))
                .add_test(systest!(task_queue_test))
                .add_test(systest!(retry_test))
                .add_test(systest!(renewal_expiration_test))
                .add_test(systest!(certificate_export_test)),
        )
        .execute_from_args()?;
    Ok(())
}
