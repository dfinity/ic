#[rustfmt::skip]

use anyhow::Result;
use ic_tests::{
    certificate_orchestrator::{
        access_control_test, certificate_export_test, config, registration_test, task_queue_test,
    },
    driver::group::{SystemTestGroup, SystemTestSubGroup},
    systest,
};

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(config)
        .add_parallel(
            SystemTestSubGroup::new()
                .add_test(systest!(access_control_test))
                .add_test(systest!(registration_test))
                .add_test(systest!(task_queue_test))
                .add_test(systest!(certificate_export_test)),
        )
        .execute_from_args()?;
    Ok(())
}
