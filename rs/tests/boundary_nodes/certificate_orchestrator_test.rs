#[rustfmt::skip]

use anyhow::Result;
use ic_tests::{
    certificate_orchestrator::{
        access_control_test, certificate_export_test, config, expiration_test, registration_test,
        renewal_expiration_test, task_queue_test,
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
                .add_test(systest!(expiration_test))
                .add_test(systest!(task_queue_test))
                // TODO: the retry_test is flaky so it has been commented out for now.
                // See: https://dfinity.atlassian.net/browse/BOUN-1037
                // .add_test(systest!(retry_test))
                .add_test(systest!(renewal_expiration_test))
                .add_test(systest!(certificate_export_test)),
        )
        .execute_from_args()?;
    Ok(())
}
