#[rustfmt::skip]

use anyhow::Result;
use slog::info;

// use ic_tests::basic_health_test;
use ic_tests::driver::new::group::SystemTestGroup;
use ic_tests::driver::test_env::TestEnv;
use ic_tests::systest;

pub fn mock_setup(env: TestEnv) {
    println!("Mock setup");
    let logger = env.logger();
    info!(logger, "Mock setup");
}

pub fn mock_test(env: TestEnv) {
    println!("Mock test");
    let logger = env.logger();
    info!(logger, "Mock test");
}

/// Intended file structure
/// cp -r group_dir/setup group_dir/tests/mock_test_1
/// cp -r group_dir/setup group_dir/tests/mock_test_2
fn main() -> Result<()> {
    // SystemTestGroup::new()
    //     .with_setup(basic_health_test::config_single_host)
    //     .add_test(systest!(basic_health_test::test))
    //     .execute_from_args()?;

    SystemTestGroup::new()
        .with_setup(mock_setup)
        .add_test(systest!(mock_test))
        .execute_from_args()?;

    Ok(())
}
