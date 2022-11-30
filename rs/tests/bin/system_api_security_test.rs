#[rustfmt::skip]

use anyhow::Result;

use ic_tests::driver::new::group::SystemTestGroup;
use ic_tests::execution::system_api_security_test;
use ic_tests::systest;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(system_api_security_test::config)
        .add_test(systest!(system_api_security_test::malicious_inputs))
        .add_test(systest!(
            system_api_security_test::malicious_intercanister_calls
        ))
        .execute_from_args()?;
    Ok(())
}
