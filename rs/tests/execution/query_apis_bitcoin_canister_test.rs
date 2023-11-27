use anyhow::Result;

use ic_tests::driver::group::SystemTestGroup;
use ic_tests::execution::config_system_verified_application_subnets_with_specified_ids;
use ic_tests::execution::queries::test_bitcoin_query_apis;
use ic_tests::systest;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(config_system_verified_application_subnets_with_specified_ids)
        .add_test(systest!(test_bitcoin_query_apis))
        .execute_from_args()?;

    Ok(())
}
