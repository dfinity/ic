/* tag::catalog[]
Title:: Specification compliance test

Goal:: Ensure that the replica implementation is compliant with the formal specification.

Runbook::
. Set up system and application subnet containing two nodes each
. Run ic-ref-test against system subnet

Success:: The ic-ref-test binary does not return an error.

end::catalog[] */

use anyhow::Result;

use ic_registry_subnet_type::SubnetType;
use ic_tests::driver::group::SystemTestGroup;
use ic_tests::driver::test_env::TestEnv;
use ic_tests::spec_compliance::{config_impl, test_subnet};
use ic_tests::systest;

pub fn config(env: TestEnv) {
    config_impl(env);
}

pub fn test(env: TestEnv) {
    test_subnet(
        env,
        Some(SubnetType::Application),
        None,
        vec![],
        vec!["($0 ~ /API availability/)"],
    );
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(config)
        .add_test(systest!(test))
        .execute_from_args()?;

    Ok(())
}
