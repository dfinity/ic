/* tag::catalog[]
Title:: Specification compliance test

Goal:: Ensure that the replica implementation is compliant with the formal specification.

Runbook::
. Set up application subnet containing one node
. Run ic-ref-test

Success:: The ic-ref-test binary does not return an error.

end::catalog[] */

use anyhow::Result;

use ic_registry_subnet_type::SubnetType;
use ic_tests::driver::new::group::SystemTestGroup;
use ic_tests::driver::test_env::TestEnv;
use ic_tests::spec_compliance::{config_with_subnet_type, test_subnet};
use ic_tests::systest;

pub fn config(env: TestEnv) {
    config_with_subnet_type(env, SubnetType::Application);
}

pub fn test(env: TestEnv) {
    test_subnet(env, SubnetType::Application);
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(config)
        .add_test(systest!(test))
        .execute_from_args()?;

    Ok(())
}
