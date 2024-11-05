/* tag::catalog[]
Title:: Specification compliance test

Goal:: Ensure that the replica implementation is compliant with the formal specification.

Runbook::
. Set up system and application subnet containing two nodes each
. Run ic-ref-test against application subnet

Success:: The ic-ref-test binary does not return an error.

end::catalog[] */

use anyhow::Result;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::systest;
use spec_compliance::{group_all, setup_impl, test_subnet};

pub fn setup(env: TestEnv) {
    setup_impl(env, true, false);
}

pub fn test(env: TestEnv) {
    test_subnet(
        env,
        true,
        false,
        Some(SubnetType::Application),
        None,
        group_all(),
        vec![],
    );
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;

    Ok(())
}
