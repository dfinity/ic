/* tag::catalog[]
Title:: Specification compliance test

Goal:: Ensure that the replica implementation is compliant with the formal specification.

Runbook::
. Set up system system and application subnet containing two nodes each
. Run ic-ref-test against application subnet

Success:: The ic-ref-test binary does not return an error.

end::catalog[] */

use anyhow::Result;

use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::systest;
use spec_compliance::{config_impl, test_subnet};

pub fn config(env: TestEnv) {
    config_impl(env, false, false);
}

pub fn test(env: TestEnv) {
    test_subnet(
        env,
        false,
        false,
        None,
        Some(SubnetType::Application),
        vec![],
        vec!["($0 ~ /NNS canisters/)"],
    );
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(config)
        .add_test(systest!(test))
        .execute_from_args()?;

    Ok(())
}
