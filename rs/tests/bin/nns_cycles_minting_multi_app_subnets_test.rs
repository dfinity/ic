use anyhow::Result;

use ic_tests::driver::group::SystemTestGroup;
use ic_tests::nns_tests::cycles_minting::{
    config_with_multiple_app_subnets, create_canister_on_specific_subnet_type,
};
use ic_tests::systest;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(config_with_multiple_app_subnets)
        .add_test(systest!(create_canister_on_specific_subnet_type))
        .execute_from_args()?;
    Ok(())
}
