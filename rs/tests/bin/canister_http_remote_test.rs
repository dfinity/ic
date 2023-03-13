#[rustfmt::skip]

use anyhow::Result;

use ic_tests::canister_http;
use ic_tests::driver::group::SystemTestGroup;
use ic_tests::systest;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(canister_http::lib::config)
        .add_test(systest!(canister_http::http_basic_remote::test))
        .execute_from_args()?;

    Ok(())
}
