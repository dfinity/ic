#[rustfmt::skip]

use anyhow::Result;

use ic_tests::canister_http;
use ic_tests::driver::new::group::SystemTestGroup;
use ic_tests::systest;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(canister_http::http_socks::config)
        .add_test(systest!(canister_http::http_socks::test))
        .execute_from_args()?;

    Ok(())
}
