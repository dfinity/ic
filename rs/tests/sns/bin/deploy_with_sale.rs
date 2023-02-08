#[rustfmt::skip]

use anyhow::Result;

use ic_tests::driver::new::group::SystemTestGroup;
use ic_tests::nns_tests::sns_deployment::{initiate_token_swap, sns_setup};
use ic_tests::systest;

/// This is a non-interactive load test:
/// 1. Install NNS and SNS
/// 2. Start the token sale
fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(sns_setup)
        .add_test(systest!(initiate_token_swap))
        .execute_from_args()?;
    Ok(())
}
