use anyhow::Result;
use std::time::Duration;

use ic_tests::driver::new::group::SystemTestGroup;
use ic_tests::nns_tests::sns_deployment::{
    check_all_participants, init_participants, initiate_token_swap,
    sns_setup_with_many_sale_participants,
};
use ic_tests::systest;

/// This is a non-interactive load test:
/// 1. Install NNS with many sale-ready identities (see `SNS_SALE_PARTICIPANTS`)
/// 2. Install SNS
/// 3. Start the token sale
/// 4. Initiate all the participants via `refresh_buyer_tokens`
/// 3. Check that all participations have been set up correctly via `get_buyer_state`
fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_overall_timeout(Duration::from_secs(25 * 60)) // 25 min
        .with_timeout_per_test(Duration::from_secs(15 * 60)) // 15 min
        .with_setup(sns_setup_with_many_sale_participants)
        .add_test(systest!(initiate_token_swap))
        .add_test(systest!(init_participants))
        .add_test(systest!(check_all_participants))
        .execute_from_args()?;
    Ok(())
}
