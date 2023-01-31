#[rustfmt::skip]

use anyhow::Result;

use ic_tests::driver::new::group::SystemTestGroup;
use ic_tests::nns_tests::sns_deployment::{
    initiate_token_swap, sns_setup, workload_rps400_get_state_query,
};
use ic_tests::systest;

fn main() -> Result<()> {
    let mut g = SystemTestGroup::new().with_setup(sns_setup);

    // if std::env::var("SYSTEST_STAY_ALIVE").is_ok() {
    //     // The group will be kept alive for 50 minutes after the setup completes
    //     let max_group_lifetime = Duration::from_secs(55 * 60);
    //     let experiment_duration = Duration::from_secs(50 * 60);
    //     g = g
    //     .with_overall_timeout(max_group_lifetime)
    //     .with_timeout_per_test(experiment_duration)
    //     .add_task_with_minimal_lifetime(systest!(initiate_token_swap), experiment_duration);
    // } else {
    //     // Do not keep group alive if all the tasks have completed
    // g = g
    // .add_test(systest!(initiate_token_swap))
    // .add_test(systest!(workload_rps400_get_state_query));
    // };

    g = g
        .add_test(systest!(initiate_token_swap))
        .add_test(systest!(workload_rps400_get_state_query));

    g.execute_from_args()?;
    Ok(())
}
