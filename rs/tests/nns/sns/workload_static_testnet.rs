use anyhow::Result;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::systest;
use slog::info;
use sns_system_test_lib::sns_deployment::{
    setup_static_testnet, workload_static_testnet_fe_users, workload_static_testnet_get_account,
    workload_static_testnet_sale_bot,
};
use std::time::Duration;

fn workload_static_testnet(env: TestEnv) {
    let log = env.logger();
    if std::env::var("SALE_BOT").is_ok() {
        info!(
            log,
            ">>> Running workload generation to model an SNS sale bot's behavior ..."
        );
        workload_static_testnet_sale_bot(env)
    } else if std::env::var("GET_ACCOUNT").is_ok() {
        info!(
            log,
            ">>> Running workload generation to model an SNS users reloading the launchpag page ..."
        );
        workload_static_testnet_get_account(env)
    } else {
        info!(
            log,
            ">>> Running workload generation to model an SNS FE users' behavior ..."
        );
        workload_static_testnet_fe_users(env)
    }
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_overall_timeout(Duration::from_secs(60 * 60))
        .with_timeout_per_test(Duration::from_secs(60 * 60))
        .with_setup(setup_static_testnet)
        .add_test(systest!(workload_static_testnet))
        .execute_from_args()?;

    Ok(())
}
