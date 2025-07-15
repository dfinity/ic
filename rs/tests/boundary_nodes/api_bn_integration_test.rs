use anyhow::Result;
use ic_boundary_nodes_integration_test_common::{
    api_call_test, api_canister_read_state_test, api_query_test, api_status_test,
    api_subnet_read_state_test, api_sync_call_test, content_type_headers_test,
    logs_websocket_cors_test,
};
use ic_boundary_nodes_system_test_utils::setup::setup_ic;
use ic_system_test_driver::{
    driver::group::{SystemTestGroup, SystemTestSubGroup},
    systest,
};

fn main() -> Result<()> {
    let setup = |env| setup_ic(env, 1);
    SystemTestGroup::new()
        .with_setup(setup)
        .add_parallel(
            SystemTestSubGroup::new()
                .add_test(systest!(api_status_test))
                .add_test(systest!(api_query_test))
                .add_test(systest!(api_call_test))
                .add_test(systest!(api_sync_call_test))
                .add_test(systest!(api_canister_read_state_test))
                .add_test(systest!(api_subnet_read_state_test))
                .add_test(systest!(content_type_headers_test))
                .add_test(systest!(logs_websocket_cors_test)),
        )
        .execute_from_args()?;

    Ok(())
}
