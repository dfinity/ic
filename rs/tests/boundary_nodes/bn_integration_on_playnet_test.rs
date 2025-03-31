#[rustfmt::skip]

use anyhow::Result;

use ic_boundary_nodes_integration_test_common::{
    api_call_test, api_canister_read_state_test, api_query_test, api_status_test,
    api_subnet_read_state_test, api_sync_call_test, canister_denylist_test,
    content_type_headers_test, cors_headers_test, http_endpoints_test, legacy_asset_canister_test,
    long_asset_canister_test, proxy_http_canister_test, redirect_http_to_https_test,
    redirect_to_dashboard_test,
};
use ic_boundary_nodes_system_test_utils::{
    constants::BOUNDARY_NODE_NAME, helpers::BoundaryNodeHttpsConfig, setup::setup_ic_with_bn,
};
use ic_system_test_driver::{
    driver::group::{SystemTestGroup, SystemTestSubGroup},
    systest,
};

fn main() -> Result<()> {
    let setup = |env| {
        setup_ic_with_bn(
            BOUNDARY_NODE_NAME,
            BoundaryNodeHttpsConfig::UseRealCertsAndDns,
            env,
        )
    };
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
                .add_test(systest!(legacy_asset_canister_test))
                .add_test(systest!(long_asset_canister_test))
                .add_test(systest!(content_type_headers_test))
                .add_test(systest!(cors_headers_test))
                .add_test(systest!(proxy_http_canister_test))
                .add_test(systest!(redirect_http_to_https_test))
                .add_test(systest!(redirect_to_dashboard_test))
                .add_test(systest!(http_endpoints_test)),
        )
        .add_test(systest!(canister_denylist_test))
        .execute_from_args()?;

    Ok(())
}
