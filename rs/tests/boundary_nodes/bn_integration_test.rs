#[rustfmt::skip]

use anyhow::Result;

use ic_boundary_nodes_integration_test_common::{
    api_endpoints_test, asset_canister_test, canister_denylist_test, content_type_headers_test,
    cors_headers_test, http_endpoints_test, proxy_http_canister_test, reboot_test,
    redirect_http_to_https_test, redirect_to_dashboard_test,
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
            BoundaryNodeHttpsConfig::AcceptInvalidCertsAndResolveClientSide,
            env,
        )
    };
    SystemTestGroup::new()
        .with_setup(setup)
        .add_parallel(
            SystemTestSubGroup::new()
                .add_test(systest!(api_endpoints_test))
                .add_test(systest!(asset_canister_test))
                .add_test(systest!(content_type_headers_test))
                .add_test(systest!(cors_headers_test))
                .add_test(systest!(proxy_http_canister_test))
                .add_test(systest!(redirect_http_to_https_test))
                .add_test(systest!(redirect_to_dashboard_test))
                .add_test(systest!(http_endpoints_test)),
        )
        .add_test(systest!(canister_denylist_test))
        .add_test(systest!(reboot_test))
        .execute_from_args()?;

    Ok(())
}
