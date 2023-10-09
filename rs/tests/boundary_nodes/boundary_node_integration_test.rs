#[rustfmt::skip]

use anyhow::Result;

use ic_tests::{
    boundary_nodes::{
        boundary_nodes_integration::{
            canister_allowlist_test, canister_routing_test, canister_test, denylist_test,
            direct_to_replica_options_test, direct_to_replica_rosetta_test, direct_to_replica_test,
            http_canister_test, icx_proxy_test, nginx_valid_config_test, reboot_test,
            redirect_http_to_https_test, redirect_to_dashboard_test, redirect_to_non_raw_test,
            seo_test, sw_test,
        },
        setup::{setup_ic_with_bn, BoundaryNodeType},
        {constants::BOUNDARY_NODE_NAME, helpers::BoundaryNodeHttpsConfig},
    },
    driver::group::{SystemTestGroup, SystemTestSubGroup},
    systest,
};

fn main() -> Result<()> {
    let setup = |env| {
        setup_ic_with_bn(
            BOUNDARY_NODE_NAME,
            BoundaryNodeType::BoundaryNode,
            BoundaryNodeHttpsConfig::AcceptInvalidCertsAndResolveClientSide,
            env,
        )
    };
    SystemTestGroup::new()
        .with_setup(setup)
        .add_parallel(
            SystemTestSubGroup::new()
                .add_test(systest!(canister_test))
                .add_test(systest!(http_canister_test))
                .add_test(systest!(nginx_valid_config_test))
                .add_test(systest!(redirect_http_to_https_test))
                .add_test(systest!(redirect_to_dashboard_test))
                .add_test(systest!(redirect_to_non_raw_test))
                .add_test(systest!(sw_test))
                .add_test(systest!(icx_proxy_test))
                .add_test(systest!(direct_to_replica_test))
                .add_test(systest!(direct_to_replica_rosetta_test))
                .add_test(systest!(direct_to_replica_options_test))
                .add_test(systest!(seo_test))
                .add_test(systest!(canister_routing_test)),
        )
        .add_test(systest!(denylist_test))
        .add_test(systest!(canister_allowlist_test))
        .add_test(systest!(reboot_test))
        .execute_from_args()?;

    Ok(())
}
