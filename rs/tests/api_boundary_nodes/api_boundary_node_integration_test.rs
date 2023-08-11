#[rustfmt::skip]

use anyhow::Result;

use ic_tests::{
    api_boundary_nodes_integration::api_bn::{
        canister_routing_test, canister_test, direct_to_replica_options_test,
        direct_to_replica_test, mk_setup, nginx_valid_config_test, reboot_test,
        redirect_http_to_https_test, ApiBoundaryNodeHttpsConfig,
    },
    driver::group::{SystemTestGroup, SystemTestSubGroup},
    systest,
};

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(mk_setup(
            ApiBoundaryNodeHttpsConfig::AcceptInvalidCertsAndResolveClientSide,
        ))
        .add_parallel(
            SystemTestSubGroup::new()
                .add_test(systest!(canister_test))
                .add_test(systest!(nginx_valid_config_test))
                .add_test(systest!(redirect_http_to_https_test))
                .add_test(systest!(direct_to_replica_test))
                .add_test(systest!(direct_to_replica_options_test))
                .add_test(systest!(canister_routing_test)),
        )
        .add_test(systest!(reboot_test))
        .execute_from_args()?;

    Ok(())
}
