use anyhow::Result;

use ic_tests::{
    boundary_nodes::{
        api_boundary_nodes::{
            canister_routing_test, canister_test, direct_to_replica_options_test,
            direct_to_replica_test, nginx_valid_config_test, reboot_test,
            redirect_http_to_https_test,
        },
        constants::API_BOUNDARY_NODE_NAME,
        helpers::BoundaryNodeHttpsConfig,
        setup::{setup_ic_with_bn, BoundaryNodeType},
    },
    driver::group::{SystemTestGroup, SystemTestSubGroup},
    systest,
};

fn main() -> Result<()> {
    let setup = |env| {
        setup_ic_with_bn(
            API_BOUNDARY_NODE_NAME,
            BoundaryNodeType::ApiBoundaryNode,
            BoundaryNodeHttpsConfig::AcceptInvalidCertsAndResolveClientSide,
            env,
        )
    };
    SystemTestGroup::new()
        .with_setup(setup)
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
