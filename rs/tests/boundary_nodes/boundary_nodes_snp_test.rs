#[rustfmt::skip]

use anyhow::Result;

use ic_tests::boundary_nodes::boundary_nodes_snp::{snp_basic_test, snp_kernel_test};
use ic_tests::boundary_nodes::setup::{setup_ic_with_bn, BoundaryNodeType};
use ic_tests::boundary_nodes::{
    constants::BOUNDARY_NODE_SNP_NAME, helpers::BoundaryNodeHttpsConfig,
};
use ic_tests::driver::group::SystemTestGroup;
use ic_tests::systest;

fn main() -> Result<()> {
    let setup = |env| {
        setup_ic_with_bn(
            BOUNDARY_NODE_SNP_NAME,
            BoundaryNodeType::BoundaryNode,
            BoundaryNodeHttpsConfig::AcceptInvalidCertsAndResolveClientSide,
            env,
        )
    };
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(snp_kernel_test))
        .add_test(systest!(snp_basic_test))
        .execute_from_args()?;

    Ok(())
}
