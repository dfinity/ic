#[rustfmt::skip]

use anyhow::Result;

use ic_tests::boundary_nodes_snp_tests::boundary_nodes_snp::{
    config, snp_basic_test, snp_kernel_test,
};
use ic_tests::driver::new::group::SystemTestGroup;
use ic_tests::systest;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(config)
        .add_test(systest!(snp_kernel_test))
        .add_test(systest!(snp_basic_test))
        .execute_from_args()?;

    Ok(())
}
