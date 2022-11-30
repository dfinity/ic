#[rustfmt::skip]

use anyhow::Result;

use ic_tests::consensus::payload_builder_test::{
    max_ingress_payload_size_test, max_payload_size_config,
};
use ic_tests::driver::new::group::SystemTestGroup;
use ic_tests::systest;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(max_payload_size_config)
        .add_test(systest!(max_ingress_payload_size_test))
        .execute_from_args()?;
    Ok(())
}
