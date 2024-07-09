#[rustfmt::skip]

use anyhow::Result;

use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use ic_tests::consensus::payload_builder_test::{
    max_payload_size_config, max_xnet_payload_size_test,
};

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(max_payload_size_config)
        .add_test(systest!(max_xnet_payload_size_test))
        .execute_from_args()?;
    Ok(())
}
