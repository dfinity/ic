use anyhow::Result;

use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use ic_tests::message_routing::rejoin_test::Config;

const NUM_NODES: usize = 4;

fn main() -> Result<()> {
    let config = Config::new(NUM_NODES);
    let test = config.clone().test();
    SystemTestGroup::new()
        .with_setup(config.build())
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}
