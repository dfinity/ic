use anyhow::Result;
use ic_tests::consensus::adding_nodes_to_subnet_test::{
    adding_new_nodes_to_subnet_test as test, setup,
};

use ic_system_test_driver::{driver::group::SystemTestGroup, systest};

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()
}
