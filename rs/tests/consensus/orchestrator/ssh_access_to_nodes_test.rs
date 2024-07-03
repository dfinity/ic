#[rustfmt::skip]

use anyhow::Result;
use ic_system_test_driver::{driver::group::SystemTestGroup, systest};
use ic_tests::orchestrator::ssh_access_to_nodes::{
    can_add_max_number_of_readonly_and_backup_keys,
    cannot_add_more_than_max_number_of_readonly_or_backup_keys, config,
    keys_for_unassigned_nodes_can_be_updated, keys_in_the_subnet_record_can_be_updated,
    multiple_keys_can_access_one_account, multiple_keys_can_access_one_account_on_unassigned_nodes,
    readonly_cannot_authenticate_with_random_key, readonly_cannot_authenticate_without_a_key,
    root_cannot_authenticate, updating_readonly_does_not_remove_backup_keys,
};

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(config)
        .add_test(systest!(root_cannot_authenticate))
        .add_test(systest!(readonly_cannot_authenticate_without_a_key))
        .add_test(systest!(readonly_cannot_authenticate_with_random_key))
        .add_test(systest!(keys_in_the_subnet_record_can_be_updated))
        .add_test(systest!(keys_for_unassigned_nodes_can_be_updated))
        .add_test(systest!(multiple_keys_can_access_one_account))
        .add_test(systest!(
            multiple_keys_can_access_one_account_on_unassigned_nodes
        ))
        .add_test(systest!(updating_readonly_does_not_remove_backup_keys))
        .add_test(systest!(can_add_max_number_of_readonly_and_backup_keys))
        .add_test(systest!(
            cannot_add_more_than_max_number_of_readonly_or_backup_keys
        ))
        .execute_from_args()?;

    Ok(())
}
