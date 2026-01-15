mod general_execution_tests;

use anyhow::Result;
use general_execution_tests::api_tests::node_metrics_history_another_subnet_succeeds;
use general_execution_tests::api_tests::node_metrics_history_non_existing_subnet_fails;
use general_execution_tests::api_tests::node_metrics_history_query_fails;
use general_execution_tests::api_tests::test_controller;
use general_execution_tests::api_tests::test_cycles_burn;
use general_execution_tests::api_tests::test_in_replicated_execution;
use general_execution_tests::api_tests::test_raw_rand_api;
use general_execution_tests::api_tests::{root_key_on_nns_subnet, root_key_on_non_nns_subnet};
use general_execution_tests::big_stable_memory::*;
use general_execution_tests::canister_heartbeat::*;
use general_execution_tests::canister_lifecycle::*;
use general_execution_tests::cycles_transfer::*;
use general_execution_tests::ingress_rate_limiting::*;
use general_execution_tests::input_deduplication::input_deduplication_test;
use general_execution_tests::malicious_input::malicious_input_test;
use general_execution_tests::nns_shielding::*;
use general_execution_tests::queries::query_reply_sizes;
use general_execution_tests::security::stack_overflow;
use general_execution_tests::wasm_chunk_store::*;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::group::SystemTestSubGroup;
use ic_system_test_driver::driver::{
    ic::{InternetComputer, Subnet},
    test_env::TestEnv,
};
use ic_system_test_driver::systest;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_parallel(
            SystemTestSubGroup::new()
                .add_test(systest!(malicious_input_test))
                .add_test(systest!(input_deduplication_test))
                .add_test(systest!(test_raw_rand_api))
                .add_test(systest!(test_controller))
                .add_test(systest!(test_in_replicated_execution))
                .add_test(systest!(test_cycles_burn))
                .add_test(systest!(node_metrics_history_query_fails))
                .add_test(systest!(node_metrics_history_another_subnet_succeeds))
                .add_test(systest!(node_metrics_history_non_existing_subnet_fails))
                .add_test(systest!(can_access_big_heap_and_big_stable_memory))
                .add_test(systest!(can_access_big_stable_memory))
                .add_test(systest!(can_handle_overflows_when_indexing_stable_memory))
                .add_test(systest!(can_handle_out_of_bounds_access))
                .add_test(systest!(canister_traps_if_32_bit_api_used_on_big_memory))
                .add_test(systest!(create_canister_via_ingress_fails))
                .add_test(systest!(create_canister_via_canister_succeeds))
                .add_test(systest!(create_canister_with_one_controller))
                .add_test(systest!(create_canister_with_no_controllers))
                .add_test(systest!(create_canister_with_multiple_controllers))
                .add_test(systest!(create_canister_with_too_many_controllers_fails))
                .add_test(systest!(create_canister_with_no_settings_field))
                .add_test(systest!(create_canister_with_none_settings_field))
                .add_test(systest!(create_canister_with_empty_settings))
                .add_test(systest!(create_canister_with_settings))
                .add_test(systest!(provisional_create_canister_with_no_settings))
                .add_test(systest!(create_canister_with_freezing_threshold))
                .add_test(systest!(
                    create_canister_with_invalid_freezing_threshold_fails
                ))
                .add_test(systest!(managing_a_canister_with_wrong_controller_fails))
                .add_test(systest!(delete_stopped_canister_succeeds))
                .add_test(systest!(delete_running_canister_fails))
                .add_test(systest!(canister_can_manage_other_canister))
                .add_test(systest!(canister_can_manage_other_canister_batched))
                .add_test(systest!(canister_large_wasm_small_memory_allocation))
                .add_test(systest!(
                    canister_large_initial_memory_small_memory_allocation
                ))
                .add_test(systest!(refunds_after_uninstall_are_refunded))
                .add_test(systest!(update_settings_of_frozen_canister))
                .add_test(systest!(update_settings_multiple_controllers))
                .add_test(systest!(can_transfer_cycles_from_a_canister_to_another))
                .add_test(systest!(
                    trapping_with_large_blob_does_not_cause_cycles_underflow
                ))
                .add_test(systest!(
                    rejecting_with_large_blob_does_not_cause_cycles_underflow
                ))
                .add_test(systest!(canister_accepts_ingress_by_default))
                .add_test(systest!(empty_canister_inspect_rejects_all_messages))
                .add_test(systest!(canister_can_accept_ingress))
                .add_test(systest!(canister_only_accepts_ingress_with_payload))
                .add_test(systest!(canister_rejects_ingress_only_from_one_caller))
                .add_test(systest!(query_reply_sizes))
                .add_test(systest!(mint_cycles128_not_supported_on_application_subnet))
                .add_test(systest!(no_cycle_balance_limit_on_nns_subnet))
                .add_test(systest!(app_canister_attempt_initiating_dkg_fails))
                .add_test(systest!(canister_heartbeat_is_called_at_regular_intervals))
                .add_test(systest!(stopping_a_canister_with_a_heartbeat_succeeds))
                .add_test(systest!(canister_heartbeat_can_call_another_canister))
                .add_test(systest!(
                    canister_heartbeat_can_call_multiple_canisters_xnet
                ))
                .add_test(systest!(canister_heartbeat_can_stop))
                .add_test(systest!(canister_heartbeat_cannot_reply))
                .add_test(systest!(install_large_wasm))
                .add_test(systest!(install_large_wasm_with_other_store))
                .add_test(systest!(
                    install_large_wasm_with_other_store_fails_cross_subnet
                ))
                .add_test(systest!(stack_overflow))
                .add_test(systest!(root_key_on_nns_subnet))
                .add_test(systest!(root_key_on_non_nns_subnet)),
        )
        .execute_from_args()?;

    Ok(())
}

pub fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::fast_single_node(SubnetType::System))
        .add_subnet(Subnet::fast_single_node(SubnetType::VerifiedApplication))
        .add_subnet(Subnet::fast_single_node(SubnetType::Application))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}
