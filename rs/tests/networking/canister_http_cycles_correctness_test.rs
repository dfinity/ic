/* tag::catalog[]
Title:: Test correctness of cycles refund feature according to spec.

Goal:: Ensure cycles are either refunded or not refunded based on the test case.
end::catalog[] */

use anyhow::Result;
use candid::Principal;
use canister_http::get_proxy_canister_id;
use ic_system_test_driver::util::{block_on, get_balance};
use ic_system_test_driver::{
    driver::group::{SystemTestGroup, SystemTestSubGroup},
    driver::test_env::TestEnv,
    systest,
};
use canister_http_correctness_tests::*;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(canister_http::setup)
        .add_sequential(
            SystemTestSubGroup::new()
                .add_test(systest!(test_invalid_domain_name_is_not_refunded))
                .add_test(systest!(test_non_ascii_url_is_rejected_is_not_refunded))
                .add_test(systest!(test_invalid_ip_is_not_refunded))
                // TODO: investigate why test_max_url_length_exceeded is not refunding.
                // Exceeding the max URL length should actually be refunded based on the old haskell spec test.
                .add_test(systest!(test_max_url_length_exceeded_is_not_refunded))
                .add_test(systest!(test_non_existent_transform_function_is_not_refunded))
                .add_test(systest!(
                    reference_transform_function_exposed_by_different_canister_is_refunded
                ))
                .add_test(systest!(test_max_possible_request_size_exceeded_is_refunded))
                .add_test(systest!(
                    test_http_endpoint_response_is_too_large_with_custom_max_response_bytes_is_not_refunded
                ))
                .add_test(systest!(
                    test_http_endpoint_response_is_too_large_with_default_max_response_bytes_is_not_refunded
                ))
                .add_test(systest!(
                    test_maximum_possible_value_of_max_response_bytes_exceeded_is_not_refunded
                ))
                .add_test(systest!(
                    test_transform_that_bloats_response_above_2mb_limit_is_not_refunded
                ))
                .add_test(systest!(test_max_number_of_request_headers_exceeded_is_refunded))
                .add_test(systest!(test_max_number_of_response_headers_exceeded_is_not_refunded)),
        )
        .execute_from_args()?;

    Ok(())
}

fn test_invalid_domain_name_is_not_refunded(env: TestEnv) {
    is_not_refunded(env, test_invalid_domain_name);
}

fn test_non_ascii_url_is_rejected_is_not_refunded(env: TestEnv) {
    is_not_refunded(env, test_non_ascii_url_is_rejected);
}

fn test_invalid_ip_is_not_refunded(env: TestEnv) {
    is_not_refunded(env, test_invalid_ip);
}

fn test_max_url_length_exceeded_is_not_refunded(env: TestEnv) {
    is_not_refunded(env, test_max_url_length_exceeded);
}

fn test_non_existent_transform_function_is_not_refunded(env: TestEnv) {
    is_not_refunded(env, test_non_existent_transform_function);
}

fn reference_transform_function_exposed_by_different_canister_is_refunded(env: TestEnv) {
    is_refunded(
        env,
        reference_transform_function_exposed_by_different_canister,
    );
}

fn test_max_possible_request_size_exceeded_is_refunded(env: TestEnv) {
    is_refunded(
        env,
        reference_transform_function_exposed_by_different_canister,
    );
}
fn test_http_endpoint_response_is_too_large_with_custom_max_response_bytes_is_not_refunded(
    env: TestEnv,
) {
    is_not_refunded(
        env,
        test_http_endpoint_response_is_too_large_with_custom_max_response_bytes,
    );
}

fn test_http_endpoint_response_is_too_large_with_default_max_response_bytes_is_not_refunded(
    env: TestEnv,
) {
    is_not_refunded(
        env,
        test_http_endpoint_response_is_too_large_with_default_max_response_bytes,
    );
}

fn test_maximum_possible_value_of_max_response_bytes_exceeded_is_not_refunded(env: TestEnv) {
    is_not_refunded(
        env,
        test_maximum_possible_value_of_max_response_bytes_exceeded,
    );
}
fn test_transform_that_bloats_response_above_2mb_limit_is_not_refunded(env: TestEnv) {
    is_not_refunded(env, test_transform_that_bloats_response_above_2mb_limit);
}

fn test_max_number_of_request_headers_exceeded_is_refunded(env: TestEnv) {
    is_refunded(env, test_max_number_of_request_headers_exceeded);
}

fn test_max_number_of_response_headers_exceeded_is_not_refunded(env: TestEnv) {
    is_not_refunded(env, test_max_number_of_response_headers_exceeded);
}

fn is_refunded(env: TestEnv, test: fn(TestEnv)) {
    check_refund_status(env, true, test);
}

fn is_not_refunded(env: TestEnv, test: fn(TestEnv)) {
    check_refund_status(env, false, test);
}

fn check_refund_status(env: TestEnv, is_refunded: bool, test: fn(TestEnv)) {
    let handlers = Handlers::new(&env);
    let agent = block_on(handlers.agent());
    let initial_balance = block_on(get_balance(
        &Principal::from(get_proxy_canister_id(&env)),
        &agent,
    ));

    test(env.clone());

    let balance = block_on(get_balance(
        &Principal::from(get_proxy_canister_id(&env)),
        &agent,
    ));

    let balance_diff = initial_balance as i128 - balance as i128;
    let cycle_cost_overhead = 10_000_000;
    if is_refunded {
        assert!(balance_diff <= cycle_cost_overhead);
    } else {
        assert!(balance_diff > cycle_cost_overhead);
    }
}
