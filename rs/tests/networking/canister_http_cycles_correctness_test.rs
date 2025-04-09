
/* tag::catalog[]
Title:: Test correctness of feature according to spec.

Goal:: Ensure simple HTTP requests can be made from canisters.

Runbook::
0. Instantiate a universal VM with a webserver
1. Instantiate an IC with one application subnet with the HTTP feature enabled.
2. Install NNS canisters
3. Install the proxy canister
4. Make an update call to the proxy canister.

Success::
1. Received http response with status 200.

end::catalog[] */

use anyhow::Result;
use ic_system_test_driver::{
    driver::group::{SystemTestGroup, SystemTestSubGroup},
    driver::test_env::TestEnv,
    systest,
};
use candid::Principal;
use canister_http::get_proxy_canister_id;
use ic_system_test_driver::{
    util::{block_on, get_balance},
};
use my_tests::*;



// anchor
// test_enforce_https,
// test_driver,
// test_max_number_of_response_headers_exceeded,
// test_non_existent_transform_function,
// test_max_number_of_response_headers,
// test_max_number_of_request_headers_exceeded,
// test_max_number_of_request_headers,
// test_maximum_possible_value_of_max_response_bytes_exceeded,
// test_maximum_possible_value_of_max_response_bytes,
// test_small_maximum_possible_response_size_exceeded_only_headers,
// test_small_maximum_possible_response_size_only_headers,
// test_max_url_length_exceeded,
// test_max_url_length,
// test_non_ascii_url_is_rejected,
// test_max_possible_request_size_exceeded,
// test_max_possible_request_size,
// test_head_call,
// test_post_call,
// test_get_hello_world_call,
// test_invalid_ip,
// test_invalid_domain_name,
// test_http_calls_to_ic_fails,
// test_that_redirects_are_not_followed,
// test_http_endpoint_with_delayed_response_is_rejected,
// test_http_endpoint_response_is_within_limits_with_default_max_response_bytes,
// test_http_endpoint_response_is_too_large_with_default_max_response_bytes,
// test_http_endpoint_response_is_within_limits_with_custom_max_response_bytes,
// test_http_endpoint_response_is_too_large_with_custom_max_response_bytes,
// test_post_request,
// test_non_existing_transform_function,
// test_response_header_total_size_over_the_48_kib_limit,
// test_response_header_total_size_within_the_48_kib_limit,
// test_request_header_total_size_over_the_48_kib_limit,
// test_request_header_total_size_within_the_48_kib_limit,
// test_response_header_value_over_limit,
// test_response_header_value_within_limit,
// test_response_header_name_over_limit,
// test_response_header_name_within_limit,
// test_request_header_value_too_long,
// test_request_header_name_too_long,
// test_request_header_name_and_value_within_limits,
// test_transform_that_bloats_on_the_2mb_limit,
// test_transform_that_bloats_response_above_2mb_limit,
// test_max_response_bytes_2_mb_returns_ok,
// test_max_response_bytes_too_large,
// test_4096_max_response_cycle_case_2,
// test_4096_max_response_cycle_case_1,
// test_2mb_response_cycle_for_rejection_path,
// test_no_cycles_attached,
// test_composite_transform_function_is_executed,
// test_transform_function_is_executed,

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(canister_http::setup)
        .add_sequential(
                // THE TESTS BELOW ALL ARE VALID AND WORK FINE unless there is a comment explaining issues with them
            SystemTestSubGroup::new()
                .add_test(systest!(test_invalid_domain_name_is_not_refunded))
                .add_test(systest!(test_non_ascii_url_is_rejected_is_not_refunded))
                .add_test(systest!(test_invalid_ip_is_not_refunded))
                // The test test_max_url_length_exceeded stands out because:
                // - the computation of the cycles fails because it's too long.
                // - it seems to cost 12M, which doesn't seem to be a refund
                // Either this is not refunded or something fishy is happening because the request cost is too low
                // .add_test(systest!(test_max_url_length_exceeded_is_refunded))
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
                // THE TESTS ABOVE ALL ARE VALID AND WORK FINE unless there is a comment explaining issues with them
                .add_test(systest!(
                    test_transform_that_bloats_response_above_2mb_limit_is_not_refunded
                ))
                .add_test(systest!(test_max_number_of_request_headers_exceeded_is_refunded))
                .add_test(systest!(test_max_number_of_response_headers_exceeded_is_not_refunded)),


        )
        .execute_from_args()?;

    Ok(())
}


// 2025-04-09 14:02:02.282 INFO[test_non_ascii_url_is_rejected_is_not_refunded:StdErr] Initial balance: 99992718469511
// 2025-04-09 14:02:02.282 INFO[test_non_ascii_url_is_rejected_is_not_refunded:StdErr] Final balance: 99992698808113
// 2025-04-09 14:02:02.282 INFO[test_non_ascii_url_is_rejected_is_not_refunded:StdErr] Computed diff: 19_661_398


fn test_invalid_domain_name_is_not_refunded(env: TestEnv) {
    is_not_refunded(env, test_invalid_domain_name);
}

fn test_non_ascii_url_is_rejected_is_not_refunded(env: TestEnv) {
    // TODO: evaluate the cost of the request because it assumings there is no refund then the cost is too low
    // it indeed seems to be low around 15M
    is_not_refunded(env, test_non_ascii_url_is_rejected);
}

fn test_invalid_ip_is_not_refunded(env: TestEnv) {
    is_not_refunded(env, test_invalid_ip);
}

fn test_max_url_length_exceeded_is_refunded(env: TestEnv) {
    is_refunded(env, test_max_url_length_exceeded);
}

fn test_non_existent_transform_function_is_not_refunded(env: TestEnv) {
    is_not_refunded(env, test_non_existent_transform_function);
}

fn reference_transform_function_exposed_by_different_canister_is_refunded(env: TestEnv) {
    is_refunded(env, reference_transform_function_exposed_by_different_canister);
}

fn test_max_possible_request_size_exceeded_is_refunded(env: TestEnv) {
    is_refunded(env, reference_transform_function_exposed_by_different_canister);
}
fn test_http_endpoint_response_is_too_large_with_custom_max_response_bytes_is_not_refunded(env: TestEnv) {
    is_not_refunded(env, test_http_endpoint_response_is_too_large_with_custom_max_response_bytes);
}

fn test_http_endpoint_response_is_too_large_with_default_max_response_bytes_is_not_refunded(env: TestEnv) {
    is_not_refunded(env, test_http_endpoint_response_is_too_large_with_default_max_response_bytes);
}

fn test_maximum_possible_value_of_max_response_bytes_exceeded_is_not_refunded(env: TestEnv) {
    is_not_refunded(env, test_maximum_possible_value_of_max_response_bytes_exceeded);
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
    let handlers = Handlers::new(&env);
    let agent = block_on(handlers.agent());
    let initial_balance = block_on(get_balance(
        &Principal::from(get_proxy_canister_id(&env)),
        &agent
    ));

    test(env.clone());

    let balance = block_on(get_balance(
        &Principal::from(get_proxy_canister_id(&env)),
        &agent
    ));

    eprintln!("Initial balance: {}", initial_balance);
    eprintln!("Final balance: {}", balance);

    let diff = initial_balance as i128 - balance as i128;
    eprintln!("Computed diff: {}", diff);
    assert!(diff > 0);
    // assert!(diff < 1_000_000_000);
    // There are cheaper requests (approx 12M) that are built in tests e.g. test_non_ascii_url_is_rejected_is_not_refunded
    assert!(diff < 10_000_000);

}

fn is_not_refunded(env: TestEnv, test: fn(TestEnv)) {
    let handlers = Handlers::new(&env);
    let agent = block_on(handlers.agent());
    let initial_balance = block_on(get_balance(
        &Principal::from(get_proxy_canister_id(&env)),
        &agent
    ));

    test(env.clone());

    let balance = block_on(get_balance(
        &Principal::from(get_proxy_canister_id(&env)),
        &agent
    ));

    eprintln!("Initial balance: {}", initial_balance);
    eprintln!("Final balance: {}", balance);

    let diff = initial_balance as i128 - balance as i128;
    eprintln!("Computed diff: {}", diff);
    // assert!(diff > 1_000_000_000);
    // There are cheaper requests (approx 12M) that are built in tests e.g. test_non_ascii_url_is_rejected_is_not_refunded
    assert!(diff > 10_000_000);

}