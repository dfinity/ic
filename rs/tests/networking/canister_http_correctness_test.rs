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
    systest,
};
use canister_http_correctness_tests_lib::*;



fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(canister_http::setup)
        .add_parallel(
            SystemTestSubGroup::new()
                .add_test(systest!(test_enforce_https))
                .add_test(systest!(test_transform_function_is_executed))
                .add_test(systest!(test_composite_transform_function_is_executed))
                .add_test(systest!(test_no_cycles_attached))
                .add_test(systest!(test_2mb_response_cycle_for_rejection_path))
                .add_test(systest!(test_4096_max_response_cycle_case_1))
                .add_test(systest!(test_4096_max_response_cycle_case_2))
                .add_test(systest!(test_max_response_bytes_too_large))
                .add_test(systest!(test_max_response_bytes_2_mb_returns_ok))
                .add_test(systest!(
                    test_transform_that_bloats_response_above_2mb_limit
                ))
                .add_test(systest!(test_transform_that_bloats_on_the_2mb_limit))
                .add_test(systest!(test_request_header_name_and_value_within_limits))
                .add_test(systest!(test_request_header_name_too_long))
                .add_test(systest!(test_request_header_value_too_long))
                .add_test(systest!(test_response_header_name_within_limit))
                .add_test(systest!(test_response_header_name_over_limit))
                .add_test(systest!(test_response_header_value_within_limit))
                .add_test(systest!(test_response_header_value_over_limit))
                .add_test(systest!(
                    test_request_header_total_size_within_the_48_kib_limit
                ))
                .add_test(systest!(
                    test_request_header_total_size_over_the_48_kib_limit
                ))
                .add_test(systest!(
                    test_response_header_total_size_within_the_48_kib_limit
                ))
                .add_test(systest!(
                    test_response_header_total_size_over_the_48_kib_limit
                ))
                .add_test(systest!(test_post_request))
                .add_test(systest!(
                    test_http_endpoint_response_is_too_large_with_custom_max_response_bytes
                ))
                .add_test(systest!(
                    test_http_endpoint_response_is_within_limits_with_custom_max_response_bytes
                ))
                .add_test(systest!(
                    test_http_endpoint_response_is_too_large_with_default_max_response_bytes
                ))
                .add_test(systest!(
                    test_http_endpoint_response_is_within_limits_with_default_max_response_bytes
                ))
                .add_test(systest!(
                    test_http_endpoint_with_delayed_response_is_rejected
                ))
                .add_test(systest!(test_that_redirects_are_not_followed))
                .add_test(systest!(test_http_calls_to_ic_fails))
                .add_test(systest!(test_invalid_domain_name))
                .add_test(systest!(test_invalid_ip))
                .add_test(systest!(test_get_hello_world_call))
                .add_test(systest!(test_post_call))
                .add_test(systest!(test_head_call))
                .add_test(systest!(test_max_possible_request_size))
                .add_test(systest!(test_max_possible_request_size_exceeded))
                .add_test(systest!(test_non_ascii_url_is_rejected))
                .add_test(systest!(test_max_url_length))
                .add_test(systest!(test_max_url_length_exceeded))
                .add_test(systest!(
                    test_small_maximum_possible_response_size_only_headers
                ))
                .add_test(systest!(
                    test_small_maximum_possible_response_size_exceeded_only_headers
                ))
                .add_test(systest!(test_maximum_possible_value_of_max_response_bytes))
                .add_test(systest!(
                    test_maximum_possible_value_of_max_response_bytes_exceeded
                ))
                .add_test(systest!(check_caller_id_on_transform_function))
                .add_test(systest!(
                    reference_transform_function_exposed_by_different_canister
                ))
                .add_test(systest!(test_max_number_of_request_headers))
                .add_test(systest!(test_max_number_of_request_headers_exceeded))
                .add_test(systest!(test_max_number_of_response_headers))
                .add_test(systest!(test_non_existent_transform_function))
                .add_test(systest!(test_max_number_of_response_headers_exceeded)),
        )
        .execute_from_args()?;

    Ok(())
}
